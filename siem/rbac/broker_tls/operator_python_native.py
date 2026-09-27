"""Dormant current-process native mapping observer; NOT a loader or guard.

Requires an independently trusted root Linux interpreter, kernel and procfs.
Checks the nine C3 backing objects, not relocated/COW memory, symbol bindings,
earlier/unmapped loads or future dlopen. No commands, execution or writes.
Not in the entry capsule and not called by startup.
"""
from contextlib import ExitStack
from dataclasses import dataclass, field
import hashlib
import os
import re

from . import operator_core as core
from . import operator_fs as fs
from . import operator_python_policy as policy


MAX_MAPS = 1024 * 1024
MAX_ROWS = 4096
PAGE = 4096  # Candidate x86-64 policy, not a portable default.
_LINE = re.compile(
    r'([0-9a-f]{1,16})-([0-9a-f]{1,16}) ([r-][w-][x-][ps]) '
    r'([0-9a-f]{1,16}) ([0-9a-f]{2,8}):([0-9a-f]{2,8}) '
    r'([0-9]{1,20})(?: +([^ \n][^\n]*)| *)')
_SPECIAL = {'[heap]': 'rw-p', '[stack]': 'rw-p', '[vvar]': 'r--p',
            '[vvar_vclock]': 'r--p', '[vdso]': 'r-xp', '[vsyscall]': '--xp'}


@dataclass(frozen=True)
class _Map:
    start: int
    end: int
    permissions: str
    offset: int
    major: int
    minor: int
    inode: int
    path: str

    @property
    def link(self):
        return f'{self.start:x}-{self.end:x}'


def _parse_maps(raw):
    """Strict candidate policy on supplied bytes, never a live proof itself.

    Keep every file segment, including non-executable ones. Only anonymous
    non-executable private mappings and six explicit kernel names are allowed
    alongside the pinned files. No pathname unescaping or deleted-file fallback.
    Non-executable anonymous extents may change as the observer allocates.
    """
    core.require(type(raw) is bytes and 0 < len(raw) <= MAX_MAPS, 'PY_MAPS_SIZE')
    try:
        text = raw.decode('ascii')
    except UnicodeError:
        raise core.OperatorError('PY_MAPS_FORMAT') from None
    core.require(text.endswith('\n') and text.count('\n') <= MAX_ROWS,
                 'PY_MAPS_FORMAT')
    pins = {p.path: p for p in policy.MAPPED_FILES}
    groups = {path: [] for path in pins}
    selected, previous, specials = [], 0, set()
    for line in text[:-1].split('\n'):
        core.require(0 < len(line) <= 512, 'PY_MAPS_FORMAT')
        match = _LINE.fullmatch(line)
        core.require(match is not None, 'PY_MAPS_FORMAT')
        start, end, offset, major, minor = (int(match[i], 16) for i in (1, 2, 4, 5, 6))
        inode, perms, path = int(match[7]), match[3], match[8] or ''
        core.require(start >= previous and start < end and
                     not (start % PAGE or end % PAGE or offset % PAGE), 'PY_MAPS_RANGE')
        previous = end
        core.require(perms[3] == 'p' and not ('w' in perms and 'x' in perms), 'PY_MAPS_PERMISSIONS')
        row = _Map(start, end, perms, offset, major, minor, inode, path)
        if path in pins:
            core.require(inode > 0 and inode < 2**64 and (major or minor), 'PY_MAPS_IDENTITY')
            core.require(offset < pins[path].size and
                         offset + end - start <= ((pins[path].size + PAGE - 1) // PAGE) * PAGE,
                         'PY_MAPS_FILE_RANGE')
            groups[path].append(row)
            core.require(len(groups[path]) <= 16, 'PY_MAPS_SEGMENTS')
            selected.append(row)
        else:
            core.require(inode == major == minor == offset == 0, 'PY_MAPS_UNEXPECTED')
            if path:
                core.require(path in _SPECIAL and perms == _SPECIAL[path] and path not in specials,
                             'PY_MAPS_UNEXPECTED')
                specials.add(path)
                if 'x' in perms:
                    selected.append(row)
            else:
                core.require('x' not in perms, 'PY_MAPS_ANONYMOUS_EXEC')
    for rows in groups.values():
        core.require(rows and any(r.offset == 0 and r.permissions[0] == 'r' for r in rows)
                     and any(r.permissions == 'r-xp' for r in rows), 'PY_MAPS_MISSING')
        core.require(len({(r.major, r.minor, r.inode) for r in rows}) == 1,
                     'PY_MAPS_IDENTITY')
    core.require('[vdso]' in specials, 'PY_MAPS_VDSO')
    return tuple(selected)


def _key(st):
    # Proc directory times/size change normally; identity and policy still held.
    return st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid


def _open_checked(stack, parent, name, records, *, directory, proc=False):
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    fs._trusted(before, directory, ((0, 0),))
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    fd = os.open(name, flags | (os.O_DIRECTORY if directory else 0), dir_fd=parent)
    stack.callback(os.close, fd)
    stamp = _key if proc else fs._stamp
    core.require(stamp(before) == stamp(os.fstat(fd)), 'PY_NATIVE_CHANGED')
    records.append((parent, name, fd, stamp, stamp(before)))
    return fd


def _recheck(records):
    for parent, name, fd, stamp, original in reversed(records):
        core.require(original == stamp(os.fstat(fd)) == stamp(
            os.stat(name, dir_fd=parent, follow_symlinks=False)), 'PY_NATIVE_CHANGED')


def _read_maps(directory):
    # procfs files report size zero: bound actual bytes, not st_size.
    with ExitStack() as stack:
        records = []
        fd = _open_checked(stack, directory, 'maps', records, directory=False, proc=True)
        data = bytearray()
        while len(data) <= MAX_MAPS:
            part = os.read(fd, min(65536, MAX_MAPS + 1 - len(data)))
            if not part:
                break
            data.extend(part)
        core.require(len(data) <= MAX_MAPS, 'PY_MAPS_SIZE')
        _recheck(records)
        return _parse_maps(bytes(data))


def _hold_named(stack, root, pin, records):
    parent = root
    parts = tuple(pin.path.split('/')[1:])
    fs._components(parts)
    for i, name in enumerate(parts):
        parent = _open_checked(stack, parent, name, records, directory=i < len(parts) - 1)
    return parent


def _identity(st):
    return os.major(st.st_dev), os.minor(st.st_dev), st.st_ino


def _check_link(directory, row, expected):
    core.require(os.readlink(row.link, dir_fd=directory) == row.path, 'PY_NATIVE_LINK')
    # Explicit, fixed procfs magic-link exception; never open the returned text.
    current = os.stat(row.link, dir_fd=directory, follow_symlinks=True)
    core.require(fs._stamp(current) == fs._stamp(expected) and
                 _identity(current) == (row.major, row.minor, row.inode), 'PY_NATIVE_IDENTITY')


def _hash_fd(fd, pin, expected):
    core.require(fs._stamp(os.fstat(fd)) == fs._stamp(expected), 'PY_NATIVE_CHANGED')
    core.require(expected.st_size == pin.size, 'PY_NATIVE_SIZE')
    os.lseek(fd, 0, os.SEEK_SET)
    count, digest = 0, hashlib.sha256()
    while count <= pin.size:
        part = os.read(fd, min(65536, pin.size + 1 - count))
        if not part:
            break
        count += len(part)
        digest.update(part)
    core.require(count == pin.size, 'PY_NATIVE_SIZE')
    core.require(digest.hexdigest() == pin.sha256, 'PY_NATIVE_DIGEST')
    core.require(fs._stamp(os.fstat(fd)) == fs._stamp(expected), 'PY_NATIVE_CHANGED')


@dataclass(frozen=True)
class PythonNativeObservation:
    file_count: int = field(default=9, init=False)
    byte_passes: int = field(default=2, init=False)
    maps_reads: int = field(default=4, init=False)
    mapped_backing_pins_match: bool = field(default=True, init=False)
    native_resolution_proven: bool = field(default=False, init=False)
    loaded_memory_proven: bool = field(default=False, init=False)
    symbol_bindings_proven: bool = field(default=False, init=False)
    package_authenticity_proven: bool = field(default=False, init=False)
    atomic_snapshot_proven: bool = field(default=False, init=False)
    runtime_trusted: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)


def observe_python_native():
    """No-argument, fresh self observation; no report/path/PID/reader injection.

    Hold root-owned no-follow canonical files and kernel map_files backing FDs.
    Hash the mapped backing objects twice, bracketed by four maps reads. Require
    each segment's dev/inode and link target to match the held named object, and
    /proc/<self>/exe to match the interpreter pin. Fail on denied proc access;
    never downgrade to pathname-only hashing. Procfs/kernel are prerequisites.

    Equal file segments are not an atomic snapshot. Anonymous non-executable
    extents may grow; memory bytes/relocations are not inspected. This observer
    cannot retroactively secure loader initialization or bootstrap its own trust.
    """
    try:
        fs._platform()
        core.require(os.readlink in os.supports_dir_fd and
                     all(hasattr(os, n) for n in ('major', 'minor', 'lseek', 'getpid')),
                     'PY_NATIVE_PLATFORM')
        pid = os.getpid()
        core.require(type(pid) is int and 1 < pid < 2**32, 'PY_NATIVE_PID')
        with ExitStack() as stack:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            root = os.open('/', flags)
            stack.callback(os.close, root)
            root_st = os.fstat(root)
            fs._trusted(root_st, True, ((0, 0),))
            records = []
            proc = _open_checked(stack, root, 'proc', records, directory=True, proc=True)
            current = _open_checked(stack, proc, str(pid), records, directory=True, proc=True)
            links = _open_checked(stack, current, 'map_files', records, directory=True, proc=True)
            rows = _read_maps(current)
            backing = {}
            for pin in policy.MAPPED_FILES:
                named = _hold_named(stack, root, pin, records)
                before = os.fstat(named)
                core.require(before.st_size == pin.size, 'PY_NATIVE_SIZE')
                row = next(r for r in rows if r.path == pin.path and r.offset == 0)
                _check_link(links, row, before)
                fd = os.open(row.link, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=links)
                stack.callback(os.close, fd)
                core.require(fs._stamp(before) == fs._stamp(os.fstat(fd)), 'PY_NATIVE_IDENTITY')
                backing[pin.path] = (fd, before)
            for number in range(2):
                if number:
                    core.require(_read_maps(current) == rows, 'PY_NATIVE_MAPS_CHANGED')
                for row in rows:
                    if row.path in backing:
                        _check_link(links, row, backing[row.path][1])
                for pin in policy.MAPPED_FILES:
                    fd, before = backing[pin.path]
                    _hash_fd(fd, pin, before)
                core.require(os.readlink('exe', dir_fd=current) == policy.MAPPED_FILES[0].path and
                             fs._stamp(os.stat('exe', dir_fd=current, follow_symlinks=True)) ==
                             fs._stamp(backing[policy.MAPPED_FILES[0].path][1]), 'PY_NATIVE_EXECUTABLE')
                core.require(_read_maps(current) == rows, 'PY_NATIVE_MAPS_CHANGED')
                for row in rows:
                    if row.path in backing:
                        _check_link(links, row, backing[row.path][1])
                _recheck(records)
                core.require(fs._stamp(root_st) == fs._stamp(os.fstat(root)), 'PY_NATIVE_CHANGED')
            return PythonNativeObservation()
    except OSError as error:
        raise core.OperatorError(fs._os_error_code(error)) from None
