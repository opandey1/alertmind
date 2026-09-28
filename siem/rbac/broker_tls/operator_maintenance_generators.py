"""Dormant default-path unit/environment-generator inventory, no admission.

Requires an already trusted root/Linux host and runtime. Does not inspect PID1's
environment, invoke systemd, follow generator symlinks or import observed bytes.
Default-directory precedence is evidence for review, NOT effective selection.
"""
from contextlib import ExitStack
from dataclasses import dataclass, field, asdict
import hashlib
import json
import os
import stat
import threading
import time

from . import operator_core as core
from . import operator_fs as fs

DIRECTORIES = (
    ('run', 'systemd', 'system-generators'),
    ('etc', 'systemd', 'system-generators'),
    ('usr', 'local', 'lib', 'systemd', 'system-generators'),
    ('usr', 'lib', 'systemd', 'system-generators'),
)
ENV_DIRECTORIES = (
    ('run', 'systemd', 'system-environment-generators'),
    ('etc', 'systemd', 'system-environment-generators'),
    ('usr', 'local', 'lib', 'systemd', 'system-environment-generators'),
    ('usr', 'lib', 'systemd', 'system-environment-generators'),
)
MAX_ENTRIES = 256  # Across one pass, including both classes and shadowed entries.
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024  # Per pass, including link text.
MAX_LINK_BYTES = 4096
MAX_WINDOW_NS = 30_000_000_000
CHUNK = 64 * 1024


@dataclass(frozen=True)
class GeneratorEntry:
    directory: int
    name: str
    kind: str
    bytes: int
    mode: int
    uid: int
    gid: int
    sha256: str
    # All earlier same-named entries, even non-executable files/symlinks.
    # This is not a statement that these entries mask a later executable.
    earlier_same_name: tuple


@dataclass(frozen=True)
class GeneratorInventory:
    directories: tuple
    entries: tuple
    inventory_sha256: str
    collection_elapsed_ms: int
    passes: int = field(default=2, init=False)
    effective_search_path_proven: bool = field(default=False, init=False)
    effective_selection_proven: bool = field(default=False, init=False)
    symlink_targets_verified: bool = field(default=False, init=False)
    generator_effects_proven: bool = field(default=False, init=False)
    dependency_closure_proven: bool = field(default=False, init=False)
    package_authenticity_proven: bool = field(default=False, init=False)
    atomic_snapshot_proven: bool = field(default=False, init=False)
    continuous_control_proven: bool = field(default=False, init=False)
    mutation_authorized: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)
    review_required: bool = field(default=True, init=False)


@dataclass(frozen=True)
class GeneratorCatalog:
    unit: GeneratorInventory
    environment: GeneratorInventory
    catalog_sha256: str
    collection_elapsed_ms: int
    passes: int = field(default=2, init=False)
    effective_search_paths_proven: bool = field(default=False, init=False)
    effective_selection_proven: bool = field(default=False, init=False)
    symlink_targets_verified: bool = field(default=False, init=False)
    generator_effects_proven: bool = field(default=False, init=False)
    generated_environment_proven: bool = field(default=False, init=False)
    dependency_closure_proven: bool = field(default=False, init=False)
    package_authenticity_proven: bool = field(default=False, init=False)
    atomic_snapshot_proven: bool = field(default=False, init=False)
    continuous_control_proven: bool = field(default=False, init=False)
    mutation_authorized: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)
    review_required: bool = field(default=True, init=False)


def _clock():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def _same(before, after):
    core.require(fs._stamp(before) == fs._stamp(after), 'GENERATORS_CHANGED')


def _name(name):
    fs._components((name,))  # Bounded ASCII components; no traversal/control text.


def _charge(budget, amount):
    budget[1] += amount
    core.require(budget[1] <= MAX_TOTAL_BYTES, 'GENERATORS_BYTES')


def _leaf(directory, name, budget, check):
    check()
    before = os.stat(name, dir_fd=directory, follow_symlinks=False)
    mode = before.st_mode
    if stat.S_ISLNK(mode):
        # Symlink permissions normally are 0777. Ownership, not these write
        # bits, governs the link; its parent must pass the directory policy.
        core.require((before.st_uid, before.st_gid) == (0, 0), 'GENERATORS_OWNER')
        core.require(0 < before.st_size <= MAX_LINK_BYTES, 'GENERATORS_LINK')
        target = os.readlink(name, dir_fd=directory)
        raw = os.fsencode(target)
        core.require(0 < len(raw) <= MAX_LINK_BYTES and len(raw) == before.st_size,
                     'GENERATORS_LINK')
        _charge(budget, len(raw))
        digest = hashlib.sha256(raw).hexdigest()
        # Only the literal is observed. Do not claim /dev/null's target/device
        # has been verified, and never open an arbitrary target.
        kind = 'null_link_literal' if raw == b'/dev/null' else 'unresolved_symlink'
    else:
        fs._trusted(before, False, ((0, 0),))  # Reject dirs/FIFOs/devices/sockets.
        core.require(0 <= before.st_size <= MAX_FILE_BYTES, 'GENERATORS_SIZE')
        _charge(budget, before.st_size)
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        fd = os.open(name, flags, dir_fd=directory)
        try:
            _same(before, os.fstat(fd))
            digest_state = hashlib.sha256()
            length = 0
            while True:
                check()
                chunk = os.read(fd, min(CHUNK, before.st_size + 1 - length))
                check()
                if not chunk:
                    break
                length += len(chunk)
                core.require(length <= before.st_size, 'GENERATORS_CHANGED')
                digest_state.update(chunk)
            core.require(length == before.st_size, 'GENERATORS_CHANGED')
            _same(before, os.fstat(fd))
            digest = digest_state.hexdigest()
        finally:
            os.close(fd)
        kind = ('empty_regular' if before.st_size == 0 else
                'executable_regular' if mode & 0o111 else 'nonexecutable_regular')
    check()
    _same(before, os.stat(name, dir_fd=directory, follow_symlinks=False))
    return (kind, before.st_size, stat.S_IMODE(mode), before.st_uid,
            before.st_gid, digest), fs._stamp(before)


def _directory_at(root, parts, budget, check):
    """Private descriptor-relative primitive. No public root/path override."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    with ExitStack() as stack:
        initial = os.fstat(root)
        fs._trusted(initial, True, ((0, 0),))
        ancestors = []
        parent = root
        missing = None
        for name in parts:
            check()
            try:
                before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                missing = (parent, name)
                break  # ENOENT only: denied access is never reported absent.
            fs._trusted(before, True, ((0, 0),))
            fd = os.open(name, flags, dir_fd=parent)
            stack.callback(os.close, fd)
            _same(before, os.fstat(fd))
            ancestors.append((parent, name, fd, before))
            parent = fd
        rows = []
        if missing is None:
            names = set()
            with os.scandir(parent) as entries:
                for entry in entries:
                    check()
                    name = entry.name
                    _name(name)
                    core.require(name not in names, 'GENERATORS_DUPLICATE')
                    names.add(name)
                    budget[0] += 1
                    core.require(budget[0] <= MAX_ENTRIES, 'GENERATORS_COUNT')
            for name in sorted(names):
                data, stamp = _leaf(parent, name, budget, check)
                rows.append((name, data, stamp))
            # Recheck each name after the entire directory read, not just its
            # individual hash. No atomic or future-writer exclusion claim.
            for name, _, stamp in rows:
                check()
                core.require(stamp == fs._stamp(os.stat(name, dir_fd=parent,
                                     follow_symlinks=False)), 'GENERATORS_CHANGED')
        else:
            check()
            try:
                os.stat(missing[1], dir_fd=missing[0], follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise core.OperatorError('GENERATORS_CHANGED')
        for directory, name, fd, before in reversed(ancestors):
            check()
            _same(before, os.fstat(fd))
            _same(before, os.stat(name, dir_fd=directory, follow_symlinks=False))
        _same(initial, os.fstat(root))
        # Include held ancestor metadata and the first absent component in the
        # private equality check, not in the portable content inventory digest.
        stamps = (fs._stamp(initial), tuple((name, fs._stamp(before))
                  for _, name, _, before in ancestors), None if missing is None else missing[1])
        return missing is None, tuple(rows), stamps


def _scan_at(root, check, paths=DIRECTORIES, budget=None):
    # Test-only descriptor root; production always starts at the held `/` FD.
    core.require(paths in (DIRECTORIES, ENV_DIRECTORIES), 'GENERATORS_SCOPE')
    if budget is None:
        budget = [0, 0]
    return tuple(_directory_at(root, parts, budget, check) for parts in paths)


def _result(snapshot, elapsed, paths=DIRECTORIES):
    core.require(paths in (DIRECTORIES, ENV_DIRECTORIES) and len(snapshot) == len(paths),
                 'GENERATORS_SCOPE')
    entries = []
    seen = {}
    directories = []
    for index, (present, rows, _) in enumerate(snapshot):
        directories.append(('/' + '/'.join(paths[index]), present))
        for name, data, _ in rows:
            entries.append(GeneratorEntry(index, name, *data, tuple(seen.get(name, ()))))
            seen.setdefault(name, []).append(index)
    payload = dict(version=1, directories=directories,
                   entries=[asdict(entry) for entry in entries])
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':'),
                                      ensure_ascii=True).encode('ascii')).hexdigest()
    return GeneratorInventory(tuple(directories), tuple(entries), digest, elapsed)


def _collect(groups):
    core.require(groups in ((DIRECTORIES,), (ENV_DIRECTORIES,),
                            (DIRECTORIES, ENV_DIRECTORIES)), 'GENERATORS_SCOPE')
    try:
        fs._platform()
        core.require(hasattr(time, 'CLOCK_BOOTTIME') and hasattr(time, 'clock_gettime_ns')
                     and os.scandir in os.supports_fd and os.readlink in os.supports_dir_fd,
                     'GENERATORS_PLATFORM')
        owner = os.getpid(), threading.get_native_id()
        started = previous = _clock()

        def check():
            nonlocal previous
            core.require((os.getpid(), threading.get_native_id()) == owner, 'GENERATORS_CALLER')
            now = _clock()
            core.require(previous <= now and 0 <= now - started < MAX_WINDOW_NS,
                         'GENERATORS_TIMEOUT')
            previous = now

        check()
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open('/', flags)
        try:
            def scan():
                # One aggregate limit per pass. A large unit directory cannot
                # hide environment-generator bytes or entries from the budget.
                budget = [0, 0]
                return tuple(_scan_at(fd, check, paths, budget) for paths in groups)

            first = scan()
            check()
            second = scan()
            check()
            core.require(first == second, 'GENERATORS_CHANGED')
            elapsed = (previous - started) // 1_000_000
            inventories = tuple(_result(snapshot, elapsed, paths)
                                for snapshot, paths in zip(first, groups))
            if len(groups) == 1:
                result = inventories[0]
            else:
                unit, environment = inventories
                payload = dict(version=1, unit=unit.inventory_sha256,
                               environment=environment.inventory_sha256)
                digest = hashlib.sha256(json.dumps(payload, sort_keys=True,
                                     separators=(',', ':')).encode('ascii')).hexdigest()
                result = GeneratorCatalog(unit, environment, digest, elapsed)
        finally:
            os.close(fd)
        check()  # No successful receipt on cleanup/window/caller failure.
        return result
    except OSError as error:
        raise core.OperatorError(fs._os_error_code(error)) from None


def observe_maintenance_generators():
    """Unit generators only; preserved no-argument read-only candidate."""
    return _collect((DIRECTORIES,))


def observe_maintenance_environment_generators():
    """System environment generators only; no values/outputs are inspected."""
    return _collect((ENV_DIRECTORIES,))


def observe_maintenance_generator_catalog():
    """Both default-path classes in one held-root/window, not an atomic snapshot."""
    return _collect((DIRECTORIES, ENV_DIRECTORIES))
