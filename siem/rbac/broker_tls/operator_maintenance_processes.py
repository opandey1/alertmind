"""Read-only, bounded process-leader census; not host-wide quiescence proof.

Find service UID/GID or exact packaged-Node-path candidates inside/outside the
Dashboard unit. No argv, environment, executable contents, signals or writes.
Requires trusted host namespaces, procfs/kernel and root/Python/busctl context.
No CLI, guard/planner wiring, receipt replay or permission to perform maintenance.
"""
from contextlib import ExitStack
from dataclasses import dataclass, field
import hashlib
import os
import re
import stat
import time

from . import operator_core as core
from . import operator_fs as fs
from . import operator_maintenance_cgroup as cg
from . import operator_maintenance_state as state

LIMITS = {'stat': 8192, 'status': 65536, 'cgroup': 8192}
MAX_PIDS = 8192
MAX_ENTRIES = 16384
MAX_COLLECTION_NS = 30_000_000_000
PF_KTHREAD = 0x00200000  # Candidate Linux policy; native compatibility still required.


def _uint(raw, maximum, code):
    core.require(re.fullmatch(rb'(?:0|[1-9][0-9]{0,19})', raw) is not None, code)
    value = int(raw)
    core.require(value <= maximum, code)
    return value


def _stat_record(raw, pid):
    core.require(type(raw) is bytes and 0 < len(raw) <= LIMITS['stat']
                 and raw.startswith(str(pid).encode() + b' (') and raw.endswith(b'\n'), 'CENSUS_STAT')
    end = raw.rfind(b') ')
    items = raw[end + 2:].split() if end >= 0 else []
    core.require(len(items) >= 20 and items[0] in
                 (b'R', b'S', b'D', b'Z', b'T', b't', b'W', b'X', b'x', b'K', b'P', b'I'), 'CENSUS_STAT')
    flags = _uint(items[6], 2**32 - 1, 'CENSUS_STAT')
    start = _uint(items[19], 2**64 - 1, 'CENSUS_STAT')
    # PID 1 / early kernel tasks can have starttime zero. Boot binding is separate.
    return start, bool(flags & PF_KTHREAD), items[0] == b'Z'


def _status(raw, pid):
    core.require(type(raw) is bytes and 0 < len(raw) <= LIMITS['status']
                 and raw.endswith(b'\n'), 'CENSUS_STATUS')
    fields = {}
    selected = (b'Uid', b'Gid', b'Pid', b'Tgid', b'Threads')
    for line in raw.split(b'\n'):
        name, sep, data = line.partition(b':')
        if name in selected:
            core.require(sep and name not in fields, 'CENSUS_STATUS')
            fields[name] = tuple(_uint(v, 2**32 - 1, 'CENSUS_STATUS') for v in data.split())
    core.require(set(fields) == set(selected) and len(fields[b'Uid']) == 4
                 and len(fields[b'Gid']) == 4 and fields[b'Pid'] == (pid,)
                 and fields[b'Tgid'] == (pid,) and len(fields[b'Threads']) == 1
                 and 0 < fields[b'Threads'][0] <= MAX_PIDS, 'CENSUS_STATUS')
    return fields[b'Uid'], fields[b'Gid'], fields[b'Threads'][0]


def _membership(raw):
    core.require(type(raw) is bytes and 0 < len(raw) <= LIMITS['cgroup']
                 and raw.startswith(b'0::/') and raw.endswith(b'\n')
                 and b'\n' not in raw[:-1] and b'\x00' not in raw, 'CENSUS_CGROUP')
    path = raw[3:-1]
    core.require(path == b'/' or all(p and p not in (b'.', b'..') for p in path[1:].split(b'/')),
                 'CENSUS_CGROUP')
    unit = cg.CGROUP_NAME.encode('ascii')
    return path == unit or path.startswith(unit + b'/')


def _proc_device(raw):
    core.require(type(raw) is bytes and 0 < len(raw) <= cg.MAX_MOUNTINFO
                 and raw.endswith(b'\n'), 'CENSUS_MOUNT')
    rows = raw[:-1].split(b'\n')
    core.require(len(rows) <= 4096, 'CENSUS_MOUNT')
    found, ids = [], set()
    for row in rows:
        halves = row.split(b' - ')
        core.require(len(halves) == 2, 'CENSUS_MOUNT')
        left, right = halves[0].split(b' '), halves[1].split(b' ')
        core.require(len(left) >= 6 and len(right) == 3 and all(left + right), 'CENSUS_MOUNT')
        mount_id = _uint(left[0], 2**64 - 1, 'CENSUS_MOUNT')
        _uint(left[1], 2**64 - 1, 'CENSUS_MOUNT')
        core.require(mount_id > 0 and mount_id not in ids, 'CENSUS_MOUNT')
        ids.add(mount_id)
        core.require(re.fullmatch(rb'[0-9]{1,10}:[0-9]{1,10}', left[2]) is not None, 'CENSUS_MOUNT')
        if left[4].startswith(b'/proc/'):
            component = left[4][6:].split(b'/')[0]
            boot_path = b'/proc/sys/kernel/random/boot_id'
            shadows_boot = boot_path == left[4] or boot_path.startswith(left[4] + b'/')
            core.require(not component.isdigit() and not shadows_boot, 'CENSUS_PROC_SUBMOUNT')
        if left[4] == b'/proc':
            core.require(left[3] == b'/' and right[0] == b'proc', 'CENSUS_MOUNT')
            options = left[5].split(b',') + right[2].split(b',')
            core.require(all((not o.startswith(b'hidepid') or o == b'hidepid=0')
                             and not o.startswith(b'subset') for o in options), 'CENSUS_VISIBILITY')
            found.append(tuple(int(n) for n in left[2].split(b':')))
    core.require(len(found) == 1, 'CENSUS_MOUNT')
    return found[0]


def _tick(deadline):
    core.require(time.clock_gettime_ns(time.CLOCK_BOOTTIME) <= deadline, 'CENSUS_TIMEOUT')


def _pids(proc, deadline):
    values = set()
    with os.scandir(proc) as entries:
        for count, entry in enumerate(entries, 1):
            _tick(deadline)
            core.require(count <= MAX_ENTRIES, 'CENSUS_COUNT')
            name = entry.name
            if name.isascii() and name.isdecimal():
                value = _uint(name.encode('ascii'), 2**31 - 1, 'CENSUS_PID')
                core.require(value > 0 and value not in values, 'CENSUS_PID')
                values.add(value)
                core.require(len(values) <= MAX_PIDS, 'CENSUS_COUNT')
    core.require(1 in values and os.getpid() in values, 'CENSUS_VISIBILITY')
    return tuple(sorted(values))


def _metadata(value, directory, device):
    # Procfs files have kernel-defined per-process owners, NOT a root-only policy.
    # A verified procfs mount and trusted kernel are required before using this.
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    core.require(kind(value.st_mode) and value.st_dev == device
                 and not value.st_mode & 0o6222, 'CENSUS_METADATA')


def _small(directory, name, device, deadline):
    core.require(name in LIMITS, 'CENSUS_TARGET')
    _tick(deadline)
    before = os.stat(name, dir_fd=directory, follow_symlinks=False)
    _metadata(before, False, device)
    core.require(0 <= before.st_size <= LIMITS[name], 'CENSUS_SIZE')
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory)
    try:
        key = cg._key(before)
        core.require(key == cg._key(os.fstat(fd)), 'CENSUS_CHANGED')
        raw = bytearray()
        while len(raw) <= LIMITS[name]:
            _tick(deadline)
            part = os.read(fd, min(4096, LIMITS[name] + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        core.require(len(raw) <= LIMITS[name], 'CENSUS_SIZE')
        core.require(key == cg._key(os.fstat(fd)) == cg._key(
            os.stat(name, dir_fd=directory, follow_symlinks=False)), 'CENSUS_CHANGED')
        return bytes(raw)
    finally:
        os.close(fd)


def _exe(directory, device):
    before = os.stat('exe', dir_fd=directory, follow_symlinks=False)
    core.require(stat.S_ISLNK(before.st_mode) and before.st_dev == device, 'CENSUS_EXE')
    try:
        target = os.readlink('exe', dir_fd=directory)
    except FileNotFoundError:
        target = None  # Only caller's kernel/zombie policy may accept this.
    core.require(target is None or (type(target) is str and 0 < len(target) <= 4096
                                   and '\x00' not in target), 'CENSUS_EXE')
    core.require(cg._key(before) == cg._key(os.stat('exe', dir_fd=directory, follow_symlinks=False)),
                 'CENSUS_CHANGED')
    return target


@dataclass(frozen=True, repr=False)
class _Record:
    pid: int
    start: int
    service_identity: bool
    packaged_node_path: bool
    in_unit: bool
    token: tuple


def _process(proc, pid, identity, device, deadline):
    name = str(pid)
    before = os.stat(name, dir_fd=proc, follow_symlinks=False)
    _metadata(before, True, device)
    directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=proc)
    try:
        key = cg._key(before)
        core.require(key == cg._key(os.fstat(directory)), 'CENSUS_CHANGED')
        def sample():
            _tick(deadline)
            start, kernel, zombie = _stat_record(_small(directory, 'stat', device, deadline), pid)
            uids, gids, threads = _status(_small(directory, 'status', device, deadline), pid)
            group = _small(directory, 'cgroup', device, deadline)
            inside = _membership(group)
            executable = _exe(directory, device)
            core.require(executable is not None or kernel or (zombie and threads == 1), 'CENSUS_EXE_MISSING')
            service = identity[0] in uids or identity[1] in gids
            node = executable in (core.NODE, core.NODE + ' (deleted)')
            # Retain private hashes for equality, never executable/path text in output.
            token = (uids, gids, threads, kernel, zombie, hashlib.sha256(group).digest(),
                     None if executable is None else hashlib.sha256(executable.encode('utf-8')).digest())
            return _Record(pid, start, service, node, inside, token)
        first = sample()
        core.require(sample() == first, 'CENSUS_CHANGED')
        core.require(key == cg._key(os.fstat(directory)) == cg._key(
            os.stat(name, dir_fd=proc, follow_symlinks=False)), 'CENSUS_CHANGED')
        return first
    finally:
        os.close(directory)


@dataclass(frozen=True)
class _Scan:
    boot_id: str
    records: tuple = field(repr=False)
    token: tuple = field(repr=False)


def _native_scan(identity, deadline):
    with ExitStack() as stack:
        root = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        stack.callback(os.close, root)
        tree = cg._Tree(root, stack)
        boot = tree.read(cg.BOOT_PARTS, 37)
        boot_id = cg._boot(boot[0])
        mount_path = ('proc', str(os.getpid()), 'mountinfo')
        mount = tree.read(mount_path, cg.MAX_MOUNTINFO)
        device = _proc_device(mount[0])
        proc = tree.directory(('proc',))
        st = os.fstat(proc)
        core.require((os.major(st.st_dev), os.minor(st.st_dev)) == device, 'CENSUS_DEVICE')
        names = _pids(proc, deadline)
        records = tuple(_process(proc, pid, identity, st.st_dev, deadline) for pid in names)
        core.require(names == _pids(proc, deadline), 'CENSUS_CHANGED')
        core.require(boot == tree.read(cg.BOOT_PARTS, 37)
                     and mount == tree.read(mount_path, cg.MAX_MOUNTINFO), 'CENSUS_CHANGED')
        metadata = tree.verify()
        _tick(deadline)
        return _Scan(boot_id, records, (boot[1], mount[1], hashlib.sha256(mount[0]).digest(), metadata))


@dataclass(frozen=True)
class MaintenanceProcessObservation:
    boot_id: str
    captured_boottime_ms: int
    collection_elapsed_ms: int
    process_leaders_examined: int
    service_identity_matches: int
    packaged_node_path_matches: int
    matched_in_unit: int
    matched_outside_unit: int
    passes: int = field(default=2, init=False)
    process_leader_scope_only: bool = field(default=True, init=False)
    host_namespace_proven: bool = field(default=False, init=False)
    all_dashboard_copies_excluded: bool = field(default=False, init=False)
    process_quiescence_proven: bool = field(default=False, init=False)
    exclusive_control_proven: bool = field(default=False, init=False)
    atomic_snapshot_proven: bool = field(default=False, init=False)
    mutation_authorized: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)
    review_required: bool = field(default=True, init=False)


def observe_maintenance_processes():
    """Two stable leader scans bracketed by fixed masked/stopped manager reads.

    Errors/disappearance are never skipped. Known candidates are conservative
    matches, not attribution to a particular script or proof of full absence.
    Nonleader credentials, renamed copies under other IDs and future launches
    remain outside this observation. No cooperative lock is acquired here.
    """
    try:
        state.service._check_tool()
        core.require(os.scandir in os.supports_fd and os.readlink in os.supports_dir_fd
                     and hasattr(time, 'CLOCK_BOOTTIME'), 'CENSUS_PLATFORM')
        started = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        deadline = started + MAX_COLLECTION_NS
        identity = fs._identity()
        mask, manager = state._read_mask(), state._read_manager()
        core.require(mask[0] is True, 'CENSUS_MASK')
        cg._manager_ready(manager)
        first = _native_scan(identity, deadline)
        core.require(_native_scan(identity, deadline) == first, 'CENSUS_CHANGED')
        core.require(fs._identity() == identity and state._read_manager() == manager
                     and state._read_mask() == mask, 'CENSUS_CHANGED')
        ended = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        core.require(0 <= ended - started <= MAX_COLLECTION_NS, 'CENSUS_TIMEOUT')
        records = first.records
        matched = [r for r in records if r.service_identity or r.packaged_node_path]
        return MaintenanceProcessObservation(first.boot_id, started // 1_000_000,
            (ended - started) // 1_000_000, len(records), sum(r.service_identity for r in records),
            sum(r.packaged_node_path for r in records), sum(r.in_unit for r in matched),
            sum(not r.in_unit for r in matched))
    except (OSError, UnicodeError) as error:
        code = fs._os_error_code(error) if isinstance(error, OSError) else 'CENSUS_ENCODING'
        raise core.OperatorError(code) from None
