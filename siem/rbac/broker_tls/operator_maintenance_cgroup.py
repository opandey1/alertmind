"""Dormant, read-only Dashboard cgroup-v2 observations; NOT maintenance admission.

Requires a trusted root/Linux caller in the host's mount/cgroup/PID namespaces,
trusted procfs/kernel, Python and busctl. No signals, cgroup writes, enumeration
of unrelated processes, CLI or guard/planner integration. An empty service tree
does not exclude escaped/manually launched instances or establish exclusivity.
"""
from contextlib import ExitStack
from dataclasses import dataclass, field
import hashlib
import os
import re
import time

from . import operator_core as core
from . import operator_fs as fs
from . import operator_maintenance_state as state

CGROUP_ROOT = ('sys', 'fs', 'cgroup')
CGROUP_PARENT = CGROUP_ROOT + ('system.slice',)
CGROUP_PARTS = CGROUP_PARENT + ('wazuh-dashboard.service',)
CGROUP_NAME = '/system.slice/wazuh-dashboard.service'
BOOT_PARTS = ('proc', 'sys', 'kernel', 'random', 'boot_id')
MAX_MOUNTINFO = 256 * 1024
MAX_EVENTS = 128
MAX_COLLECTION_MS = 30000  # Candidate native timing, not accepted VM performance.


def _key(value):
    # Kernel directory sizes/timestamps can change for unrelated activity.
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid


def _boot(raw):
    core.require(type(raw) is bytes and re.fullmatch(
        rb'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\n', raw),
        'CGROUP_BOOT')
    return raw[:-1].decode('ascii')


def _events(raw):
    core.require(type(raw) is bytes and 0 < len(raw) <= MAX_EVENTS and raw.endswith(b'\n'),
                 'CGROUP_EVENTS')
    rows = raw[:-1].split(b'\n')
    core.require(len(rows) == 2, 'CGROUP_EVENTS')
    values = {}
    for row in rows:
        match = re.fullmatch(rb'(populated|frozen) ([01])', row)
        core.require(match is not None and match[1] not in values, 'CGROUP_EVENTS')
        values[match[1]] = match[2] == b'1'
    core.require(set(values) == {b'populated', b'frozen'}, 'CGROUP_EVENTS')
    return values[b'populated'], values[b'frozen']


def _mount_device(raw):
    """Read current-namespace mountinfo; accept one unshadowed full v2 mount.

    No decoding/following paths supplied by this file. Only the literal fixed
    mountpoint is used; submounts are refused. Namespace authenticity is an
    external launch requirement, not established by this parser or root UID.
    """
    core.require(type(raw) is bytes and 0 < len(raw) <= MAX_MOUNTINFO and raw.endswith(b'\n'),
                 'CGROUP_MOUNTINFO')
    rows = raw[:-1].split(b'\n')
    core.require(len(rows) <= 4096, 'CGROUP_MOUNTINFO')
    found, ids = [], set()
    for row in rows:
        halves = row.split(b' - ')
        core.require(len(halves) == 2, 'CGROUP_MOUNTINFO')
        left, right = halves[0].split(b' '), halves[1].split(b' ')
        core.require(len(left) >= 6 and len(right) == 3 and all(left + right), 'CGROUP_MOUNTINFO')
        core.require(re.fullmatch(rb'[1-9][0-9]{0,19}', left[0]) is not None
                     and left[0] not in ids and re.fullmatch(rb'[0-9]{1,20}', left[1]) is not None,
                     'CGROUP_MOUNTINFO')
        ids.add(left[0])
        core.require(re.fullmatch(rb'[0-9]{1,10}:[0-9]{1,10}', left[2]) is not None,
                     'CGROUP_MOUNTINFO')
        mountpoint = left[4]
        core.require(not mountpoint.startswith(b'/sys/fs/cgroup/'), 'CGROUP_SUBMOUNT')
        if mountpoint == b'/sys/fs/cgroup':
            core.require(left[3] == b'/' and right[0] == b'cgroup2', 'CGROUP_MOUNT')
            found.append(tuple(int(n) for n in left[2].split(b':')))
    core.require(len(found) == 1, 'CGROUP_MOUNT')
    return found[0]


class _Tree:
    """Private descriptor reader; caller anchors /, tests use disposable trees.

    Fixed paths are chosen by _native_snapshot. Do not expose this as a generic
    caller-controlled filesystem API. No symlink traversal or payload writes.
    """
    def __init__(self, root_fd, stack):
        self.stack = stack
        self.fds = {(): root_fd}
        self.records = []
        self.absent = []
        self.root_key = _key(os.fstat(root_fd))
        fs._trusted(os.fstat(root_fd), True, ((0, 0),))

    def directory(self, parts, *, optional=False):
        fs._components(parts)
        core.require(not optional or parts == CGROUP_PARTS, 'CGROUP_TARGET')
        for length in range(1, len(parts) + 1):
            prefix = parts[:length]
            if prefix in self.fds:
                continue
            parent, name = self.fds[prefix[:-1]], prefix[-1]
            try:
                before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                if optional and prefix == CGROUP_PARTS:
                    self.absent.append((parent, name))
                    return None
                raise
            fs._trusted(before, True, ((0, 0),))
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=parent)
            self.stack.callback(os.close, fd)
            core.require(_key(before) == _key(os.fstat(fd)), 'CGROUP_CHANGED')
            self.records.append((parent, name, fd, _key(before)))
            self.fds[prefix] = fd
        return self.fds[parts]

    def read(self, parts, limit):
        fs._components(parts)
        allowed = {BOOT_PARTS: 37, CGROUP_PARTS + ('cgroup.type',): 32,
                   CGROUP_PARTS + ('cgroup.events',): MAX_EVENTS,
                   ('proc', str(os.getpid()), 'mountinfo'): MAX_MOUNTINFO}
        core.require(parts in allowed and type(limit) is int and limit == allowed[parts], 'CGROUP_TARGET')
        parent = self.directory(parts[:-1])
        name = parts[-1]
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        fs._trusted(before, False, ((0, 0),))
        core.require(0 <= before.st_size <= limit, 'CGROUP_SIZE')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent)
        try:
            stamp = fs._stamp(before)
            core.require(stamp == fs._stamp(os.fstat(fd)), 'CGROUP_CHANGED')
            raw = bytearray()
            while len(raw) <= limit:
                chunk = os.read(fd, min(4096, limit + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
            # procfs/kernfs files normally have size zero despite readable data.
            core.require(len(raw) <= limit, 'CGROUP_SIZE')
            core.require(stamp == fs._stamp(os.fstat(fd)) == fs._stamp(
                os.stat(name, dir_fd=parent, follow_symlinks=False)), 'CGROUP_CHANGED')
            return bytes(raw), stamp
        finally:
            os.close(fd)

    def verify(self):
        for parent, name in self.absent:
            try:
                os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise core.OperatorError('CGROUP_CHANGED')
        for parent, name, fd, before in reversed(self.records):
            core.require(before == _key(os.fstat(fd)) == _key(
                os.stat(name, dir_fd=parent, follow_symlinks=False)), 'CGROUP_CHANGED')
        core.require(self.root_key == _key(os.fstat(self.fds[()])), 'CGROUP_CHANGED')
        return self.root_key, tuple(record[3] for record in self.records)


@dataclass(frozen=True)
class _Snapshot:
    boot_id: str
    present: bool
    populated: bool
    frozen: bool | None
    token: tuple = field(repr=False)


def _native_snapshot():
    mount_parts = ('proc', str(os.getpid()), 'mountinfo')
    with ExitStack() as stack:
        root = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        stack.callback(os.close, root)
        tree = _Tree(root, stack)
        boot = tree.read(BOOT_PARTS, 37)
        boot_id = _boot(boot[0])
        mount = tree.read(mount_parts, MAX_MOUNTINFO)
        device = _mount_device(mount[0])
        cgroot = tree.directory(CGROUP_ROOT)
        st = os.fstat(cgroot)
        core.require((os.major(st.st_dev), os.minor(st.st_dev)) == device, 'CGROUP_DEVICE')
        # Require the slice anchor; absence is accepted ONLY at the unit leaf.
        parent = tree.directory(CGROUP_PARENT)
        core.require(os.fstat(parent).st_dev == st.st_dev, 'CGROUP_DEVICE')
        unit = tree.directory(CGROUP_PARTS, optional=True)
        populated, frozen, detail = False, None, ()
        if unit is not None:
            core.require(os.fstat(unit).st_dev == st.st_dev, 'CGROUP_DEVICE')
            kind = tree.read(CGROUP_PARTS + ('cgroup.type',), 32)
            core.require(kind[0] == b'domain\n', 'CGROUP_TYPE')
            events = tree.read(CGROUP_PARTS + ('cgroup.events',), MAX_EVENTS)
            populated, frozen = _events(events[0])
            for data in (kind, events):
                core.require(data[1][0] == st.st_dev, 'CGROUP_DEVICE')
            detail = kind, events
        # Full mount bytes and boot identity bracket the kernel observation.
        core.require(boot == tree.read(BOOT_PARTS, 37)
                     and mount == tree.read(mount_parts, MAX_MOUNTINFO), 'CGROUP_CHANGED')
        metadata = tree.verify()
        return _Snapshot(boot_id, unit is not None, populated, frozen,
                         (boot[1], mount[1], hashlib.sha256(mount[0]).digest(), metadata, detail))


def _manager_ready(value):
    # Called only on this process's strict fixed-property parser output.
    core.require(value['Id'] == state.UNIT and value['LoadState'] == 'masked'
                 and value['UnitFileState'] == 'masked' and value['NeedDaemonReload'] is False
                 and (value['ActiveState'], value['SubState']) in
                     (('inactive', 'dead'), ('failed', 'failed'))
                 and value['MainPID'] == 0 and value['ControlPID'] == 0
                 and value['Job'][0] == 0, 'CGROUP_MANAGER_STATE')
    core.require(value['ControlGroup'] in ('', CGROUP_NAME), 'CGROUP_MANAGER_PATH')


@dataclass(frozen=True)
class MaintenanceCgroupObservation:
    boot_id: str
    captured_boottime_ms: int
    collection_elapsed_ms: int
    unit_cgroup_present: bool
    unit_tree_populated: bool
    unit_tree_empty_observed: bool
    cgroup_frozen: bool | None
    passes: int = field(default=2, init=False)
    persistent_inhibition_observed: bool = field(default=True, init=False)
    host_namespace_proven: bool = field(default=False, init=False)
    outside_unit_processes_checked: bool = field(default=False, init=False)
    process_quiescence_proven: bool = field(default=False, init=False)
    exclusive_control_proven: bool = field(default=False, init=False)
    atomic_snapshot_proven: bool = field(default=False, init=False)
    mutation_authorized: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)
    review_required: bool = field(default=True, init=False)


def observe_maintenance_cgroup():
    """Fresh fixed cgroup evidence, not all-process absence or an execution gate.

    CLOCK_BOOTTIME includes suspend; its timestamp is deliberately NOT the
    planner's monotonic claim. No conversion/receipt replay adapter is provided.
    Only same-boot equal snapshots with unchanged mask/manager are returned.
    Host namespaces, no hostile root and trusted kernel remain prerequisites.
    """
    try:
        state.service._check_tool()
        core.require(all(hasattr(os, n) for n in ('major', 'minor', 'O_PATH'))
                     and os.readlink in os.supports_dir_fd
                     and hasattr(time, 'CLOCK_BOOTTIME') and hasattr(time, 'clock_gettime_ns'),
                     'CGROUP_PLATFORM')
        started = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        mask = state._read_mask()
        core.require(mask[0] is True, 'CGROUP_MASK')
        manager = state._read_manager()
        _manager_ready(manager)
        first = _native_snapshot()
        second = _native_snapshot()
        core.require(first == second, 'CGROUP_CHANGED')
        core.require(state._read_manager() == manager and state._read_mask() == mask, 'CGROUP_CHANGED')
        ended = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        core.require(0 <= ended - started <= MAX_COLLECTION_MS * 1000000, 'CGROUP_TIMEOUT')
        return MaintenanceCgroupObservation(first.boot_id, started // 1000000,
            (ended - started) // 1000000, first.present, first.populated,
            not first.populated, first.frozen)
    except OSError as error:
        raise core.OperatorError(fs._os_error_code(error)) from None
