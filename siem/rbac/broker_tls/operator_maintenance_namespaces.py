"""Hold/recheck namespace alignment around a maintenance observation window.

Linux x86-64, trusted root/kernel/procfs and a single-threaded caller only.
Visible PID 1 alignment is NOT attestation of the intended host. No setns,
unshare, namespace creation, subprocess, signals, writes or startup permission.
This module is outside the guard capsule and has no CLI.
"""
from contextlib import contextmanager, ExitStack
from dataclasses import dataclass, field
import os
import re
import stat
import threading
import time

from . import operator_core as core
from . import operator_fs as fs
from . import operator_maintenance_cgroup as cg
from . import operator_maintenance_processes as census

# Linux x86-64 UAPI: _IO(0xb7, 3), returning a CLONE_NEW* namespace type.
NS_GET_NSTYPE = 0xb703
NAMES = (('mnt', 'mnt', 0x00020000), ('pid', 'pid', 0x20000000),
         ('user', 'user', 0x10000000), ('cgroup', 'cgroup', 0x02000000),
         ('time', 'time', 0x00000080), ('pid_for_children', 'pid', 0x20000000),
         ('time_for_children', 'time', 0x00000080))
MAX_WINDOW_NS = 30_000_000_000


def _kind(fd):
    import fcntl  # Deferred for Windows offline fixtures; no fallback on error.
    return fcntl.ioctl(fd, NS_GET_NSTYPE)


def _caller(pid):
    core.require(os.getpid() == pid and pid > 1
                 and threading.get_native_id() == pid, 'NAMESPACE_CALLER')


def _now(started):
    value = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    core.require(0 <= value - started <= MAX_WINDOW_NS, 'NAMESPACE_TIMEOUT')
    return value


def _link(directory, name, label, device):
    st = os.stat(name, dir_fd=directory, follow_symlinks=False)
    core.require(stat.S_ISLNK(st.st_mode) and st.st_dev == device
                 and st.st_uid == 0 and st.st_gid == 0, 'NAMESPACE_LINK')
    text = os.readlink(name, dir_fd=directory)
    match = re.fullmatch(re.escape(label) + r':\[([1-9][0-9]{0,19})\]', text)
    core.require(match is not None, 'NAMESPACE_LINK')
    inode = int(match[1])
    core.require(inode <= 2**64 - 1, 'NAMESPACE_LINK')
    return cg._key(st), inode


def _descriptor(fd, kind, inode):
    st = os.fstat(fd)
    core.require(stat.S_ISREG(st.st_mode) and not st.st_mode & 0o6222
                 and st.st_uid == 0 and st.st_gid == 0 and st.st_ino == inode,
                 'NAMESPACE_DESCRIPTOR')
    core.require(os.get_inheritable(fd) is False, 'NAMESPACE_INHERITABLE')
    core.require(_kind(fd) == kind, 'NAMESPACE_TYPE')
    return cg._key(st)


@contextmanager
def _opened(directory, entry, device):
    name, label, kind = entry
    before, inode = _link(directory, name, label, device)
    # Only these seven kernel magic links are intentionally followed. Every
    # ancestor was opened with O_NOFOLLOW on the verified, unshadowed procfs.
    fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
    try:
        key = _descriptor(fd, kind, inode)
        core.require((before, inode) == _link(directory, name, label, device),
                     'NAMESPACE_CHANGED')
        yield fd, key, before, inode
    finally:
        os.close(fd)


@dataclass(frozen=True)
class MaintenanceNamespaceObservation:
    boot_id: str
    captured_boottime_ms: int
    window_elapsed_ms: int
    namespace_types_checked: int = field(default=5, init=False)
    child_namespace_targets_checked: int = field(default=2, init=False)
    visible_pid1_alignment_observed: bool = field(default=True, init=False)
    host_namespace_proven: bool = field(default=False, init=False)
    process_coverage_complete: bool = field(default=False, init=False)
    process_quiescence_proven: bool = field(default=False, init=False)
    exclusive_control_proven: bool = field(default=False, init=False)
    atomic_snapshot_proven: bool = field(default=False, init=False)
    mutation_authorized: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)
    review_required: bool = field(default=True, init=False)


class _HeldNamespaces:
    """Private, same-caller observation handle, not a serializable authority.

    Do not transfer/duplicate its descriptors, change credentials/namespaces,
    raw-fork/delegate this handle or use it from another thread. The census's
    existing fixed busctl children use close_fds=True, no pass_fds/preexec_fn,
    and bounded wait/cleanup; they do not receive or use the handle. Alignment
    checks child targets too; it does not authorize arbitrary child launches.
    """
    def __init__(self, tree, stack, pid, started):
        self._active = True
        self._tree, self._pid, self._started = tree, pid, started
        self._mount_path = ('proc', str(pid), 'mountinfo')
        self._boot = tree.read(cg.BOOT_PARTS, 37)
        self._boot_id = cg._boot(self._boot[0])
        self._mount = tree.read(self._mount_path, cg.MAX_MOUNTINFO)
        device = census._proc_device(self._mount[0])
        self._device = os.fstat(tree.directory(('proc',))).st_dev
        core.require((os.major(self._device), os.minor(self._device)) == device,
                     'NAMESPACE_DEVICE')
        self._records = []
        self._processes = []
        keys = {}
        for process in (1, pid):
            directory = tree.directory(('proc', str(process)))
            ns = tree.directory(('proc', str(process), 'ns'))
            core.require(os.fstat(directory).st_dev == self._device
                         and os.fstat(ns).st_dev == self._device, 'NAMESPACE_DEVICE')
            identity = self._identity(directory, process)
            self._processes.append((directory, process, identity))
            for entry in NAMES:
                _now(started)
                fd, key, link_key, inode = stack.enter_context(_opened(ns, entry, self._device))
                self._records.append((ns, entry, fd, key, link_key, inode))
                # Compare actual held namespace objects, not link text alone.
                base = (key[0], key[1])
                label = entry[1]
                core.require(label not in keys or keys[label] == base, 'NAMESPACE_ALIGNMENT')
                keys[label] = base

    def __repr__(self):
        return '<private maintenance namespace handle>'

    def _identity(self, directory, pid):
        deadline = self._started + MAX_WINDOW_NS
        start, kernel, zombie = census._stat_record(
            census._small(directory, 'stat', self._device, deadline), pid)
        uids, gids, threads = census._status(
            census._small(directory, 'status', self._device, deadline), pid)
        core.require(not kernel and not zombie and uids == (0,) * 4 and gids == (0,) * 4,
                     'NAMESPACE_IDENTITY')
        core.require(pid != self._pid or threads == 1, 'NAMESPACE_THREADS')
        return start, uids, gids, threads

    def checkpoint(self):
        core.require(self._active, 'NAMESPACE_CLOSED')
        _caller(self._pid)
        try:
            _now(self._started)
            core.require(self._boot == self._tree.read(cg.BOOT_PARTS, 37)
                         and self._mount == self._tree.read(self._mount_path, cg.MAX_MOUNTINFO),
                         'NAMESPACE_CHANGED')
            for directory, pid, identity in self._processes:
                core.require(self._identity(directory, pid) == identity, 'NAMESPACE_CHANGED')
            for directory, entry, fd, key, link_key, inode in self._records:
                _now(self._started)
                core.require(_descriptor(fd, entry[2], inode) == key, 'NAMESPACE_CHANGED')
                with _opened(directory, entry, self._device) as (_, current, link, number):
                    core.require((current, link, number) == (key, link_key, inode), 'NAMESPACE_CHANGED')
            self._tree.verify()
            _caller(self._pid)
            ended = _now(self._started)
            return MaintenanceNamespaceObservation(self._boot_id, self._started // 1_000_000,
                                                   (ended - self._started) // 1_000_000)
        except OSError as error:
            raise core.OperatorError(fs._os_error_code(error)) from None


@contextmanager
def _hold_at(root, pid, started):
    """Private fixture seam. Production supplies /, current PID and BOOTTIME."""
    with ExitStack() as stack:
        handle = None
        try:
            handle = _HeldNamespaces(cg._Tree(root, stack), stack, pid, started)
            handle.checkpoint()
            yield handle
            handle.checkpoint()
        except OSError as error:
            raise core.OperatorError(fs._os_error_code(error)) from None
        finally:
            if handle is not None:
                handle._active = False


@contextmanager
def hold_maintenance_namespaces():
    """Hold alignment across a bounded observation; never enter a namespace.

    Matching visible PID 1 in a container is possible. A separately trusted
    host launch boundary is still required; this check cannot manufacture it.
    Missing/denied namespaces and child-only divergence abort without fallback.
    Successful exit rechecks; failures close all handles, without recovery I/O.
    """
    fs._platform()
    core.require(os.uname().machine == 'x86_64' and os.readlink in os.supports_dir_fd
                 and hasattr(time, 'CLOCK_BOOTTIME'), 'NAMESPACE_PLATFORM')
    pid = os.getpid()
    _caller(pid)
    started = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    try:
        with ExitStack() as stack:
            root = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            stack.callback(os.close, root)
            with _hold_at(root, pid, started) as handle:
                yield handle
    except OSError as error:
        raise core.OperatorError(fs._os_error_code(error)) from None
