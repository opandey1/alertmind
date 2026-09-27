"""Dormant APT/dpkg record-lock barrier for observation/backup, NOT upgrades.

Trusted root Linux x86-64 host, local filesystems and default package-manager
lock paths are external requirements. No CLI, package command, payload write,
lock-file creation/removal, timer/service change or planner/startup permission.
"""
from contextlib import contextmanager, ExitStack
from dataclasses import dataclass, field
import errno
import os
import stat
import struct
import sys
import threading

from . import operator_core as core
from . import operator_fs as fs
from . import operator_maintenance_cgroup as cg

# Fixed order, all nonblocking. No user/config/environment-selected paths.
LOCK_PATHS = (
    ('var', 'lib', 'dpkg', 'lock-frontend'),
    ('var', 'lib', 'dpkg', 'lock'),
    ('var', 'lib', 'apt', 'lists', 'lock'),
    ('var', 'cache', 'apt', 'archives', 'lock'),
)
# Linux x86-64 struct flock: short/short, four padding bytes, off_t/off_t,
# pid_t, four tail-padding bytes. No ABI guessing on other architectures.
FLOCK_FORMAT = '<hh4xqqi4x'


def _api():
    import fcntl  # Linux only; deferred so Windows offline fixtures can import.
    core.require(all(hasattr(fcntl, name) for name in
        ('F_OFD_SETLK', 'F_GETLK', 'F_WRLCK')), 'PACKAGE_LOCK_PLATFORM')
    return fcntl


def _request(api):
    return struct.pack(FLOCK_FORMAT, api.F_WRLCK, os.SEEK_SET, 0, 0, 0)


def _acquire(fd):
    api = _api()
    try:
        # OFD record locks conflict with APT/dpkg's traditional F_SETLK locks.
        # flock() is a different lock family and would not provide this barrier.
        api.fcntl(fd, api.F_OFD_SETLK, _request(api))
    except OSError as error:
        suffix = 'BUSY' if error.errno in (errno.EAGAIN, errno.EACCES) else 'ACQUIRE'
        raise core.OperatorError('PACKAGE_LOCK_' + suffix) from None


def _check_locked(fd):
    api = _api()
    try:
        # Traditional GETLK conflicts even with our own OFD lock. OFD_GETLK
        # would ignore a lock on this same open-file description. Never renew
        # a missing lock: reacquiring would hide a gap in the protected interval.
        raw = api.fcntl(fd, api.F_GETLK, _request(api))
    except OSError:
        raise core.OperatorError('PACKAGE_LOCK_CHECK') from None
    core.require(type(raw) is bytes and len(raw) == 32, 'PACKAGE_LOCK_STATE')
    core.require(struct.unpack(FLOCK_FORMAT, raw) == (api.F_WRLCK, os.SEEK_SET, 0, 0, -1),
                 'PACKAGE_LOCK_STATE')
    # This reports an OFD conflict, not its owner's identity. Ownership relies
    # on this trusted code retaining its private acquired descriptor unchanged.


def _leaf(st):
    fs._trusted(st, False, ((0, 0),))
    core.require(stat.S_IMODE(st.st_mode) in (0o600, 0o640, 0o644)
                 and st.st_nlink == 1 and st.st_size == 0, 'PACKAGE_LOCK_METADATA')


def _close(fd):
    try:
        os.close(fd)
    except OSError:
        raise core.OperatorError('PACKAGE_LOCK_CLEANUP') from None


@dataclass(frozen=True)
class MaintenancePackageLockObservation:
    fixed_record_locks_held: int = field(default=4, init=False)
    fixed_paths_rechecked: bool = field(default=True, init=False)
    default_lock_paths_only: bool = field(default=True, init=False)
    host_namespace_proven: bool = field(default=False, init=False)
    installed_package_config_verified: bool = field(default=False, init=False)
    noncooperating_writers_excluded: bool = field(default=False, init=False)
    service_starts_inhibited: bool = field(default=False, init=False)
    process_quiescence_proven: bool = field(default=False, init=False)
    exclusive_control_proven: bool = field(default=False, init=False)
    package_transaction_authorized: bool = field(default=False, init=False)
    mutation_authorized: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)
    review_required: bool = field(default=True, init=False)


class _HeldPackageLocks:
    """Private same-process/thread handle. No raw fork/dup/pass/exec/delegation.

    Observation-only fixed child queries must close unrelated FDs, never use
    pass_fds/preexec_fn, and be reaped. No APT/dpkg call while this barrier is
    held: it would conflict with these locks. Upgrade handover is separate work.
    Use a dedicated controller with no pre-existing traditional record locks on
    these inodes: closing any FD could release that caller's POSIX locks. This
    is not an adapter to run inside a package-manager/libapt process.
    """
    def __init__(self, tree, records):
        self._tree, self._records = tree, records
        self._pid, self._tid = os.getpid(), threading.get_native_id()
        self._active = True

    def __repr__(self):
        return '<private package-lock handle>'

    def checkpoint(self):
        core.require(self._active, 'PACKAGE_LOCK_CLOSED')
        core.require((os.getpid(), threading.get_native_id()) == (self._pid, self._tid),
                     'PACKAGE_LOCK_OWNER')
        try:
            for parent, name, fd, stamp in self._records:
                current = os.fstat(fd)
                named = os.stat(name, dir_fd=parent, follow_symlinks=False)
                _leaf(current)
                _leaf(named)
                core.require(stamp == fs._stamp(current) == fs._stamp(named), 'PACKAGE_LOCK_CHANGED')
                core.require(os.get_inheritable(fd) is False, 'PACKAGE_LOCK_INHERITABLE')
                _check_locked(fd)
            self._tree.verify()
            return MaintenancePackageLockObservation()
        except OSError as error:
            raise core.OperatorError(fs._os_error_code(error)) from None


@contextmanager
def _hold_at(root):
    """Private disposable-tree fixture seam; production anchors only /."""
    with ExitStack() as stack:
        handle = None
        try:
            tree = cg._Tree(root, stack)
            records, identities = [], set()
            for path in LOCK_PATHS:
                parent = tree.directory(path[:-1])
                before = os.stat(path[-1], dir_fd=parent, follow_symlinks=False)
                _leaf(before)
                core.require(before.st_dev == os.fstat(parent).st_dev, 'PACKAGE_LOCK_DEVICE')
                identity = before.st_dev, before.st_ino
                core.require(identity not in identities, 'PACKAGE_LOCK_ALIAS')
                identities.add(identity)
                # Write access is required by F_WRLCK; no O_CREAT/TRUNC or I/O.
                fd = os.open(path[-1], os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                             dir_fd=parent)
                stack.callback(_close, fd)
                core.require(fs._stamp(before) == fs._stamp(os.fstat(fd)), 'PACKAGE_LOCK_CHANGED')
                core.require(os.get_inheritable(fd) is False, 'PACKAGE_LOCK_INHERITABLE')
                _acquire(fd)
                records.append((parent, path[-1], fd, fs._stamp(before)))
            handle = _HeldPackageLocks(tree, records)
            handle.checkpoint()
            yield handle
            handle.checkpoint()
        except OSError as error:
            raise core.OperatorError(fs._os_error_code(error)) from None
        finally:
            if handle is not None:
                handle._active = False
        # Close only, never F_UNLCK. Partial acquisition is unwound by ExitStack;
        # an illicit fork/dup can prolong the OFD lifetime but cannot justify
        # deleting a file or stealing its lock. No per-file early-release API.


@contextmanager
def hold_maintenance_package_locks():
    """Fail-fast barrier at four existing default APT/dpkg lock inodes.

    Not read-only kernel state: locks are acquired, but no file bytes/settings
    are changed. A bounded, approved maintenance controller must own lifetime;
    this module does not kill competing updaters or provide a watchdog. The
    kernel releases locks on last close/process exit, not persistently on disk.
    Neither success nor file presence permits package installation or startup.
    """
    fs._platform()
    core.require(os.uname().machine == 'x86_64' and sys.byteorder == 'little'
                 and struct.calcsize('P') == 8 and struct.calcsize(FLOCK_FORMAT) == 32,
                 'PACKAGE_LOCK_PLATFORM')
    _api()
    try:
        with ExitStack() as stack:
            root = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            stack.callback(_close, root)
            with _hold_at(root) as handle:
                yield handle
    except OSError as error:
        raise core.OperatorError(fs._os_error_code(error)) from None
