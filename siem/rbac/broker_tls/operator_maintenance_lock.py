"""Dormant cooperative maintenance lock; NOT host-wide exclusive control.

Requires a trusted root/Linux caller, host mount namespace and local /run.
The fixed root-owned directory and empty lock file must already be provisioned
by a separately reviewed installer. This module never creates, writes, removes
or repairs them. No CLI, planner adapter, service action or startup permission.
"""
from contextlib import contextmanager, ExitStack
from dataclasses import dataclass, field
import errno
import os
import stat

from . import operator_core as core
from . import operator_fs as fs

PARENT = ('run', 'alertmind-broker-maintenance')
NAME = 'owner.lock'


def _key(st):
    # / and /run can change timestamps as unrelated services create files.
    return st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid


def _directory(st, private=False):
    fs._trusted(st, True, ((0, 0),))
    if private:
        core.require(stat.S_IMODE(st.st_mode) == 0o700, 'MAINTENANCE_LOCK_METADATA')


def _leaf(st):
    fs._trusted(st, False, ((0, 0),))
    core.require(stat.S_IMODE(st.st_mode) == 0o600 and st.st_nlink == 1
                 and st.st_size == 0, 'MAINTENANCE_LOCK_METADATA')


def _close(fd):
    try:
        os.close(fd)
    except OSError:
        # Do not retry close with a possibly recycled descriptor number.
        raise core.OperatorError('MAINTENANCE_LOCK_CLEANUP') from None


def _try_lock(fd):
    # Lazy import keeps offline tests importable on Windows. Never downgrade to
    # another lock type, retry, wait, truncate a PID file or steal a "stale" lock.
    import fcntl
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        code = ('MAINTENANCE_LOCK_BUSY' if error.errno in (errno.EAGAIN, errno.EACCES)
                else 'MAINTENANCE_LOCK_ACQUIRE')
        raise core.OperatorError(code) from None


@dataclass(frozen=True)
class MaintenanceLockObservation:
    cooperative_lock_held: bool = field(default=True, init=False)
    fixed_path_rechecked: bool = field(default=True, init=False)
    host_namespace_proven: bool = field(default=False, init=False)
    noncooperating_writers_excluded: bool = field(default=False, init=False)
    exclusive_control_proven: bool = field(default=False, init=False)
    process_quiescence_proven: bool = field(default=False, init=False)
    persistent_inhibition_proven: bool = field(default=False, init=False)
    mutation_authorized: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)
    review_required: bool = field(default=True, init=False)


class _HeldLease:
    """Lifetime-bound handle for trusted code, not a serializable authority.

    Do not fork, duplicate/pass descriptors, exec or delegate this handle while
    holding it. A child cannot checkpoint it. Closing (never LOCK_UN) avoids a
    child releasing its parent's shared open-file-description lock. An illicit
    inherited descriptor can delay release until that child exits: fail closed,
    not permission to unlink the file. Python internals are not an adversary API.
    """
    def __init__(self, root, records, parent, fd, stamp):
        self._root = root
        self._root_key = _key(os.fstat(root))
        self._records = records
        self._parent = parent
        self._fd = fd
        self._stamp = stamp
        self._pid = os.getpid()
        self._active = True

    def __repr__(self):
        return '<private maintenance lock handle>'

    def checkpoint(self):
        """Recheck the still-held descriptor and its fixed name; not a permit.

        Call before each future protected operation and let a failure abort the
        transaction. A stored observation or the handle's mere existence is not
        evidence of current ownership. Exit also checks successful bodies.
        """
        core.require(self._active, 'MAINTENANCE_LOCK_CLOSED')
        core.require(os.getpid() == self._pid, 'MAINTENANCE_LOCK_OWNER')
        try:
            current = os.fstat(self._fd)
            named = os.stat(NAME, dir_fd=self._parent, follow_symlinks=False)
            _leaf(current)
            _leaf(named)
            core.require(self._stamp == fs._stamp(current) == fs._stamp(named),
                         'MAINTENANCE_LOCK_CHANGED')
            core.require(os.get_inheritable(self._fd) is False, 'MAINTENANCE_LOCK_INHERITABLE')
            for parent, name, fd, before, private in reversed(self._records):
                held = os.fstat(fd)
                named = os.stat(name, dir_fd=parent, follow_symlinks=False)
                _directory(held, private)
                _directory(named, private)
                compare = fs._stamp if private else _key
                core.require(before == compare(held) == compare(named), 'MAINTENANCE_LOCK_CHANGED')
            root = os.fstat(self._root)
            _directory(root)
            core.require(self._root_key == _key(root), 'MAINTENANCE_LOCK_CHANGED')
            return MaintenanceLockObservation()
        except OSError as error:
            raise core.OperatorError(fs._os_error_code(error)) from None


@contextmanager
def _hold_at(root):
    """Private descriptor fixture seam; production always anchors at /."""
    with ExitStack() as stack:
        try:
            original_root = os.fstat(root)
            _directory(original_root)
            parent, records = root, []
            run_device = None
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            for index, name in enumerate(PARENT):
                private = index == 1
                before = os.stat(name, dir_fd=parent, follow_symlinks=False)
                _directory(before, private)
                fd = os.open(name, flags, dir_fd=parent)
                stack.callback(_close, fd)
                compare = fs._stamp if private else _key
                core.require(compare(before) == compare(os.fstat(fd)), 'MAINTENANCE_LOCK_CHANGED')
                if index == 0:
                    run_device = before.st_dev
                core.require(before.st_dev == run_device, 'MAINTENANCE_LOCK_DEVICE')
                records.append((parent, name, fd, compare(before), private))
                parent = fd
            before = os.stat(NAME, dir_fd=parent, follow_symlinks=False)
            _leaf(before)
            core.require(before.st_dev == run_device, 'MAINTENANCE_LOCK_DEVICE')
            # No O_CREAT/O_TRUNC, no bytes read/written and no cleanup unlink.
            fd = os.open(NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                         dir_fd=parent)
            stack.callback(_close, fd)
            core.require(fs._stamp(before) == fs._stamp(os.fstat(fd)), 'MAINTENANCE_LOCK_CHANGED')
            core.require(os.get_inheritable(fd) is False, 'MAINTENANCE_LOCK_INHERITABLE')
            _try_lock(fd)
            core.require(_key(original_root) == _key(os.fstat(root)), 'MAINTENANCE_LOCK_CHANGED')
            lease = _HeldLease(root, records, parent, fd, fs._stamp(before))
        except OSError as error:
            raise core.OperatorError(fs._os_error_code(error)) from None
        try:
            lease.checkpoint()
            yield lease
            lease.checkpoint()
        finally:
            lease._active = False
        # ExitStack closes the lock descriptor before the ancestors. No LOCK_UN:
        # releasing a copied child's descriptor must not unlock a parent's lease.


@contextmanager
def hold_maintenance_lock():
    """Hold a nonblocking cooperative lock for the entire caller context.

    Fixed existing local /run anchor only. Absence is an error, not a setup
    request. Host namespaces, local filesystem and no hostile root are external
    prerequisites. Advisory flock does not exclude apt/dpkg, systemd, service-
    owned code changes or administrators that ignore this same lock. It cannot
    satisfy the planner's exclusive_control=True or authorize any operation.
    """
    fs._platform()
    try:
        root = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise core.OperatorError(fs._os_error_code(error)) from None
    try:
        with _hold_at(root) as lease:
            yield lease
    finally:
        _close(root)
