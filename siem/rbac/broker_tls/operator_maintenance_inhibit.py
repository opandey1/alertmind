"""Persistent-mask disk primitive, NOT a released maintenance executor.

Only the private descriptor seam can write. The public entry refuses before
I/O until trusted owner/lock/host authorization and manager lifecycle wiring
exist. Tests use disposable roots; no live invocation or CLI is provided.
"""
from contextlib import ExitStack
from dataclasses import dataclass, field
import os
import stat
import threading

from . import operator_core as core
from . import operator_fs as fs
from . import operator_maintenance_cgroup as cg
from . import operator_maintenance_state as state
from . import operator_python_paths as paths

PARENT = state.MASK_PARENT
UNIT = state.UNIT
TARGET = '/dev/null'


@dataclass(frozen=True)
class MaintenanceMaskResult:
    mask_created: bool
    persistent_mask_entry_present: bool = field(default=True, init=False)
    directory_sync_completed: bool = field(default=True, init=False)
    manager_reloaded: bool = field(default=False, init=False)
    manager_inhibition_proven: bool = field(default=False, init=False)
    process_quiescence_proven: bool = field(default=False, init=False)
    exclusive_control_proven: bool = field(default=False, init=False)
    reboot_persistence_tested: bool = field(default=False, init=False)
    mutation_authorized: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)
    review_required: bool = field(default=True, init=False)


def _link_metadata(value, parent):
    core.require(stat.S_ISLNK(value.st_mode) and stat.S_IMODE(value.st_mode) == 0o777
                 and (value.st_uid, value.st_gid) == (0, 0) and value.st_nlink == 1
                 and value.st_size == len(TARGET) and value.st_dev == os.fstat(parent).st_dev,
                 'INHIBIT_MASK_METADATA')


def _open_mask(parent, stack, *, absent_ok=False):
    try:
        before = os.stat(UNIT, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        core.require(absent_ok, 'INHIBIT_MASK_MISSING')
        return None
    _link_metadata(before, parent)
    core.require(os.readlink(UNIT, dir_fd=parent) == TARGET, 'INHIBIT_MASK_TARGET')
    # O_PATH|O_NOFOLLOW holds the symlink itself, not the device it names.
    fd = os.open(UNIT, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    stack.callback(os.close, fd)
    record = fd, fs._stamp(before)
    _verify_mask(parent, record)
    return record


def _verify_mask(parent, record):
    fd, stamp = record
    held = os.fstat(fd)
    named = os.stat(UNIT, dir_fd=parent, follow_symlinks=False)
    _link_metadata(held, parent)
    _link_metadata(named, parent)
    core.require(stamp == fs._stamp(held) == fs._stamp(named), 'INHIBIT_MASK_CHANGED')
    core.require(os.readlink(UNIT, dir_fd=parent) == TARGET, 'INHIBIT_MASK_TARGET')
    core.require(os.get_inheritable(fd) is False, 'INHIBIT_INHERITABLE')


def _prepare_at(root, *, checkpoint):
    """Private disk-only seam for disposable tests / a FUTURE trusted controller.

    The root FD and checkpoint are trusted implementation inputs, not a user
    API. A callable returning None is NOT authorization. A future controller
    must establish owner downtime approval, trusted host/runtime, writer and
    start-path control, held locks, bounded lifetime and recovery before use.
    No fork, delegation or credential/namespace change within this operation.

    Never remove a created/existing mask on failure. After interrupted creation
    its durability is unknown; a new authorized attempt rechecks and syncs an
    exact existing mask from scratch. It does not adopt EEXIST races or read a
    journal as evidence. Existing unit files/other symlinks are never replaced.
    """
    core.require(callable(checkpoint), 'INHIBIT_CHECKPOINT')
    owner = os.getpid(), threading.get_native_id()

    def check():
        core.require((os.getpid(), threading.get_native_id()) == owner, 'INHIBIT_OWNER')
        try:
            answer = checkpoint()
        except Exception:
            raise core.OperatorError('INHIBIT_CHECKPOINT') from None
        core.require(answer is None, 'INHIBIT_CHECKPOINT')
        core.require((os.getpid(), threading.get_native_id()) == owner, 'INHIBIT_OWNER')

    try:
        with ExitStack() as stack:
            check()
            tree = cg._Tree(root, stack)
            parent = tree.directory(PARENT)
            null = paths._null_anchor_at(root)
            record = _open_mask(parent, stack, absent_ok=True)

            def verify():
                tree.verify()
                core.require(paths._null_anchor_at(root) == null, 'INHIBIT_NULL_CHANGED')
                if record is not None:
                    _verify_mask(parent, record)

            check()
            verify()
            created = record is None
            if created:
                try:
                    # symlinkat is no-clobber even when absence just raced.
                    os.symlink(TARGET, UNIT, dir_fd=parent)
                except FileExistsError:
                    raise core.OperatorError('INHIBIT_COLLISION') from None
                record = _open_mask(parent, stack)
            verify()

            # The symlink is never fsync-opened through its target. Synchronize
            # the held containing directory and each existing ancestor, deepest
            # first. No temporary name, rename, overwrite or cleanup unlink.
            for length in range(len(PARENT), -1, -1):
                check()
                verify()
                try:
                    os.fsync(tree.fds[PARENT[:length]])
                except OSError:
                    raise core.OperatorError('INHIBIT_SYNC') from None
                verify()
            check()
            verify()
            result = MaintenanceMaskResult(created)
        # A failed descriptor cleanup cannot return a successful result.
        return result
    except OSError as error:
        raise core.OperatorError(fs._os_error_code(error)) from None


def prepare_maintenance_inhibition():
    """Not released: no boolean, environment flag or receipt enables this entry.

    Private filesystem tests do not establish live systemd inhibition. The
    manager must later reload, report the persistent mask, stop and be rechecked
    with the cgroup/census under continuous controls before any protected work.
    """
    raise core.OperatorError('INHIBIT_NOT_RELEASED')
