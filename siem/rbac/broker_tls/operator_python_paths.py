"""Dormant fixed-path observations, NOT a trusted launcher or import proof.

Requires an already trusted root/Linux caller. Never opens device payloads,
imports observed code, launches a process, or writes. Not in the guard capsule.
Equal observations neither lock names nor prevent earlier loader injection.
"""
from contextlib import ExitStack
from dataclasses import dataclass, field
import os
import stat

from . import operator_core as core
from . import operator_fs as fs


# Reject ANY object at these optional names, including empty files/symlinks.
# Required ancestors must exist and be root:root, not service-owned.
ABSENT_INPUTS = (
    (('usr', 'lib'), ('python314.zip',), 'PY_ZIP_PRESENT'),
    (('etc',), ('ld.so.preload',), 'PY_PRELOAD_PRESENT'),
)


def _root_owners(_parts):
    return ((0, 0),)


def _device_stamp(value):
    # The shared regular-file stamp deliberately has no device number.
    return fs._stamp(value) + (value.st_rdev,)


def _null_metadata(value):
    core.require(stat.S_ISCHR(value.st_mode) and
                 (value.st_uid, value.st_gid) == (0, 0) and
                 not value.st_mode & 0o7111 and
                 (os.major(value.st_rdev), os.minor(value.st_rdev)) == (1, 3),
                 'PY_NULL_METADATA')


def _null_anchor_at(root_fd):
    """Hold /dev and an O_PATH descriptor to null; no device read/write open.

    Usual 0666 permissions (or stricter rw-only bits) are valid for this
    character device. The regular-file no-group-write rule does not apply.
    A character-device anchor cannot be traversed as a cache directory, but
    this observation does NOT establish the interpreter's actual cache prefix.
    """
    with ExitStack() as stack:
        root_before = os.fstat(root_fd)
        fs._trusted(root_before, True, ((0, 0),))
        dev_before = os.stat('dev', dir_fd=root_fd, follow_symlinks=False)
        fs._trusted(dev_before, True, ((0, 0),))
        dev_fd = os.open('dev', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                         os.O_CLOEXEC, dir_fd=root_fd)
        stack.callback(os.close, dev_fd)
        core.require(fs._stamp(dev_before) == fs._stamp(os.fstat(dev_fd)), 'FS_CHANGED')
        before = os.stat('null', dir_fd=dev_fd, follow_symlinks=False)
        _null_metadata(before)
        null_fd = os.open('null', os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dev_fd)
        stack.callback(os.close, null_fd)
        opened = os.fstat(null_fd)
        _null_metadata(opened)
        stamp = _device_stamp(before)
        core.require(stamp == _device_stamp(opened), 'FS_CHANGED')
        core.require(stamp == _device_stamp(os.fstat(null_fd)) ==
                     _device_stamp(os.stat('null', dir_fd=dev_fd, follow_symlinks=False)),
                     'FS_CHANGED')
        core.require(fs._stamp(dev_before) == fs._stamp(os.fstat(dev_fd)) ==
                     fs._stamp(os.stat('dev', dir_fd=root_fd, follow_symlinks=False)),
                     'FS_CHANGED')
        core.require(fs._stamp(root_before) == fs._stamp(os.fstat(root_fd)), 'FS_CHANGED')
        return stamp


@dataclass(frozen=True)
class PythonPathObservation:
    file_passes: int = field(default=2, init=False)
    absent_input_count: int = field(default=2, init=False)
    fixed_optional_inputs_absent: bool = field(default=True, init=False)
    null_anchor_matches: bool = field(default=True, init=False)
    complete_search_path_proven: bool = field(default=False, init=False)
    effective_cache_redirection_proven: bool = field(default=False, init=False)
    loader_environment_proven: bool = field(default=False, init=False)
    native_resolution_proven: bool = field(default=False, init=False)
    loaded_code_proven: bool = field(default=False, init=False)
    atomic_snapshot_proven: bool = field(default=False, init=False)
    runtime_trusted: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)


def observe_python_path_inputs():
    """Observe three fixed names twice, separately from the byte-pin adapter.

    No configurable root, path, reader, principal or result replay. O_PATH is
    mandatory: no fallback opens a device for reading. Names/metadata can
    change after checking; these observations do not attest loaded code or
    compose a snapshot with operator_python_runtime's independent reads.
    """
    try:
        fs._platform()
        core.require(all(hasattr(os, name) for name in ('O_PATH', 'major', 'minor')),
                     'PY_PATH_PLATFORM')
        with ExitStack() as stack:
            root_fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            stack.callback(os.close, root_fd)
            root_before = os.fstat(root_fd)
            fs._trusted(root_before, True, ((0, 0),))
            previous = None
            for _ in range(2):
                for parent, child, code in ABSENT_INPUTS:
                    core.require(fs._absent_below_at(root_fd, parent, child, _root_owners), code)
                current = _null_anchor_at(root_fd)
                core.require(previous is None or current == previous, 'PY_NULL_CHANGED')
                previous = current
            core.require(fs._stamp(root_before) == fs._stamp(os.fstat(root_fd)), 'FS_CHANGED')
        return PythonPathObservation()
    except OSError as error:
        raise core.OperatorError(fs._os_error_code(error)) from None
