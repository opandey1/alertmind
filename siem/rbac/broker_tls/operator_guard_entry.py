"""Candidate isolated pre-start entry boundary; deliberately NOT deployable.

This standalone script has no project imports. A future reviewed installer may
copy it into a root-controlled tree and invoke it with an approved, pinned
interpreter in isolated/no-site/no-bytecode mode. It always exits nonzero:
there is no guard decision or systemd drop-in in this package.

Post-load metadata checks cannot authenticate code that Python already read.
The service unit, interpreter, standard library and installation transaction
must be trusted and reviewed before this entrypoint can form a real guard.
"""
from contextlib import ExitStack
import os
import stat
import sys


CANDIDATE_ROOT = '/usr/local/libexec/alertmind-broker-tls'
ENTRY_PATH = CANDIDATE_ROOT + '/guard_entry.py'
ENTRY_PARTS = ('usr', 'local', 'libexec', 'alertmind-broker-tls', 'guard_entry.py')
MAX_ENTRY_BYTES = 65536


class GuardLaunchError(Exception):
    """Fixed diagnostic codes only, never supplier paths or values."""


def _require(condition, code):
    if not condition:
        raise GuardLaunchError(code)


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _trusted(info, directory):
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    _require(kind(info.st_mode) and info.st_uid == 0 and info.st_gid == 0
             and not info.st_mode & 0o6022, 'GUARD_PATH')
    if not directory:
        _require(info.st_nlink == 1 and 0 < info.st_size <= MAX_ENTRY_BYTES,
                 'GUARD_PATH')


def _check_isolation():
    """Require an isolated root Python process before any project import.

    This cannot undo linker/interpreter inputs already consumed at process
    creation. A future unit policy must inspect those sources separately.
    """
    _require(sys.platform == 'linux' and hasattr(os, 'geteuid') and
             os.geteuid() == 0 and all(hasattr(os, name) for name in
             ('O_NOFOLLOW', 'O_DIRECTORY', 'O_CLOEXEC')) and
             os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd
             and os.stat in os.supports_follow_symlinks,
             'GUARD_PLATFORM')
    flags = sys.flags
    _require(all(getattr(flags, name, None) == 1 for name in
                 ('isolated', 'ignore_environment', 'no_site',
                  'dont_write_bytecode')), 'GUARD_ISOLATION')
    _require(sys.argv == [ENTRY_PATH], 'GUARD_ARGUMENTS')
    _require(all(type(path) is str and path.startswith('/') and
                 path != CANDIDATE_ROOT for path in sys.path),
             'GUARD_IMPORT_PATH')


def _check_entry_at(root_fd):
    """No-follow, descriptor-relative metadata recheck of the fixed entry.

    root_fd is private test isolation only. This is after Python has loaded the
    script, so it is NOT an executable trust anchor or an atomic file lock.
    """
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    with ExitStack() as stack:
        root_before = os.fstat(root_fd)
        _trusted(root_before, True)
        parent = root_fd
        records = []
        for index, name in enumerate(ENTRY_PARTS):
            directory = index < len(ENTRY_PARTS) - 1
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            _trusted(before, directory)
            opened = os.open(name, flags | (os.O_DIRECTORY if directory else 0),
                             dir_fd=parent)
            stack.callback(os.close, opened)
            _require(_stamp(before) == _stamp(os.fstat(opened)), 'GUARD_CHANGED')
            records.append((parent, name, opened, before))
            parent = opened
        for parent, name, opened, before in reversed(records):
            _require(_stamp(before) == _stamp(os.fstat(opened)) ==
                     _stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                     'GUARD_CHANGED')
        _require(_stamp(root_before) == _stamp(os.fstat(root_fd)), 'GUARD_CHANGED')


def _check_entry():
    _check_isolation()
    try:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY |
                     os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            _check_entry_at(fd)
        finally:
            os.close(fd)
    except OSError:
        raise GuardLaunchError('GUARD_IO') from None


def main():
    """Always fail closed: no installed guard or startup permit exists yet."""
    try:
        _check_entry()
    except GuardLaunchError as error:
        print(str(error), file=sys.stderr)
        return 1
    except Exception:
        print('GUARD_UNEXPECTED', file=sys.stderr)
        return 1
    print('GUARD_NOT_READY', file=sys.stderr)
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
