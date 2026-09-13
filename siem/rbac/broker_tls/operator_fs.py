"""Read-only Linux vendor-file adapter, NOT a startup guard or installer.

Only the core's pinned inventory is readable. No alternate root or caller-
selected identity is exposed. Service-owned code remains service-mutable:
equal reads are not an atomic snapshot or dependency-resolution proof.
"""
from contextlib import ExitStack
import errno
import os
from pathlib import PurePosixPath
import stat
import sys

from .operator_core import installed_checks, require, OperatorError

VENDOR = ('usr', 'share', 'wazuh-dashboard')
SERVICE = 'wazuh-dashboard'
CHUNK = 65536


def _platform():
    require(sys.platform == 'linux' and all(hasattr(os, name) for name in
            ('O_NOFOLLOW', 'O_DIRECTORY', 'O_NONBLOCK', 'O_CLOEXEC', 'geteuid')),
            'FS_PLATFORM')
    require(os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd
            and os.stat in os.supports_follow_symlinks, 'FS_PLATFORM')
    require(os.geteuid() == 0, 'FS_ROOT_REQUIRED')


def _identity():
    import pwd
    import grp
    try:
        user, group = pwd.getpwnam(SERVICE), grp.getgrnam(SERVICE)
    except KeyError:
        raise OperatorError('FS_SERVICE_IDENTITY') from None
    require(user.pw_name == SERVICE and group.gr_name == SERVICE
            and user.pw_uid > 0 and group.gr_gid > 0
            and user.pw_gid == group.gr_gid, 'FS_SERVICE_IDENTITY')
    return user.pw_uid, group.gr_gid


def _owners(parts, identity):
    return ((0, 0), identity) if parts[:len(VENDOR)] == VENDOR else ((0, 0),)


def _stamp(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid,
            st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _trusted(st, directory, owners):
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    require(kind(st.st_mode) and (st.st_uid, st.st_gid) in owners
            and not st.st_mode & 0o6022, 'FS_METADATA')


def _read_at(root_fd, parts, limit, owners_for):
    """Private primitive: production always supplies / and fixed owner policy.

    Tests can anchor a temporary tree without root or a Wazuh installation.
    Caller owns root_fd; all opened descendants close here, also on failure.
    """
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with ExitStack() as stack:
        root_before = os.fstat(root_fd)
        _trusted(root_before, True, owners_for(()))
        records = []
        parent = root_fd
        for index, name in enumerate(parts):
            directory = index < len(parts) - 1
            owners = owners_for(parts[:index + 1])
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            _trusted(before, directory, owners)
            if not directory:
                require(0 <= before.st_size <= limit, 'FS_SIZE')
            fd = os.open(name, flags | (os.O_DIRECTORY if directory else 0),
                         dir_fd=parent)
            stack.callback(os.close, fd)
            opened = os.fstat(fd)
            _trusted(opened, directory, owners)
            require(_stamp(before) == _stamp(opened), 'FS_CHANGED')
            records.append((parent, name, fd, before))
            parent = fd
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(CHUNK, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        require(len(data) <= limit and len(data) == before.st_size, 'FS_SIZE')
        # Recheck held descriptors AND names relative to their held parents.
        for parent, name, opened_fd, original in reversed(records):
            require(_stamp(original) == _stamp(os.fstat(opened_fd))
                    == _stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                    'FS_CHANGED')
        require(_stamp(root_before) == _stamp(os.fstat(root_fd)), 'FS_CHANGED')
        return bytes(data)


def _read_native(parts, limit, identity):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    with ExitStack() as stack:
        root_fd = os.open('/', flags)
        stack.callback(os.close, root_fd)
        return _read_at(root_fd, parts, limit, lambda p: _owners(p, identity))


class InstalledReader:
    """Callback for verify_installed_bytes; construction performs no filesystem IO.

    This Python process/caller must be trusted, not an adversarial plugin.
    Bootstrap validation of guard/manifest/trust paths remains separate work.
    """
    def __init__(self, manifest):
        self._limits = {check.path: check.limit for check in installed_checks(manifest)}

    def __call__(self, path, limit):
        require(type(path) is str and type(limit) is int
                and path in self._limits and limit == self._limits[path], 'FS_TARGET')
        try:
            _platform()
            identity = _identity()
            return _read_native(PurePosixPath(path).parts[1:], limit, identity)
        except OSError as error:
            code = {errno.ENOENT: 'FS_MISSING', errno.EACCES: 'FS_ACCESS',
                    errno.EPERM: 'FS_ACCESS', errno.ELOOP: 'FS_SYMLINK',
                    errno.ENOTDIR: 'FS_NOT_DIRECTORY'}.get(error.errno, 'FS_IO')
            raise OperatorError(code) from None
