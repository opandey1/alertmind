"""Offline reader policy/fault tests plus Linux-only real temporary-tree tests."""
import errno
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_fs as f
from siem.rbac.broker_tls import operator_core as core


def metadata(directory=False, **changes):
    values = dict(st_dev=1, st_ino=1, st_mode=(stat.S_IFDIR | 0o755) if directory
                  else (stat.S_IFREG | 0o640), st_uid=0, st_gid=0, st_nlink=1,
                  st_size=0 if directory else 3, st_mtime_ns=1, st_ctime_ns=1)
    values.update(changes)
    return NS(**values)


class FakeFS:
    """Descriptor tree, not host IO. Flags/relative operations remain observable."""
    O_RDONLY, O_NOFOLLOW, O_NONBLOCK, O_CLOEXEC, O_DIRECTORY = 0, 1, 2, 4, 8

    def __init__(self):
        self.nodes = {10: metadata(True), 11: metadata(True, st_ino=2),
                      12: metadata(st_ino=3)}
        self.names = {(10, 'dir'): 11, (11, 'file'): 12}
        self.open = Mock(side_effect=lambda name, flags, dir_fd: self.names[dir_fd, name])
        self.stat = Mock(side_effect=lambda name, dir_fd, follow_symlinks:
                         self.nodes[self.names[dir_fd, name]])
        self.fstat = Mock(side_effect=lambda fd: self.nodes[fd])
        self.read = Mock(side_effect=[b'a', b'bc', b''])
        self.close = Mock()


class ReaderPolicyTests(unittest.TestCase):
    def reader(self):
        with patch.object(f, 'installed_checks', return_value=(
                core.FileCheck(core.CLIENT, '0' * 64, 99, 3),)):
            return f.InstalledReader(b'fixture')

    def test_manifest_validated_before_any_native_io(self):
        with patch.object(f, '_platform') as guard, self.assertRaises(core.OperatorError):
            f.InstalledReader(b'{}')
        guard.assert_not_called()

    def test_exact_target_and_limit_before_native_io(self):
        reader = self.reader()
        with patch.object(f, '_platform') as guard, patch.object(f, '_identity') as identity, patch.object(
                f, '_read_native') as read:
            for path, limit in [('/etc/shadow', 99), (core.CLIENT + '/..', 99),
                                (core.CLIENT, 100), (core.CLIENT, True), (None, 99),
                                ([], 99), (core.CLIENT, 99.0)]:
                with self.subTest(path=path, limit=limit), self.assertRaisesRegex(
                        core.OperatorError, '^FS_TARGET$'):
                    reader(path, limit)
            guard.assert_not_called()
            identity.assert_not_called()
            read.assert_not_called()

    def test_dispatch_uses_fresh_identity_and_fixed_root_wrapper(self):
        reader = self.reader()
        with patch.object(f, '_platform') as platform, patch.object(f, '_identity',
                return_value=(126, 128)) as identity, patch.object(f, '_read_native',
                return_value=b'abc') as read:
            self.assertEqual(reader(core.CLIENT, 99), b'abc')
            self.assertEqual(reader(core.CLIENT, 99), b'abc')
            self.assertEqual(identity.call_count, 2)
            self.assertEqual(platform.call_count, 2)
            read.assert_called_with(tuple(core.CLIENT.split('/')[1:]), 99, (126, 128))
        fake = FakeFS()
        fake.open = Mock(return_value=10)
        with patch.object(f, 'os', fake), patch.object(f, '_read_at', return_value=b'abc') as at:
            self.assertEqual(f._read_native(('dir', 'file'), 3, (126, 128)), b'abc')
            fake.open.assert_called_once_with('/', 13)
            self.assertEqual(at.call_args.args[:3], (10, ('dir', 'file'), 3))
            self.assertEqual(at.call_args.args[3](('usr',)), ((0, 0),))
            fake.close.assert_called_once_with(10)
        fake.close.reset_mock()
        with patch.object(f, 'os', fake), patch.object(f, '_read_at', side_effect=OSError), self.assertRaises(OSError):
            f._read_native(('dir', 'file'), 3, (126, 128))
        fake.close.assert_called_once_with(10)

    def test_static_os_errors_suppress_sensitive_details(self):
        reader = self.reader()
        for number, code in [(errno.ENOENT, 'FS_MISSING'), (errno.EACCES, 'FS_ACCESS'),
                             (errno.EPERM, 'FS_ACCESS'), (errno.ELOOP, 'FS_SYMLINK'),
                             (errno.ENOTDIR, 'FS_NOT_DIRECTORY'), (errno.EIO, 'FS_IO')]:
            with self.subTest(number=number), patch.object(f, '_platform'), patch.object(
                    f, '_identity', return_value=(126, 128)), patch.object(f, '_read_native',
                    side_effect=OSError(number, 'SECRET')), self.assertRaises(
                    core.OperatorError) as caught:
                reader(core.CLIENT, 99)
            self.assertEqual(str(caught.exception), code)
            self.assertTrue(caught.exception.__suppress_context__)
            self.assertIsNone(caught.exception.__cause__)

    def test_platform_capabilities_and_root_fail_closed(self):
        fake = FakeFS()
        fake.geteuid = lambda: 0
        fake.supports_dir_fd = {fake.open, fake.stat}
        fake.supports_follow_symlinks = {fake.stat}
        with patch.object(f, 'os', fake), patch.object(f.sys, 'platform', 'linux'):
            f._platform()
            fake.geteuid = lambda: 1000
            with self.assertRaisesRegex(core.OperatorError, '^FS_ROOT_REQUIRED$'):
                f._platform()
            fake.supports_dir_fd = set()
            with self.assertRaisesRegex(core.OperatorError, '^FS_PLATFORM$'):
                f._platform()
        with patch.object(f.sys, 'platform', 'win32'), self.assertRaisesRegex(
                core.OperatorError, '^FS_PLATFORM$'):
            f._platform()

    def test_named_service_identity_required(self):
        user = NS(pw_name=f.SERVICE, pw_uid=126, pw_gid=128)
        group = NS(gr_name=f.SERVICE, gr_gid=128)
        pwd, grp = NS(getpwnam=Mock(return_value=user)), NS(getgrnam=Mock(return_value=group))
        with patch.dict(sys.modules, pwd=pwd, grp=grp):
            self.assertEqual(f._identity(), (126, 128))
            for attribute, value in [('pw_uid', 0), ('pw_gid', 129), ('pw_name', 'other')]:
                old = getattr(user, attribute)
                setattr(user, attribute, value)
                with self.assertRaisesRegex(core.OperatorError, '^FS_SERVICE_IDENTITY$'):
                    f._identity()
                setattr(user, attribute, old)
            pwd.getpwnam.side_effect = KeyError('SECRET')
            with self.assertRaisesRegex(core.OperatorError, '^FS_SERVICE_IDENTITY$'):
                f._identity()

    def test_service_owner_exception_is_component_scoped(self):
        service = (126, 128)
        for parts in [(), ('usr',), ('usr', 'share'), ('usr', 'share', 'wazuh-dashboard-old')]:
            self.assertEqual(f._owners(parts, service), ((0, 0),))
        for parts in [f.VENDOR, f.VENDOR + ('node', 'bin', 'node')]:
            self.assertEqual(f._owners(parts, service), ((0, 0), service))
        with self.assertRaisesRegex(core.OperatorError, '^FS_COMPONENTS$'):
            f._owners(f.VENDOR + ('..', '..', '..', 'etc', 'shadow'), service)

    def test_metadata_rejects_links_special_files_writes_and_wrong_owner(self):
        f._trusted(metadata(), False, ((0, 0),))
        f._trusted(metadata(st_uid=126, st_gid=128), False, ((0, 0), (126, 128)))
        for st in [metadata(st_uid=1), metadata(st_gid=1), metadata(True),
                   metadata(st_mode=stat.S_IFLNK | 0o777), metadata(st_mode=stat.S_IFIFO | 0o600),
                   metadata(st_mode=stat.S_IFCHR | 0o600)] + [
                   metadata(st_mode=stat.S_IFREG | 0o640 | bit) for bit in (0o002, 0o020, 0o2000, 0o4000)]:
            with self.assertRaisesRegex(core.OperatorError, '^FS_METADATA$'):
                f._trusted(st, False, ((0, 0),))
        for changes in ({'st_mode': stat.S_IFDIR | 0o777}, {'st_uid': 126, 'st_gid': 128}):
            fs = FakeFS()
            fs.nodes[10] = metadata(True, **changes)
            with self.assertRaisesRegex(core.OperatorError, '^FS_METADATA$'):
                self.run_fake(fs)
            fs.open.assert_not_called()
            fs.read.assert_not_called()

    def test_primitive_components_rejected_before_any_io(self):
        bad = ((), [], 'dir/file', ('dir', '..', 'file'), ('.', 'file'),
               ('dir/file',), ('/etc',), ('dir', ''), ('a\\b',), ('a:b',),
               ('a\x00b',), ('a\nb',), ('\ud800',), ('\u00e9',), (None,), ('x' * 256,), ('x',) * 129)
        for parts in bad:
            fs = FakeFS()
            with self.subTest(parts=parts), patch.object(f, 'os', fs):
                for call in (lambda: f._read_at(10, parts, 3, lambda p: ((0, 0),)),
                             lambda: f._read_root_owned(parts, 3)):
                    with self.assertRaisesRegex(core.OperatorError, '^FS_COMPONENTS$'):
                        call()
                fs.fstat.assert_not_called()
                fs.stat.assert_not_called()
                fs.open.assert_not_called()

    def test_primitive_limit_rejected_before_any_io(self):
        for limit in (None, True, 3.0, -1, f.MAX_READ + 1):
            fs = FakeFS()
            with self.subTest(limit=limit), patch.object(f, 'os', fs):
                for call in (lambda: f._read_at(10, ('file',), limit, lambda p: ((0, 0),)),
                             lambda: f._read_root_owned(('file',), limit)):
                    with self.assertRaisesRegex(core.OperatorError, '^FS_BOUND$'):
                        call()
                fs.fstat.assert_not_called()
                fs.open.assert_not_called()

    def run_fake(self, fs, limit=3):
        with patch.object(f, 'os', fs):
            return f._read_at(10, ('dir', 'file'), limit, lambda parts: ((0, 0),))

    def test_traversal_flags_relative_names_partial_reads_and_closure(self):
        fs = FakeFS()
        self.assertEqual(self.run_fake(fs), b'abc')
        self.assertEqual(fs.open.call_args_list[0].args, ('dir', 15))
        self.assertEqual(fs.open.call_args_list[1].args, ('file', 7))
        self.assertEqual(fs.open.call_args_list[0].kwargs, {'dir_fd': 10})
        self.assertEqual(fs.open.call_args_list[1].kwargs, {'dir_fd': 11})
        self.assertTrue(all(c.kwargs['follow_symlinks'] is False for c in fs.stat.call_args_list))
        self.assertEqual([c.args[1] for c in fs.read.call_args_list], [4, 3, 1])
        self.assertEqual([c.args[0] for c in fs.close.call_args_list], [12, 11])

    def test_preopen_bounds_and_postread_growth_truncation(self):
        fs = FakeFS()
        with self.assertRaisesRegex(core.OperatorError, '^FS_SIZE$'):
            self.run_fake(fs, 2)
        fs.read.assert_not_called()
        self.assertEqual(fs.open.call_count, 1)
        for chunks in ([b'abcd'], [b'a', b'']):
            fs = FakeFS()
            fs.read.side_effect = chunks
            with self.assertRaisesRegex(core.OperatorError, '^FS_SIZE$'):
                self.run_fake(fs)
            self.assertEqual(fs.close.call_count, 2)

    def test_replaced_descriptor_leaf_parent_and_root_detected(self):
        for target in (10, 11, 12):
            fs = FakeFS()
            def read(fd, amount):
                fs.nodes[target] = NS(**dict(vars(fs.nodes[target]), st_ctime_ns=2))
                fs.read.side_effect = [b'']
                return b'abc'
            fs.read.side_effect = read
            with self.subTest(target=target), self.assertRaisesRegex(core.OperatorError, '^FS_CHANGED$'):
                self.run_fake(fs)
            self.assertEqual(fs.close.call_count, 2)
        fs = FakeFS()
        fs.fstat.side_effect = lambda fd: metadata(st_ino=999) if fd == 12 else fs.nodes[fd]
        with self.assertRaisesRegex(core.OperatorError, '^FS_CHANGED$'):
            self.run_fake(fs)
        fs.read.assert_not_called()
        self.assertEqual(fs.close.call_count, 2)

    def test_directory_entry_replacement_and_read_error_close_descriptors(self):
        for replace_parent in (False, True):
            fs = FakeFS()
            def read(fd, amount):
                key = (10, 'dir') if replace_parent else (11, 'file')
                fs.nodes[13] = NS(**dict(vars(fs.nodes[fs.names[key]]), st_ino=999))
                fs.names[key] = 13
                fs.read.side_effect = [b'']
                return b'abc'
            fs.read.side_effect = read
            with self.assertRaisesRegex(core.OperatorError, '^FS_CHANGED$'):
                self.run_fake(fs)
            self.assertEqual(fs.close.call_count, 2)
        fs = FakeFS()
        fs.read.side_effect = OSError(errno.EIO, 'SECRET')
        with self.assertRaises(OSError):
            self.run_fake(fs)
        self.assertEqual(fs.close.call_count, 2)


@unittest.skipUnless(sys.platform == 'linux', 'requires Linux descriptor-relative filesystem semantics')
class NativeReaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'dir').mkdir(mode=0o700)
        self.file = self.root / 'dir/file'
        self.file.write_bytes(b'a\x00\xff')
        self.file.chmod(0o600)
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)

    def read(self, limit=3):
        return f._read_at(self.fd, ('dir', 'file'), limit,
                          lambda parts: ((os.getuid(), os.getgid()),))

    def test_native_binary_empty_and_bounds(self):
        self.assertEqual(self.read(), b'a\x00\xff')
        with self.assertRaisesRegex(core.OperatorError, '^FS_SIZE$'):
            self.read(2)
        self.file.write_bytes(b'')
        self.assertEqual(self.read(0), b'')

    def test_native_symlink_directory_link_and_fifo_fail_without_read(self):
        self.file.unlink()
        self.file.symlink_to('/etc/passwd')
        with self.assertRaisesRegex(core.OperatorError, '^FS_METADATA$'):
            self.read()
        self.file.unlink()
        os.mkfifo(self.file, 0o600)
        with self.assertRaisesRegex(core.OperatorError, '^FS_METADATA$'):
            self.read()
        self.file.unlink()
        (self.root / 'dir').rmdir()
        (self.root / 'dir').symlink_to('/etc', target_is_directory=True)
        with self.assertRaisesRegex(core.OperatorError, '^FS_METADATA$'):
            self.read()

    def test_native_leaf_replacement_is_detected(self):
        read = os.read
        changed = False
        def swap(fd, count):
            nonlocal changed
            data = read(fd, count)
            if not changed:
                changed = True
                other = self.root / 'dir/new'
                other.write_bytes(b'xyz')
                other.chmod(0o600)
                os.replace(other, self.file)
            return data
        with patch.object(f.os, 'read', side_effect=swap), self.assertRaisesRegex(
                core.OperatorError, '^FS_CHANGED$'):
            self.read()

    def test_native_failure_does_not_leak_descriptors(self):
        before = len(list(Path('/proc/self/fd').iterdir()))
        self.file.chmod(0o666)
        for _ in range(10):
            with self.assertRaisesRegex(core.OperatorError, '^FS_METADATA$'):
                self.read()
        self.assertEqual(len(list(Path('/proc/self/fd').iterdir())), before)


if __name__ == '__main__':
    unittest.main()
