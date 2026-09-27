"""Offline fixed-name policy and syscall-composition tests; no VM access."""
from contextlib import contextmanager
from dataclasses import FrozenInstanceError
import errno
import inspect
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_core as core
from siem.rbac.broker_tls import operator_fs as fs
from siem.rbac.broker_tls import operator_guard_entry as guard
from siem.rbac.broker_tls import operator_python_paths as paths
if __package__:
    from .test_broker_tls_operator_fs import FakeFS, metadata
else:
    from test_broker_tls_operator_fs import FakeFS, metadata


class PathFS(FakeFS):
    O_PATH = 16
    major = staticmethod(lambda value: value >> 8)
    minor = staticmethod(lambda value: value & 255)

    def __init__(self):
        super().__init__()
        self.nodes[12] = metadata(st_mode=stat.S_IFCHR | 0o666, st_rdev=259)
        self.nodes.update({i: metadata(True, st_ino=i) for i in (13, 14, 15)})
        self.names = {(10, 'dev'): 11, (11, 'null'): 12, (10, 'usr'): 13,
                      (13, 'lib'): 14, (10, 'etc'): 15}
        self.open = Mock(side_effect=lambda name, flags, dir_fd=None:
                         10 if name == '/' and dir_fd is None else self.names[dir_fd, name])
        self.stat = Mock(side_effect=self.lookup)
        self.write = Mock()

    def lookup(self, name, dir_fd, follow_symlinks):
        if (dir_fd, name) not in self.names:
            raise FileNotFoundError(errno.ENOENT, 'not present')
        return self.nodes[self.names[dir_fd, name]]


@contextmanager
def fake_host(fake):
    with patch.object(fs, '_platform'), patch.object(paths, 'os', fake), patch.object(fs, 'os', fake):
        yield


class PythonPathTests(unittest.TestCase):
    def test_fixed_paths_two_passes_and_no_payload_or_identity_lookup(self):
        fake = PathFS()
        with fake_host(fake), patch.object(fs, '_identity') as nss, patch.object(
                fs, '_absent_below_at', wraps=fs._absent_below_at) as absent:
            result = paths.observe_python_path_inputs()
        expected = [(10, ('usr', 'lib'), ('python314.zip',)), (10, ('etc',), ('ld.so.preload',))] * 2
        self.assertEqual([call.args[:3] for call in absent.call_args_list], expected)
        for call in absent.call_args_list:
            for parts in ((), ('dev',), fs.VENDOR):
                self.assertEqual(call.args[3](parts), ((0, 0),))
        self.assertEqual((result.file_passes, result.absent_input_count), (2, 2))
        self.assertIs(result.fixed_optional_inputs_absent, True)
        self.assertIs(result.null_anchor_matches, True)
        fake.read.assert_not_called()
        fake.write.assert_not_called()
        nss.assert_not_called()
        self.assertEqual(fake.close.call_count, len(fake.open.call_args_list))

    def test_every_optional_object_is_rejected_without_opening_it(self):
        for parent, name, code in ((14, 'python314.zip', 'PY_ZIP_PRESENT'), (15, 'ld.so.preload', 'PY_PRELOAD_PRESENT')):
            for mode in (stat.S_IFREG | 0o600, stat.S_IFDIR | 0o700, stat.S_IFLNK | 0o777, stat.S_IFIFO | 0o600):
                for bad_pass in (1, 2):
                    fake = PathFS()
                    seen = 0
                    def lookup(target, dir_fd, follow_symlinks):
                        nonlocal seen
                        if (dir_fd, target) == (parent, name):
                            seen += 1
                            # Each successful absence checks the name twice.
                            if seen == 1 + (bad_pass - 1) * 2:
                                return metadata(st_mode=mode, st_size=0)
                        return fake.lookup(target, dir_fd, follow_symlinks)
                    fake.stat.side_effect = lookup
                    with self.subTest(name=name, mode=mode, bad_pass=bad_pass), fake_host(fake), self.assertRaisesRegex(
                            core.OperatorError, '^' + code + '$'):
                        paths.observe_python_path_inputs()
                    self.assertFalse(any(call.args[0] == name for call in fake.open.call_args_list))
                    self.assertEqual(fake.close.call_count, fake.open.call_count)

    def test_absence_recheck_detects_new_child(self):
        fake = PathFS()
        seen = 0
        def lookup(name, dir_fd, follow_symlinks):
            nonlocal seen
            if name == 'python314.zip':
                seen += 1
                if seen == 2:
                    return metadata()
            return fake.lookup(name, dir_fd, follow_symlinks)
        fake.stat.side_effect = lookup
        with fake_host(fake), self.assertRaisesRegex(core.OperatorError, '^FS_CHANGED$'):
            paths.observe_python_path_inputs()
        self.assertEqual(fake.close.call_count, fake.open.call_count)

    def test_required_ancestors_cannot_be_missing_service_owned_or_symlinked(self):
        for node in (10, 11, 13, 14, 15):
            for changes in ({'st_uid': 126}, {'st_gid': 128}, {'st_mode': stat.S_IFDIR | 0o777},
                            {'st_mode': stat.S_IFLNK | 0o777}):
                fake = PathFS()
                fake.nodes[node] = metadata(True, **changes)
                with fake_host(fake), self.assertRaisesRegex(core.OperatorError, '^FS_METADATA$'):
                    paths.observe_python_path_inputs()
                self.assertEqual(fake.close.call_count, fake.open.call_count)
        fake = PathFS()
        del fake.names[13, 'lib']
        with fake_host(fake), self.assertRaisesRegex(core.OperatorError, '^FS_MISSING$'):
            paths.observe_python_path_inputs()

    def test_null_metadata_rejects_wrong_type_owner_device_or_unsafe_mode(self):
        bad = [{'st_mode': kind | 0o666} for kind in (stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK, stat.S_IFIFO, stat.S_IFBLK)]
        bad += [{'st_uid': 126}, {'st_gid': 128}, {'st_rdev': 260}, {'st_rdev': 515}]
        bad += [{'st_mode': stat.S_IFCHR | bits | 0o666} for bits in (0o4000, 0o2000, 0o1000, 0o100, 0o10, 0o1)]
        for changes in bad:
            fake = PathFS()
            fake.nodes[12] = metadata(st_rdev=259)
            fake.nodes[12].st_mode = stat.S_IFCHR | 0o666
            vars(fake.nodes[12]).update(changes)
            with self.subTest(changes=changes), fake_host(fake), self.assertRaisesRegex(core.OperatorError, '^PY_NULL_METADATA$'):
                paths.observe_python_path_inputs()
            self.assertFalse(any(call.args[0] == 'null' for call in fake.open.call_args_list))
            fake.read.assert_not_called()
            self.assertEqual(fake.close.call_count, fake.open.call_count)

    def test_null_allows_normal_writability_but_opens_only_metadata(self):
        for mode in (0o666, 0o660, 0o600, 0):
            fake = PathFS()
            fake.nodes[12].st_mode = stat.S_IFCHR | mode
            with fake_host(fake):
                paths.observe_python_path_inputs()
            null_opens = [call for call in fake.open.call_args_list if call.args[0] == 'null']
            self.assertEqual(len(null_opens), 2)
            for call in null_opens:
                self.assertEqual(call.args, ('null', fake.O_PATH | fake.O_NOFOLLOW | fake.O_CLOEXEC))
                self.assertEqual(call.kwargs, {'dir_fd': 11})
            fake.read.assert_not_called()
            fake.write.assert_not_called()

    def test_null_open_race_rejects_changed_type_and_device(self):
        for change in ({'st_mode': stat.S_IFLNK | 0o777}, {'st_rdev': 260}):
            fake = PathFS()
            def fstat(fd):
                if fd == 12:
                    value = metadata(**vars(fake.nodes[12]))
                    vars(value).update(change)
                    return value
                return fake.nodes[fd]
            fake.fstat.side_effect = fstat
            with fake_host(fake), self.assertRaisesRegex(core.OperatorError, '^PY_NULL_METADATA$'):
                paths._null_anchor_at(10)
            self.assertEqual(fake.close.call_count, 2)

    def test_anchor_before_open_after_and_name_drift_closes_descriptors(self):
        cases = [('fstat', 12, 1), ('fstat', 12, 2), ('fstat', 11, 1), ('fstat', 11, 2),
                 ('fstat', 10, 2), ('stat', 'null', 2), ('stat', 'dev', 2)]
        for method, target, nth in cases:
            fake = PathFS()
            seen = 0
            def observe(*args, **kwargs):
                nonlocal seen
                value = fake.nodes[args[0]] if method == 'fstat' else fake.lookup(*args, **kwargs)
                if args[0] == target:
                    seen += 1
                    if seen == nth:
                        value = metadata(**vars(value))
                        value.st_ino += 99
                return value
            getattr(fake, method).side_effect = observe
            with self.subTest(case=(method, target, nth)), fake_host(fake), self.assertRaisesRegex(core.OperatorError, '^FS_CHANGED$'):
                paths._null_anchor_at(10)
            self.assertEqual(fake.close.call_count, fake.open.call_count)

    def test_device_number_in_post_read_stamp_cannot_be_omitted(self):
        fake = PathFS()
        seen = 0
        def fstat(fd):
            nonlocal seen
            if fd == 12:
                seen += 1
                if seen == 2:
                    return metadata(**{**vars(fake.nodes[12]), 'st_rdev': 260})
            return fake.nodes[fd]
        fake.fstat.side_effect = fstat
        with fake_host(fake), self.assertRaisesRegex(core.OperatorError, '^FS_CHANGED$'):
            paths._null_anchor_at(10)

    def test_cross_pass_device_replacement_and_outer_root_drift_fail(self):
        fake = PathFS()
        with fake_host(fake), patch.object(paths, '_null_anchor_at', side_effect=[('first',), ('second',)]), self.assertRaisesRegex(
                core.OperatorError, '^PY_NULL_CHANGED$'):
            paths.observe_python_path_inputs()
        fake = PathFS()
        def changed(_fd):
            fake.nodes[10] = metadata(True, st_ino=999)
            return ('same',)
        with fake_host(fake), patch.object(paths, '_null_anchor_at', side_effect=changed), self.assertRaisesRegex(
                core.OperatorError, '^FS_CHANGED$'):
            paths.observe_python_path_inputs()
        self.assertEqual(fake.close.call_count, fake.open.call_count)

    def test_platform_and_required_capability_fail_before_io(self):
        fake = PathFS()
        with fake_host(fake), patch.object(fs, '_platform', side_effect=core.OperatorError('FS_ROOT_REQUIRED')), self.assertRaisesRegex(
                core.OperatorError, '^FS_ROOT_REQUIRED$'):
            paths.observe_python_path_inputs()
        fake.open.assert_not_called()
        for missing in ('O_PATH', 'major', 'minor'):
            # A plain instance without this capability; no fallback read-open.
            incomplete = type('IncompleteOS', (), {name: getattr(fake, name) for name in
                ('O_PATH', 'major', 'minor', 'open') if name != missing})()
            with patch.object(fs, '_platform'), patch.object(paths, 'os', incomplete), self.assertRaisesRegex(
                    core.OperatorError, '^PY_PATH_PLATFORM$'):
                paths.observe_python_path_inputs()
        fake.open.assert_not_called()

    def test_sanitized_os_failures_and_open_failure_cleanup(self):
        for number, code in ((errno.ENOENT, 'FS_MISSING'), (errno.EACCES, 'FS_ACCESS'),
                             (errno.ELOOP, 'FS_SYMLINK'), (errno.EIO, 'FS_IO')):
            for fail_name in ('/', 'lib', 'null'):
                fake = PathFS()
                original = fake.open.side_effect
                def failing(name, *args, **kwargs):
                    if name == fail_name:
                        raise OSError(number, 'PRIVATE_VALUE')
                    return original(name, *args, **kwargs)
                fake.open.side_effect = failing
                with fake_host(fake), self.assertRaises(core.OperatorError) as caught:
                    paths.observe_python_path_inputs()
                self.assertEqual(str(caught.exception), code)
                self.assertTrue(caught.exception.__suppress_context__)
                self.assertEqual(fake.close.call_count, fake.open.call_count - 1)

    def test_no_public_overrides_and_non_authorizing_frozen_result(self):
        self.assertEqual(len(inspect.signature(paths.observe_python_path_inputs).parameters), 0)
        fake = PathFS()
        with fake_host(fake):
            with self.assertRaises(TypeError):
                paths.observe_python_path_inputs('/tmp')
            result = paths.observe_python_path_inputs()
        for name in ('complete_search_path_proven', 'effective_cache_redirection_proven', 'loader_environment_proven',
                     'native_resolution_proven', 'loaded_code_proven', 'atomic_snapshot_proven', 'runtime_trusted', 'startup_authorized'):
            self.assertIs(getattr(result, name), False)
        with self.assertRaises(FrozenInstanceError):
            result.startup_authorized = True
        self.assertNotIn('operator_python_paths.py', {pin[0] for pin in guard.PINNED_MODULES})
        self.assertIn('operator_python_paths.py', {pin[0] for pin in guard.RUNTIME_MODULES})


@unittest.skipUnless(sys.platform == 'linux', 'requires Linux descriptor-relative metadata syscalls')
class PythonPathNativeTests(unittest.TestCase):
    def test_native_absence_present_empty_file_and_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'usr/lib').mkdir(parents=True)
            (root / 'etc').mkdir()
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                for parent, child, _code in paths.ABSENT_INPUTS:
                    def absent():
                        return fs._absent_below_at(fd, parent, child, lambda _: ((os.geteuid(), os.getegid()),))
                    self.assertTrue(absent())
                    leaf = root.joinpath(*parent, *child)
                    leaf.write_bytes(b'')
                    self.assertFalse(absent())
                    leaf.unlink()
                    leaf.symlink_to('nonexistent-target')
                    self.assertFalse(absent())
                    leaf.unlink()
            finally:
                os.close(fd)

    def test_native_null_metadata_only_no_device_payload_io(self):
        # Host metadata only, not lab VM evidence; needs no root privileges.
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        try:
            with patch.object(paths.os, 'read', side_effect=AssertionError('payload read forbidden')), patch.object(
                    paths.os, 'write', side_effect=AssertionError('payload write forbidden')):
                first = paths._null_anchor_at(fd)
                self.assertEqual(first, paths._null_anchor_at(fd))
        finally:
            os.close(fd)


if __name__ == '__main__':
    unittest.main()
