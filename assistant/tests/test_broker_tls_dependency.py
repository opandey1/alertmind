"""Offline direct-axios shadow tests; never import vendor code or start Node."""
from dataclasses import asdict
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_bootstrap as bootstrap
from siem.rbac.broker_tls import operator_core as core
from siem.rbac.broker_tls import operator_dependency as dep
from siem.rbac.broker_tls import operator_fs as fs
from siem.rbac.broker_tls import operator_runtime as runtime
if __package__:
    from .test_broker_tls_operator_fs import FakeFS, metadata
else:
    from test_broker_tls_operator_fs import FakeFS, metadata

CLIENT_BYTES = b'patched-client'
AXIOS_BYTES = b'{"name":"axios"}'
CHECKS = (
    core.FileCheck(core.CLIENT, core.sha(CLIENT_BYTES), 99, len(CLIENT_BYTES)),
    core.FileCheck(dep.ROOT_AXIOS, core.sha(AXIOS_BYTES), 99, len(AXIOS_BYTES)),
)
PACKAGE = runtime.PackageIdentity(core.PACKAGE_VERSION, 'amd64', 'install')
BOOT = bootstrap.Bootstrap(b'fixture', b'public-cert')


class DependencyTests(unittest.TestCase):
    def observe(self, *, shadows=None, blobs=None, packages=None, boots=None, checks=CHECKS):
        read = Mock(side_effect=blobs or [CLIENT_BYTES, AXIOS_BYTES] * 2)
        with patch.object(dep.fs, '_platform') as platform, patch.object(
                dep.fs, '_identity', return_value=(126, 128)) as identity, patch.object(
                dep.bootstrap, 'load_bootstrap', side_effect=boots or [BOOT, BOOT]) as loader, patch.object(
                dep.core, 'installed_checks', return_value=checks), patch.object(
                dep.fs, 'InstalledReader', return_value=read) as factory, patch.object(
                dep.fs, '_absent_native', side_effect=shadows or [True] * 38) as absent, patch.object(
                dep.runtime, 'read_package_identity', side_effect=packages or [PACKAGE] * 3) as registry:
            result = dep.observe_direct_axios_shadow()
            platform.assert_called_once_with()
            identity.assert_called_once_with()
            self.assertEqual(loader.call_count, 2)
            factory.assert_called_once_with(BOOT.manifest)
            self.assertEqual(absent.call_count, 38)
            self.assertEqual([call.args[:2] for call in absent.call_args_list],
                             [(PurePosixPath(parent).parts[1:], child)
                              for parent, child in dep.SHADOW_TARGETS] * 2)
            self.assertEqual(registry.call_count, 3)
            self.assertEqual([c.args for c in read.call_args_list],
                             [(check.path, check.limit) for check in CHECKS] * 2)
            return result

    def test_exact_ancestor_set_and_non_authorizing_result(self):
        result = self.observe()
        self.assertEqual(dep.SHADOW_NAMES, ('axios', 'axios.js', 'axios.json', 'axios.node'))
        self.assertEqual(len(dep.SHADOW_PARENTS), 4)
        self.assertEqual(len(dep.SHADOW_TARGETS), 19)
        self.assertEqual(result.shadow_candidate_count, 19)
        self.assertEqual(result.pinned_files_checked, 2)
        self.assertTrue(result.direct_shadow_candidates_absent)
        self.assertFalse(result.root_axios_selected_proven)
        self.assertFalse(result.transitive_resolution_proven)
        self.assertFalse(result.effective_environment_proven)
        self.assertFalse(result.startup_authorized)
        self.assertNotIn('manifest', asdict(result))

    def test_shadow_on_either_pass_stops_before_success(self):
        for index in (0, 15, 16, 18, 19, 37):
            shadows = [True] * 38
            shadows[index] = False
            with self.subTest(index=index), patch.object(dep.fs, '_platform'), patch.object(
                    dep.fs, '_identity', return_value=(126, 128)), patch.object(
                    dep.bootstrap, 'load_bootstrap', return_value=BOOT), patch.object(
                    dep.core, 'installed_checks', return_value=CHECKS), patch.object(
                    dep.fs, 'InstalledReader', return_value=Mock(side_effect=[CLIENT_BYTES, AXIOS_BYTES] * 2)), patch.object(
                    dep.fs, '_absent_native', side_effect=shadows) as absent, patch.object(
                    dep.runtime, 'read_package_identity', return_value=PACKAGE), self.assertRaisesRegex(
                    core.OperatorError, '^DEPENDENCY_SHADOW$'):
                dep.observe_direct_axios_shadow()
            self.assertEqual(absent.call_count, index + 1)

    def test_missing_pinned_root_package_stops_before_shadow_reads(self):
        with patch.object(dep.fs, '_platform'), patch.object(dep.fs, '_identity', return_value=(126, 128)), patch.object(
                dep.bootstrap, 'load_bootstrap', return_value=BOOT), patch.object(
                dep.core, 'installed_checks', return_value=CHECKS[:1]), patch.object(
                dep.fs, '_absent_native') as absent, self.assertRaisesRegex(
                core.OperatorError, '^DEPENDENCY_MANIFEST$'):
            dep.observe_direct_axios_shadow()
        absent.assert_not_called()

    def test_size_and_digest_mismatch_fail_closed(self):
        for first, code in ((CLIENT_BYTES[:-1], 'DEPENDENCY_SIZE'),
                            (b'xatched-client', 'DEPENDENCY_DIGEST')):
            with self.subTest(code=code), patch.object(dep.fs, '_platform'), patch.object(
                    dep.fs, '_identity', return_value=(126, 128)), patch.object(
                    dep.bootstrap, 'load_bootstrap', return_value=BOOT), patch.object(
                    dep.core, 'installed_checks', return_value=CHECKS), patch.object(
                    dep.fs, 'InstalledReader', return_value=Mock(return_value=first)), patch.object(
                    dep.fs, '_absent_native', return_value=True), patch.object(
                    dep.runtime, 'read_package_identity', return_value=PACKAGE), self.assertRaisesRegex(
                    core.OperatorError, '^' + code + '$'):
                dep.observe_direct_axios_shadow()

    def test_package_and_bootstrap_drift_fail_closed(self):
        changed = runtime.PackageIdentity('other', 'amd64', 'install')
        with patch.object(dep.fs, '_platform'), patch.object(dep.fs, '_identity', return_value=(126, 128)), patch.object(
                dep.bootstrap, 'load_bootstrap', return_value=BOOT), patch.object(
                dep.core, 'installed_checks', return_value=CHECKS), patch.object(
                dep.fs, 'InstalledReader', side_effect=lambda _: Mock(side_effect=[CLIENT_BYTES, AXIOS_BYTES] * 2)), patch.object(
                dep.fs, '_absent_native', return_value=True), patch.object(
                dep.runtime, 'read_package_identity', side_effect=[PACKAGE, changed]), self.assertRaisesRegex(
                core.OperatorError, '^PACKAGE_CHANGED$'):
            dep.observe_direct_axios_shadow()
        with self.assertRaisesRegex(core.OperatorError, '^DEPENDENCY_BOOTSTRAP_CHANGED$'):
            self.observe(boots=[BOOT, bootstrap.Bootstrap(b'changed', b'public-cert')])

    def test_os_error_is_static_and_private(self):
        with patch.object(dep.fs, '_platform'), patch.object(dep.fs, '_identity', return_value=(126, 128)), patch.object(
                dep.bootstrap, 'load_bootstrap', return_value=BOOT), patch.object(
                dep.core, 'installed_checks', return_value=CHECKS), patch.object(
                dep.fs, 'InstalledReader'), patch.object(
                dep.fs, '_absent_native', side_effect=OSError(5, 'SECRET')) as absent, patch.object(
                dep.runtime, 'read_package_identity', return_value=PACKAGE), self.assertRaises(
                core.OperatorError) as caught:
            dep.observe_direct_axios_shadow()
        absent.assert_called_once()
        self.assertEqual(str(caught.exception), 'FS_IO')
        self.assertNotIn('SECRET', str(caught.exception))

    def test_descriptor_absence_and_present_shadow_without_following(self):
        fake = FakeFS()
        fake.nodes[11] = metadata(True, st_ino=2)
        fake.names = {(10, 'plugin'): 11}

        def lookup(name, *, dir_fd, follow_symlinks):
            self.assertFalse(follow_symlinks)
            if (dir_fd, name) not in fake.names:
                raise FileNotFoundError()
            return fake.nodes[fake.names[dir_fd, name]]

        fake.stat = Mock(side_effect=lookup)
        owners = lambda _: ((0, 0),)
        with patch.object(fs, 'os', fake):
            self.assertTrue(fs._absent_below_at(10, ('plugin',),
                            ('node_modules', 'axios'), owners))
            fake.nodes[12] = metadata(True, st_ino=3)
            fake.names[11, 'node_modules'] = 12
            self.assertTrue(fs._absent_below_at(10, ('plugin',),
                            ('node_modules', 'axios'), owners))
            fake.nodes[13] = metadata(st_ino=4, st_mode=stat.S_IFLNK | 0o777)
            fake.names[12, 'axios'] = 13
            self.assertFalse(fs._absent_below_at(10, ('plugin',),
                             ('node_modules', 'axios'), owners))
            # Optional intermediate symlinks must not be followed either.
            fake.nodes[12] = metadata(st_ino=3, st_mode=stat.S_IFLNK | 0o777)
            with self.assertRaisesRegex(core.OperatorError, '^FS_METADATA$'):
                fs._absent_below_at(10, ('plugin',), ('node_modules', 'axios'), owners)
        self.assertTrue(all(call.kwargs['follow_symlinks'] is False
                            for call in fake.stat.call_args_list))

    def test_descriptor_rejects_absence_race(self):
        fake = FakeFS()
        fake.names = {(10, 'plugin'): 11}
        fake.nodes[11] = metadata(True, st_ino=2)
        probes = 0

        def lookup(name, *, dir_fd, follow_symlinks):
            nonlocal probes
            if (dir_fd, name) == (11, 'node_modules'):
                probes += 1
                if probes == 1:
                    raise FileNotFoundError()
                return metadata(True, st_ino=3)
            return fake.nodes[fake.names[dir_fd, name]]

        fake.stat = Mock(side_effect=lookup)
        with patch.object(fs, 'os', fake), self.assertRaisesRegex(
                core.OperatorError, '^FS_CHANGED$'):
            fs._absent_below_at(10, ('plugin',), ('node_modules', 'axios'),
                                lambda _: ((0, 0),))
        self.assertEqual(probes, 2)

    @unittest.skipUnless(sys.platform == 'linux' and hasattr(os, 'O_DIRECTORY'),
                         'native descriptor test requires Linux')
    def test_native_absence_and_present_directory_or_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            plugin = Path(temp, 'plugin')
            plugin.mkdir(mode=0o700)
            root = os.open(temp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                owners = lambda _: ((os.getuid(), os.getgid()),)
                self.assertTrue(fs._absent_below_at(root, ('plugin',),
                                ('node_modules', 'axios'), owners))
                modules = plugin / 'node_modules'
                modules.mkdir(mode=0o700)
                self.assertTrue(fs._absent_below_at(root, ('plugin',),
                                ('node_modules', 'axios'), owners))
                target = modules / 'axios'
                target.mkdir(mode=0o700)
                self.assertFalse(fs._absent_below_at(root, ('plugin',),
                                 ('node_modules', 'axios'), owners))
                target.rmdir()
                target.symlink_to(temp, target_is_directory=True)
                self.assertFalse(fs._absent_below_at(root, ('plugin',),
                                 ('node_modules', 'axios'), owners))
            finally:
                os.close(root)

    @unittest.skipUnless(sys.platform == 'linux' and hasattr(os, 'O_DIRECTORY'),
                         'native descriptor test requires Linux')
    def test_native_rejects_untrusted_parent_or_bad_components(self):
        with tempfile.TemporaryDirectory() as temp:
            plugin = Path(temp, 'plugin')
            plugin.mkdir(mode=0o700)
            root = os.open(temp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                owners = lambda _: ((os.getuid(), os.getgid()),)
                with self.assertRaisesRegex(core.OperatorError, '^FS_COMPONENTS$'):
                    fs._absent_below_at(root, ('plugin',), ('..', 'axios'), owners)
                plugin.chmod(0o777)
                with self.assertRaisesRegex(core.OperatorError, '^FS_METADATA$'):
                    fs._absent_below_at(root, ('plugin',), ('node_modules', 'axios'), owners)
            finally:
                os.close(root)
