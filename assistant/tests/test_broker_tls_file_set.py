"""Offline package-root file-set closure; no Dashboard or Node execution."""
from dataclasses import asdict
from contextlib import nullcontext
import os
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
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
from siem.rbac.broker_tls import operator_dependency_graph as graph
from siem.rbac.broker_tls import operator_file_set as fileset
from siem.rbac.broker_tls import operator_runtime as runtime
if __package__:
    from .test_broker_tls_operator_fs import metadata
else:
    from test_broker_tls_operator_fs import metadata

AXIOS = graph.ROOT
NESTED = AXIOS + '/node_modules/foo'
OTHER = core.BASE + 'node_modules/bar'
PATHS = (AXIOS + '/package.json', AXIOS + '/lib/index.js',
         NESTED + '/package.json', OTHER + '/package.json')
CHECKS = (core.FileCheck(core.CLIENT, '0' * 64, 16, 1),) + tuple(
    core.FileCheck(path, '0' * 64, 16, 1) for path in PATHS)
PACKAGES = {root: next(check for check in CHECKS
                       if check.path == root + '/package.json')
            for root in (AXIOS, NESTED, OTHER)}
BOOT = bootstrap.Bootstrap(b'manifest', b'certificate')
PACKAGE = runtime.PackageIdentity(core.PACKAGE_VERSION, 'amd64', 'install')


class FileSetPolicyTests(unittest.TestCase):
    def plan(self, checks=CHECKS):
        with patch.object(fileset.core, 'installed_checks', return_value=checks), patch.object(
                fileset.graph, '_package_checks', return_value=(CHECKS[0], PACKAGES)):
            return fileset._plan(b'manifest')

    def test_plan_covers_nested_roots_once_and_rejects_orphan(self):
        roots, outer, files = self.plan()
        self.assertEqual(roots, tuple(sorted(PACKAGES)))
        self.assertEqual(outer, (AXIOS, OTHER))
        self.assertEqual(files, frozenset(PurePosixPath(path).parts[1:] for path in PATHS))
        orphan = core.FileCheck(core.BASE + 'node_modules/unknown/x.js', '0' * 64, 16, 1)
        with self.assertRaisesRegex(core.OperatorError, '^FILE_SET_MANIFEST$'):
            self.plan(CHECKS + (orphan,))

    def observe(self, *, scans=None, packages=None, boots=None):
        roots, outer, expected = self.plan()
        observed = {path: (1,) for path in expected}
        observed.update({PurePosixPath(root).parts[1:]: (1,) for root in outer})
        calls = []

        def scan(root, selected, identity, budget):
            calls.append(root)
            self.assertEqual(identity, (126, 128))
            prefix = PurePosixPath(root).parts[1:]
            self.assertEqual(selected, frozenset(path for path in expected
                                                  if path[:len(prefix)] == prefix))
            budget[0] += len(selected)
            budget[1] += 1
            return {key: value for key, value in observed.items()
                    if key[:len(prefix)] == prefix}

        with patch.object(fileset.fs, '_platform'), patch.object(fileset.os, 'supports_fd',
                {fileset.os.scandir}), patch.object(fileset.fs, '_identity',
                return_value=(126, 128)), patch.object(fileset.bootstrap,
                'load_bootstrap', side_effect=boots or [BOOT, BOOT]) as load, patch.object(
                fileset, '_plan', return_value=(roots, outer, expected)), patch.object(
                fileset, '_walk_native', side_effect=scans or scan) as walk, patch.object(
                fileset.runtime, 'read_package_identity', side_effect=packages or [PACKAGE] * 3) as registry:
            result = fileset.observe_package_file_set()
        self.assertEqual(load.call_count, 2)
        self.assertEqual(registry.call_count, 3)
        self.assertEqual(walk.call_count, 4)
        self.assertEqual(calls, [AXIOS, OTHER] * 2)
        return result

    def test_observation_is_sanitized_and_never_authorizes(self):
        result = self.observe()
        self.assertEqual((result.package_roots_checked, result.outer_roots_scanned,
                          result.manifest_files_seen, result.directory_entries_seen,
                          result.directories_seen), (3, 2, 4, 4, 2))
        for flag in ('file_bytes_verified', 'unlisted_files_outside_package_roots_excluded',
                     'actual_node_resolution_proven', 'loaded_code_proven', 'startup_authorized'):
            self.assertFalse(getattr(result, flag))
        self.assertNotIn('axios', repr(result) + str(asdict(result)))

    def test_later_pass_tree_drift_rejected(self):
        calls = 0

        def changed(root, selected, identity, budget):
            nonlocal calls
            calls += 1
            budget[0] += len(selected)
            budget[1] += 1
            return {next(iter(selected)): (2 if calls == 3 else 1,)}

        with self.assertRaisesRegex(core.OperatorError, '^FILE_SET_CHANGED$'):
            self.observe(scans=changed)

    def test_package_and_bootstrap_drift_rejected(self):
        with self.assertRaisesRegex(core.OperatorError, '^PACKAGE_CHANGED$'):
            self.observe(packages=[PACKAGE, runtime.PackageIdentity('changed', 'amd64', 'install')])
        with self.assertRaisesRegex(core.OperatorError, '^FILE_SET_BOOTSTRAP_CHANGED$'):
            self.observe(boots=[BOOT, bootstrap.Bootstrap(b'modified', b'certificate')])

    def test_scandir_capability_missing_fails_before_identity_or_bootstrap(self):
        with patch.object(fileset.fs, '_platform'), patch.object(fileset.os, 'supports_fd',
                set()), patch.object(fileset.fs, '_identity') as identity, patch.object(
                fileset.bootstrap, 'load_bootstrap') as load, self.assertRaisesRegex(
                core.OperatorError, '^FILE_SET_PLATFORM$'):
            fileset.observe_package_file_set()
        identity.assert_not_called()
        load.assert_not_called()

    def test_os_failure_is_static_and_does_not_return_private_name(self):
        with self.assertRaises(core.OperatorError) as caught:
            self.observe(scans=OSError(5, '/secret/unlisted.js'))
        self.assertEqual(str(caught.exception), 'FS_IO')
        self.assertNotIn('/secret/', str(caught.exception))

    def fake_directory(self, *, extra=False, symlink=False):
        root, package, file = metadata(True), metadata(True, st_ino=2), metadata(st_ino=3)
        nodes = {10: root, 11: package, 12: file}
        names = {(10, 'pkg'): 11, (11, 'package.json'): 12}
        entries = [SimpleNamespace(name='package.json')]
        if extra or symlink:
            nodes[13] = metadata(st_ino=4, st_mode=(stat.S_IFLNK | 0o777)
                                 if symlink else (stat.S_IFREG | 0o644))
            names[11, 'extra.js'] = 13
            entries.append(SimpleNamespace(name='extra.js'))
        fake = SimpleNamespace(O_RDONLY=1, O_DIRECTORY=2, O_NOFOLLOW=4,
                               O_CLOEXEC=8, O_NONBLOCK=16)
        fake.fstat = Mock(side_effect=lambda fd: nodes[fd])
        fake.stat = Mock(side_effect=lambda name, dir_fd, follow_symlinks:
                         nodes[names[dir_fd, name]])
        fake.open = Mock(side_effect=lambda name, flags, dir_fd: names[dir_fd, name])
        fake.close = Mock()
        fake.scandir = Mock(side_effect=lambda fd: nullcontext(entries if fd == 11 else []))
        return fake

    def test_fd_walk_uses_no_follow_and_closes_children(self):
        fake = self.fake_directory()
        with patch.object(fileset, 'os', fake):
            result = fileset._walk_at(10, ('pkg',),
                frozenset({('pkg', 'package.json')}), lambda _: ((0, 0),), [0, 0])
        self.assertIn(('pkg', 'package.json'), result)
        self.assertEqual([call.args[0] for call in fake.close.call_args_list], [12, 11])
        self.assertTrue(all(call.kwargs['follow_symlinks'] is False
                            for call in fake.stat.call_args_list))
        self.assertTrue(all(call.args[1] & fake.O_NOFOLLOW
                            for call in fake.open.call_args_list))
        fake.scandir.assert_called_once_with(11)

    def test_fd_walk_rejects_extra_file_or_symlink_without_opening_it(self):
        for symlink, code in ((False, 'FILE_SET_UNLISTED'), (True, 'FS_METADATA')):
            fake = self.fake_directory(extra=not symlink, symlink=symlink)
            with self.subTest(symlink=symlink), patch.object(fileset, 'os', fake), self.assertRaisesRegex(
                    core.OperatorError, '^' + code + '$'):
                fileset._walk_at(10, ('pkg',), frozenset({('pkg', 'package.json')}),
                                 lambda _: ((0, 0),), [0, 0])
            self.assertEqual([call.args[0] for call in fake.close.call_args_list], [12, 11])
            self.assertNotIn(13, [call.args[0] for call in fake.close.call_args_list])

    def test_directory_cannot_satisfy_an_expected_file(self):
        fake = self.fake_directory()
        fake.scandir = Mock(return_value=nullcontext([]))
        with patch.object(fileset, 'os', fake), self.assertRaisesRegex(
                core.OperatorError, '^FILE_SET_MISSING$'):
            fileset._walk_at(10, ('pkg',), frozenset({('pkg',)}),
                             lambda _: ((0, 0),), [0, 0])


@unittest.skipUnless(sys.platform == 'linux', 'native directory FDs require Linux')
class NativeFileSetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='alertmind-file-set-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        (self.base / 'pkg/lib').mkdir(parents=True)
        (self.base / 'pkg/empty').mkdir()
        (self.base / 'pkg/package.json').write_bytes(b'{}')
        (self.base / 'pkg/lib/index.js').write_bytes(b'module.exports = 1;')
        for path in (self.base / 'pkg', self.base / 'pkg/lib', self.base / 'pkg/empty'):
            path.chmod(0o700)
        for path in (self.base / 'pkg/package.json', self.base / 'pkg/lib/index.js'):
            path.chmod(0o600)
        self.expected = frozenset({('pkg', 'package.json'), ('pkg', 'lib', 'index.js')})
        self.owners = lambda _: ((os.getuid(), os.getgid()),)

    def walk(self):
        fd = os.open(self.base, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            budget = [0, 0]
            result = fileset._walk_at(fd, ('pkg',), self.expected, self.owners, budget)
            return result, budget
        finally:
            os.close(fd)

    def test_real_descriptor_walk_sees_expected_files_and_empty_directory(self):
        found, budget = self.walk()
        self.assertEqual({key for key in found if key in self.expected}, self.expected)
        self.assertIn(('pkg', 'empty'), found)
        self.assertEqual(budget, [4, 3])

    def test_unlisted_file_fails_closed(self):
        (self.base / 'pkg/lib/extra.js').write_bytes(b'PRIVATE')
        (self.base / 'pkg/lib/extra.js').chmod(0o600)
        with self.assertRaisesRegex(core.OperatorError, '^FILE_SET_UNLISTED$') as caught:
            self.walk()
        self.assertNotIn('PRIVATE', str(caught.exception))

    def test_missing_expected_file_fails_closed(self):
        (self.base / 'pkg/lib/index.js').unlink()
        with self.assertRaisesRegex(core.OperatorError, '^FILE_SET_MISSING$'):
            self.walk()

    def test_symlink_and_entry_budget_fail_without_following(self):
        (self.base / 'pkg/link.js').symlink_to(self.base / 'pkg/lib/index.js')
        with self.assertRaisesRegex(core.OperatorError, '^FS_METADATA$'):
            self.walk()
        (self.base / 'pkg/link.js').unlink()
        with patch.object(fileset, 'MAX_ENTRIES', 1), self.assertRaisesRegex(
                core.OperatorError, '^FILE_SET_LIMIT$'):
            self.walk()


if __name__ == '__main__':
    unittest.main()
