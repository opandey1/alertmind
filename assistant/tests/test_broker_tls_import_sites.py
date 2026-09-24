"""Pinned-code import-site overapproximation; no live Node or VM access."""
from dataclasses import asdict
from pathlib import Path, PurePosixPath
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_bootstrap as bootstrap
from siem.rbac.broker_tls import operator_core as core
from siem.rbac.broker_tls import operator_dependency_graph as graph
from siem.rbac.broker_tls import operator_import_sites as sites
from siem.rbac.broker_tls import operator_runtime as runtime

AXIOS = graph.ROOT
FOO = AXIOS + '/node_modules/foo'
BAR = core.BASE + 'node_modules/bar'
PACKAGE_BYTES = {
    AXIOS: b'{"name":"axios","dependencies":{"foo":"1","bar":"1"}}',
    FOO: b'{"name":"foo","dependencies":{"bar":"1"}}',
    BAR: b'{"name":"bar"}',
}
CODE_BYTES = {
    AXIOS + '/index.js': b'module.exports = 1;',
    AXIOS + '/lib/client.js': b'module.exports = 2;',
    FOO + '/index.cjs': b'module.exports = 3;',
    BAR + '/index.js': b'module.exports = 4;',
}
CLIENT_BYTES = b'pinned-client'
DATA = {core.CLIENT: CLIENT_BYTES,
        **{root + '/package.json': raw for root, raw in PACKAGE_BYTES.items()},
        **CODE_BYTES}
CHECKS = tuple(core.FileCheck(path, core.sha(raw), 4096, len(raw))
               for path, raw in DATA.items())
CLIENT_CHECK = CHECKS[0]
PACKAGES = {root: next(check for check in CHECKS
                       if check.path == root + '/package.json') for root in PACKAGE_BYTES}
SOURCES = tuple(sorted((check for check in CHECKS if check.path in CODE_BYTES),
                       key=lambda check: check.path))
SITE_MAP = {AXIOS: {AXIOS, AXIOS + '/lib'}, FOO: {FOO}, BAR: {BAR}}
DEPS = {AXIOS: ('bar', 'foo'), FOO: ('bar',), BAR: ()}
BOOT = bootstrap.Bootstrap(b'manifest', b'certificate')
PACKAGE = runtime.PackageIdentity(core.PACKAGE_VERSION, 'amd64', 'install')


class ImportSiteTests(unittest.TestCase):
    def plan(self):
        return sites._plan_sites(PACKAGES, DEPS, SITE_MAP)

    def observe(self, *, data=None, shadows=None, packages=None, boots=None):
        data = DATA if data is None else data
        reader = Mock(side_effect=data if callable(data) else lambda path, limit: data[path])
        expected = self.plan()
        with (
            patch.object(sites.fs, '_platform') as platform,
            patch.object(sites.fs, '_identity', return_value=(126, 128)) as identity,
            patch.object(sites.bootstrap, 'load_bootstrap', side_effect=boots or [BOOT, BOOT]) as load,
            patch.object(sites, '_inventory', return_value=(CLIENT_CHECK, PACKAGES, SOURCES, SITE_MAP)),
            patch.object(sites.fs, 'InstalledReader', return_value=reader),
            patch.object(sites.fs, '_absent_native', side_effect=shadows or
                         [True] * (2 * len(expected[4]))) as absent,
            patch.object(sites.runtime, 'read_package_identity',
                         side_effect=packages or [PACKAGE] * 3) as registry,
        ):
            result = sites.observe_pinned_import_sites()
            platform.assert_called_once_with()
            identity.assert_called_once_with()
            self.assertEqual(load.call_count, 2)
            self.assertEqual(registry.call_count, 3)
            self.assertEqual(reader.call_count, 2 * len(DATA))
            self.assertEqual(absent.call_count, 2 * len(expected[4]))
            self.assertEqual([call.args[:2] for call in absent.call_args_list],
                             [(PurePosixPath(parent).parts[1:], child)
                              for parent, child in expected[4]] * 2)
            return result

    def test_pinned_code_site_plan_and_false_authority(self):
        package_count, edges, dirs, pairs, shadows = self.plan()
        self.assertEqual((package_count, edges, dirs, pairs), (3, 3, 4, 5))
        self.assertTrue(set(graph._plan(PACKAGES, DEPS)[2]) <= set(shadows))
        self.assertIn((AXIOS + '/lib', ('node_modules', 'bar')), shadows)
        self.assertEqual(len(shadows), len(set(shadows)))
        result = self.observe()
        self.assertEqual((result.pinned_code_files_checked,
                          result.distinct_code_directories_checked,
                          result.site_dependency_pairs_checked,
                          result.shadow_candidates_checked), (4, 4, 5, len(shadows)))
        self.assertTrue(result.pinned_code_sites_observed)
        for flag in ('executed_imports_proven', 'unlisted_code_absent_proven',
                     'actual_node_resolution_proven', 'loaded_code_proven',
                     'effective_environment_proven', 'startup_authorized'):
            self.assertFalse(getattr(result, flag))
        self.assertNotIn('manifest', asdict(result))

    def test_inventory_uses_deepest_package_root_and_requires_code(self):
        with patch.object(sites.core, 'installed_checks', return_value=CHECKS):
            client, packages, sources, mapped = sites._inventory(b'fixture')
        self.assertEqual(client, CLIENT_CHECK)
        self.assertEqual(packages, PACKAGES)
        self.assertEqual(sources, SOURCES)
        self.assertEqual(mapped, SITE_MAP)
        without_bar_code = tuple(check for check in CHECKS if check.path != BAR + '/index.js')
        with patch.object(sites.core, 'installed_checks', return_value=without_bar_code), self.assertRaisesRegex(
                core.OperatorError, '^SITE_MANIFEST$'):
            sites._inventory(b'fixture')

    def test_inventory_rejects_unowned_code_and_source_limit(self):
        extra = core.FileCheck(core.BASE + 'node_modules/unknown/x.js', '0' * 64, 1, 1)
        with patch.object(sites.core, 'installed_checks', return_value=CHECKS + (extra,)), self.assertRaisesRegex(
                core.OperatorError, '^SITE_MANIFEST$'):
            sites._inventory(b'fixture')
        with patch.object(sites.core, 'installed_checks', return_value=CHECKS), patch.object(
                sites, 'MAX_CODE_FILES', 3), self.assertRaisesRegex(core.OperatorError, '^SITE_MANIFEST$'):
            sites._inventory(b'fixture')

    def test_plan_rejects_outside_site_or_selection_divergence(self):
        invalid = {root: set(value) for root, value in SITE_MAP.items()}
        invalid[AXIOS].add(core.BASE + 'plugins')
        with self.assertRaisesRegex(core.OperatorError, '^SITE_MANIFEST$'):
            sites._plan_sites(PACKAGES, DEPS, invalid)
        original = graph._slots

        def changed_slot(root, name):
            if root == AXIOS + '/lib' and name == 'bar':
                return iter((FOO,))
            return original(root, name)

        with patch.object(sites.graph, '_plan', return_value=(3, 3, ())), patch.object(
                sites.graph, '_slots', side_effect=changed_slot), self.assertRaisesRegex(
                core.OperatorError, '^SITE_SELECTION$'):
            sites._plan_sites(PACKAGES, DEPS, SITE_MAP)

    def test_plan_rejects_missing_site_resolution(self):
        original = graph._slots

        def missing_slot(root, name):
            if root == AXIOS + '/lib' and name == 'bar':
                return iter(())
            return original(root, name)

        with patch.object(sites.graph, '_plan', return_value=(3, 3, ())), patch.object(
                sites.graph, '_slots', side_effect=missing_slot), self.assertRaisesRegex(
                core.OperatorError, '^SITE_MISSING$'):
            sites._plan_sites(PACKAGES, DEPS, SITE_MAP)

    def test_shadow_on_first_or_later_pass_fails_closed(self):
        count = len(self.plan()[4])
        for index in (0, count - 1, count, 2 * count - 1):
            values = [True] * (2 * count)
            values[index] = False
            with self.subTest(index=index), patch.object(sites.fs, '_platform'), patch.object(
                    sites.fs, '_identity', return_value=(126, 128)), patch.object(
                    sites.bootstrap, 'load_bootstrap', return_value=BOOT), patch.object(
                    sites, '_inventory', return_value=(CLIENT_CHECK, PACKAGES, SOURCES, SITE_MAP)), patch.object(
                    sites.fs, 'InstalledReader', return_value=lambda path, limit: DATA[path]), patch.object(
                    sites.fs, '_absent_native', side_effect=values) as absent, patch.object(
                    sites.runtime, 'read_package_identity', return_value=PACKAGE), self.assertRaisesRegex(
                    core.OperatorError, '^SITE_SHADOW$'):
                sites.observe_pinned_import_sites()
            self.assertEqual(absent.call_count, index + 1)

    def test_second_pass_code_digest_drift_rejected(self):
        seen = 0

        def changing_reader(path, limit):
            nonlocal seen
            if path == BAR + '/index.js':
                seen += 1
                if seen == 2:
                    return DATA[path].replace(b'4', b'5')
            return DATA[path]

        with self.assertRaisesRegex(core.OperatorError, '^GRAPH_DIGEST$'):
            self.observe(data=changing_reader)
        self.assertEqual(seen, 2)

    def test_package_and_bootstrap_drift_rejected(self):
        changed = runtime.PackageIdentity('other', 'amd64', 'install')
        with self.assertRaisesRegex(core.OperatorError, '^PACKAGE_CHANGED$'):
            self.observe(packages=[PACKAGE, changed])
        with self.assertRaisesRegex(core.OperatorError, '^SITE_BOOTSTRAP_CHANGED$'):
            self.observe(boots=[BOOT, bootstrap.Bootstrap(b'changed', b'certificate')])

    def test_os_error_is_static_and_private(self):
        with (
            patch.object(sites.fs, '_platform'),
            patch.object(sites.fs, '_identity', return_value=(126, 128)),
            patch.object(sites.bootstrap, 'load_bootstrap', return_value=BOOT),
            patch.object(sites, '_inventory', return_value=(CLIENT_CHECK, PACKAGES, SOURCES, SITE_MAP)),
            patch.object(sites.fs, 'InstalledReader', return_value=lambda path, limit: DATA[path]),
            patch.object(sites.fs, '_absent_native', side_effect=OSError(5, '/secret/path')),
            patch.object(sites.runtime, 'read_package_identity', return_value=PACKAGE),
            self.assertRaises(core.OperatorError) as caught,
        ):
            sites.observe_pinned_import_sites()
        self.assertEqual(str(caught.exception), 'FS_IO')
        self.assertNotIn('/secret/path', str(caught.exception))

    def test_pair_and_shadow_budgets_are_enforced(self):
        with patch.object(sites, 'MAX_SITE_PAIRS', 1), self.assertRaisesRegex(
                core.OperatorError, '^SITE_LIMIT$'):
            self.plan()
        with patch.object(sites, 'MAX_SHADOWS', 1), self.assertRaisesRegex(
                core.OperatorError, '^SITE_LIMIT$'):
            self.plan()
