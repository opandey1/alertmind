"""Declared dependency checks are offline observations, never startup authority."""
from dataclasses import asdict
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_bootstrap as bootstrap
from siem.rbac.broker_tls import operator_core as core
from siem.rbac.broker_tls import operator_dependency_graph as graph
from siem.rbac.broker_tls import operator_runtime as runtime

AXIOS = graph.ROOT
FOO = AXIOS + '/node_modules/foo'
BAR = core.BASE + 'node_modules/bar'
PACKAGE_BYTES = {
    AXIOS: b'{"name":"axios","dependencies":{"foo":"1","bar":"1"}}',
    FOO: b'{"name":"foo","dependencies":{"bar":"1"}}',
    BAR: b'{"name":"bar"}',
}
CLIENT = b'pinned-client'
CHECKS = {
    root: core.FileCheck(root + '/package.json', core.sha(raw), 4096, len(raw))
    for root, raw in PACKAGE_BYTES.items()
}
CLIENT_CHECK = core.FileCheck(core.CLIENT, core.sha(CLIENT), 4096, len(CLIENT))
BOOT = bootstrap.Bootstrap(b'manifest', b'certificate')
PACKAGE = runtime.PackageIdentity(core.PACKAGE_VERSION, 'amd64', 'install')


class DeclaredGraphTests(unittest.TestCase):
    def plan(self, deps=None, packages=None):
        return graph._plan(packages or CHECKS, deps or {
            AXIOS: ('bar', 'foo'), FOO: ('bar',), BAR: (),
        })

    def observe(self, *, absent=None, data=None, packages=None, boots=None):
        data = data or {core.CLIENT: CLIENT, **{
            root + '/package.json': raw for root, raw in PACKAGE_BYTES.items()
        }}
        reader = Mock(side_effect=data if callable(data) else lambda path, limit: data[path])
        expected = self.plan()
        with patch.object(graph.fs, '_platform') as platform, patch.object(
                graph.fs, '_identity', return_value=(126, 128)) as identity, patch.object(
                graph.bootstrap, 'load_bootstrap', side_effect=boots or [BOOT, BOOT]) as load, patch.object(
                graph, '_package_checks', return_value=(CLIENT_CHECK, CHECKS)), patch.object(
                graph.fs, 'InstalledReader', return_value=reader), patch.object(
                graph.fs, '_absent_native', side_effect=absent or [True] * (2 * len(expected[2]))) as shadow, patch.object(
                graph.runtime, 'read_package_identity', side_effect=packages or [PACKAGE] * 3) as registry:
            result = graph.observe_declared_axios_graph()
            platform.assert_called_once_with()
            identity.assert_called_once_with()
            self.assertEqual(load.call_count, 2)
            self.assertEqual(registry.call_count, 3)
            self.assertEqual(shadow.call_count, 2 * len(expected[2]))
            self.assertEqual([c.args[:2] for c in shadow.call_args_list],
                             [(tuple(Path(parent).parts[1:]), child)
                              for parent, child in expected[2]] * 2)
            self.assertEqual(reader.call_count, 2 * (1 + len(CHECKS)))
            return result

    def test_reachable_graph_and_non_authorizing_result(self):
        packages, edges, shadows = self.plan()
        self.assertEqual((packages, edges), (3, 3))
        self.assertIn((AXIOS, ('node_modules', 'bar')), shadows)
        self.assertIn((core.BASE.rstrip('/'), ('node_modules', 'bar.js')), shadows)
        self.assertEqual(len(shadows), len(set(shadows)))
        result = self.observe()
        self.assertEqual((result.declared_packages_checked, result.declared_edges_checked,
                          result.shadow_candidates_checked), (packages, edges, len(shadows)))
        self.assertTrue(result.declared_graph_and_shadows_observed)
        self.assertTrue(result.package_root_search_only)
        for key in ('import_sites_proven', 'actual_node_resolution_proven', 'loaded_code_proven',
                    'effective_environment_proven', 'startup_authorized'):
            self.assertFalse(getattr(result, key))
        self.assertNotIn('manifest', asdict(result))

    def test_missing_and_orphan_roots_fail_closed(self):
        for deps, code in (({AXIOS: ('missing',), FOO: (), BAR: ()}, 'GRAPH_MISSING'),
                           ({AXIOS: ('foo',), FOO: (), BAR: ()}, 'GRAPH_ORPHAN')):
            with self.subTest(code=code), self.assertRaisesRegex(core.OperatorError, '^' + code + '$'):
                self.plan(deps=deps)

    def test_metadata_requires_name_and_safe_dependencies(self):
        for raw in (b'{}', b'{"name":"wrong"}', b'{"name":"axios","name":"axios"}',
                    b'{"name":"axios","dependencies":{"../bad":"1"}}',
                    b'{"name":"axios","dependencies":{"foo":7}}',
                    b'{"name":"axios","dependencies":[]}', b'{'):
            with self.subTest(raw=raw), self.assertRaisesRegex(
                    core.OperatorError, '^GRAPH_METADATA$'):
                graph._metadata(raw, 'axios')
        self.assertEqual(graph._metadata(PACKAGE_BYTES[AXIOS], 'axios'), ('bar', 'foo'))

    def test_manifest_requires_client_and_root_and_bounded_package_count(self):
        checks = (CLIENT_CHECK, *CHECKS.values())
        with patch.object(graph.core, 'installed_checks', return_value=checks):
            self.assertEqual(graph._package_checks(b'fixture'), (CLIENT_CHECK, CHECKS))
        for bad in (checks[1:], (CLIENT_CHECK,),
                    checks + (core.FileCheck(core.BASE + 'node_modules/axios/lib/package.json',
                                             '0' * 64, 99, 1),)):
            with self.subTest(bad=bad), patch.object(
                    graph.core, 'installed_checks', return_value=bad), self.assertRaisesRegex(
                    core.OperatorError, '^GRAPH_MANIFEST$'):
                graph._package_checks(b'fixture')

    def test_pinned_byte_size_and_digest_rejections(self):
        for raw, code in ((CLIENT[:-1], 'GRAPH_SIZE'),
                          (b'Pinned-client', 'GRAPH_DIGEST')):
            with self.subTest(code=code), self.assertRaisesRegex(
                    core.OperatorError, '^' + code + '$'):
                graph._read_pinned(lambda *_: raw, CLIENT_CHECK)
        data = {core.CLIENT: CLIENT, **{root + '/package.json': raw
                                       for root, raw in PACKAGE_BYTES.items()}}
        seen = 0

        def changing_reader(path, limit):
            nonlocal seen
            if path == BAR + '/package.json':
                seen += 1
                if seen == 2:
                    return data[path].replace(b'bar', b'bad')
            return data[path]

        with self.assertRaisesRegex(core.OperatorError, '^GRAPH_DIGEST$'):
            self.observe(data=changing_reader)
        self.assertEqual(seen, 2)

    def test_shadow_on_first_or_second_pass_rejected(self):
        count = len(self.plan()[2])
        for index in (0, count - 1, count, 2 * count - 1):
            values = [True] * (2 * count)
            values[index] = False
            with self.subTest(index=index), patch.object(graph.fs, '_platform'), patch.object(
                    graph.fs, '_identity', return_value=(126, 128)), patch.object(
                    graph.bootstrap, 'load_bootstrap', return_value=BOOT), patch.object(
                    graph, '_package_checks', return_value=(CLIENT_CHECK, CHECKS)), patch.object(
                    graph.fs, 'InstalledReader', side_effect=lambda _: lambda path, limit: {
                        core.CLIENT: CLIENT, **{r + '/package.json': raw
                                               for r, raw in PACKAGE_BYTES.items()}
                    }[path]), patch.object(
                    graph.fs, '_absent_native', side_effect=values) as absent, patch.object(
                    graph.runtime, 'read_package_identity', return_value=PACKAGE), self.assertRaisesRegex(
                    core.OperatorError, '^GRAPH_SHADOW$'):
                graph.observe_declared_axios_graph()
            self.assertEqual(absent.call_count, index + 1)

    def test_package_and_bootstrap_drift_rejected(self):
        changed = runtime.PackageIdentity('other', 'amd64', 'install')
        with self.assertRaisesRegex(core.OperatorError, '^PACKAGE_CHANGED$'):
            self.observe(packages=[PACKAGE, changed])
        with self.assertRaisesRegex(core.OperatorError, '^GRAPH_BOOTSTRAP_CHANGED$'):
            self.observe(boots=[BOOT, bootstrap.Bootstrap(b'changed', b'certificate')])

    def test_os_errors_are_static_and_do_not_leak_paths(self):
        with patch.object(graph.fs, '_platform'), patch.object(
                graph.fs, '_identity', return_value=(126, 128)), patch.object(
                graph.bootstrap, 'load_bootstrap', return_value=BOOT), patch.object(
                graph, '_package_checks', return_value=(CLIENT_CHECK, CHECKS)), patch.object(
                graph.fs, 'InstalledReader', return_value=lambda path, limit: {
                    core.CLIENT: CLIENT, **{r + '/package.json': raw for r, raw in PACKAGE_BYTES.items()}
                }[path]), patch.object(
                graph.fs, '_absent_native', side_effect=OSError(5, '/secret/path')), patch.object(
                graph.runtime, 'read_package_identity', return_value=PACKAGE), self.assertRaises(
                core.OperatorError) as caught:
            graph.observe_declared_axios_graph()
        self.assertEqual(str(caught.exception), 'FS_IO')
        self.assertNotIn('/secret/path', str(caught.exception))

    def test_plan_rejects_excessive_edges(self):
        with patch.object(graph, 'MAX_EDGES', 1), self.assertRaisesRegex(
                core.OperatorError, '^GRAPH_LIMIT$'):
            self.plan()
