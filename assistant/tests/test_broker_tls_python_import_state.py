"""Synthetic Python 3.14 import objects; never import observed file subjects."""
import ast
from dataclasses import FrozenInstanceError
import hashlib
from importlib.machinery import (BuiltinImporter, ExtensionFileLoader, FrozenImporter,
                                ModuleSpec, PathFinder, SourceFileLoader)
import inspect
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace as NS
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_core as core
from siem.rbac.broker_tls import operator_fs as fs
from siem.rbac.broker_tls import operator_guard_entry as guard
from siem.rbac.broker_tls import operator_python_import_state as state
from siem.rbac.broker_tls import operator_python_policy as policy


def fixture():
    builtin = ModuleType('_frozen_importlib')
    builtin.ModuleSpec, builtin.BuiltinImporter, builtin.FrozenImporter = ModuleSpec, BuiltinImporter, FrozenImporter
    external = ModuleType('_frozen_importlib_external')
    external.SourceFileLoader, external.ExtensionFileLoader, external.PathFinder = SourceFileLoader, ExtensionFileLoader, PathFinder
    modules = {builtin.__name__: builtin, external.__name__: external}
    for name, origin, package in state.SELECTED_MODULES:
        module = ModuleType(name)
        loader = (SourceFileLoader if origin.endswith('.py') else ExtensionFileLoader)(name, origin)
        spec = ModuleSpec(name, loader, origin=origin, is_package=package)
        spec.has_location = True
        spec._cached = state.CACHE_PREFIX + origin[:-3] + '.cpython-314.pyc' if origin.endswith('.py') else None
        module.__file__, module.__cached__, module.__loader__, module.__spec__ = origin, spec._cached, loader, spec
        if package:
            module.__path__ = [origin.rsplit('/', 1)[0]]
            spec.submodule_search_locations = list(module.__path__)
        modules[name] = module
    for name, module in tuple(modules.items()):
        if '.' in name:
            parent, child = name.rsplit('.', 1)
            setattr(modules[parent], child, module)
    return NS(platform='linux', executable='/usr/bin/python3.14', version_info=(3, 14, 4, 'final', 0),
              implementation=NS(name='cpython', cache_tag='cpython-314'),
              flags=NS(**dict(state.FLAG_VALUES), safe_path=True), dont_write_bytecode=True,
              orig_argv=list(policy.CANDIDATE_ARGV), argv=[policy.CANDIDATE_ARGV[-1]],
              path=list(state.SEARCH_PATH), pycache_prefix=state.CACHE_PREFIX,
              _xoptions={'pycache_prefix': state.CACHE_PREFIX}, modules=modules,
              meta_path=[BuiltinImporter, FrozenImporter, PathFinder])


class PythonImportStateTests(unittest.TestCase):
    def run_fixture(self, host=None):
        with patch.object(state, 'sys', host or fixture()), patch.object(fs, '_platform'):
            return state.observe_python_import_state()

    def test_selected_file_names_packages_and_origin_manifest_match_c1_c2(self):
        rows = state.SELECTED_MODULES
        self.assertEqual(len(rows), 50)
        self.assertEqual(len({name for name, _, _ in rows}), 50)
        self.assertEqual({path for _, path, _ in rows}, {pin.path for pin in policy.SOURCE_FILES} | {policy.MAPPED_FILES[1].path})
        self.assertEqual(hashlib.sha256(('\n'.join(sorted(path for _, path, _ in rows)) + '\n').encode()).hexdigest(),
                         '41fe4f2680be2f097dcfd240ab15f6334957a629d822533212821364c5aacfeb')
        packages = {name for name, _, package in rows if package}
        self.assertEqual(packages, {'collections', 'encodings', 'importlib', 'json', 'pathlib', 're'})
        self.assertEqual(next(row[1] for row in rows if row[0] == 'pathlib._os'), '/usr/lib/python3.14/pathlib/_os.py')

    def test_two_fresh_passes_never_find_load_or_read_subjects(self):
        host = fixture()
        before = tuple(host.modules.items())
        with patch.object(state, 'sys', host), patch.object(fs, '_platform'), patch.object(
                state, '_capture', wraps=state._capture) as capture, patch.object(
                PathFinder, 'find_spec', side_effect=AssertionError('no resolution')), patch.object(
                SourceFileLoader, 'get_code', side_effect=AssertionError('no source execution')), patch.object(
                ModuleSpec, 'cached', new=property(lambda _: (_ for _ in ()).throw(AssertionError('no lazy computation')))):
            result = state.observe_python_import_state()
        self.assertEqual(capture.call_count, 2)
        self.assertEqual(tuple(host.modules.items()), before)
        self.assertEqual((result.observed_module_count, result.selected_module_count, result.passes), (52, 50, 2))

    def test_platform_prevents_snapshot_and_only_held_finder_is_explicit(self):
        parameters = inspect.signature(state.observe_python_import_state).parameters
        self.assertEqual(tuple(parameters), ('held_finder',))
        self.assertIs(parameters['held_finder'].kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertIsNone(parameters['held_finder'].default)
        with patch.object(fs, '_platform', side_effect=core.OperatorError('FS_ROOT_REQUIRED')), patch.object(state, '_capture') as capture:
            for kwargs in ({}, {'held_finder': object()}):
                with self.assertRaisesRegex(core.OperatorError, '^FS_ROOT_REQUIRED$'):
                    state.observe_python_import_state(**kwargs)
            with self.assertRaises(TypeError):
                state.observe_python_import_state(fixture())
            with self.assertRaises(TypeError):
                state.observe_python_import_state(skip_checks=True)
        capture.assert_not_called()

    def test_runtime_version_and_implementation_fail_closed(self):
        for attr, bad in (('platform', 'win32'), ('executable', '/usr/bin/python3'),
                          ('version_info', (3, 14, 5, 'final', 0)), ('version_info', (3, 14, 4, 'beta', 1)),
                          ('version_info', (3, 14, 4.0, 'final', 0)), ('implementation', NS(name='pypy', cache_tag='cpython-314')),
                          ('implementation', NS(name='cpython', cache_tag='cpython-313'))):
            host = fixture()
            setattr(host, attr, bad)
            with self.subTest(attr=attr), self.assertRaisesRegex(core.OperatorError, '^PY_IMPORT_RUNTIME$'):
                self.run_fixture(host)

    def test_every_isolation_flag_and_mutable_bytecode_setting(self):
        for name, value in state.FLAG_VALUES:
            for bad in (not value, str(value), 1 - value, None):
                host = fixture()
                setattr(host.flags, name, bad)
                with self.subTest(name=name, bad=bad), self.assertRaisesRegex(core.OperatorError, '^PY_IMPORT_FLAGS$'):
                    self.run_fixture(host)
        for attr in ('safe_path', 'dont_write_bytecode'):
            host = fixture()
            setattr(host.flags if attr == 'safe_path' else host, attr, 1)
            with self.assertRaisesRegex(core.OperatorError, '^PY_IMPORT_FLAGS$'):
                self.run_fixture(host)

    def test_argv_and_search_path_are_exact_no_extra_user_site_or_empty_path(self):
        for attr in ('argv', 'orig_argv', 'path'):
            for alter in (lambda x: x + [''], lambda x: x[::-1], lambda x: tuple(x),
                          lambda x: ['/tmp/PRIVATE'] + x, lambda x: x[:-1]):
                host = fixture()
                changed = alter(getattr(host, attr))
                if changed == getattr(host, attr):
                    continue
                setattr(host, attr, changed)
                with self.subTest(attr=attr), self.assertRaisesRegex(core.OperatorError, '^PY_IMPORT_(ARGV|PATH)$'):
                    self.run_fixture(host)

    def test_cache_prefix_and_xoptions_must_both_match_without_repair(self):
        for attr, bad in (('pycache_prefix', None), ('pycache_prefix', '/tmp'), ('_xoptions', {}),
                          ('_xoptions', {'pycache_prefix': state.CACHE_PREFIX, 'dev': True}),
                          ('_xoptions', {'pycache_prefix': '/tmp'})):
            host = fixture()
            setattr(host, attr, bad)
            with self.assertRaisesRegex(core.OperatorError, '^PY_IMPORT_CACHE_PREFIX$'):
                self.run_fixture(host)
            self.assertIs(getattr(host, attr), bad)

    def test_meta_finder_identity_not_class_labels_and_order(self):
        impostor = type('BuiltinImporter', (), {'__module__': '_frozen_importlib'})
        for items in ([impostor, FrozenImporter, PathFinder], [FrozenImporter, BuiltinImporter, PathFinder],
                      [BuiltinImporter, FrozenImporter, PathFinder, object()], None):
            host = fixture()
            host.meta_path = items
            with self.assertRaisesRegex(core.OperatorError, '^PY_IMPORT_META_PATH$'):
                self.run_fixture(host)

    def test_module_table_bounds_and_missing_modules_never_trigger_import(self):
        for bad in (None, {}, {str(i): None for i in range(1025)}):
            host = fixture()
            host.modules = bad
            with self.assertRaisesRegex(core.OperatorError, '^PY_IMPORT_MODULE_TABLE$'):
                self.run_fixture(host)
        for name, _, _ in state.SELECTED_MODULES:
            host = fixture()
            del host.modules[name]
            with self.subTest(name=name), self.assertRaisesRegex(core.OperatorError, '^PY_IMPORT_(MODULE|PARENT_BINDING)$'):
                self.run_fixture(host)
            self.assertNotIn(name, host.modules)

    def test_custom_module_and_spec_are_not_introspected(self):
        class Trap:
            def __getattribute__(self, name):
                raise AssertionError('untrusted property called')
        host = fixture()
        host.modules['_hashlib'] = Trap()
        with self.assertRaisesRegex(core.OperatorError, '^PY_IMPORT_MODULE$'):
            self.run_fixture(host)
        host = fixture()
        host.modules['_hashlib'].__spec__ = Trap()
        with self.assertRaisesRegex(core.OperatorError, '^PY_IMPORT_SPEC$'):
            self.run_fixture(host)

    def test_all_module_file_and_spec_origin_names_checked_independently(self):
        for name, _, _ in state.SELECTED_MODULES:
            for target, key, code in (('module', '__file__', 'ORIGIN'), ('spec', 'origin', 'ORIGIN'),
                                      ('module', '__name__', 'NAME'), ('spec', 'name', 'NAME')):
                host = fixture()
                module = host.modules[name]
                setattr(module if target == 'module' else module.__spec__, key, '/PRIVATE')
                with self.subTest(name=name, key=key), self.assertRaisesRegex(core.OperatorError, '^PY_IMPORT_' + code + '$'):
                    self.run_fixture(host)

    def test_loader_type_identity_name_path_and_has_location(self):
        for mutate, code in (
                (lambda m: setattr(m, '__loader__', SourceFileLoader('copy', m.__file__)), 'LOADER'),
                (lambda m: setattr(m.__spec__, 'loader', object()), 'LOADER'),
                (lambda m: setattr(m.__loader__, 'path', '/PRIVATE'), 'LOADER'),
                (lambda m: setattr(m.__loader__, 'name', 'other'), 'LOADER'),
                (lambda m: setattr(m.__spec__, 'has_location', False), 'ORIGIN')):
            host = fixture()
            mutate(host.modules['copy'])
            with self.assertRaisesRegex(core.OperatorError, '^PY_IMPORT_' + code + '$'):
                self.run_fixture(host)

    def test_all_cache_paths_reject_source_tree_optimize_and_spec_module_mismatch(self):
        for name, origin, _ in state.SELECTED_MODULES:
            for target in ('module', 'spec'):
                host = fixture()
                m = host.modules[name]
                setattr(m if target == 'module' else m.__spec__, '__cached__' if target == 'module' else '_cached',
                        origin + '.pyc')
                with self.subTest(name=name, target=target), self.assertRaisesRegex(core.OperatorError, '^PY_IMPORT_CACHE_PATH$'):
                    self.run_fixture(host)

    def test_package_paths_and_child_bindings_fail_on_shadowing(self):
        for name, _, package in state.SELECTED_MODULES:
            if not package:
                continue
            for target in ('module', 'spec'):
                host = fixture()
                m = host.modules[name]
                setattr(m if target == 'module' else m.__spec__, '__path__' if target == 'module' else 'submodule_search_locations', ['/tmp'])
                with self.assertRaisesRegex(core.OperatorError, '^PY_IMPORT_PACKAGE_PATH$'):
                    self.run_fixture(host)
        host = fixture()
        host.modules['json'].decoder = ModuleType('json.decoder')
        with self.assertRaisesRegex(core.OperatorError, '^PY_IMPORT_PARENT_BINDING$'):
            self.run_fixture(host)

    def test_replacement_between_valid_passes_and_second_pass_corruption(self):
        for replacement in ('table', 'module', 'spec', 'loader', 'count', 'path'):
            host = fixture()
            original = state._capture
            calls = 0
            def capture():
                nonlocal calls
                calls += 1
                if calls == 2:
                    fresh = fixture().modules['copy']
                    m = host.modules['copy']
                    if replacement == 'table':
                        host.modules = dict(host.modules)
                    elif replacement == 'module':
                        host.modules['copy'] = fresh
                    elif replacement == 'spec':
                        fresh.__spec__.loader = m.__loader__
                        host.modules['copy'].__spec__ = fresh.__spec__
                    elif replacement == 'loader':
                        m.__loader__ = m.__spec__.loader = fresh.__loader__
                    elif replacement == 'count':
                        host.modules['extra'] = ModuleType('extra')
                    else:
                        host.path.append('/tmp')
                return original()
            with patch.object(state, '_capture', side_effect=capture), self.subTest(replacement=replacement), self.assertRaisesRegex(
                    core.OperatorError, '^PY_IMPORT_(CHANGED|PATH)$'):
                self.run_fixture(host)

    def test_metadata_faults_are_sanitized(self):
        for failure in (AttributeError('PRIVATE'), TypeError('PRIVATE'), ValueError('PRIVATE'), RuntimeError('PRIVATE')):
            with patch.object(fs, '_platform'), patch.object(state, '_capture', side_effect=failure), self.assertRaises(core.OperatorError) as caught:
                state.observe_python_import_state()
            self.assertEqual(str(caught.exception), 'PY_IMPORT_STATE')
            self.assertTrue(caught.exception.__suppress_context__)

    def test_unselected_modules_and_hooks_are_explicitly_not_attested(self):
        host = fixture()
        host.modules['unselected'] = ModuleType('unselected')
        host.path_hooks = [Mock(side_effect=AssertionError('no hooks invoked'))]
        host.path_importer_cache = {'/tmp': object()}
        result = self.run_fixture(host)
        self.assertEqual(result.observed_module_count, 53)
        for name in ('complete_module_inventory_proven', 'import_hooks_and_cache_proven', 'selected_code_bytes_proven',
                     'loader_environment_proven', 'native_resolution_proven', 'atomic_snapshot_proven', 'runtime_trusted', 'startup_authorized'):
            self.assertIs(getattr(result, name), False)
        with self.assertRaises(FrozenInstanceError):
            result.startup_authorized = True
        self.assertNotIn('operator_python_import_state.py', {pin[0] for pin in guard.PINNED_MODULES})
        self.assertIn('operator_python_import_state.py', {pin[0] for pin in guard.RUNTIME_MODULES})
        tree = ast.parse(Path(state.__file__).read_text(encoding='utf-8'))
        names = {n.func.id for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        self.assertTrue(names.isdisjoint({'open', 'exec', 'eval', '__import__'}))


if __name__ == '__main__':
    unittest.main()
