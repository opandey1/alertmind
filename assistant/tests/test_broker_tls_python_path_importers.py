"""Synthetic candidate import machinery; no VM or selected-runtime claim."""
import ast
from dataclasses import FrozenInstanceError
import importlib.machinery as machinery
import inspect
from pathlib import Path
import sys
from types import FunctionType, ModuleType
import unittest
from unittest.mock import patch
import zipimport

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_core as core
from siem.rbac.broker_tls import operator_fs as fs
from siem.rbac.broker_tls import operator_guard_entry as guard
from siem.rbac.broker_tls import operator_python_import_state as imports
from siem.rbac.broker_tls import operator_python_path_importers as paths
from test_broker_tls_python_import_state import fixture as state_fixture


def fixture():
    host = state_fixture()
    external = host.modules['_frozen_importlib_external']
    external.SourcelessFileLoader = machinery.SourcelessFileLoader
    # Fresh synthetic bootstrap dictionary/class; no mutation of real imports.
    source = vars(machinery.FileFinder)['path_hook'].__func__
    factory = FunctionType(source.__code__, vars(external), 'path_hook')
    finder_class = type('FileFinder', (), {'path_hook': classmethod(factory)})
    external.FileFinder = finder_class
    zip_module = ModuleType('zipimport')
    zip_module.zipimporter = zipimport.zipimporter
    host.modules['zipimport'] = zip_module
    classes = tuple(vars(external)[name] for name in paths.LOADER_NAMES)
    details = tuple((cls, list(suffixes)) for cls, suffixes in zip(classes, paths.SUFFIX_GROUPS))
    # Calling only the factory in this test creates its closure, not a finder.
    host.path_hooks = [zip_module.zipimporter, factory(finder_class, *details)]
    host.path_importer_cache = {paths.ZIP_PATH: None}
    for path in paths.DIRECTORY_PATHS:
        finder = object.__new__(finder_class)
        finder.path = path
        finder._loaders = [(suffix, cls) for cls, suffixes in details for suffix in suffixes]
        finder._path_mtime = 1234.25
        finder._path_cache = {'example.py', '__pycache__'}
        finder._relaxed_path_cache = set()
        host.path_importer_cache[path] = finder
    return host


class PythonPathImporterTests(unittest.TestCase):
    def run_fixture(self, host=None):
        with patch.object(imports, 'sys', host or fixture()), patch.object(fs, '_platform'):
            return paths.observe_python_path_importers()

    def test_policy_is_fixed_candidate_not_a_new_vm_inventory(self):
        self.assertEqual(len(paths.DIRECTORY_PATHS), 8)
        self.assertEqual(len(set(paths.DIRECTORY_PATHS)), 8)
        self.assertEqual(paths.DIRECTORY_PATHS[:2], imports.SEARCH_PATH[1:])
        self.assertEqual(set(paths.DIRECTORY_PATHS[2:]), {
            '/usr/lib/python3.14/' + name for name in ('collections', 'encodings', 'importlib', 'json', 'pathlib', 're')})
        self.assertEqual(paths.SUFFIX_GROUPS, (('.cpython-314-x86_64-linux-gnu.so', '.abi3.so', '.so'), ('.py',), ('.pyc',)))

    def test_valid_two_passes_are_observational(self):
        host = fixture()
        hook = host.path_hooks[1]
        before = tuple(host.path_importer_cache.items())
        with patch.object(paths, '_capture', wraps=paths._capture) as capture, patch(
                'builtins.open', side_effect=AssertionError('no filesystem')), patch.object(
                machinery.PathFinder, 'find_spec', side_effect=AssertionError('no resolution')), patch.object(
                machinery.SourceFileLoader, 'get_code', side_effect=AssertionError('no loading')):
            result = self.run_fixture(host)
        self.assertEqual(capture.call_count, 2)
        self.assertEqual((result.cached_path_count, result.passes), (9, 2))
        self.assertEqual(tuple(host.path_importer_cache.items()), before)
        self.assertIs(host.path_hooks[1], hook)
        # The fake hook globals deliberately lack _path_isdir: calling it
        # would fail. Positive observation therefore cannot have invoked it.

    def test_root_linux_precedes_capture_and_no_public_overrides(self):
        self.assertEqual(len(inspect.signature(paths.observe_python_path_importers).parameters), 0)
        with patch.object(fs, '_platform', side_effect=core.OperatorError('FS_ROOT_REQUIRED')), patch.object(paths, '_capture') as capture:
            with self.assertRaisesRegex(core.OperatorError, '^FS_ROOT_REQUIRED$'):
                paths.observe_python_path_importers()
            with self.assertRaises(TypeError):
                paths.observe_python_path_importers(fixture())
        capture.assert_not_called()

    def test_existing_runtime_settings_remain_required(self):
        for attr, bad in (('version_info', (3, 14, 5, 'final', 0)), ('path', ['/tmp']), ('pycache_prefix', '/tmp')):
            host = fixture()
            setattr(host, attr, bad)
            with self.subTest(attr=attr), self.assertRaisesRegex(core.OperatorError, '^PY_IMPORT_'):
                self.run_fixture(host)

    def test_module_bounds_and_missing_bootstrap_never_import(self):
        for bad in (None, {}, {str(i): None for i in range(1025)}):
            host = fixture()
            host.modules = bad
            with self.assertRaisesRegex(core.OperatorError, '^PY_PATH_MODULES$'):
                self.run_fixture(host)
        for name in ('zipimport', '_frozen_importlib_external'):
            host = fixture()
            del host.modules[name]
            with self.assertRaisesRegex(core.OperatorError, '^PY_IMPORT_MODULE$'):
                self.run_fixture(host)
            self.assertNotIn(name, host.modules)

    def test_empty_and_partial_cache_are_not_filled(self):
        for keep in ((), (paths.ZIP_PATH,), (paths.DIRECTORY_PATHS[0],)):
            host = fixture()
            host.path_importer_cache = {key: host.path_importer_cache[key] for key in keep}
            self.assertEqual(self.run_fixture(host).cached_path_count, len(keep))
            self.assertEqual(set(host.path_importer_cache), set(keep))

    def test_hook_order_identity_length_and_types(self):
        for mutation in (lambda h: tuple(h), lambda h: h[::-1], lambda h: h + [object()],
                         lambda h: [type('zipimporter', (), {}), h[1]], lambda h: []):
            host = fixture()
            host.path_hooks = mutation(host.path_hooks)
            with self.assertRaisesRegex(core.OperatorError, '^PY_PATH_HOOKS$'):
                self.run_fixture(host)

    def test_hook_function_code_globals_and_defaults_checked(self):
        for field in ('code', 'globals', 'defaults', 'kwdefaults', 'attributes'):
            host = fixture()
            hook = host.path_hooks[1]
            if field == 'code':
                def impostor(path):
                    raise AssertionError('must not call')
                host.path_hooks[1] = impostor
            elif field == 'globals':
                host.path_hooks[1] = FunctionType(hook.__code__, dict(hook.__globals__), closure=hook.__closure__)
            elif field == 'defaults':
                hook.__defaults__ = ('/tmp',)
            elif field == 'kwdefaults':
                hook.__kwdefaults__ = {'path': '/tmp'}
            else:
                hook.extra = True
            with self.subTest(field=field), self.assertRaisesRegex(core.OperatorError, '^PY_PATH_HOOK$'):
                self.run_fixture(host)

    def test_hook_factory_descriptor_and_class_cell_are_checked(self):
        for change in ('descriptor', 'factory', 'class'):
            host = fixture()
            finder = host.modules['_frozen_importlib_external'].FileFinder
            if change == 'descriptor':
                finder.path_hook = staticmethod(lambda: None)
            elif change == 'factory':
                finder.path_hook = classmethod(lambda cls: None)
            else:
                host.path_hooks[1].__closure__[0].cell_contents = type('FileFinder', (), {})
            with self.assertRaisesRegex(core.OperatorError, '^PY_PATH_HOOK$'):
                self.run_fixture(host)

    def test_all_hook_suffixes_and_loader_identities_checked(self):
        for group in range(3):
            host = fixture()
            details = host.path_hooks[1].__closure__[1].cell_contents
            details[group][1].append('.PRIVATE')
            with self.assertRaisesRegex(core.OperatorError, '^PY_PATH_LOADERS$'):
                self.run_fixture(host)
            host = fixture()
            cell = host.path_hooks[1].__closure__[1]
            rows = list(cell.cell_contents)
            rows[group] = (type(paths.LOADER_NAMES[group], (), {}), rows[group][1])
            cell.cell_contents = tuple(rows)
            with self.assertRaisesRegex(core.OperatorError, '^PY_PATH_LOADERS$'):
                self.run_fixture(host)

    def test_cache_keys_and_size_fail_closed_even_for_none_values(self):
        for bad in ('', '/tmp', paths.DIRECTORY_PATHS[0] + '/', '/usr/lib/python3.14/../python3.14', 1):
            host = fixture()
            host.path_importer_cache = {bad: None}
            with self.assertRaisesRegex(core.OperatorError, '^PY_PATH_CACHE_KEY$'):
                self.run_fixture(host)
        for bad in ([], None, {str(i): None for i in range(10)}):
            host = fixture()
            host.path_importer_cache = bad
            with self.assertRaisesRegex(core.OperatorError, '^PY_PATH_CACHE$'):
                self.run_fixture(host)

    def test_zip_must_be_negative_cache_not_an_importer(self):
        host = fixture()
        host.path_importer_cache[paths.ZIP_PATH] = object()
        with self.assertRaisesRegex(core.OperatorError, '^PY_PATH_ZIP_CACHE$'):
            self.run_fixture(host)

    def test_custom_finders_and_subclasses_are_not_inspected(self):
        class Trap:
            def __getattribute__(self, name):
                raise AssertionError('untrusted attribute')
        for factory in (lambda cls: Trap(), lambda cls: None, lambda cls: object.__new__(type('FileFinder', (cls,), {}))):
            host = fixture()
            host.path_importer_cache[paths.DIRECTORY_PATHS[0]] = factory(host.modules['_frozen_importlib_external'].FileFinder)
            with self.assertRaisesRegex(core.OperatorError, '^PY_PATH_FINDER$'):
                self.run_fixture(host)

    def test_finder_instance_method_shadows_and_path_mismatch(self):
        for key in ('find_spec', '_get_spec', '_fill_cache', 'extra'):
            host = fixture()
            finder = host.path_importer_cache[paths.DIRECTORY_PATHS[0]]
            setattr(finder, key, lambda *_: (_ for _ in ()).throw(AssertionError('not called')))
            with self.assertRaisesRegex(core.OperatorError, '^PY_PATH_FINDER_FIELDS$'):
                self.run_fixture(host)
        host = fixture()
        host.path_importer_cache[paths.DIRECTORY_PATHS[0]].path = '/tmp'
        with self.assertRaisesRegex(core.OperatorError, '^PY_PATH_FINDER_PATH$'):
            self.run_fixture(host)

    def test_every_cached_loader_and_suffix_and_order(self):
        for index in range(5):
            for kind in ('suffix', 'loader', 'tuple'):
                host = fixture()
                rows = host.path_importer_cache[paths.DIRECTORY_PATHS[0]]._loaders
                suffix, loader = rows[index]
                rows[index] = ('.bad', loader) if kind == 'suffix' else (suffix, object()) if kind == 'loader' else [suffix, loader]
                with self.assertRaisesRegex(core.OperatorError, '^PY_PATH_LOADERS$'):
                    self.run_fixture(host)
        host = fixture()
        host.path_importer_cache[paths.DIRECTORY_PATHS[0]]._loaders.reverse()
        with self.assertRaisesRegex(core.OperatorError, '^PY_PATH_LOADERS$'):
            self.run_fixture(host)

    def test_directory_cache_bounds_types_and_relaxed_policy(self):
        for field, bad in (('_path_mtime', True), ('_path_mtime', float('nan')), ('_path_mtime', float('inf')),
                           ('_path_mtime', -2), ('_path_cache', []), ('_path_cache', {'../bad'}),
                           ('_path_cache', {''}), ('_path_cache', {'x' * 256}), ('_path_cache', {'x\0y'}),
                           ('_path_cache', {1}), ('_path_cache', {str(i) for i in range(8193)}),
                           ('_relaxed_path_cache', {'example.py'})):
            host = fixture()
            setattr(host.path_importer_cache[paths.DIRECTORY_PATHS[0]], field, bad)
            with self.subTest(field=field), self.assertRaisesRegex(core.OperatorError, '^PY_PATH_DIRECTORY_CACHE$'):
                self.run_fixture(host)

    def test_reference_replacement_and_value_drift_between_passes(self):
        for change in ('hooks', 'cache', 'hook', 'finder', 'loaders', 'names', 'mtime', 'membership', 'key'):
            host = fixture()
            original = paths._capture
            calls = 0
            def capture():
                nonlocal calls
                calls += 1
                if calls == 2:
                    finder = host.path_importer_cache[paths.DIRECTORY_PATHS[0]]
                    if change == 'hooks':
                        host.path_hooks = list(host.path_hooks)
                    elif change == 'cache':
                        host.path_importer_cache = dict(host.path_importer_cache)
                    elif change == 'hook':
                        h = host.path_hooks[1]
                        host.path_hooks[1] = FunctionType(h.__code__, h.__globals__, closure=h.__closure__)
                    elif change == 'finder':
                        new = object.__new__(type(finder))
                        vars(new).update(vars(finder))
                        host.path_importer_cache[finder.path] = new
                    elif change == 'loaders':
                        finder._loaders = list(finder._loaders)
                    elif change == 'names':
                        finder._path_cache = set(finder._path_cache)
                    elif change == 'mtime':
                        finder._path_mtime += 1
                    elif change == 'membership':
                        finder._path_cache.add('other.py')
                    else:
                        del host.path_importer_cache[paths.ZIP_PATH]
                return original()
            with self.subTest(change=change), patch.object(paths, '_capture', side_effect=capture), self.assertRaisesRegex(core.OperatorError, '^PY_PATH_CHANGED$'):
                self.run_fixture(host)

    def test_second_pass_invalid_state_is_checked(self):
        host = fixture()
        original = paths._capture
        calls = 0
        def capture():
            nonlocal calls
            calls += 1
            if calls == 2:
                host.path_hooks.reverse()
            return original()
        with patch.object(paths, '_capture', side_effect=capture), self.assertRaisesRegex(core.OperatorError, '^PY_PATH_HOOKS$'):
            self.run_fixture(host)

    def test_faults_are_sanitized_including_empty_closure(self):
        for failure in (AttributeError('PRIVATE'), KeyError('PRIVATE'), TypeError('PRIVATE'), ValueError('PRIVATE'), RuntimeError('PRIVATE')):
            with patch.object(fs, '_platform'), patch.object(paths, '_capture', side_effect=failure), self.assertRaises(core.OperatorError) as caught:
                paths.observe_python_path_importers()
            self.assertEqual(str(caught.exception), 'PY_PATH_STATE')
            self.assertTrue(caught.exception.__suppress_context__)
        host = fixture()
        del host.path_hooks[1].__closure__[0].cell_contents
        with self.assertRaisesRegex(core.OperatorError, '^PY_PATH_STATE$'):
            self.run_fixture(host)

    def test_results_remain_non_authorizing_and_not_source_only_proof(self):
        result = self.run_fixture()
        for field in ('hook_code_authenticated', 'directory_contents_proven', 'bytecode_exclusion_proven',
                      'complete_module_inventory_proven', 'actual_resolution_proven', 'atomic_snapshot_proven',
                      'runtime_trusted', 'startup_authorized'):
            self.assertIs(getattr(result, field), False)
        with self.assertRaises(FrozenInstanceError):
            result.startup_authorized = True
        source = Path(paths.__file__).read_text(encoding='utf-8')
        tree = ast.parse(source)
        names = {node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
        self.assertTrue(names.isdisjoint({'open', 'exec', 'eval', '__import__'}))
        self.assertNotIn('operator_python_path_importers.py', {pin[0] for pin in guard.PINNED_MODULES})
        self.assertIn('operator_python_path_importers.py', {pin[0] for pin in guard.RUNTIME_MODULES})


if __name__ == '__main__':
    unittest.main()
