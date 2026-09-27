"""Synthetic selected Linux 3.14 state, not host/native runtime acceptance."""
import ast
import copy
from dataclasses import FrozenInstanceError, asdict
import hashlib
from importlib.machinery import BuiltinImporter, FrozenImporter, ModuleSpec, PathFinder
import inspect
from pathlib import Path
import sys
from types import ModuleType
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_core as core
from siem.rbac.broker_tls import operator_fs as fs
from siem.rbac.broker_tls import operator_guard_entry as guard
from siem.rbac.broker_tls import operator_python_embedded as embedded
from siem.rbac.broker_tls import operator_python_import_state as imports
if __package__:
    from .test_broker_tls_python_import_state import fixture as file_fixture
else:
    from test_broker_tls_python_import_state import fixture as file_fixture


def fixture():
    host = ModuleType('sys')
    vars(host).update(vars(file_fixture()))
    host.modules['sys'] = host
    host.builtin_module_names = embedded.BUILTIN_NAMES + ('unused_builtin',)
    rows = [(n, n, n, '', None, 'built-in') for n in embedded.BUILTIN_NAMES]
    rows += [(*r[:4], '/usr/lib/python3.14/' + r[4], 'frozen') for r in embedded.FROZEN_MODULES]
    for key, name, spec_name, package, path, origin in rows:
        module = host.modules.setdefault(key, ModuleType(name))
        module.__name__, module.__package__ = name, package
        loader = BuiltinImporter if origin == 'built-in' else FrozenImporter
        module.__loader__ = loader
        module.__spec__ = ModuleSpec(spec_name, loader, origin=origin)
        if path is not None:
            module.__file__ = path
    for original, alias in embedded.ALIASES:
        host.modules[alias] = host.modules[original]
    for key, *_ in embedded.FROZEN_MODULES:
        if '.' in key:
            parent, child = key.rsplit('.', 1)
            setattr(host.modules[parent], child, host.modules[key])
    b, e = (vars(host.modules[k]) for k in ('_frozen_importlib', '_frozen_importlib_external'))
    for name in embedded.MACHINERY_NAMES:
        setattr(host.modules['importlib.machinery'], name, b.get(name, e.get(name)))
    return host


def clone(module):
    result = ModuleType(module.__name__)
    vars(result).update(vars(module))
    return result


class PythonEmbeddedTests(unittest.TestCase):
    def run_fixture(self, host=None):
        with patch.object(imports, 'sys', host or fixture()), patch.object(fs, '_platform'):
            return embedded.observe_python_embedded_modules()

    def test_retained_b2_projection_pins_all_53_keys_without_inventing_identity_evidence(self):
        raw = (ROOT / 'evidence/rbac/python-runtime-b2-embedded-modules-2026-09-27.tsv').read_bytes()
        raw = raw.replace(b'\r\n', b'\n')
        self.assertEqual(hashlib.sha256(raw).hexdigest(), '496131f4994debb5b56767bcf7478b404a699cd1a0b916ce0f5d6753dc6ada3e')
        rows = [line.split('\t') for line in raw.decode().splitlines()]
        self.assertEqual(rows[0], ['name', 'origin', 'file', 'cached'])
        expected = [[n, 'built-in', '-', '-'] for n in embedded.BUILTIN_NAMES]
        expected += [[r[0], 'frozen', '/usr/lib/python3.14/' + r[4], '-'] for r in embedded.FROZEN_MODULES]
        self.assertEqual(rows[1:], sorted(expected))
        self.assertEqual((len(embedded.BUILTIN_NAMES), len(embedded.FROZEN_MODULES)), (36, 17))
        names = {r[0] for r in expected}
        self.assertEqual(len(names), 53)
        self.assertTrue(names.isdisjoint({r[0] for r in imports.SELECTED_MODULES}))

    def test_candidate_alias_policy_is_explicit_and_not_naive_dotted_name_equality(self):
        self.assertEqual(embedded.ALIASES, (('_collections_abc', 'collections.abc'),
                         ('_frozen_importlib', 'importlib._bootstrap'),
                         ('_frozen_importlib_external', 'importlib._bootstrap_external'), ('posixpath', 'os.path')))
        rows = {r[0]: r[1:] for r in embedded.FROZEN_MODULES}
        self.assertEqual(rows['collections.abc'], ('collections.abc', '_collections_abc', '', '_collections_abc.py'))
        self.assertEqual(rows['importlib._bootstrap'], ('importlib._bootstrap', '_frozen_importlib', 'importlib', 'importlib/_bootstrap.py'))
        self.assertEqual(rows['os.path'], ('posixpath', 'posixpath', '', 'posixpath.py'))

    def test_positive_two_passes_and_file_observer_can_share_the_same_fixture(self):
        host = fixture()
        with patch.object(imports, 'sys', host), patch.object(fs, '_platform'), patch.object(
                embedded, '_capture', wraps=embedded._capture) as capture:
            result = embedded.observe_python_embedded_modules()
            files = imports.observe_python_import_state()
        self.assertEqual(capture.call_count, 2)
        self.assertEqual((result.observed_module_count, result.selected_module_keys, result.alias_pairs, result.passes), (103, 53, 4, 2))
        self.assertEqual(files.observed_module_count, 103)

    def test_no_subject_resolution_reads_lazy_properties_or_module_side_effects(self):
        host = fixture()
        before = {k: dict(vars(m)) for k, m in host.modules.items()}
        def trap(*args, **kwargs):
            raise AssertionError('subject machinery must not execute')
        with patch.object(BuiltinImporter, 'find_spec', side_effect=trap), patch.object(
                FrozenImporter, 'get_code', side_effect=trap), patch.object(
                PathFinder, 'find_spec', side_effect=trap), patch.object(
                ModuleSpec, 'cached', new=property(trap)), patch('builtins.open', side_effect=trap):
            self.run_fixture(host)
        self.assertEqual(before, {k: dict(vars(m)) for k, m in host.modules.items()})

    def test_public_root_platform_gate_precedes_capture_and_has_no_overrides(self):
        self.assertFalse(inspect.signature(embedded.observe_python_embedded_modules).parameters)
        with patch.object(fs, '_platform', side_effect=core.OperatorError('FS_ROOT_REQUIRED')), patch.object(embedded, '_capture') as capture:
            with self.assertRaisesRegex(core.OperatorError, '^FS_ROOT_REQUIRED$'):
                embedded.observe_python_embedded_modules()
        capture.assert_not_called()

    def test_runtime_checks_reused_in_each_pass(self):
        host = fixture()
        host.version_info = (3, 14, 5, 'final', 0)
        with self.assertRaisesRegex(core.OperatorError, '^PY_IMPORT_RUNTIME$'):
            self.run_fixture(host)
        with patch.object(imports, '_settings', wraps=imports._settings) as settings:
            self.run_fixture()
        self.assertEqual(settings.call_count, 2)

    def test_table_bounds_and_sys_identity(self):
        for table in ({}, None, {str(i): None for i in range(1025)}):
            host = fixture()
            host.modules = table
            with self.assertRaisesRegex(core.OperatorError, '^PY_EMBED_TABLE$'):
                self.run_fixture(host)
        host = fixture()
        host.modules['sys'] = clone(host)
        with self.assertRaisesRegex(core.OperatorError, '^PY_EMBED_SYS$'):
            self.run_fixture(host)

    def test_missing_each_selected_key_fails_without_preload(self):
        for name in (*embedded.BUILTIN_NAMES, *(r[0] for r in embedded.FROZEN_MODULES)):
            host = fixture()
            del host.modules[name]
            with self.subTest(name=name), self.assertRaises(core.OperatorError):
                self.run_fixture(host)
            self.assertNotIn(name, host.modules)

    def test_custom_modules_specs_and_text_cannot_run_properties_or_equality(self):
        class Trap:
            def __getattribute__(self, name):
                raise AssertionError('untrusted property')
            def __eq__(self, other):
                raise AssertionError('untrusted equality')
        for kind, code in (('module', 'PY_IMPORT_MODULE'), ('spec', 'PY_EMBED_SPEC'), ('name', 'PY_EMBED_NAME')):
            host = fixture()
            if kind == 'module':
                host.modules['abc'] = Trap()
            elif kind == 'spec':
                host.modules['abc'].__spec__ = Trap()
            else:
                host.modules['abc'].__name__ = Trap()
            with self.assertRaisesRegex(core.OperatorError, '^' + code + '$'):
                self.run_fixture(host)

    def test_every_name_spec_origin_and_informational_file_checked(self):
        for name in (*embedded.BUILTIN_NAMES, *(r[0] for r in embedded.FROZEN_MODULES)):
            for target, key, code in (('module', '__name__', 'NAME'), ('spec', 'name', 'NAME'),
                                      ('module', '__file__', 'FILE'), ('spec', 'origin', 'ORIGIN')):
                host = fixture()
                m = host.modules[name]
                setattr(m if target == 'module' else m.__spec__, key, '/PRIVATE')
                with self.subTest(name=name, key=key), self.assertRaisesRegex(core.OperatorError, '^PY_EMBED_' + code + '$'):
                    self.run_fixture(host)

    def test_cached_package_and_location_metadata_rejected(self):
        for name in ('_abc', 'abc', 'collections.abc', 'importlib._bootstrap', 'os.path'):
            for target, key, value, code in (
                    ('module', '__cached__', '/PRIVATE', 'CACHE'), ('spec', '_cached', '/PRIVATE', 'CACHE'),
                    ('module', '__path__', [], 'PACKAGE'), ('spec', 'submodule_search_locations', [], 'PACKAGE'),
                    ('module', '__package__', 'wrong', 'PACKAGE'), ('spec', '_set_fileattr', True, 'ORIGIN'),
                    ('spec', '_set_fileattr', 0, 'ORIGIN')):
                host = fixture()
                m = host.modules[name]
                setattr(m if target == 'module' else m.__spec__, key, value)
                with self.subTest(name=name, key=key), self.assertRaisesRegex(core.OperatorError, '^PY_EMBED_' + code + '$'):
                    self.run_fixture(host)

    def test_both_loader_fields_require_current_class_identity_not_label(self):
        impostor = type('FrozenImporter', (), {'__module__': '_frozen_importlib'})
        for name in ('_abc', 'abc'):
            for target in ('module', 'spec'):
                for value in (impostor, FrozenImporter()):
                    host = fixture()
                    m = host.modules[name]
                    setattr(m if target == 'module' else m.__spec__, '__loader__' if target == 'module' else 'loader', value)
                    with self.assertRaisesRegex(core.OperatorError, '^PY_EMBED_LOADER$'):
                        self.run_fixture(host)

    def test_all_aliases_require_identity_even_with_matching_metadata_and_parent(self):
        for original, alias in embedded.ALIASES:
            host = fixture()
            replacement = clone(host.modules[original])
            host.modules[alias] = replacement
            parent, child = alias.rsplit('.', 1)
            setattr(host.modules[parent], child, replacement)
            with self.subTest(alias=alias), self.assertRaisesRegex(core.OperatorError, '^PY_EMBED_ALIAS$'):
                self.run_fixture(host)

    def test_all_dotted_parent_bindings_checked(self):
        for key, *_ in embedded.FROZEN_MODULES:
            if '.' not in key:
                continue
            host = fixture()
            parent, child = key.rsplit('.', 1)
            setattr(host.modules[parent], child, clone(host.modules[key]))
            with self.subTest(key=key), self.assertRaisesRegex(core.OperatorError, '^PY_EMBED_PARENT$'):
                self.run_fixture(host)

    def test_builtin_availability_is_bounded_not_auto_learned_or_complete_inventory(self):
        for names in (None, list(embedded.BUILTIN_NAMES), embedded.BUILTIN_NAMES[:-1],
                      embedded.BUILTIN_NAMES + ('sys',), embedded.BUILTIN_NAMES + ('x' * 129,),
                      embedded.BUILTIN_NAMES + (None,), tuple(str(i) for i in range(1025))):
            host = fixture()
            host.builtin_module_names = names
            with self.assertRaisesRegex(core.OperatorError, '^PY_EMBED_BUILTINS$'):
                self.run_fixture(host)
        self.run_fixture()  # Extra available, unloaded builtin is allowed.

    def test_meta_path_and_public_machinery_bindings_checked(self):
        for name in embedded.MACHINERY_NAMES:
            host = fixture()
            setattr(host.modules['importlib.machinery'], name, type(name, (), {}))
            with self.assertRaisesRegex(core.OperatorError, '^PY_EMBED_MACHINERY$'):
                self.run_fixture(host)
        host = fixture()
        host.meta_path.reverse()
        with self.assertRaisesRegex(core.OperatorError, '^PY_EMBED_MACHINERY$'):
            self.run_fixture(host)
        host = fixture()
        host.modules['_frozen_importlib'].ModuleSpec = object()
        with self.assertRaisesRegex(core.OperatorError, '^PY_EMBED_MACHINERY$'):
            self.run_fixture(host)

    def test_two_valid_passes_reject_table_count_module_spec_parent_and_builtin_list_changes(self):
        for change in ('table', 'count', 'module', 'spec', 'parent', 'builtins'):
            host = fixture()
            capture = embedded._capture
            calls = 0
            def observe():
                nonlocal calls
                calls += 1
                if calls == 2:
                    if change == 'table':
                        host.modules = dict(host.modules)
                    elif change == 'count':
                        host.modules['extra'] = ModuleType('extra')
                    elif change == 'module':
                        host.modules['abc'] = clone(host.modules['abc'])
                    elif change == 'spec':
                        host.modules['abc'].__spec__ = copy.copy(host.modules['abc'].__spec__)
                    elif change == 'parent':
                        host.modules['importlib'] = clone(host.modules['importlib'])
                    else:
                        host.builtin_module_names += ('another_unused_builtin',)
                return capture()
            with patch.object(embedded, '_capture', side_effect=observe), self.subTest(change=change), self.assertRaisesRegex(
                    core.OperatorError, '^PY_EMBED_CHANGED$'):
                self.run_fixture(host)

    def test_second_pass_corruption_is_not_repaired(self):
        host = fixture()
        capture = embedded._capture
        def observe():
            result = capture()
            host.modules['abc'].__cached__ = '/PRIVATE'
            return result
        with patch.object(embedded, '_capture', side_effect=observe), self.assertRaisesRegex(core.OperatorError, '^PY_EMBED_CACHE$'):
            self.run_fixture(host)
        self.assertEqual(host.modules['abc'].__cached__, '/PRIVATE')

    def test_metadata_faults_have_fixed_sanitized_codes(self):
        for error in (AttributeError, KeyError, TypeError, ValueError, RuntimeError):
            with patch.object(fs, '_platform'), patch.object(embedded, '_capture', side_effect=error('PRIVATE')), self.assertRaises(core.OperatorError) as caught:
                embedded.observe_python_embedded_modules()
            self.assertEqual(str(caught.exception), 'PY_EMBED_STATE')
            self.assertTrue(caught.exception.__suppress_context__)

    def test_extra_entry_and_private_modules_remain_unproven_and_guard_unwired(self):
        host = fixture()
        for key in ('__main__', '_alertmind_guard_held', 'unselected'):
            host.modules[key] = ModuleType(key)
        result = self.run_fixture(host)
        self.assertEqual(result.observed_module_count, 106)
        flags = asdict(result)
        for key in ('complete_module_inventory_proven', 'embedded_code_proven', 'bootstrap_code_proven',
                    'native_resolution_proven', 'atomic_snapshot_proven', 'runtime_trusted', 'startup_authorized'):
            self.assertIs(flags[key], False)
        with self.assertRaises(FrozenInstanceError):
            result.startup_authorized = True
        self.assertNotIn('operator_python_embedded.py', {p[0] for p in guard.PINNED_MODULES})
        self.assertNotIn('operator_python_embedded', Path(guard.__file__).read_text(encoding='utf-8'))
        tree = ast.parse(Path(embedded.__file__).read_text(encoding='utf-8'))
        calls = {n.func.id for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        self.assertTrue(calls.isdisjoint({'open', 'exec', 'eval', '__import__'}))


if __name__ == '__main__':
    unittest.main()
