"""Closed-table candidate policy, synthetic state and real held-loader output.

No VM, guard activation or selected-runtime compatibility claim. The policy
consumes supplied tables, not the test runner's ambient module inventory.
"""
import ast
import builtins
from contextlib import ExitStack, contextmanager, redirect_stderr
import copy
from io import StringIO
from importlib.machinery import SourceFileLoader
from pathlib import Path
import sys
from types import FunctionType, ModuleType
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_guard_entry as entry
from siem.rbac.broker_tls import operator_python_embedded as embedded
from siem.rbac.broker_tls import operator_python_import_state as imports
if __package__:
    from .test_broker_tls_python_embedded import fixture as embedded_fixture
else:
    from test_broker_tls_python_embedded import fixture as embedded_fixture


def fixture(held=False):
    host = embedded_fixture()
    modules = host.modules
    main = ModuleType('__main__')
    main.__file__ = entry.ENTRY_PATH
    main.__cached__ = None
    main.__loader__ = SourceFileLoader('__main__', entry.ENTRY_PATH)
    main.__builtins__ = modules['builtins']
    for name in ('sys', 'os', 'stat', 'hashlib'):
        setattr(main, name, modules[name])
    for name, value in (('ExitStack', ExitStack), ('contextmanager', contextmanager)):
        setattr(main, name, value)
        setattr(modules['contextlib'], name, value)
    main.HELD_PACKAGE = entry.HELD_PACKAGE
    # Rebind the real candidate function's code into synthetic direct-entry
    # globals. Never execute the predicate to validate table metadata.
    method = entry._DenyHeldFallback.find_spec
    function = FunctionType(method.__code__.replace(co_filename=entry.ENTRY_PATH),
                            vars(main), 'find_spec', (None, None))
    main._DenyHeldFallback = type('_DenyHeldFallback', (), {'__module__': '__main__', 'find_spec': function})
    modules['__main__'] = main
    loaded = None
    if held:
        package = ModuleType(entry.HELD_PACKAGE)
        package.__package__, package.__path__ = entry.HELD_PACKAGE, ()
        loaded = {entry.HELD_PACKAGE: package}
        for name, _, _ in entry.PINNED_MODULES:
            stem = name[:-3]
            key = entry.HELD_PACKAGE + '.' + stem
            m = ModuleType(key)
            m.__package__ = entry.HELD_PACKAGE
            m.__file__ = '<alertmind-guard>/' + name
            m.__builtins__ = vars(modules['builtins'])
            loaded[key] = m
            setattr(package, stem, m)
        modules.update(loaded)
        host.meta_path.insert(0, main._DenyHeldFallback())
    return modules, loaded


def clone(m):
    other = ModuleType(m.__name__)
    vars(other).update(vars(m))
    return other


class GuardModuleTableTests(unittest.TestCase):
    def test_fixed_sets_match_b2_c1_and_pinned_capsule_without_import_expansion(self):
        selected = {r[0] for r in imports.SELECTED_MODULES} | set(embedded.BUILTIN_NAMES) | {r[0] for r in embedded.FROZEN_MODULES}
        self.assertEqual(set(entry.STDLIB_MODULE_KEYS), selected)
        self.assertEqual(len(entry.STDLIB_MODULE_KEYS), 103)
        self.assertEqual(entry.PREPARED_MODULE_KEYS, selected | {'__main__'})
        self.assertEqual(entry.HELD_MODULE_KEYS, {entry.HELD_PACKAGE} | {
            entry.HELD_PACKAGE + '.' + n[:-3] for n, _, _ in entry.PINNED_MODULES})
        self.assertEqual((len(entry.PREPARED_MODULE_KEYS), len(entry.HELD_MODULE_KEYS)), (104, 14))
        self.assertEqual({frozenset(p) for p in entry.MODULE_ALIASES}, {frozenset(p) for p in embedded.ALIASES})
        tree = ast.parse(Path(entry.__file__).read_text(encoding='utf-8'))
        self.assertEqual([n.module if isinstance(n, ast.ImportFrom) else n.names[0].name
                          for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))],
                         ['contextlib', 'hashlib', 'os', 'stat', 'sys'])

    def test_both_fixed_phases_two_passes_return_no_authorization(self):
        for held, count in ((False, 104), (True, 118)):
            modules, loaded = fixture(held)
            with patch.object(entry, '_table_capture', wraps=entry._table_capture) as capture:
                self.assertIsNone(entry._check_module_table(modules, held=held, loaded=loaded))
            self.assertEqual(capture.call_count, 2)
            self.assertEqual(len(modules), count)

    def test_policy_does_not_lookup_ambient_table_import_invoke_or_change_inputs(self):
        modules, loaded = fixture(True)
        before = {k: dict(vars(m)) for k, m in modules.items()}
        method = vars(modules['__main__']._DenyHeldFallback)['find_spec']
        with patch('builtins.open', side_effect=AssertionError('no read')), patch.object(
                SourceFileLoader, 'get_code', side_effect=AssertionError('no load')), patch.object(
                entry, '_loaded_verified_bundle', side_effect=AssertionError('no implicit execution')):
            entry._check_module_table(modules, held=True, loaded=loaded)
        self.assertEqual(before, {k: dict(vars(m)) for k, m in modules.items()})
        self.assertIs(method, vars(modules['__main__']._DenyHeldFallback)['find_spec'])
        self.assertNotEqual(set(sys.modules), entry.PREPARED_MODULE_KEYS)

    def test_each_missing_key_or_unknown_key_fails_even_at_same_count(self):
        for held in (False, True):
            for key in sorted(entry.PREPARED_MODULE_KEYS | (entry.HELD_MODULE_KEYS if held else set())):
                for replacement in (False, True):
                    modules, loaded = fixture(held)
                    del modules[key]
                    if replacement:
                        modules['unexpected'] = ModuleType('unexpected')
                    with self.subTest(held=held, key=key, replacement=replacement), self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_TABLE_SET$'):
                        entry._check_module_table(modules, held=held, loaded=loaded)

    def test_no_optional_module_prefix_or_partial_bundle_allowance(self):
        for key in ('site', 'usercustomize', 'siem', entry.HELD_PACKAGE + '.unknown', entry.HELD_PACKAGE + '_lookalike'):
            modules, _ = fixture()
            modules[key] = ModuleType(key)
            with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_TABLE_SET$'):
                entry._check_module_table(modules)
        modules, loaded = fixture(True)
        with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_TABLE_SET$'):
            entry._check_module_table(modules)
        modules, _ = fixture()
        with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_TABLE_SET$'):
            entry._check_module_table(modules, held=True, loaded=loaded)

    def test_phase_and_registry_cannot_be_omitted_or_auto_selected(self):
        for held in (0, 1, None, 'held'):
            with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_TABLE_PHASE$'):
                entry._check_module_table({}, held=held)
        modules, _ = fixture()
        with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_TABLE_PHASE$'):
            entry._check_module_table(modules, loaded={})
        modules, _ = fixture(True)
        for loaded in (None, {}, []):
            with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_TABLE_SET$'):
                entry._check_module_table(modules, held=True, loaded=loaded)

    def test_registry_keys_and_identity_must_match_every_private_object(self):
        for key in entry.HELD_MODULE_KEYS:
            modules, loaded = fixture(True)
            loaded[key] = clone(loaded[key])
            with self.subTest(key=key), self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_TABLE_REGISTRY$'):
                entry._check_module_table(modules, held=True, loaded=loaded)
        modules, loaded = fixture(True)
        loaded['unexpected'] = ModuleType('unexpected')
        with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_TABLE_SET$'):
            entry._check_module_table(modules, held=True, loaded=loaded)

    def test_keys_and_module_objects_are_exact_types_not_property_traps(self):
        class Trap:
            def __getattribute__(self, key):
                raise AssertionError('property executed')
        modules, _ = fixture()
        modules['abc'] = Trap()
        with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_TABLE_MODULE$'):
            entry._check_module_table(modules)
        modules, _ = fixture()
        modules[1] = modules.pop('abc')
        with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_TABLE_KEY$'):
            entry._check_module_table(modules)
        modules, _ = fixture()
        modules['abc'] = None
        with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_TABLE_MODULE$'):
            entry._check_module_table(modules)

    def test_all_approved_aliases_require_identity(self):
        for _, alias in entry.MODULE_ALIASES:
            modules, _ = fixture()
            modules[alias] = clone(modules[alias])
            with self.subTest(alias=alias), self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_TABLE_ALIAS$'):
                entry._check_module_table(modules)

    def test_unapproved_module_identity_aliases_rejected(self):
        for a, b in (('abc', 'codecs'), ('__main__', 'types'), ('_abc', 'abc')):
            modules, _ = fixture()
            modules[a] = modules[b]
            with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_TABLE_ALIAS$'):
                entry._check_module_table(modules)

    def test_main_direct_script_metadata_not_stdin_module_mode_or_package(self):
        for key, bad in (('__name__', 'entry'), ('__file__', '<stdin>'), ('__file__', '/tmp/guard_entry.py'),
                         ('__spec__', object()), ('__package__', 'siem'), ('__cached__', '/tmp/x.pyc'), ('__path__', [])):
            modules, _ = fixture()
            setattr(modules['__main__'], key, bad)
            with self.subTest(key=key), self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_TABLE_ENTRY$'):
                entry._check_module_table(modules)

    def test_main_loader_type_name_path_and_instance_overrides_rejected(self):
        for mutate, code in (
                (lambda m: setattr(m, '__loader__', None), 'LOADER'),
                (lambda m: setattr(m.__loader__, 'name', 'other'), 'LOADER'),
                (lambda m: setattr(m.__loader__, 'path', '/PRIVATE'), 'LOADER'),
                (lambda m: setattr(m.__loader__, 'get_code', lambda: None), 'SET')):
            modules, _ = fixture()
            mutate(modules['__main__'])
            with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_TABLE_' + code + '$'):
                entry._check_module_table(modules)

    def test_main_import_bindings_and_builtins_are_identity_based(self):
        for name in ('sys', 'os', 'stat', 'hashlib', 'ExitStack', 'contextmanager', '__builtins__'):
            modules, _ = fixture()
            setattr(modules['__main__'], name, object())
            with self.subTest(name=name), self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_TABLE_BINDING$'):
                entry._check_module_table(modules)
        modules, _ = fixture()
        modules['__main__'].__builtins__ = vars(modules['builtins'])
        entry._check_module_table(modules)

    def test_held_package_has_only_empty_path_and_exact_children(self):
        for key, value, code in (('__path__', [], 'HELD'), ('__path__', ('/tmp',), 'HELD'),
                                 ('__name__', 'wrong', 'HELD'), ('__package__', 'wrong', 'HELD'),
                                 ('__loader__', object(), 'HELD'), ('__spec__', object(), 'HELD'),
                                 ('__file__', '/PRIVATE', 'SET'), ('unexpected', object(), 'SET')):
            modules, loaded = fixture(True)
            setattr(modules[entry.HELD_PACKAGE], key, value)
            with self.subTest(key=key), self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_TABLE_' + code + '$'):
                entry._check_module_table(modules, held=True, loaded=loaded)

    def test_every_private_child_metadata_and_parent_binding_checked(self):
        for key in sorted(entry.HELD_MODULE_KEYS - {entry.HELD_PACKAGE}):
            for attr in ('__name__', '__package__', '__file__', '__spec__', '__loader__', '__cached__', '__path__', '__builtins__', 'parent'):
                modules, loaded = fixture(True)
                if attr == 'parent':
                    setattr(modules[entry.HELD_PACKAGE], key.rsplit('.', 1)[1], object())
                else:
                    setattr(modules[key], attr, '/PRIVATE')
                with self.subTest(key=key, attr=attr), self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_TABLE_HELD$'):
                    entry._check_module_table(modules, held=True, loaded=loaded)

    def test_meta_finders_have_explicit_phase_order_not_generic_extra_allowance(self):
        for held in (False, True):
            for op in ('reverse', 'missing', 'extra', 'impostor'):
                modules, loaded = fixture(held)
                meta = modules['sys'].meta_path
                if op == 'reverse': meta.reverse()
                elif op == 'missing': meta.pop()
                elif op == 'extra': meta.append(object())
                else: meta[-1] = type('PathFinder', (), {})
                with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_TABLE_FINDER$'):
                    entry._check_module_table(modules, held=held, loaded=loaded)

    def test_held_finder_instance_method_and_global_metadata(self):
        for op in ('instance_shadow', 'wrong_class', 'class_module', 'function_globals', 'filename', 'defaults', 'kwdefaults'):
            modules, loaded = fixture(True)
            cls = modules['__main__']._DenyHeldFallback
            method = vars(cls)['find_spec']
            if op == 'instance_shadow': modules['sys'].meta_path[0].find_spec = lambda: None
            elif op == 'wrong_class': modules['sys'].meta_path[0] = object()
            elif op == 'class_module': cls.__module__ = 'other'
            elif op == 'function_globals': cls.find_spec = FunctionType(method.__code__, {}, 'find_spec', (None, None))
            elif op == 'filename': method.__code__ = method.__code__.replace(co_filename='/PRIVATE')
            elif op == 'defaults': method.__defaults__ = (None,)
            else: method.__kwdefaults__ = {'target': None}
            with self.subTest(op=op), self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_TABLE_FINDER$'):
                entry._check_module_table(modules, held=True, loaded=loaded)

    def test_two_valid_passes_reject_module_loader_finder_and_binding_replacement(self):
        for change in ('module', 'main_loader', 'meta_list', 'finder', 'method_code', 'binding'):
            modules, loaded = fixture(True)
            original = entry._table_capture
            count = 0
            def capture(*args):
                nonlocal count
                count += 1
                if count == 2:
                    if change == 'module': modules['abc'] = clone(modules['abc'])
                    elif change == 'main_loader': modules['__main__'].__loader__ = copy.copy(modules['__main__'].__loader__)
                    elif change == 'meta_list': modules['sys'].meta_path = list(modules['sys'].meta_path)
                    elif change == 'finder': modules['sys'].meta_path[0] = modules['__main__']._DenyHeldFallback()
                    elif change == 'method_code':
                        method = vars(modules['__main__']._DenyHeldFallback)['find_spec']
                        method.__code__ = method.__code__.replace()
                    else:
                        modules['__main__'].ExitStack = modules['contextlib'].ExitStack = object()
                return original(*args)
            with patch.object(entry, '_table_capture', side_effect=capture), self.subTest(change=change), self.assertRaisesRegex(
                    entry.GuardLaunchError, '^GUARD_TABLE_CHANGED$'):
                entry._check_module_table(modules, held=True, loaded=loaded)

    def test_second_pass_missing_and_corrupt_state_not_repaired(self):
        for corrupt in (False, True):
            modules, loaded = fixture(True)
            original = entry._table_capture
            def capture(*args):
                result = original(*args)
                if corrupt: modules['__main__'].__file__ = '/PRIVATE'
                else: modules.pop('abc', None)
                return result
            with patch.object(entry, '_table_capture', side_effect=capture), self.assertRaises(entry.GuardLaunchError):
                entry._check_module_table(modules, held=True, loaded=loaded)

    def test_fixed_errors_do_not_echo_supplier_exception(self):
        for error in (AttributeError, KeyError, TypeError, ValueError, RuntimeError):
            with patch.object(entry, '_table_capture', side_effect=error('PRIVATE')), self.assertRaises(entry.GuardLaunchError) as caught:
                entry._check_module_table({})
            self.assertEqual(str(caught.exception), 'GUARD_TABLE_STATE')
            self.assertTrue(caught.exception.__suppress_context__)

    def test_existing_held_loader_produces_matching_private_metadata(self):
        modules, _ = fixture()
        # Use the current trusted test interpreter's builtins for real exec;
        # all other stdlib/main metadata remains the synthetic candidate state.
        modules['builtins'] = builtins
        modules['__main__'].__builtins__ = builtins
        sources = tuple((n, (Path(entry.__file__).parent / n).read_bytes()) for n, _, _ in entry.PINNED_MODULES)
        old_finders = tuple(sys.meta_path)
        with patch.object(entry, '_DenyHeldFallback', modules['__main__']._DenyHeldFallback):
            with entry._loaded_verified_bundle(sources) as loaded:
                modules.update(loaded)
                modules['sys'].meta_path.insert(0, sys.meta_path[0])
                entry._check_module_table(modules, held=True, loaded=loaded)
        self.assertEqual(tuple(sys.meta_path), old_finders)
        self.assertTrue(entry.HELD_MODULE_KEYS.isdisjoint(sys.modules))

    def test_table_match_is_not_stdlib_content_or_live_process_validation(self):
        modules, _ = fixture()
        # Entry/table policy is deliberately separate from the selected-origin
        # observers and byte checks; a metadata-shaped supplied table is not
        # authenticated Python code or proof it is the current sys.modules.
        modules['json'].__file__ = '/not-the-approved-source'
        with patch.object(imports, 'observe_python_import_state', side_effect=AssertionError('not composed')):
            self.assertIsNone(entry._check_module_table(modules))

    def test_checks_not_wired_into_entry_and_compile_only_behavior_retained(self):
        with redirect_stderr(StringIO()), patch.object(entry, '_check_entry'), patch.object(entry, '_check_module_table', side_effect=AssertionError('must stay dormant')) as checked:
            self.assertEqual(entry.main(), 1)
        checked.assert_not_called()
        tree = ast.parse(Path(entry.__file__).read_text(encoding='utf-8'))
        caller = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_check_entry')
        called = {n.func.id for n in ast.walk(caller) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        self.assertNotIn('_check_module_table', called)
        self.assertNotIn('_loaded_verified_bundle', called)
        self.assertEqual(len(entry.PINNED_MODULES), 13)


if __name__ == '__main__':
    unittest.main()
