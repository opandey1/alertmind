"""Dormant initializer fixture tests; NOT native preparation or guard execution."""
import ast
import builtins
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
import sys
from types import FunctionType, ModuleType
import unittest
from unittest.mock import Mock, patch
import zipimport

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_guard_entry as entry
from siem.rbac.broker_tls import operator_python_policy as policy
from siem.rbac.broker_tls import operator_python_import_state as imports
if __package__:
    from .test_broker_tls_guard_module_table import fixture as table_fixture, clone
    from .test_broker_tls_guard_entry import FakeOS
else:
    from test_broker_tls_guard_module_table import fixture as table_fixture, clone
    from test_broker_tls_guard_entry import FakeOS


class PreparationFixture:
    def __init__(self, grow=False):
        self.modules, _ = table_fixture()
        self.host = self.modules['sys']
        self.os = self.modules['os']
        fake = FakeOS()
        for name in dir(fake):
            if not name.startswith('__'):
                setattr(self.os, name, getattr(fake, name))
        self.os.environ = dict(entry.PREPARATION_ENV)
        self.os.getcwd = Mock(return_value='/')
        self.modules['builtins'] = builtins
        self.modules['zipimport'].zipimporter = zipimport.zipimporter
        self.host.path_hooks = [zipimport.zipimporter, lambda path: None]
        self.main = self.modules['__main__']
        self.main.__builtins__ = builtins  # FunctionType captures this at creation.
        # Bind actual entry functions into a synthetic direct-file __main__.
        # No source loader, subject import, file read or guard call occurs here.
        original_main = vars(self.main).copy()
        for name, value in vars(entry).items():
            if not name.startswith('__'):
                if isinstance(value, FunctionType):
                    copied = FunctionType(value.__code__, vars(self.main), name,
                                          value.__defaults__, value.__closure__)
                    copied.__kwdefaults__ = value.__kwdefaults__
                    value = copied
                setattr(self.main, name, value)
        vars(self.main).update(original_main)
        self.main.__builtins__ = builtins
        self.main.sys, self.main.os = self.host, self.os
        self.main.stat, self.main.hashlib = self.modules['stat'], self.modules['hashlib']
        self.all_modules = dict(self.modules)
        if grow:
            anchors = {'__main__', 'sys', 'os', 'stat', 'hashlib', 'contextlib', 'builtins',
                       '_frozen_importlib', '_frozen_importlib_external', 'zipimport'}
            for key in tuple(self.modules):
                if key not in anchors:
                    del self.modules[key]
        self.imported = []
        self.action = None
        self.grow = grow
        self.main._import_preparation_root = Mock(side_effect=self.import_root)

    def import_root(self, name):
        self.imported.append(name)
        if self.grow:
            self.modules.setdefault(name, self.all_modules[name])
            if name == entry.PREPARATION_ROOTS[-1]:
                self.modules.update(self.all_modules)
        if self.action:
            self.action(name)
        return self.modules.get(name)

    def run(self):
        return self.main._prepare_stdlib()


class GuardPreparationTests(unittest.TestCase):
    def test_policy_roots_order_match_existing_b2_and_launch_data(self):
        runbook = (ROOT / 'docs/runbooks/rbac-guard-python-runtime-trust.md').read_text(encoding='utf-8')
        source = runbook.split("<<'ALERTMIND_IMPORT_ORIGINS'\n", 1)[1].split('\nALERTMIND_IMPORT_ORIGINS', 1)[0]
        roots = tuple(alias.name for n in ast.parse(source).body if isinstance(n, ast.Import) for alias in n.names)
        self.assertEqual(entry.PREPARATION_ROOTS, roots)
        self.assertEqual(len(roots), 18)
        self.assertEqual(entry.PREPARATION_ARGV, policy.CANDIDATE_ARGV)
        self.assertEqual(entry.PREPARATION_ENV, policy.CANDIDATE_ENVIRONMENT)
        self.assertEqual(entry.PREPARATION_SEARCH_PATH, imports.SEARCH_PATH)

    def test_exact_root_sequence_and_final_closed_table_no_authorization(self):
        f = PreparationFixture()
        table = f.main._check_module_table
        f.main._check_module_table = Mock(wraps=table)
        self.assertIsNone(f.run())
        self.assertEqual(tuple(f.imported), entry.PREPARATION_ROOTS)
        f.main._check_module_table.assert_called_once_with(f.modules)
        self.assertEqual(len(f.modules), 104)

    def test_growth_retains_preexisting_bindings_without_auto_learning(self):
        f = PreparationFixture(grow=True)
        before = dict(f.modules)
        self.assertIsNone(f.run())
        self.assertTrue(all(f.modules[k] is v for k, v in before.items()))
        self.assertEqual(f.modules.keys(), entry.PREPARED_MODULE_KEYS)

    def test_settings_rechecked_before_after_each_root_and_after_final_table(self):
        f = PreparationFixture()
        settings = f.main._preparation_settings
        f.main._preparation_settings = Mock(wraps=settings)
        f.run()
        self.assertEqual(f.main._preparation_settings.call_count, 20)
        self.assertEqual(f.os.getcwd.call_count, 20)

    def test_no_configuration_repair_and_no_capsule_or_native_observers_called(self):
        f = PreparationFixture()
        env, path, hooks, finders = dict(f.os.environ), list(f.host.path), list(f.host.path_hooks), list(f.host.meta_path)
        f.main._loaded_verified_bundle = Mock(side_effect=AssertionError('no capsule'))
        f.main._check_entry = Mock(side_effect=AssertionError('no guard'))
        f.run()
        self.assertEqual((dict(f.os.environ), f.host.path, f.host.path_hooks, f.host.meta_path),
                         (env, path, hooks, finders))
        f.main._loaded_verified_bundle.assert_not_called()
        f.main._check_entry.assert_not_called()
        f.os.open.assert_not_called()

    def test_initializer_is_unused_by_entry_and_entry_always_fails_closed(self):
        output = StringIO()
        with patch.object(entry, '_check_entry') as check, patch.object(entry, '_prepare_stdlib') as prepare, redirect_stderr(output):
            self.assertEqual(entry.main(), 1)
        prepare.assert_not_called()
        self.assertEqual(output.getvalue(), 'GUARD_NOT_READY\n')
        with patch.object(entry, '_check_isolation'), patch.object(entry, 'os', FakeOS()), patch.object(
                entry, '_check_entry_at'), patch.object(entry, '_verify_bundle_at'), patch.object(
                entry, '_compile_verified_bundle'), patch.object(entry, '_prepare_stdlib') as prepare:
            entry._check_entry()
        prepare.assert_not_called()

    def test_wrong_runtime_version_implementation_or_executable_fails_before_import(self):
        for obj, name, value in (('host', 'version_info', (3, 14, 5, 'final', 0)),
                                 ('host', 'version_info', (True, 14, 4, 'final', 0)),
                                 ('host', 'executable', '/usr/bin/python3'),
                                 ('implementation', 'name', 'other'), ('implementation', 'cache_tag', 'cpython-312')):
            f = PreparationFixture()
            target = f.host.implementation if obj == 'implementation' else f.host
            setattr(target, name, value)
            with self.subTest(name=name), self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_PREP_RUNTIME$'):
                f.run()
            self.assertEqual(f.imported, [])

    def test_all_required_flags_and_exact_safe_booleans(self):
        for name in ('isolated', 'ignore_environment', 'no_site', 'no_user_site',
                     'dont_write_bytecode', 'safe_path', 'optimize'):
            f = PreparationFixture()
            setattr(f.host.flags, name, 1 if name == 'optimize' else 0)
            with self.subTest(name=name), self.assertRaises(entry.GuardLaunchError):
                f.run()
            self.assertEqual(f.imported, [])
        for name in ('isolated', 'no_user_site'):
            f = PreparationFixture()
            setattr(f.host.flags, name, True)
            with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_PREP_FLAGS$'):
                f.run()

    def test_exact_argv_paths_cache_prefix_and_working_directory(self):
        for name, value in (('orig_argv', ['python']), ('argv', ['-c']), ('path', ['/tmp']),
                            ('pycache_prefix', None), ('_xoptions', {}),
                            ('_xoptions', {'pycache_prefix': '/tmp'})):
            f = PreparationFixture()
            setattr(f.host, name, value)
            with self.subTest(name=name), self.assertRaises(entry.GuardLaunchError):
                f.run()
            self.assertEqual(f.imported, [])
        f = PreparationFixture()
        f.os.getcwd.return_value = '/tmp'
        with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_PREP_CWD$'):
            f.run()

    def test_environment_missing_extra_empty_and_changed_values_no_secret_output(self):
        for env in ({}, {**dict(entry.PREPARATION_ENV), 'LD_PRELOAD': ''},
                    {**dict(entry.PREPARATION_ENV), 'HOME': 'PRIVATE_SECRET'},
                    {**dict(entry.PREPARATION_ENV), 'PYTHONPATH': '/tmp'}):
            f = PreparationFixture()
            f.os.environ = env.copy()
            with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_PREP_ENV$'):
                f.run()
            self.assertEqual(f.os.environ, env)
            self.assertEqual(f.imported, [])

    def test_unknown_private_site_and_nonmodule_state_rejected_before_import(self):
        for name in ('site', 'usercustomize', 'siem', entry.HELD_PACKAGE, entry.HELD_PACKAGE + '.x', 'unknown'):
            f = PreparationFixture(grow=True)
            f.modules[name] = ModuleType(name)
            with self.subTest(name=name), self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_PREP_SET$'):
                f.run()
            self.assertEqual(f.imported, [])
        for value in (None, object(), 'PRIVATE'):
            f = PreparationFixture()
            f.modules['types'] = value
            with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_TABLE_MODULE$'):
                f.run()

    def test_entry_metadata_and_global_bindings_must_be_direct_script(self):
        for name, value in (('__file__', '<stdin>'), ('__name__', 'other'), ('__loader__', None),
                            ('__spec__', object()), ('__package__', 'siem')):
            f = PreparationFixture()
            setattr(f.main, name, value)
            with self.subTest(name=name), self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_PREP_ENTRY$'):
                f.run()
            self.assertEqual(f.imported, [])
        f = PreparationFixture()
        f.modules['__main__'] = clone(f.main)
        with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_PREP_BINDING$'):
            f.run()

    def test_preparation_rejects_held_or_replaced_finders_and_nondefault_importer(self):
        for field, value in (('meta_path', []), ('meta_path', [object()] * 3), ('path_hooks', []),
                             ('path_hooks', [zipimport.zipimporter, object()])):
            f = PreparationFixture()
            setattr(f.host, field, value)
            with self.subTest(field=field), self.assertRaises(entry.GuardLaunchError):
                f.run()
            self.assertEqual(f.imported, [])
        f = PreparationFixture()
        f.modules['builtins'] = clone(builtins)
        f.modules['builtins'].__import__ = lambda *args: None
        f.main.__builtins__ = f.modules['builtins']
        with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_PREP_IMPORT$'):
            f.run()

    def test_each_import_failure_stops_once_without_retry_or_cleanup(self):
        for stop in entry.PREPARATION_ROOTS:
            f = PreparationFixture(grow=True)
            def failed(name):
                if name == stop:
                    raise ImportError('PRIVATE_DIAGNOSTIC')
            f.action = failed
            with self.subTest(root=stop), self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_PREP_FAILED$') as caught:
                f.run()
            self.assertEqual(f.imported, list(entry.PREPARATION_ROOTS[:entry.PREPARATION_ROOTS.index(stop) + 1]))
            self.assertIsNone(caught.exception.__cause__)
            self.assertTrue(caught.exception.__suppress_context__)
            self.assertIn(stop, f.modules)  # No pretend rollback of executed imports.

    def test_system_exit_and_interrupt_are_fixed_failures_not_success(self):
        for error in (SystemExit(0), KeyboardInterrupt(), RuntimeError('PRIVATE')):
            f = PreparationFixture()
            f.main._import_preparation_root.side_effect = error
            with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_PREP_FAILED$'):
                f.run()

    def test_import_cannot_smuggle_a_private_guard_exception_message(self):
        f = PreparationFixture()
        f.main._import_preparation_root.side_effect = entry.GuardLaunchError('PRIVATE_PAYLOAD')
        with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_PREP_FAILED$') as caught:
            f.run()
        self.assertIsNone(caught.exception.__cause__)
        self.assertTrue(caught.exception.__suppress_context__)

    def test_preparation_is_not_a_selected_origin_or_hook_code_attestation(self):
        f = PreparationFixture()
        f.modules['json'].__file__ = '/not-an-authenticated-source'
        # Synthetic hook is intentionally not FileFinder's real closure.
        self.assertIsNone(f.run())
        # Separate source/hook/byte observers and trusted composition are still
        # mandatory; do not mistake a matching prepared table for runtime trust.

    def test_result_must_be_identical_module_not_none_proxy_or_other_module(self):
        for result in (None, object(), ModuleType('sys')):
            f = PreparationFixture()
            f.main._import_preparation_root.side_effect = None
            f.main._import_preparation_root.return_value = result
            with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_PREP_RESULT$'):
                f.run()

    def test_each_root_cannot_delete_or_replace_prior_module(self):
        for stop in entry.PREPARATION_ROOTS:
            f = PreparationFixture()
            def changed(name):
                if name == stop:
                    f.modules['abc'] = clone(f.modules['abc'])
            f.action = changed
            with self.subTest(root=stop), self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_PREP_CHANGED$'):
                f.run()
        f = PreparationFixture()
        f.action = lambda name: f.modules.pop('abc', None)
        with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_PREP_CHANGED$'):
            f.run()

    def test_replaced_table_meta_hook_or_entry_loader_identity_fails(self):
        for change in (lambda f: setattr(f.host, 'modules', dict(f.modules)),
                       lambda f: setattr(f.host, 'meta_path', list(f.host.meta_path)),
                       lambda f: setattr(f.host, 'path_hooks', list(f.host.path_hooks)),
                       lambda f: setattr(f.main, '__loader__', type(f.main.__loader__)('__main__', entry.ENTRY_PATH))):
            f = PreparationFixture()
            f.action = lambda name: change(f)
            with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_PREP_CHANGED$'):
                f.run()

    def test_post_import_configuration_drift_and_unknown_addition_are_not_accepted(self):
        for change in (lambda f: f.os.environ.update(HOME='PRIVATE'),
                       lambda f: f.host.path.append('/tmp'),
                       lambda f: f.modules.update(unknown=ModuleType('unknown'))):
            f = PreparationFixture()
            f.action = lambda name: change(f)
            with self.assertRaises(entry.GuardLaunchError):
                f.run()
            self.assertEqual(len(f.imported), 1)

    def test_final_policy_catches_missing_closure_alias_and_selected_entry_metadata(self):
        for change in (lambda f: f.modules.pop('_ast'),
                       lambda f: f.modules.update({'collections.abc': clone(f.modules['collections.abc'])})):
            f = PreparationFixture()
            change(f)
            with self.assertRaises(entry.GuardLaunchError):
                f.run()
            self.assertEqual(len(f.imported), 18)

    def test_final_table_checker_drift_rechecked_after_it_returns(self):
        f = PreparationFixture()
        real = f.main._check_module_table
        def changed(modules):
            real(modules)
            modules['abc'] = clone(modules['abc'])
        f.main._check_module_table = changed
        with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_PREP_CHANGED$'):
            f.run()

    def test_private_import_seam_rejects_arbitrary_name_before_builtin_import(self):
        for name in ('os.path', 'site', 'siem', '', None, ['os']):
            with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_PREP_ROOT$'):
                entry._import_preparation_root(name)
        with patch.object(entry, '__import__', create=True, return_value=sys) as imp:
            self.assertIs(entry._import_preparation_root('sys'), sys)
        self.assertEqual(imp.call_args.args, ('sys', vars(entry), vars(entry), (), 0))

    def test_no_added_top_level_import_and_initializer_has_no_configurable_inputs(self):
        source = Path(entry.__file__).read_text(encoding='utf-8')
        tree = ast.parse(source, feature_version=(3, 10))
        self.assertEqual([n.module if isinstance(n, ast.ImportFrom) else n.names[0].name
                          for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))],
                         ['contextlib', 'hashlib', 'os', 'stat', 'sys'])
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_prepare_stdlib')
        self.assertFalse(node.args.args or node.args.kwonlyargs or node.args.vararg or node.args.kwarg)
        self.assertLess(len(source.encode()), entry.MAX_ENTRY_BYTES)
        self.assertEqual(len(entry.PINNED_MODULES), 13)


if __name__ == '__main__':
    unittest.main()
