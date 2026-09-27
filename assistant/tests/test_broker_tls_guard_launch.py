"""Offline launch-boundary and phase-order tests; no VM or installation."""
import ast
from contextlib import contextmanager, redirect_stderr
import hashlib
from io import StringIO
from pathlib import Path
import shutil
import stat
import subprocess
import sys
from types import ModuleType, SimpleNamespace as NS
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_guard_entry as entry
from siem.rbac.broker_tls import build_guard_launch as build
from siem.rbac.broker_tls import operator_python_policy as policy
from siem.rbac.broker_tls import operator_python_import_state as imports
from siem.rbac.broker_tls import operator_python_embedded as embedded
if __package__:
    from .test_broker_tls_guard_module_table import fixture
    from .test_broker_tls_guard_entry import FakeOS
else:
    from test_broker_tls_guard_module_table import fixture
    from test_broker_tls_guard_entry import FakeOS


PYTHON = ('observe_python_path_inputs', 'observe_python_runtime',
          'observe_python_import_candidates', 'observe_python_native',
          'observe_python_path_importers', 'observe_python_import_state',
          'observe_python_embedded_modules')
BROKER = ('observe_service_configuration', 'observe_launch_files',
          'observe_unit_sources', 'observe_manager_environment',
          'observe_node_options', 'observe_direct_axios_shadow',
          'observe_declared_axios_graph', 'observe_pinned_import_sites',
          'observe_package_file_set')
ORDER = PYTHON + ('load_bootstrap', 'observe_package_runtime') + BROKER + (
    'verify_installed_bytes', 'load_bootstrap', 'observe_package_runtime') + PYTHON


def loaded_fixture(fail_at=None, mutate=None):
    """Stub I/O subjects only; execute the real composition function."""
    loaded, calls = {}, []
    first = NS(manifest=b'PRIVATE MANIFEST', certificate=b'PUBLIC CERT')
    runtime = NS(package=NS(version='4.14.7-1'))
    for name, _, _ in entry._bundle_pins(True):
        stem = name[:-3]
        real = __import__('siem.rbac.broker_tls.' + stem, fromlist=[stem])
        module = NS()
        for method in set(ORDER):
            if hasattr(real, method):
                def call(*args, _name=method, **kwargs):
                    index = len(calls)
                    calls.append((_name, args, kwargs))
                    if index == fail_at:
                        raise RuntimeError('PRIVATE ERROR')
                    if mutate:
                        mutate(index)
                    return first if _name == 'load_bootstrap' else (
                        runtime if _name == 'observe_package_runtime' else None)
                setattr(module, method, call)
        loaded[entry.HELD_PACKAGE + '.' + stem] = module
    loaded[entry.HELD_PACKAGE + '.operator_core'].NODE = '/pinned/node'
    loaded[entry.HELD_PACKAGE + '.operator_fs'].InstalledReader = Mock(return_value=object())
    return loaded, calls


class GuardLaunchTests(unittest.TestCase):
    def launch_fixture(self, failure=None, alter=None):
        events = []
        table = {'already_loaded': ModuleType('already_loaded')}
        host = NS(modules=table)
        os = NS(O_RDONLY=0, O_DIRECTORY=1, O_NOFOLLOW=2, O_CLOEXEC=4,
                open=Mock(return_value=90), close=Mock())
        sources, loaded = object(), object()
        def step(name, result=None):
            def run(*args, **kwargs):
                events.append(name)
                if failure == name:
                    raise entry.GuardLaunchError('TEST_FAILURE')
                if alter:
                    alter(name, host)
                return result
            return run
        @contextmanager
        def load(value, *, runtime):
            self.assertIs(value, sources)
            self.assertIs(runtime, True)
            step('load')()
            try:
                yield loaded
            finally:
                events.append('unload')
        return events, host, os, sources, loaded, step, load

    def invoke_launch_fixture(self, fixture):
        events, host, os, sources, loaded, step, load = fixture
        from contextlib import ExitStack
        with ExitStack() as stack:
            stack.enter_context(patch.object(entry, 'sys', host))
            stack.enter_context(patch.object(entry, 'os', os))
            for name, event, result in (
                ('_preparation_settings', 'settings', None), ('_check_entry_at', 'entry', None),
                ('_verify_bundle_at', 'bundle', sources), ('_prepare_stdlib', 'prepare', None),
                ('_observe_held', 'observe', None), ('_check_module_table', 'prepared_table', None)):
                stack.enter_context(patch.object(entry, name, side_effect=step(event, result)))
            stack.enter_context(patch.object(entry, '_loaded_verified_bundle', side_effect=load))
            return entry._observe_launch()

    def test_launch_verifies_before_preparing_loading_and_observing(self):
        f = self.launch_fixture()
        self.assertIsNone(self.invoke_launch_fixture(f))
        self.assertEqual(f[0], ['settings', 'entry', 'bundle', 'prepare', 'load',
                                'observe', 'unload', 'settings', 'prepared_table'])
        f[2].open.assert_called_once_with('/', 7)
        f[2].close.assert_called_once_with(90)

    def test_prelaunch_failures_never_execute_private_capsule(self):
        for event in ('settings', 'entry', 'bundle', 'prepare'):
            f = self.launch_fixture(failure=event)
            with self.subTest(event=event), self.assertRaisesRegex(entry.GuardLaunchError, '^TEST_FAILURE$'):
                self.invoke_launch_fixture(f)
            self.assertNotIn('load', f[0])
            self.assertNotIn('observe', f[0])
            self.assertEqual(f[2].close.call_count, int(event != 'settings'))

    def test_load_or_observer_failure_prevents_completion(self):
        for event in ('load', 'observe'):
            f = self.launch_fixture(failure=event)
            with self.subTest(event=event), self.assertRaises(entry.GuardLaunchError):
                self.invoke_launch_fixture(f)
            self.assertNotIn('prepared_table', f[0])
            self.assertEqual('unload' in f[0], event == 'observe')
            f[2].close.assert_called_once_with(90)

    def test_loading_cannot_replace_existing_module_or_table(self):
        for replace_table in (False, True):
            def alter(event, host):
                if event == 'load':
                    if replace_table:
                        host.modules = dict(host.modules)
                    else:
                        host.modules['already_loaded'] = ModuleType('replacement')
            f = self.launch_fixture(alter=alter)
            with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_PHASE_CHANGED$'):
                self.invoke_launch_fixture(f)
            self.assertNotIn('observe', f[0])
            self.assertIn('unload', f[0])

    def test_cleanup_cannot_hide_replaced_prepared_module(self):
        def alter(event, host):
            if event == 'observe':
                host.modules['already_loaded'] = ModuleType('replacement')
        f = self.launch_fixture(alter=alter)
        with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_PHASE_CHANGED$'):
            self.invoke_launch_fixture(f)
        self.assertIn('unload', f[0])

    def test_phase_state_requires_current_main_globals_and_full_table(self):
        loaded, result = object(), object()
        with patch.object(entry, '_preparation_settings') as settings, patch.object(
                entry, 'sys', NS(modules={'__main__': entry})), patch.object(
                entry, '_check_module_table') as check, patch.object(entry, '_table_capture', return_value=result) as capture:
            self.assertIs(entry._phase_state(loaded), result)
            settings.assert_called_once_with()
            check.assert_called_once_with({'__main__': entry}, held=True, loaded=loaded, runtime=True)
            capture.assert_called_once_with({'__main__': entry}, True, loaded, True)
        with patch.object(entry, '_preparation_settings'), patch.object(
                entry, 'sys', NS(modules={'__main__': ModuleType('__main__')})), self.assertRaisesRegex(
                    entry.GuardLaunchError, '^GUARD_PHASE_ENTRY$'):
            entry._phase_state(loaded)

    def test_render_is_deterministic_and_contains_fixed_preexec_pins(self):
        a = build.render_launch_candidate()
        self.assertEqual(a, build.render_launch_candidate())
        self.assertNotIn(b'\r', a)
        self.assertEqual(len(build.launch_records()), 81)
        self.assertLess(len(a), 128 * 1024)
        for path, limit, size, digest in build.launch_records():
            self.assertIn(f'{path} {limit} {size} {digest}\n'.encode(), a)
        entry_row = next(r for r in build.launch_records() if r[0] == entry.ENTRY_PATH)
        self.assertEqual(entry_row[3], hashlib.sha256(Path(entry.__file__).read_bytes()).hexdigest())

    def test_builder_rejects_stale_source_pin_before_emitting_launcher(self):
        row = entry.RUNTIME_MODULES[0]
        with patch.object(entry, 'RUNTIME_MODULES', ((row[0], row[1], '0' * 64),) + entry.RUNTIME_MODULES[1:]):
            with self.assertRaisesRegex(ValueError, '^GUARD_LAUNCH_BUILD$'):
                build.render_launch_candidate()

    def test_builder_has_no_launch_or_install_and_no_public_override(self):
        import inspect
        self.assertFalse(inspect.signature(build.render_launch_candidate).parameters)
        tree = ast.parse(Path(build.__file__).read_bytes())
        attributes = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        self.assertTrue(attributes.isdisjoint({'write_bytes', 'write_text', 'Popen', 'run', 'system', 'execve'}))
        self.assertNotIn('build_guard_launch.py', {p[0] for p in entry._bundle_pins(True)})

    def test_template_keeps_clean_exec_and_refusal_checks_before_python(self):
        text = build.render_launch_candidate().decode()
        tail = text[text.index('exec /usr/bin/env -i'):]
        self.assertEqual(tail, 'exec /usr/bin/env -i HOME=/nonexistent LC_ALL=C PATH=/usr/bin:/bin \\\n'
                         '    /usr/bin/python3.14 -I -S -B -X pycache_prefix=/dev/null/alertmind-c2 \\\n'
                         '    /usr/local/libexec/alertmind-broker-tls/guard_entry.py\n')
        for check in ('[ "$#" -eq 0 ] || fail', 'cd /', 'ulimit -c 0',
                      'exec </dev/null', 'for pass in 1 2;', 'sha256sum --check --status',
                      'check_chain "${path%/*}"', '[ ! -L "$path" ]',
                      '[ "$4" = 1 ]', '[ "$5" -le "$limit" ]', '06022'):
            self.assertIn(check, text[:text.index('exec /usr/bin/env -i')])
        self.assertNotIn('eval ', text)
        self.assertNotIn('"$@"', text)

    def test_absence_set_covers_loader_injection_and_python_alternates(self):
        paths = build.absent_paths()
        self.assertEqual(len(paths), 517)
        self.assertEqual(len(paths), len(set(paths)))
        for path in ('/etc/ld.so.preload', '/usr/lib/python314.zip',
                     '/usr/lib/x86_64-linux-gnu/glibc-hwcaps'):
            self.assertIn(path, paths)
        self.assertTrue({r[0] for r in build.launch_records()}.isdisjoint(paths))
        text = build.render_launch_candidate().decode()
        self.assertIn('[ ! -e "$1" ] && [ ! -L "$1" ] || fail', text)

    def test_loader_aliases_resolve_only_to_hashed_c3_targets(self):
        links = build.loader_links()
        self.assertEqual(len(links), 7)
        self.assertEqual(links[0], ('/lib64/ld-linux-x86-64.so.2', policy.MAPPED_FILES[2].path))
        self.assertTrue({p[1] for p in links} <= {r[0] for r in build.launch_records()})

    def test_rendered_shell_syntax_without_execution(self):
        shell = (shutil.which('dash') if sys.platform != 'win32' else
                 r'C:\Program Files\Git\usr\bin\bash.exe')
        if not shell or not Path(shell).is_file():
            self.skipTest('POSIX syntax parser unavailable')
        result = subprocess.run([shell, '-n'], input=build.render_launch_candidate(),
                                capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))

    def test_full_capsule_pins_exact_bytes_and_still_excludes_post_start(self):
        pins = entry._bundle_pins(True)
        self.assertEqual(len(pins), 21)
        self.assertEqual(len(entry.PINNED_MODULES), 13)
        self.assertEqual(len(entry.RUNTIME_MODULES), 8)
        for name, size, digest in pins:
            raw = (Path(entry.__file__).parent / name).read_bytes()
            self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (size, digest))
        self.assertFalse({'operator_process.py', 'operator_effective_launch.py'} & {p[0] for p in pins})

    def test_full_bundle_verifies_each_runtime_source_and_closes_descriptors(self):
        fs = FakeOS(runtime=True)
        with patch.object(entry, 'os', fs):
            sources = entry._verify_bundle_at(10, runtime=True)
        self.assertEqual(tuple(n for n, _ in sources), tuple(n for n, _, _ in entry._bundle_pins(True)))
        self.assertEqual(fs.close.call_count, fs.open.call_count)
        self.assertEqual(len(sources), 21)
        for name, _, _ in entry.RUNTIME_MODULES:
            for change, code in (({'st_uid': 126}, 'GUARD_PATH'),
                                 ({'st_mode': stat.S_IFLNK | 0o777}, 'GUARD_PATH'),
                                 ({'st_size': 1}, 'GUARD_BUNDLE_SIZE'),
                                 ({}, 'GUARD_BUNDLE_DIGEST')):
                fs = FakeOS(runtime=True)
                fd = fs.names[14, name]
                values = vars(fs.nodes[fd]).copy()
                values.update(change)
                fs.nodes[fd] = NS(**values)
                if not change:
                    fs.contents[fd] = b'X' + fs.contents[fd][1:]
                with self.subTest(name=name, code=code), patch.object(entry, 'os', fs):
                    with self.assertRaisesRegex(entry.GuardLaunchError, '^' + code + '$'):
                        entry._verify_bundle_at(10, runtime=True)
                self.assertEqual(fs.close.call_count, fs.open.call_count)

    def test_full_bundle_missing_or_extra_file_fails_before_any_source_read(self):
        for missing in (False, True):
            fs = FakeOS(runtime=True)
            if missing:
                del fs.names[14, entry.RUNTIME_MODULES[-1][0]]
            else:
                fs.names[14, 'unlisted.py'] = 100
            with self.subTest(missing=missing), patch.object(entry, 'os', fs):
                with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_BUNDLE_SET$'):
                    entry._verify_bundle_at(10, runtime=True)
            fs.read.assert_not_called()
            self.assertEqual(fs.close.call_count, fs.open.call_count)

    def test_full_loader_rechecks_each_runtime_digest_before_execution(self):
        sources = tuple((n, (Path(entry.__file__).parent / n).read_bytes()) for n, _, _ in entry._bundle_pins(True))
        for index in range(len(entry.PINNED_MODULES), len(sources)):
            name, raw = sources[index]
            changed = sources[:index] + ((name, b'X' + raw[1:]),) + sources[index + 1:]
            before = tuple(sys.meta_path)
            with self.subTest(name=name), self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_COMPILE_BYTES$'):
                with entry._loaded_verified_bundle(changed, runtime=True):
                    self.fail('unverified runtime source reached execution')
            self.assertEqual(tuple(sys.meta_path), before)
            self.assertTrue(entry._held_keys(True).isdisjoint(sys.modules))

    def test_full_loader_keeps_unknown_private_import_blocked_and_cleans_on_failure(self):
        sources = tuple((n, (Path(entry.__file__).parent / n).read_bytes()) for n, _, _ in entry._bundle_pins(True))
        before = tuple(sys.meta_path)
        ambient = Mock()
        ambient.find_spec = Mock(side_effect=AssertionError('AMBIENT_FALLBACK'))
        with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_LOAD$'):
            with entry._loaded_verified_bundle(sources, runtime=True):
                # Insert after the deny-finder, only after normal imports finish.
                sys.meta_path.insert(1, ambient)
                __import__(entry.HELD_PACKAGE + '.unlisted')
        ambient.find_spec.assert_not_called()
        self.assertEqual(tuple(sys.meta_path), before)
        self.assertTrue(entry._held_keys(True).isdisjoint(sys.modules))

    def test_extended_sources_add_no_new_stdlib_roots(self):
        for name, _, _ in entry.RUNTIME_MODULES:
            tree = ast.parse((Path(entry.__file__).parent / name).read_bytes())
            roots = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    roots.update(a.name.split('.')[0] for a in node.names)
                if isinstance(node, ast.ImportFrom) and not node.level:
                    roots.add(node.module.split('.')[0])
            self.assertTrue(roots <= set(entry.PREPARATION_ROOTS), (name, roots))

    def test_actual_full_loader_uses_only_held_bytes_and_cleans_namespace(self):
        sources = tuple((n, (Path(entry.__file__).parent / n).read_bytes()) for n, _, _ in entry._bundle_pins(True))
        before = tuple(sys.meta_path)
        with entry._loaded_verified_bundle(sources, runtime=True) as loaded:
            self.assertEqual(set(loaded), entry._held_keys(True))
            self.assertEqual(len(loaded), 22)
            self.assertIsInstance(sys.meta_path[0], entry._DenyHeldFallback)
            self.assertEqual(tuple(sys.meta_path[1:]), before)
        self.assertEqual(tuple(sys.meta_path), before)
        self.assertTrue(entry._held_keys(True).isdisjoint(sys.modules))

    def test_full_table_is_explicit_not_auto_detected(self):
        modules, loaded = fixture(True)
        pkg = loaded[entry.HELD_PACKAGE]
        for name, _, _ in entry.RUNTIME_MODULES:
            stem = name[:-3]
            key = entry.HELD_PACKAGE + '.' + stem
            m = ModuleType(key)
            m.__package__ = entry.HELD_PACKAGE
            m.__file__ = '<alertmind-guard>/' + name
            m.__builtins__ = vars(modules['builtins'])
            modules[key] = loaded[key] = m
            setattr(pkg, stem, m)
        self.assertEqual(len(modules), 126)
        self.assertIsNone(entry._check_module_table(modules, held=True, loaded=loaded, runtime=True))
        with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_TABLE_SET$'):
            entry._check_module_table(modules, held=True, loaded=loaded)
        for key in tuple(loaded):
            replacement = loaded.pop(key)
            with self.assertRaises(entry.GuardLaunchError):
                entry._check_module_table(modules, held=True, loaded=loaded, runtime=True)
            loaded[key] = replacement

    def test_import_observers_accept_exact_held_finder_without_removing_it(self):
        modules, _ = fixture(True)
        host = modules['sys']
        finder = host.meta_path[0]
        before = tuple(host.meta_path)
        with patch.object(imports, 'sys', host), patch.object(imports.fs, '_platform'):
            imports.observe_python_import_state(held_finder=finder)
            embedded.observe_python_embedded_modules(held_finder=finder)
            self.assertEqual(tuple(host.meta_path), before)
            for observe in (imports.observe_python_import_state, embedded.observe_python_embedded_modules):
                with self.assertRaises(imports.core.OperatorError):
                    observe()  # Prepared-default contract still rejects held state.
                for wrong in (object(), type(finder)(), True):
                    with self.assertRaises(imports.core.OperatorError):
                        observe(held_finder=wrong)

    def test_held_finder_requires_entry_class_source_and_exact_position(self):
        for damage in ('extra', 'missing', 'class', 'path', 'dict'):
            modules, _ = fixture(True)
            host = modules['sys']
            finder = host.meta_path[0]
            if damage == 'extra': host.meta_path.append(object())
            if damage == 'missing': del host.meta_path[0]
            if damage == 'class': modules['__main__']._DenyHeldFallback = object
            if damage == 'path': modules['__main__'].__file__ = '/wrong'
            if damage == 'dict': finder.extra = True
            with self.subTest(damage=damage), patch.object(imports, 'sys', host), patch.object(imports.fs, '_platform'):
                for observe in (imports.observe_python_import_state, embedded.observe_python_embedded_modules):
                    with self.assertRaises(imports.core.OperatorError):
                        observe(held_finder=finder)

    def test_sequence_brackets_broker_with_python_checks_and_returns_no_permit(self):
        loaded, calls = loaded_fixture()
        state = (object(),)
        finder = object()
        with patch.object(entry, '_phase_state', return_value=state) as phase, patch.object(entry, 'sys', NS(meta_path=[finder])):
            self.assertIsNone(entry._observe_held(loaded))
        self.assertEqual(tuple(c[0] for c in calls), ORDER)
        self.assertEqual(phase.call_count, 2 + 2 * len(ORDER))
        for name, _, kwargs in calls:
            if name in ('observe_python_import_state', 'observe_python_embedded_modules'):
                self.assertEqual(kwargs, {'held_finder': finder})

    def test_each_subject_failure_stops_without_later_calls_or_retry(self):
        for index in range(len(ORDER)):
            loaded, calls = loaded_fixture(fail_at=index)
            with self.subTest(index=index), patch.object(entry, '_phase_state', return_value=()), self.assertRaisesRegex(RuntimeError, 'PRIVATE ERROR'):
                entry._observe_held(loaded)
            self.assertEqual(tuple(c[0] for c in calls), ORDER[:index + 1])

    def test_every_phase_drift_stops_before_next_subject(self):
        for index in range(2 + 2 * len(ORDER)):
            loaded, calls = loaded_fixture()
            original = object()
            states = [(original,)] * index + [(object(),)] + [(original,)] * 100
            with self.subTest(index=index), patch.object(entry, '_phase_state', side_effect=states), self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_PHASE_CHANGED$'):
                entry._observe_held(loaded)
            self.assertEqual(tuple(c[0] for c in calls), ORDER[:index // 2])

    def test_changed_bootstrap_or_package_refuses_before_final_python_pass(self):
        for stem, method, code in (('operator_bootstrap', 'load_bootstrap', 'GUARD_PHASE_BOOTSTRAP'),
                                   ('operator_runtime', 'observe_package_runtime', 'GUARD_PHASE_PACKAGE')):
            loaded, calls = loaded_fixture()
            module = loaded[entry.HELD_PACKAGE + '.' + stem]
            original = getattr(module, method)
            count = 0
            def changed(*args):
                nonlocal count
                count += 1
                result = original(*args)
                return result if count == 1 else object()
            setattr(module, method, changed)
            with patch.object(entry, '_phase_state', return_value=()), self.assertRaisesRegex(entry.GuardLaunchError, '^' + code + '$'):
                entry._observe_held(loaded)
            self.assertEqual(sum(c[0] == PYTHON[0] for c in calls), 1)

    def test_main_never_returns_success_or_echoes_subject_exception(self):
        for error in (None, entry.GuardLaunchError('PRIVATE'), RuntimeError('PRIVATE'), SystemExit(0), KeyboardInterrupt()):
            output = StringIO()
            with patch.object(entry, '_observe_launch', side_effect=error) as observe, redirect_stderr(output):
                self.assertEqual(entry.main(), 1)
            observe.assert_called_once_with()
            self.assertIn(output.getvalue().strip(), ('GUARD_NOT_READY', 'GUARD_OBSERVATION_FAILED', 'GUARD_UNEXPECTED'))
            self.assertNotIn('PRIVATE', output.getvalue())


if __name__ == '__main__':
    unittest.main()
