"""Offline clone-source/launch boundaries; never execute the native observer."""
import base64
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac import build_pid1_clone_packet as build


def entry():
    module = ModuleType('_test_clone_entry')
    exec(compile(build.render_packet(), '<clone-entry-test>', 'exec'), module.__dict__)
    return module


class CloneSourcePacketTests(unittest.TestCase):
    @contextmanager
    def runtime_fixture(self, m):
        """Synthetic runtime only, including file reads; never open the host image."""
        info = SimpleNamespace(st_dev=1, st_ino=2, st_mode=0o100755, st_uid=0,
                               st_gid=0, st_nlink=1, st_size=7477160,
                               st_mtime_ns=3, st_ctime_ns=4, st_atime_ns=0)
        resource = ModuleType('resource')
        resource.RLIMIT_CORE = 4
        resource.getrlimit = Mock(return_value=(0, 0))
        digest = Mock()
        digest.hexdigest.return_value = m.PYTHON_SHA256
        remaining = [info.st_size]
        def read(_, count):
            take = min(remaining[0], count)
            remaining[0] -= take
            return b'x' * take
        opened, closed = Mock(return_value=17), Mock()
        from contextlib import ExitStack
        with ExitStack() as stack:
            stack.enter_context(patch.dict(sys.modules, {'resource': resource}))
            for name, value in (('platform', 'linux'), ('version_info', (3, 14, 4)),
                                ('executable', '/usr/bin/python3.14'),
                                ('argv', [m.ENTRY, '--observe']),
                                ('flags', SimpleNamespace(isolated=1, ignore_environment=1,
                                                          no_site=1, dont_write_bytecode=1)),
                                ('pycache_prefix', m.CACHE_PREFIX),
                                ('path', ['/usr/lib/python314.zip', '/usr/lib/python3.14',
                                          '/usr/lib/python3.14/lib-dynload'])):
                stack.enter_context(patch.object(sys, name, value))
            for name, value in (('geteuid', Mock(return_value=0)),
                                ('getegid', Mock(return_value=0)),
                                ('uname', Mock(return_value=SimpleNamespace(machine='x86_64'))),
                                ('readlink', Mock(return_value='/usr/bin/python3.14')),
                                ('getcwd', Mock(return_value='/')),
                                ('open', opened), ('close', closed),
                                ('fstat', Mock(return_value=info)),
                                ('stat', Mock(return_value=info)), ('read', Mock(side_effect=read)),
                                ('O_NOFOLLOW', 131072), ('O_CLOEXEC', 524288)):
                stack.enter_context(patch.object(os, name, value, create=True))
            stack.enter_context(patch.dict(os.environ, {'HOME': '/nonexistent',
                                'LC_ALL': 'C', 'PATH': '/usr/bin:/bin'}, clear=True))
            stack.enter_context(patch.object(hashlib, 'sha256', return_value=digest))
            yield info, resource, digest, opened, closed

    def test_render_is_exact_reproducible_lf_and_checksum_pinned(self):
        raw = build.render_packet()
        self.assertEqual(raw, build.render_packet())
        self.assertTrue(raw.endswith(b'\n'))
        self.assertNotIn(b'\r', raw)
        self.assertLessEqual(len(raw), build.MAX_PACKET)
        expected = (ROOT / 'siem/rbac/PID1-CLONE-SHA256SUMS').read_text().split()
        self.assertEqual(expected, [hashlib.sha256(raw).hexdigest(), build.ARTIFACT])

    def test_fixed_sources_are_the_current_exact_eager_closure(self):
        records = build.source_records()
        self.assertEqual(tuple(row[0] for row in records), build.ORDER)
        for name, size, digest, encoded in records:
            raw = (build.BASE / 'broker_tls' / (name + '.py')).read_bytes()
            self.assertEqual(base64.b64decode(encoded), raw)
            self.assertEqual((size, digest), (len(raw), hashlib.sha256(raw).hexdigest()))

    def test_builder_rejects_eager_import_order_or_missing_source(self):
        with patch.object(build, 'ORDER', tuple(reversed(build.ORDER))):
            with self.assertRaisesRegex(ValueError, '^CLONE_PACKET_BUILD$'):
                build.source_records()
        with patch.object(build, 'ORDER', ('not_a_module',)):
            with self.assertRaises(FileNotFoundError):
                build.source_records()

    def test_builder_checks_input_lf_and_template_marker(self):
        with patch.object(Path, 'read_bytes', return_value=b'pass\r\n'):
            with self.assertRaisesRegex(ValueError, '^CLONE_PACKET_BUILD$'):
                build.source_records()
        with patch.object(Path, 'read_bytes', return_value=b'pass\n'):
            with self.assertRaisesRegex(ValueError, '^CLONE_PACKET_BUILD$'):
                build.render_packet()

    def test_eager_conditional_import_is_checked_but_unused_deferred_import_is_not(self):
        raw = b'if True:\n    from . import missing_module\n'
        with patch.object(Path, 'read_bytes', return_value=raw):
            with self.assertRaisesRegex(ValueError, '^CLONE_PACKET_BUILD$'):
                build.source_records()
        raw = b'def unused():\n    from . import missing_module\n'
        with patch.object(Path, 'read_bytes', return_value=raw):
            self.assertEqual(len(build.source_records()), 8)

    def test_verify_only_compiles_sources_without_registering_subject(self):
        m = entry()
        with patch.object(m, 'held_modules') as held, patch.object(m, 'launch_policy') as launch:
            with patch.object(sys, 'argv', ['test', '--verify-only']), patch('sys.stdout', new=io.StringIO()) as out:
                self.assertEqual(m.main(), 0)
            self.assertIn('8 modules; none executed', out.getvalue())
            held.assert_not_called()
            launch.assert_not_called()
        self.assertFalse(any(k.startswith(m.PACKAGE) for k in sys.modules))

    def test_source_tamper_fails_before_any_subject_execution(self):
        m = entry()
        rows = list(m.SOURCES)
        name, size, digest, encoded = rows[-1]
        raw = base64.b64decode(encoded).replace(b'30_000_000_000', b'31_000_000_000')
        rows[-1] = (name, size, digest, base64.b64encode(raw).decode())
        m.SOURCES = tuple(rows)
        with self.assertRaisesRegex(m.Stop, '^SOURCE_HASH$'):
            m.verified_sources()

    def test_source_order_duplicate_size_and_base64_are_rejected(self):
        m = entry()
        original = m.SOURCES
        for bad in (original[:-1], tuple(reversed(original)),
                    (original[1],) + original[1:],
                    ((original[0][0], True, original[0][2], original[0][3]),) + original[1:],
                    ((original[0][0], original[0][1], original[0][2], '!'),) + original[1:]):
            with self.subTest(bad=bad[0][:3]):
                m.SOURCES = bad
                with self.assertRaises((m.Stop, ValueError)):
                    m.verified_sources()

    def test_held_import_executes_exact_bytes_and_cleans_namespace(self):
        m = entry()
        with patch.object(subprocess, 'Popen') as popen, patch.object(os, 'open') as opened:
            with m.held_modules(m.verified_sources()) as package:
                image = package.operator_maintenance_pid1_image
                self.assertEqual(image.IMAGE_PATH, '/usr/lib/systemd/systemd')
                self.assertEqual(package.__path__, [])
                self.assertEqual(image.core, package.operator_core)
                self.assertEqual(image.census, package.operator_maintenance_processes)
                self.assertNotIn('siem.rbac.broker_tls.operator_maintenance_pid1_image',
                                 [image.__name__])
                self.assertIsNone(package.operator_core.require(True, 'unused'))
            opened.assert_not_called()
            popen.assert_not_called()
        self.assertFalse(any(k.startswith(m.PACKAGE) for k in sys.modules))

    def test_held_namespace_collision_and_execution_failure_cleanup(self):
        m = entry()
        with patch.dict(sys.modules, {m.PACKAGE + '.foreign': ModuleType('foreign')}):
            with self.assertRaisesRegex(m.Stop, '^SOURCE_NAMESPACE$'):
                with m.held_modules(m.verified_sources()):
                    self.fail('collision accepted')
        broken = ((build.ORDER[0], compile('raise RuntimeError("private")', '<test>', 'exec')),)
        with self.assertRaises(RuntimeError):
            with m.held_modules(broken):
                self.fail('exception ignored')
        self.assertFalse(any(k.startswith(m.PACKAGE) for k in sys.modules))

    def test_unused_deferred_project_import_has_no_filesystem_fallback(self):
        m = entry()
        with m.held_modules(m.verified_sources()):
            with self.assertRaises(ImportError):
                __import__(m.PACKAGE + '.operator_maintenance_namespaces', fromlist=['x'])

    def test_observe_is_blocked_before_loading_subject_on_bad_launch(self):
        m = entry()
        with patch.object(m, 'launch_policy', side_effect=m.Stop('RUNTIME_PLATFORM')):
            with patch.object(m, 'held_modules') as held:
                with patch.object(sys, 'argv', ['test', '--observe']), patch('sys.stdout', new=io.StringIO()) as out:
                    self.assertEqual(m.main(), 1)
                held.assert_not_called()
                self.assertEqual(out.getvalue(), 'STOP: RUNTIME_PLATFORM\n')

    def test_non_linux_platform_is_rejected_before_native_runtime_access(self):
        m = entry()
        with patch.object(sys, 'platform', 'win32'), patch.object(os, 'open') as opened:
            with self.assertRaisesRegex(m.Stop, '^RUNTIME_PLATFORM$'):
                m.launch_policy()
            opened.assert_not_called()

    def test_runtime_launch_accepts_only_exact_mocked_policy_and_closes_file(self):
        m = entry()
        with self.runtime_fixture(m) as (_, _, _, opened, closed):
            self.assertIsNone(m.launch_policy())
            opened.assert_called_once_with('/usr/bin/python3.14',
                                           os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            closed.assert_called_once_with(17)

    def test_runtime_bad_version_argv_cache_environment_or_core_limit_stops(self):
        m = entry()
        for attr, value, code in (('version_info', (3, 14, 5), 'RUNTIME_PLATFORM'),
                                  ('argv', ['test', '--observe'], 'RUNTIME_LAUNCH'),
                                  ('pycache_prefix', None, 'RUNTIME_LAUNCH')):
            with self.runtime_fixture(m) as (_, _, _, opened, _):
                with patch.object(sys, attr, value):
                    with self.assertRaisesRegex(m.Stop, '^' + code + '$'):
                        m.launch_policy()
                opened.assert_not_called()
        with self.runtime_fixture(m) as (_, _, _, opened, _):
            with patch.dict(os.environ, {'LD_PRELOAD': 'private'}):
                with self.assertRaisesRegex(m.Stop, '^RUNTIME_ENVIRONMENT$'):
                    m.launch_policy()
            opened.assert_not_called()
        with self.runtime_fixture(m) as (_, resource, _, opened, _):
            resource.getrlimit.return_value = (0, -1)
            with self.assertRaisesRegex(m.Stop, '^RUNTIME_CORES$'):
                m.launch_policy()
            opened.assert_not_called()

    def test_runtime_bad_metadata_or_digest_stops_and_closes_file(self):
        m = entry()
        with self.runtime_fixture(m) as (info, _, _, _, closed):
            info.st_uid = 1000
            with self.assertRaisesRegex(m.Stop, '^RUNTIME_METADATA$'):
                m.launch_policy()
            closed.assert_called_once_with(17)
        with self.runtime_fixture(m) as (_, _, digest, _, closed):
            digest.hexdigest.return_value = '0' * 64
            with self.assertRaisesRegex(m.Stop, '^RUNTIME_DIGEST$'):
                m.launch_policy()
            closed.assert_called_once_with(17)

    def test_runtime_stamp_ignores_read_atime_but_binds_content_metadata(self):
        m = entry()
        with self.runtime_fixture(m) as (info, _, _, _, _):
            original = m.stamp(info)
            info.st_atime_ns = 10
            self.assertEqual(m.stamp(info), original)
            info.st_ctime_ns += 1
            self.assertNotEqual(m.stamp(info), original)

    def test_summary_calls_only_image_observer_and_reports_no_authority(self):
        m = entry()
        with m.held_modules(m.verified_sources()) as package:
            image = package.operator_maintenance_pid1_image
            value = image.Pid1ImageInventory('00000000-0000-0000-0000-000000000001',
                                           1, m.IMAGE_SHA256, m.SYSTEMD_VERSION, 4)
            with patch.object(image, 'observe_pid1_image_inventory', return_value=value) as observe:
                with patch.object(package.operator_maintenance_state, '_query') as query:
                    result = m.observation_summary(package)
                    observe.assert_called_once_with()
                    query.assert_not_called()
            self.assertTrue(result['candidate_fields_match'])
            self.assertFalse(result['reference_approved'])
            self.assertFalse(result['runtime_authenticity_proven'])
            self.assertFalse(result['inventory']['mutation_authorized'])
            self.assertFalse(result['inventory']['startup_authorized'])

    def test_summary_rejects_candidate_drift_and_authority_upgrade(self):
        m = entry()
        with m.held_modules(m.verified_sources()) as package:
            image = package.operator_maintenance_pid1_image
            value = image.Pid1ImageInventory('00000000-0000-0000-0000-000000000001',
                                           1, '0' * 64, m.SYSTEMD_VERSION, 4)
            with patch.object(image, 'observe_pid1_image_inventory', return_value=value):
                with self.assertRaisesRegex(m.Stop, '^CANDIDATE_DRIFT$'):
                    m.observation_summary(package)
            object.__setattr__(value, 'executable_sha256', m.IMAGE_SHA256)
            object.__setattr__(value, 'startup_authorized', True)
            with patch.object(image, 'observe_pid1_image_inventory', return_value=value):
                with self.assertRaisesRegex(m.Stop, '^OBSERVER_AUTHORITY$'):
                    m.observation_summary(package)

    def test_subject_error_codes_and_unexpected_errors_are_sanitized(self):
        m = entry()
        with m.held_modules(m.verified_sources()) as package:
            image = package.operator_maintenance_pid1_image
            with patch.object(image, 'observe_pid1_image_inventory', side_effect=package.operator_core.OperatorError('PID1_IMAGE_CHANGED')):
                with self.assertRaisesRegex(m.Stop, '^PID1_IMAGE_CHANGED$'):
                    m.observation_summary(package)
            with patch.object(image, 'observe_pid1_image_inventory', side_effect=package.operator_core.OperatorError('private /path/token')):
                with self.assertRaisesRegex(m.Stop, '^OBSERVER_DIAGNOSTIC$'):
                    m.observation_summary(package)
        with patch.object(sys, 'argv', ['test', '--observe']), patch.object(m, 'launch_policy', side_effect=RuntimeError('private-secret')):
            with patch('sys.stdout', new=io.StringIO()) as out:
                self.assertEqual(m.main(), 1)
            self.assertEqual(out.getvalue(), 'STOP: CLONE_DIAGNOSTIC_FAILED\n')

    def test_modes_are_explicit_and_no_success_follows_failed_observation(self):
        m = entry()
        for args in (['test'], ['test', '--skip'], ['test', '--observe', '--force']):
            with patch.object(sys, 'argv', args), patch('sys.stdout', new=io.StringIO()) as out:
                self.assertEqual(m.main(), 1)
                self.assertEqual(out.getvalue(), 'STOP: MODE\n')
        with patch.object(sys, 'argv', ['test', '--observe']), patch.object(m, 'launch_policy'):
            with patch.object(m, 'observation_summary', side_effect=m.Stop('CANDIDATE_DRIFT')):
                with patch('sys.stdout', new=io.StringIO()) as out:
                    self.assertEqual(m.main(), 1)
            self.assertEqual(out.getvalue(), 'STOP: CANDIDATE_DRIFT\n')

    def test_host_render_and_verify_cli_are_portable_and_non_overwriting(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / build.ARTIFACT
            command = [sys.executable, '-B', str(build.BASE / 'build_pid1_clone_packet.py'),
                       '--output', str(target)]
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(json.loads(result.stdout)['observer_executed'])
            raw = target.read_bytes()
            verify = subprocess.run([sys.executable, '-I', '-S', '-B', str(target), '--verify-only'],
                                    capture_output=True, text=True, check=False)
            self.assertEqual(verify.returncode, 0, verify.stderr)
            self.assertIn('none executed', verify.stdout)
            rerender = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertNotEqual(rerender.returncode, 0)
            self.assertEqual(target.read_bytes(), raw)

    def test_runbook_shell_blocks_parse_and_root_observation_is_not_released(self):
        text = (ROOT / 'docs/runbooks/rbac-pid1-clone-source-launch.md').read_text()
        self.assertIn('Ubuntu SOC 201 - Current Isolated Clone', text)
        self.assertIn('No root observation command is released', text)
        self.assertIn('source_count=8', text)
        self.assertIn(hashlib.sha256(build.render_packet()).hexdigest(), text)
        self.assertIn(str(len(build.render_packet())), text)
        blocks = text.split('```bash\n')[1:]
        self.assertTrue(blocks)
        bash = (r'C:\Program Files\Git\bin\bash.exe' if sys.platform == 'win32'
                and Path(r'C:\Program Files\Git\bin\bash.exe').is_file()
                else shutil.which('bash') if sys.platform != 'win32' else None)
        for block in blocks:
            shell = block.split('\n```', 1)[0]
            self.assertNotIn('--observe', shell)
            self.assertIn('--verify-only', shell)
            self.assertIn('STOP: SOURCE_STAGE_FAILED', shell)
            if bash is not None:
                result = subprocess.run([bash, '-n'], input=shell, text=True,
                                        capture_output=True, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
