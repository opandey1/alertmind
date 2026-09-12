"""Offline safety decisions only: no subprocesses, network, service or VM I/O."""
from dataclasses import replace
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    'broker_operator_core', ROOT / 'siem/rbac/broker_tls/operator_core.py')
o = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = o
SPEC.loader.exec_module(o)


class BrokerOperatorTests(unittest.TestCase):
    def setUp(self):
        self.production_contract = dict(o.CONTRACT)
        # Isolated miniature manifest, not vendor evidence or an installed tree.
        self.files = {
            'original.cjs': b'original', 'candidate.cjs': b'candidate',
            'node_modules/axios/index.js': b'axios',
        }
        self.contract = dict(o.CONTRACT, original_sha256=o.sha(b'original'),
                             candidate_sha256=o.sha(b'candidate'),
                             packaged_linux_node_sha256=o.sha(b'node'),
                             packaged_node_header_sha256=o.sha(b'header'))
        self.manifest = dict(self.contract)
        self.manifest['files'] = {k: {'bytes': len(v), 'sha256': o.sha(v)}
                                  for k, v in self.files.items()}
        self.repin_fixture()
        self.patcher = patch.object(o, 'CONTRACT', self.contract)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.installed = {o.CLIENT: b'candidate', o.NODE: b'node', o.HEADER: b'header',
                          o.BASE + 'node_modules/axios/index.js': b'axios'}
        self.reader = Mock(side_effect=lambda path, limit: self.installed[path])

    def repin_fixture(self):
        digest = o.sha(json.dumps(self.manifest['files'], sort_keys=True,
                                  separators=(',', ':')).encode())
        self.manifest['files_digest'] = digest
        self.contract['files_digest'] = digest

    def raw(self):
        return json.dumps(self.manifest).encode()

    def verify(self, **kwargs):
        return o.verify_installed_bytes(self.raw(), self.reader,
                package_version=kwargs.get('package_version', o.PACKAGE_VERSION),
                selected_node=kwargs.get('selected_node', o.NODE))

    def observation(self, **kwargs):
        result = o.RecoveryObservation(True, True, o.CONTRACT['candidate_sha256'],
                                       o.CONTRACT['original_sha256'], True, False)
        return replace(result, **kwargs)

    def test_pins_equal_independently_reviewed_contract(self):
        expected = json.loads((ROOT / 'siem/rbac/broker_tls/contract.json').read_text())
        self.assertEqual(self.production_contract, expected)

    def test_intact_files_require_two_passes_but_never_authorize_startup(self):
        result = self.verify()
        self.assertEqual(result, {'byte_integrity_passed': True, 'checked_files': 4,
                                 'passes': 2, 'startup_authorized': False,
                                 'live_acceptance': False})
        self.assertEqual(self.reader.call_count, 8)
        self.assertEqual(self.reader.call_args_list[:4], self.reader.call_args_list[4:])
        self.assertNotIn('original.cjs', str(self.reader.call_args_list))

    def test_package_and_runtime_mismatch_stop_before_read(self):
        for kwargs, code in [({'package_version': '4.14.8-1'}, 'PACKAGE_VERSION'),
                             ({'selected_node': o.BASE + 'node/fallback/bin/node'}, 'RUNTIME_PATH')]:
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(o.OperatorError, code):
                self.verify(**kwargs)
        self.reader.assert_not_called()

    def test_manifest_size_encoding_shape_and_duplicate_keys(self):
        for raw in (b'', b' ' * (o.MAX_MANIFEST + 1), b'\xff', b'[]',
                    b'{"files":{},"files":{}}', b'{"x":NaN}'):
            with self.subTest(raw=raw[:40]), self.assertRaises(o.OperatorError):
                o.installed_checks(raw)

    def test_unknown_contract_cannot_self_authorize(self):
        self.manifest['candidate_sha256'] = '0' * 64
        with self.assertRaisesRegex(o.OperatorError, 'MANIFEST_CONTRACT'):
            self.verify()
        self.reader.assert_not_called()

    def test_manifest_file_edits_fail_even_if_top_level_contract_is_unchanged(self):
        self.manifest['files']['candidate.cjs']['sha256'] = '0' * 64
        with self.assertRaisesRegex(o.OperatorError, 'MANIFEST_FILES_DIGEST'):
            self.verify()
        self.reader.assert_not_called()

    def test_path_safety_with_synthetic_pinned_bad_manifests(self):
        for name in ('../secret', '/etc/shadow', 'node_modules/../secret',
                     'node_modules/a\\secret', 'node_modules/a:secret',
                     'node_modules//a', 'node_modules/./a', 'node_modules/a\n'):
            with self.subTest(name=name):
                self.manifest['files'][name] = {'bytes': 1, 'sha256': o.sha(b'x')}
                self.repin_fixture()
                with self.assertRaisesRegex(o.OperatorError, 'MANIFEST_PATH'):
                    self.verify()
                del self.manifest['files'][name]
        self.reader.assert_not_called()

    def test_missing_client_and_invalid_entry_fail_closed(self):
        saved = self.manifest['files']['candidate.cjs']
        for info in ({'bytes': True, 'sha256': o.sha(b'x')},
                     {'bytes': -1, 'sha256': o.sha(b'x')},
                     {'bytes': 1, 'sha256': 'invalid'},
                     {'bytes': 1, 'sha256': o.sha(b'x'), 'extra': True}):
            self.manifest['files']['candidate.cjs'] = info
            self.repin_fixture()
            with self.assertRaises(o.OperatorError):
                self.verify()
        self.manifest['files']['candidate.cjs'] = saved
        del self.manifest['files']['original.cjs']
        self.repin_fixture()
        with self.assertRaises(o.OperatorError):
            self.verify()
        self.reader.assert_not_called()

    def test_original_client_and_each_changed_dependency_or_runtime_rejected(self):
        for path in self.installed:
            with self.subTest(path=path):
                old = self.installed[path]
                self.installed[path] = b'X' * len(old)
                with self.assertRaisesRegex(o.OperatorError, 'ARTIFACT_DIGEST'):
                    self.verify()
                self.installed[path] = old
        self.installed[o.CLIENT] = b'original'
        with self.assertRaises(o.OperatorError):
            self.verify()

    def test_second_pass_drift_detected(self):
        def read(path, limit):
            raw = self.installed[path]
            return b'X' * len(raw) if self.reader.call_count == 8 else raw
        self.reader.side_effect = read
        with self.assertRaisesRegex(o.OperatorError, 'ARTIFACT_DIGEST'):
            self.verify()

    def test_reader_failures_are_static_and_suppress_details(self):
        for exc in (FileNotFoundError('secret'), PermissionError('secret'),
                    OSError('secret'), ValueError('secret')):
            self.reader.side_effect = exc
            with self.assertRaises(o.OperatorError) as raised:
                self.verify()
            self.assertEqual(str(raised.exception), 'ARTIFACT_READ')
            self.assertTrue(raised.exception.__suppress_context__)
            self.assertIsNone(raised.exception.__cause__)

    def test_returned_reader_type_and_bounds_checked(self):
        for value in ('candidate', None, b'x' * (2 * 1024 * 1024 + 1)):
            self.reader.side_effect = None
            self.reader.return_value = value
            with self.assertRaisesRegex(o.OperatorError, 'ARTIFACT_SIZE'):
                self.verify()

    def test_recovery_requires_real_booleans_and_valid_digests(self):
        for kwargs in ({'dashboard_stopped': 1}, {'startup_inhibited': 'yes'},
                       {'client_digest': 'unexpected'}, {'backup_digest': False}):
            with self.subTest(kwargs=kwargs), self.assertRaises(o.OperatorError):
                o.recovery_step(self.observation(**kwargs))

    def test_inhibition_precedes_stop_or_byte_restoration(self):
        for state in (False, None):
            self.assertEqual(o.recovery_step(self.observation(startup_inhibited=state)),
                             'INHIBIT_STARTUP_AND_REOBSERVE')
        for state in (False, None):
            self.assertEqual(o.recovery_step(self.observation(dashboard_stopped=state)),
                             'STOP_DASHBOARD_AND_REOBSERVE')

    def test_unknown_or_missing_client_is_never_overwritten(self):
        for digest in (None, '0' * 64):
            self.assertEqual(o.recovery_step(self.observation(client_digest=digest)),
                             'HOLD_UNKNOWN_CLIENT')

    def test_backup_bytes_and_private_metadata_both_required(self):
        for kwargs in ({'backup_digest': None}, {'backup_digest': '0' * 64},
                       {'backup_metadata_verified': False}, {'backup_metadata_verified': None}):
            self.assertEqual(o.recovery_step(self.observation(**kwargs)),
                             'HOLD_UNVERIFIED_BACKUP')

    def test_candidate_restoration_requires_inhibition_and_stop(self):
        self.assertEqual(o.recovery_step(self.observation()),
                         'RESTORE_ORIGINAL_ATOMICALLY_WHILE_INHIBITED')

    def test_original_bytes_do_not_prove_restored_metadata(self):
        for restored in (False, None):
            self.assertEqual(o.recovery_step(self.observation(
                client_digest=o.CONTRACT['original_sha256'], original_metadata_restored=restored)),
                'RESTORE_ORIGINAL_METADATA_WHILE_INHIBITED')

    def test_rollback_never_authorizes_restart_or_removes_inhibitor(self):
        result = o.recovery_step(self.observation(
            client_digest=o.CONTRACT['original_sha256'], original_metadata_restored=True))
        self.assertEqual(result, 'ROLLED_BACK_KEEP_STOPPED_AND_INHIBITED')

    def test_interruption_after_every_observation_transition_is_repeatable(self):
        obs = self.observation(dashboard_stopped=False, startup_inhibited=False)
        transitions = [
            ('INHIBIT_STARTUP_AND_REOBSERVE', {'startup_inhibited': True}),
            ('STOP_DASHBOARD_AND_REOBSERVE', {'dashboard_stopped': True}),
            ('RESTORE_ORIGINAL_ATOMICALLY_WHILE_INHIBITED',
             {'client_digest': o.CONTRACT['original_sha256']}),
            ('RESTORE_ORIGINAL_METADATA_WHILE_INHIBITED', {'original_metadata_restored': True}),
        ]
        for action, change in transitions:
            with self.subTest(action=action):
                # Interruption before action changes no observation. Re-read
                # after action instead of trusting any saved transaction label.
                for _ in range(3):
                    self.assertEqual(o.recovery_step(obs), action)
                obs = replace(obs, **change)
        self.assertEqual(o.recovery_step(obs), 'ROLLED_BACK_KEEP_STOPPED_AND_INHIBITED')
        # Regression after recovery must fail closed, irrespective of old log.
        self.assertEqual(o.recovery_step(replace(obs, client_digest='0' * 64)), 'HOLD_UNKNOWN_CLIENT')


if __name__ == '__main__':
    unittest.main()
