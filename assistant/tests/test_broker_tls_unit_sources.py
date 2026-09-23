"""Offline checks for explicit unit launch-source constraints."""
from dataclasses import asdict
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_core as core
from siem.rbac.broker_tls import operator_unit_sources as u
if __package__:
    from .test_broker_tls_service import values
else:
    from test_broker_tls_service import values


def base():
    config = values()
    config['ExecStartEx'][0][1] = [u.launch.WRAPPER]
    config['Environment'] = []
    return config


class UnitSourcesTests(unittest.TestCase):
    def observe(self, configs=None):
        with patch.object(u.service, '_check_tool') as tool, patch.object(
                u.service, '_read_configuration', side_effect=configs or [base(), base()]) as manager:
            result = u.observe_unit_sources()
            tool.assert_called_once_with()
            self.assertEqual(manager.call_count, 2)
            return result

    def test_exact_two_pass_result_is_frozen_and_non_authorizing(self):
        result = self.observe()
        self.assertEqual(asdict(result), dict(exact_wrapper_argv=True,
            explicit_unit_environment_empty=True, pam_session_disabled=True,
            exec_search_path_empty=True, passes=2, service_reads=2,
            manager_inheritance_proven=False, selected_config_source_proven=False,
            effective_environment_proven=False, startup_authorized=False))
        with self.assertRaises(AttributeError):
            result.startup_authorized = True

    def test_inactive_service_does_not_require_process(self):
        config = base()
        config.update(ActiveState='inactive', MainPID=0, ExecMainStartTimestampMonotonic=0)
        self.assertFalse(self.observe([config, config]).startup_authorized)

    def test_extra_command_argument_flag_or_second_row_fails_closed(self):
        cases = []
        altered = base(); altered['ExecStartEx'][0][1].append('--require=SECRET'); cases.append(altered)
        altered = base(); altered['ExecStartEx'][0][2] = ['privileged']; cases.append(altered)
        altered = base(); altered['ExecStartEx'][0][0] = '/PRIVATE'; cases.append(altered)
        altered = base(); altered['ExecStartEx'].append(altered['ExecStartEx'][0].copy()); cases.append(altered)
        for config in cases:
            with self.subTest(config=config['ExecStartEx']), self.assertRaisesRegex(
                    core.OperatorError, '^UNIT_SOURCE_EXEC$'):
                self.observe([config, config])

    def test_every_explicit_environment_source_rejects_without_value_leak(self):
        for key, value, code in (
                ('Environment', ['NODE_OPTIONS=SECRET'], 'UNIT_SOURCE_INLINE_ENV'),
                ('EnvironmentFiles', [['/PRIVATE/SECRET', True]], 'UNIT_SOURCE_ENV_FILE'),
                ('PassEnvironment', ['NODE_OPTIONS'], 'UNIT_SOURCE_PASS_ENV'),
                ('UnsetEnvironment', ['NODE_OPTIONS'], 'UNIT_SOURCE_UNSET_ENV')):
            config = base(); config[key] = value
            with self.subTest(key=key), self.assertRaises(core.OperatorError) as caught:
                self.observe([config, config])
            self.assertEqual(str(caught.exception), code)
            self.assertNotIn('SECRET', str(caught.exception))

    def test_pam_session_rejects_without_opening_its_configuration(self):
        config = base(); config['PAMName'] = 'SECRET'
        with self.assertRaisesRegex(core.OperatorError, '^UNIT_SOURCE_PAM$'):
            self.observe([config, config])

    def test_exec_search_path_rejects_without_echoing_path(self):
        config = base(); config['ExecSearchPath'] = ['/PRIVATE/SECRET']
        with self.assertRaises(core.OperatorError) as caught:
            self.observe([config, config])
        self.assertEqual(str(caught.exception), 'UNIT_SOURCE_SEARCH_PATH')
        self.assertNotIn('SECRET', str(caught.exception))

    def test_wrong_service_identity_or_working_directory_rejects(self):
        for key, value in (('User', 'root'), ('Group', 'root'), ('WorkingDirectory', '/PRIVATE')):
            config = base(); config[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(core.OperatorError, '^UNIT_SOURCE_IDENTITY$'):
                self.observe([config, config])

    def test_namespace_and_tool_gate_precede_second_read(self):
        with patch.object(u.service, '_check_tool', side_effect=core.OperatorError('FS_PLATFORM')), patch.object(
                u.service, '_read_configuration') as manager, self.assertRaisesRegex(
                core.OperatorError, '^FS_PLATFORM$'):
            u.observe_unit_sources()
        manager.assert_not_called()
        config = base(); config['RootImage'] = '/PRIVATE'
        with patch.object(u.service, '_check_tool'), patch.object(
                u.service, '_read_configuration', return_value=config) as manager, self.assertRaisesRegex(
                core.OperatorError, '^LAUNCH_NAMESPACE$'):
            u.observe_unit_sources()
        manager.assert_called_once_with()

    def test_private_manager_drift_rejects_without_returning_values(self):
        first = base(); second = base(); second['DropInPaths'] = ['/PRIVATE/SECRET']
        with self.assertRaises(core.OperatorError) as caught:
            self.observe([first, second])
        self.assertEqual(str(caught.exception), 'UNIT_SOURCE_CHANGED')
        self.assertNotIn('SECRET', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
