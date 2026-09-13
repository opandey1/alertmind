"""Offline systemd property/transport contracts; never contact the host bus."""
from dataclasses import asdict
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_core as core
from siem.rbac.broker_tls import operator_service as s


def values():
    return dict(Id=s.UNIT, LoadState='loaded', ActiveState='active',
        FragmentPath='/usr/lib/systemd/system/wazuh-dashboard.service', DropInPaths=[],
        NeedDaemonReload=False, ExecStartEx=[[core.BASE + 'bin/opensearch-dashboards',
        ['wrapper', '--password=SECRET'], [], 0, 0, 0, 0, 0, 0, 0]],
        Environment=['SOME_SECRET=SECRET'], EnvironmentFiles=[], PassEnvironment=[],
        UnsetEnvironment=[], User='wazuh-dashboard', Group='wazuh-dashboard',
        WorkingDirectory=core.BASE.rstrip('/'), RootDirectory='', RootImage='',
        MainPID=123, ExecMainStartTimestampMonotonic=456)


def reply(group, data):
    return ('\n'.join(json.dumps({'type': sig, 'data': data[name]})
                      for name, sig in s.GROUPS[group]) + '\n').encode()


class ServiceTests(unittest.TestCase):
    def test_verified_tool_is_derived_from_executed_path(self):
        with patch.object(s, 'BUSCTL', '/usr/local/bin/busctl'), patch.object(s.fs, '_platform'), patch.object(
                s.fs, '_read_root_owned') as read:
            s._check_tool()
            read.assert_called_once_with(('usr', 'local', 'bin', 'busctl'), 16 * 1024 * 1024)
        for path in ('relative', '/usr/../bin/busctl', '/usr//bin/busctl'):
            with patch.object(s, 'BUSCTL', path), patch.object(s.fs, '_platform'), patch.object(
                    s.fs, '_read_root_owned', side_effect=core.OperatorError('FS_COMPONENTS')), self.assertRaises(core.OperatorError):
                s._check_tool()

    def test_literal_unicode_separators_are_not_record_boundaries(self):
        for char in ('\u2028', '\u2029', '\u0085'):
            data = values()
            data['Environment'] = ['X=before' + char + 'after']
            raw = reply('Service', data)
            literal = raw.replace(('\\u%04x' % ord(char)).encode(), char.encode())
            self.assertEqual(s.parse_properties(raw, 'Service'), s.parse_properties(literal, 'Service'))
        raw = reply('Unit', values())
        self.assertEqual(s.parse_properties(raw, 'Unit'), s.parse_properties(raw[:-1], 'Unit'))
        with self.assertRaisesRegex(core.OperatorError, '^SERVICE_SHAPE$'):
            s.parse_properties(raw + b'\n', 'Unit')

    def test_unknown_json_keys_and_invalid_pid_types_are_rejected(self):
        raw = reply('Unit', values()).replace(b'{', b'{"extra":true,', 1)
        with self.assertRaisesRegex(core.OperatorError, '^SERVICE_SHAPE$'):
            s.parse_properties(raw, 'Unit')
        for name, value in (('MainPID', True), ('MainPID', -1), ('MainPID', 2**32),
                            ('ExecMainStartTimestampMonotonic', 2**64)):
            data = values()
            data[name] = value
            with self.assertRaisesRegex(core.OperatorError, '^SERVICE_SHAPE$'):
                s.parse_properties(reply('Service', data), 'Service')

    def observe(self, data=None, second=None):
        data = data or values()
        replies = [reply(g, v) for v in (data, second or data) for g in s.GROUPS]
        with patch.object(s.fs, '_platform'), patch.object(s.fs, '_read_root_owned') as read, patch.object(
                s, '_query', side_effect=replies) as query:
            result = s.observe_service_configuration()
            read.assert_called_once_with(('usr', 'bin', 'busctl'), 16 * 1024 * 1024)
            self.assertEqual([c.args for c in query.call_args_list], [('Unit',), ('Service',)] * 2)
            return result

    def test_structured_properties_and_minimized_result(self):
        result = self.observe()
        self.assertEqual((result.active_state, result.configured_executable), ('active', 'dashboard_wrapper'))
        self.assertEqual((result.exec_start_count, result.environment_entries, result.passes), (1, 1, 2))
        self.assertTrue(result.service_user_matches and result.service_group_matches and result.working_directory_matches)
        self.assertTrue(result.fragment_present)
        self.assertFalse(result.runtime_override_named)
        self.assertNotIn('SECRET', repr(result))
        self.assertNotIn('wrapper', json.dumps(asdict(result)).replace('dashboard_wrapper', ''))
        self.assertEqual(set(asdict(result)), set(s.ServiceObservation.__dataclass_fields__))
        for flag in ('selected_runtime_proven', 'effective_environment_proven', 'startup_authorized'):
            self.assertIs(getattr(result, flag), False)
            with self.assertRaises(AttributeError):
                setattr(result, flag, True)

    def test_executable_class_is_exact_not_selected_runtime(self):
        for path, expected in ((core.NODE, 'packaged_node'), ('/tmp/node', 'other'),
                               (core.NODE + '.evil', 'other')):
            data = values()
            data['ExecStartEx'][0][0] = path
            self.assertEqual(self.observe(data).configured_executable, expected)
        for rows in ([], values()['ExecStartEx'] * 2):
            data = values()
            data['ExecStartEx'] = rows
            self.assertEqual(self.observe(data).configured_executable, 'other')

    def test_override_flags_counts_and_unknown_values_are_not_echoed(self):
        data = values()
        data.update(Environment=['NODE_OPTIONS=SECRET'], EnvironmentFiles=[['/SECRET', True]],
                    PassEnvironment=['SECRET'], UnsetEnvironment=['SECRET=value'],
                    User='SECRET', Group='SECRET', RootDirectory='/SECRET',
                    DropInPaths=['/SECRET'], WorkingDirectory='/SECRET')
        data['ExecStartEx'][0][2] = ['ignore-failure']
        result = self.observe(data)
        self.assertTrue(result.runtime_override_named and result.exec_flags_present and result.alternate_root_present)
        self.assertEqual((result.environment_files, result.pass_environment_entries,
                          result.unset_environment_entries, result.dropin_count), (1, 1, 1, 1))
        self.assertFalse(result.service_user_matches or result.service_group_matches or result.working_directory_matches)
        self.assertNotIn('SECRET', repr(result))

    def test_identity_reload_and_transition_fail_closed(self):
        for key, value, code in (('Id', 'other.service', 'SERVICE_IDENTITY'),
                ('LoadState', 'not-found', 'SERVICE_IDENTITY'),
                ('NeedDaemonReload', True, 'SERVICE_RELOAD_PENDING'),
                ('ActiveState', 'activating', 'SERVICE_TRANSITION')):
            data = values()
            data[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(core.OperatorError, '^' + code + '$'):
                self.observe(data)
        for state in ('failed', 'inactive'):
            data = values()
            data['ActiveState'] = state
            self.assertEqual(self.observe(data).active_state, state)

    def test_full_private_snapshot_change_not_only_summary_is_rejected(self):
        second = values()
        second['Environment'] = ['SOME_SECRET=CHANGED']
        with self.assertRaisesRegex(core.OperatorError, '^SERVICE_CHANGED$'):
            self.observe(second=second)

    def test_environment_entries_require_unique_valid_names(self):
        for entries in (['no-equals'], ['BAD-NAME=x'], ['A=1', 'A=2']):
            data = values()
            data['Environment'] = entries
            with self.subTest(entries=entries), self.assertRaisesRegex(core.OperatorError, '^SERVICE_ENVIRONMENT$'):
                self.observe(data)

    def test_native_prerequisites_fail_before_query(self):
        for target in ('_platform', '_read_root_owned'):
            with patch.object(s.fs, '_platform'), patch.object(s.fs, '_read_root_owned'), patch.object(
                    s.fs, target, side_effect=core.OperatorError('FS_METADATA')), patch.object(s, '_query') as query:
                with self.assertRaisesRegex(core.OperatorError, '^FS_METADATA$'):
                    s.observe_service_configuration()
                query.assert_not_called()
        with patch.object(s.fs, '_platform'), patch.object(s.fs, '_read_root_owned',
                side_effect=PermissionError(13, 'SECRET')), self.assertRaisesRegex(core.OperatorError, '^FS_ACCESS$'):
            s.observe_service_configuration()

    def test_json_size_duplicate_and_malformed_input(self):
        for raw in (b'', 'text', bytearray(b'{}'), b'x' * (s.MAX_REPLY + 1)):
            with self.assertRaisesRegex(core.OperatorError, '^SERVICE_SIZE$'):
                s.parse_properties(raw, 'Unit')
        valid = reply('Unit', values())
        for raw in (b'\xff\n' + valid.split(b'\n', 1)[1],
                    valid.replace(b'"type": "s"', b'"type":"s","type":"s"', 1),
                    valid.replace(b'"wazuh-dashboard.service"', b'NaN', 1)):
            with self.assertRaisesRegex(core.OperatorError, '^SERVICE_JSON$'):
                s.parse_properties(raw, 'Unit')
        for raw in (valid + b'{}\n', b'{}\n', valid.replace(b'"type": "s"', b'"type": "b"', 1)):
            with self.assertRaisesRegex(core.OperatorError, '^SERVICE_SHAPE$'):
                s.parse_properties(raw, 'Unit')

    def test_exact_property_types_and_integer_ranges(self):
        for key, bad in (('Id', 3), ('NeedDaemonReload', 1), ('DropInPaths', 'x'),
                          ('Id', 'bad\x00value'), ('Id', '\ud800')):
            data = values()
            data[key] = bad
            with self.assertRaisesRegex(core.OperatorError, '^SERVICE_SHAPE$'):
                s.parse_properties(reply('Unit', data), 'Unit')
        data = values()
        for row in ([1], ['x', [], [], 0, 0, 0, 0, True, 0, 0],
                    ['x', [], [], -1, 0, 0, 0, 0, 0, 0],
                    ['x', [], [], 0, 0, 0, 0, 2**32, 0, 0],
                    ['x', [], [], 0, 0, 0, 0, 0, 2**31, 0]):
            data['ExecStartEx'] = [row]
            with self.assertRaisesRegex(core.OperatorError, '^SERVICE_SHAPE$'):
                s.parse_properties(reply('Service', data), 'Service')
        data['ExecStartEx'] = [['x', [], [], 2**64-1, 0, 0, 0, 2**32-1, -2**31, 2**31-1]]
        self.assertEqual(s.parse_properties(reply('Service', data), 'Service')['ExecStartEx'], data['ExecStartEx'])

    def test_target_allowlist_precedes_process_creation(self):
        for group in ('Manager', '../Unit', [], None):
            with patch.object(s.subprocess, 'Popen') as popen, self.assertRaisesRegex(core.OperatorError, '^SERVICE_TARGET$'):
                s._query(group)
            popen.assert_not_called()

    def run_query(self, chunks, *, exit_code=0, select_ready=True, wait_error=None):
        self.proc = Mock()
        self.proc.stdout.fileno.return_value = 19
        self.proc.poll.return_value = exit_code
        self.proc.wait.side_effect = wait_error or [exit_code, exit_code]
        selector = Mock()
        selector.select.return_value = [(1, 1)] if select_ready else []
        with patch.object(s.subprocess, 'Popen', return_value=self.proc) as popen, patch.object(
                s.selectors, 'DefaultSelector') as factory, patch.object(s.os, 'read', side_effect=chunks), patch.object(
                s.time, 'monotonic', return_value=10):
            factory.return_value.__enter__.return_value = selector
            try:
                return s._query('Unit')
            finally:
                self.call = popen.call_args

    def test_query_is_fixed_read_only_clean_environment_and_closes(self):
        self.assertEqual(self.run_query([b'abc', b'']), b'abc')
        args, kw = self.call
        self.assertEqual(args[0][:8], [s.BUSCTL, '--system', '--json=short', '--no-pager',
            '--timeout=5', '--auto-start=no', '--allow-interactive-authorization=no', 'get-property'])
        self.assertEqual(args[0][8:11], ['org.freedesktop.systemd1', s.OBJECT, 'org.freedesktop.systemd1.Unit'])
        self.assertEqual(args[0][11:], [p for p, _ in s.GROUPS['Unit']])
        self.assertEqual(kw['env'], {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        self.assertEqual(kw['cwd'], '/')
        self.assertIs(kw['shell'], False)
        self.assertIs(kw['close_fds'], True)
        self.assertEqual(kw['stderr'], subprocess.DEVNULL)
        self.assertEqual(kw['stdin'], subprocess.DEVNULL)
        self.proc.stdout.close.assert_called_once_with()

    def test_timeout_nonzero_and_oversize_do_not_return_partial_data(self):
        for chunks, options, code in (([], {'select_ready': False}, 'SERVICE_TIMEOUT'),
                ([b''], {'exit_code': 1}, 'SERVICE_QUERY'),
                ([b'x' * (s.MAX_REPLY + 1)], {}, 'SERVICE_SIZE'),
                ([b''], {'wait_error': [subprocess.TimeoutExpired('SECRET', 5), 0]}, 'SERVICE_TIMEOUT')):
            with self.subTest(code=code), self.assertRaisesRegex(core.OperatorError, '^' + code + '$'):
                self.run_query(chunks, **options)
            self.proc.stdout.close.assert_called_once_with()

    def test_failed_start_has_static_error_without_arguments(self):
        with patch.object(s.subprocess, 'Popen', side_effect=OSError('SECRET')), self.assertRaises(
                core.OperatorError) as caught:
            s._query('Unit')
        self.assertEqual(str(caught.exception), 'SERVICE_QUERY')
        self.assertTrue(caught.exception.__suppress_context__)

    def test_running_child_is_killed_and_reaped_after_read_error(self):
        proc = Mock()
        proc.stdout.fileno.return_value = 19
        proc.poll.return_value = None
        with patch.object(s.subprocess, 'Popen', return_value=proc), patch.object(
                s.selectors, 'DefaultSelector') as selector, patch.object(s.os, 'read', side_effect=OSError('SECRET')):
            selector.return_value.__enter__.return_value.select.return_value = [(1, 1)]
            with self.assertRaisesRegex(core.OperatorError, '^SERVICE_QUERY$'):
                s._query('Unit')
        proc.kill.assert_called_once_with()
        proc.wait.assert_called_once_with(timeout=1)
        proc.stdout.close.assert_called_once_with()

    def test_expired_deadline_never_reads_and_kills_child(self):
        proc = Mock()
        proc.poll.return_value = None
        with patch.object(s.subprocess, 'Popen', return_value=proc), patch.object(
                s.selectors, 'DefaultSelector'), patch.object(s.time, 'monotonic', side_effect=[10, 16]), patch.object(
                s.os, 'read') as read, self.assertRaisesRegex(core.OperatorError, '^SERVICE_TIMEOUT$'):
            s._query('Unit')
        read.assert_not_called()
        proc.kill.assert_called_once_with()
        proc.stdout.close.assert_called_once_with()

    def test_cleanup_failure_is_not_hidden_by_partial_success(self):
        with self.assertRaisesRegex(core.OperatorError, '^SERVICE_CLEANUP$'):
            self.run_query([b'abc', b''], wait_error=[0, subprocess.TimeoutExpired('SECRET', 1)])
        self.proc.stdout.close.assert_called_once_with()


if __name__ == '__main__':
    unittest.main()
