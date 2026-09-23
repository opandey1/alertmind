"""Offline manager-environment contracts; no host system bus is contacted."""
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
from siem.rbac.broker_tls import operator_manager_environment as m


def reply(entries):
    return (json.dumps({'type': 'as', 'data': entries}) + '\n').encode()


class ManagerEnvironmentTests(unittest.TestCase):
    def observe(self, first=None, second=None):
        replies = [reply([]) if first is None else first,
                   reply([]) if second is None else second]
        with patch.object(m.service, '_check_tool') as tool, patch.object(
                m.service, '_query_manager_environment', side_effect=replies) as query:
            result = m.observe_manager_environment()
            tool.assert_called_once_with()
            self.assertEqual(query.call_count, 2)
            return result

    def test_empty_export_returns_only_non_authorizing_fixed_flags(self):
        result = self.observe()
        self.assertEqual(asdict(result), dict(global_manager_environment_empty=True,
            passes=2, unit_environment_proven=False, wrapper_environment_proven=False,
            effective_environment_proven=False, startup_authorized=False))
        with self.assertRaises(AttributeError):
            result.startup_authorized = True

    def test_nonempty_export_is_rejected_without_echoing_secret_or_name(self):
        for entries in (['NODE_OPTIONS=--require=/SECRET'], ['LANG=C'], ['A=']):
            with self.subTest(entries=len(entries)), self.assertRaises(
                    core.OperatorError) as caught:
                self.observe(reply(entries), reply(entries))
            self.assertEqual(str(caught.exception), 'MANAGER_ENV_PRESENT')

    def test_private_value_drift_is_rejected_before_nonempty_policy(self):
        with self.assertRaisesRegex(core.OperatorError, '^MANAGER_ENV_CHANGED$'):
            self.observe(reply(['X=SECRET1']), reply(['X=SECRET2']))
        with self.assertRaisesRegex(core.OperatorError, '^MANAGER_ENV_CHANGED$'):
            self.observe(reply([]), reply(['X=SECRET']))

    def test_entry_names_are_unique_and_structured(self):
        for entries in (['NO_EQUALS'], ['BAD-NAME=x'], ['1START=x'],
                        ['A=1', 'A=2'], ['=value']):
            with self.subTest(entries=entries), self.assertRaisesRegex(
                    core.OperatorError, '^MANAGER_ENV_ENTRY$'):
                m._parse(reply(entries))
        self.assertEqual(m._parse(reply(['A=', '_B=one=two'])), ['A=', '_B=one=two'])

    def test_reply_signature_shape_and_control_characters_fail_closed(self):
        for raw in (b'{}\n', b'{}\n{}\n', reply([]) + b'\n',
                    b'{"type":"s","data":[]}\n',
                    b'{"type":"as","data":"X=1"}\n', reply(['X=bad\x00value']),
                    reply(['X=bad\nvalue']), reply(['X=\ud800'])):
            with self.subTest(raw=raw[:30]), self.assertRaises(core.OperatorError) as caught:
                m._parse(raw)
            self.assertIn(str(caught.exception), ('MANAGER_ENV_SHAPE', 'MANAGER_ENV_FORMAT'))

    def test_size_json_and_duplicate_keys_fail_with_static_codes(self):
        for raw in (b'', 'text', bytearray(b'{}'), b'x' * (m.service.MAX_REPLY + 1)):
            with self.assertRaisesRegex(core.OperatorError, '^MANAGER_ENV_SIZE$'):
                m._parse(raw)
        for raw in (b'\xff\n', b'{"type":"as","type":"as","data":[]}\n',
                    b'{"type":"as","data":NaN}\n'):
            with self.assertRaisesRegex(core.OperatorError, '^MANAGER_ENV_FORMAT$'):
                m._parse(raw)

    def test_tool_gate_runs_before_any_query(self):
        with (patch.object(m.service, '_check_tool', side_effect=core.OperatorError('FS_PLATFORM')),
              patch.object(m.service, '_query_manager_environment') as query,
              self.assertRaisesRegex(core.OperatorError, '^FS_PLATFORM$')):
            m.observe_manager_environment()
        query.assert_not_called()

    def test_malformed_first_reply_does_not_issue_second_query(self):
        with (patch.object(m.service, '_check_tool'), patch.object(
                m.service, '_query_manager_environment', return_value=b'{}\n') as query,
              self.assertRaisesRegex(core.OperatorError, '^MANAGER_ENV_SHAPE$')):
            m.observe_manager_environment()
        query.assert_called_once_with()

    def test_manager_query_uses_only_fixed_read_only_target_and_clean_child(self):
        proc = Mock()
        proc.stdout.fileno.return_value = 19
        proc.poll.return_value = 0
        proc.wait.side_effect = [0, 0]
        selector = Mock()
        selector.select.return_value = [(1, 1)]
        with (patch.object(m.service.subprocess, 'Popen', return_value=proc) as popen,
              patch.object(m.service.selectors, 'DefaultSelector') as factory,
              patch.object(m.service.os, 'read', side_effect=[reply([]), b'']),
              patch.object(m.service.time, 'monotonic', return_value=10)):
            factory.return_value.__enter__.return_value = selector
            self.assertEqual(m.service._query_manager_environment(), reply([]))
        command = popen.call_args.args[0]
        self.assertEqual(command, [m.service.BUSCTL, '--system', '--json=short',
            '--no-pager', '--timeout=5', '--auto-start=no',
            '--allow-interactive-authorization=no', 'get-property',
            'org.freedesktop.systemd1', m.service.MANAGER_OBJECT,
            'org.freedesktop.systemd1.Manager', 'Environment'])
        kwargs = popen.call_args.kwargs
        self.assertEqual(kwargs['env'], {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        self.assertEqual(kwargs['cwd'], '/')
        self.assertIs(kwargs['shell'], False)
        self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
        self.assertEqual(kwargs['stderr'], subprocess.DEVNULL)
        self.assertIs(kwargs['close_fds'], True)
        proc.stdout.close.assert_called_once_with()
        for target in ('Manager', 'Manager.Secret', '../Service', None, [], object()):
            with (patch.object(m.service.subprocess, 'Popen') as forbidden,
                  self.assertRaisesRegex(core.OperatorError, '^SERVICE_TARGET$')):
                m.service._run_query(target)
            forbidden.assert_not_called()


if __name__ == '__main__':
    unittest.main()
