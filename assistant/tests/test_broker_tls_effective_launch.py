"""Offline doubles for post-start Node argv/environment observation; no VM calls."""
from dataclasses import asdict
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_core as core
from siem.rbac.broker_tls import operator_effective_launch as launch
from siem.rbac.broker_tls import operator_node_options as options
from siem.rbac.broker_tls import operator_process as process
if __package__:
    from .test_broker_tls_service import values
else:
    from test_broker_tls_service import values


def nul(*fields):
    return b'\0'.join(fields) + b'\0'


def argv(*extra):
    return nul(core.NODE.encode(), *launch.PREFIX,
               options.REQUIRED.encode(), *extra, launch.ENTRYPOINT)


def environ(*extra):
    return nul(*(name + b'=' + value for name, value in launch.REQUIRED_ENV.items()), *extra)


def snapshot(*, cmdline=None, environment=None, start_time=999):
    return process._Snapshot(start_time, (1, 2),
                             argv() if cmdline is None else cmdline,
                             environ() if environment is None else environment)


class EffectiveLaunchTests(unittest.TestCase):
    def observe(self, *, snapshots=None, anchors=None, policies=None):
        policy = options.NodeOptionsObservation(1)
        with patch.object(launch.service, '_check_tool') as tool, patch.object(
                launch.fs, '_identity', return_value=(126, 128)), patch.object(
                launch.options, 'observe_node_options', side_effect=policies or [policy] * 2) as policy_read, patch.object(
                launch.process, '_anchor', side_effect=anchors or [values()] * 4) as anchor, patch.object(
                launch.process, '_native_snapshot', side_effect=snapshots or [snapshot()] * 2) as native:
            result = launch.observe_effective_launch()
            tool.assert_called_once_with()
            self.assertEqual(policy_read.call_count, 2)
            self.assertEqual(anchor.call_count, 4)
            self.assertEqual([call.args for call in native.call_args_list], [(123, (126, 128))] * 2)
            return result

    def test_stock_launch_is_observed_without_authority_or_raw_values(self):
        result = self.observe(snapshots=[snapshot(environment=environ(b'PRIVATE=SECRET'))] * 2)
        self.assertEqual((result.argument_count, result.environment_entries), (5, 5))
        self.assertTrue(result.reviewed_argv_shape_observed and result.reviewed_environment_keys_observed
                        and result.process_executable_matches_pin)
        self.assertEqual((result.process_passes, result.option_policy_passes), (2, 2))
        for name in ('actual_config_source_proven', 'external_utility_resolution_proven',
                     'complete_effective_environment_proven', 'loaded_code_proven',
                     'prestart_applicable', 'startup_authorized'):
            self.assertIs(getattr(result, name), False)
            with self.assertRaises(AttributeError):
                setattr(result, name, True)
        self.assertNotIn('SECRET', repr(result) + str(asdict(result)) + repr(snapshot(environment=environ(b'PRIVATE=SECRET'))))

    def test_optional_heap_option_may_be_in_either_reviewed_order(self):
        policy = options.NodeOptionsObservation(2)
        for args in (argv(b'--max-old-space-size=4096'),
                     nul(core.NODE.encode(), *launch.PREFIX, b'--max-old-space-size=4096',
                         options.REQUIRED.encode(), launch.ENTRYPOINT)):
            with self.subTest(args=args):
                self.assertEqual(launch._check_argv(args, policy.option_count), 6)
                self.assertEqual(self.observe(snapshots=[snapshot(cmdline=args)] * 2,
                                              policies=[policy] * 2).argument_count, 6)

    def test_extra_flags_wrong_entrypoint_and_argv_zero_fail_closed(self):
        bad = (nul(b'/bin/node', *launch.PREFIX, options.REQUIRED.encode(), launch.ENTRYPOINT),
               nul(core.NODE.encode(), b'--require=SECRET', *launch.PREFIX,
                   options.REQUIRED.encode(), launch.ENTRYPOINT),
               nul(core.NODE.encode(), *launch.PREFIX, options.REQUIRED.encode(), b'/tmp/cli'),
               nul(core.NODE.encode(), *launch.PREFIX, options.REQUIRED.encode(), launch.ENTRYPOINT, b'--extra'),
               nul(core.NODE.encode(), *launch.PREFIX, launch.ENTRYPOINT))
        for args in bad:
            with self.subTest(args=args), self.assertRaisesRegex(core.OperatorError, '^EFFECTIVE_ARGV$') as caught:
                self.observe(snapshots=[snapshot(cmdline=args)] * 2)
            self.assertNotIn('SECRET', str(caught.exception))

    def test_option_count_is_exact_and_wrong_policy_type_stops(self):
        for count in (0, True, '1', 3):
            with self.subTest(count=count), self.assertRaisesRegex(core.OperatorError, '^EFFECTIVE_POLICY$'):
                launch._check_argv(argv(), count)
        with self.assertRaisesRegex(core.OperatorError, '^EFFECTIVE_POLICY$'):
            self.observe(policies=[object()])
        with self.assertRaisesRegex(core.OperatorError, '^EFFECTIVE_ARGV$'):
            self.observe(policies=[options.NodeOptionsObservation(2)] * 2)

    def test_missing_or_changed_required_environment_rejected(self):
        for name in launch.REQUIRED_ENV:
            missing = nul(*(k + b'=' + v for k, v in launch.REQUIRED_ENV.items() if k != name))
            wrong = nul(*(k + b'=' + (b'SECRET' if k == name else v)
                          for k, v in launch.REQUIRED_ENV.items()))
            for env in (missing, wrong):
                with self.subTest(name=name, missing=env == missing), self.assertRaisesRegex(
                        core.OperatorError, '^EFFECTIVE_ENV$') as caught:
                    self.observe(snapshots=[snapshot(environment=env)] * 2)
                self.assertNotIn('SECRET', str(caught.exception))

    def test_inherited_runtime_and_loader_controls_are_rejected(self):
        for name in (b'NODE_OPTIONS', b'NODE_PATH', b'NODE_HOME', b'NODE', b'OSD_NODE_HOME',
                     b'OSD_NODE_OPTS', b'OSD_UNEXPECTED', b'LD_PRELOAD', b'LD_LIBRARY_PATH',
                     b'LD_AUDIT', b'OPENSSL_CONF', b'OPENSSL_MODULES', b'SSL_CERT_FILE',
                     b'NODE_TLS_REJECT_UNAUTHORIZED', b'NODE_EXTRA_CA_CERTS',
                     b'BASH_ENV', b'ENV', b'IFS', b'CDPATH', b'GLOBIGNORE',
                     b'SHELLOPTS', b'BASHOPTS', b'GREP_OPTIONS'):
            with self.subTest(name=name), self.assertRaisesRegex(core.OperatorError, '^EFFECTIVE_ENV$'):
                self.observe(snapshots=[snapshot(environment=environ(name + b'=SECRET'))] * 2)

    def test_malformed_environment_and_cmdline_remain_static(self):
        for attr, raw, code in (('cmdline', b'PRIVATE', 'PROCESS_CMDLINE'),
                                ('environment', b'PRIVATE=SECRET', 'PROCESS_ENVIRONMENT'),
                                ('environment', environ(b'PRIVATE=1', b'PRIVATE=2'), 'PROCESS_ENVIRONMENT')):
            kwargs = {attr: raw}
            with self.subTest(attr=attr), self.assertRaisesRegex(core.OperatorError, '^' + code + '$') as caught:
                self.observe(snapshots=[snapshot(**kwargs)] * 2)
            self.assertNotIn('SECRET', str(caught.exception))

    def test_process_anchor_or_option_policy_drift_stops(self):
        changed = values(); changed['MainPID'] = 124
        with self.assertRaisesRegex(core.OperatorError, '^PROCESS_CHANGED$'):
            self.observe(anchors=[values(), values(), values(), changed])
        with self.assertRaisesRegex(core.OperatorError, '^EFFECTIVE_CHANGED$'):
            self.observe(policies=[options.NodeOptionsObservation(1), options.NodeOptionsObservation(2)])
        with self.assertRaisesRegex(core.OperatorError, '^PROCESS_CHANGED$'):
            self.observe(snapshots=[snapshot(), snapshot(start_time=1000)])

    def test_tool_gate_precedes_all_other_reads(self):
        with patch.object(launch.service, '_check_tool', side_effect=core.OperatorError('FS_PLATFORM')), patch.object(
                launch.options, 'observe_node_options') as policy_read, patch.object(
                launch.process, '_native_snapshot') as native, self.assertRaisesRegex(
                core.OperatorError, '^FS_PLATFORM$'):
            launch.observe_effective_launch()
        policy_read.assert_not_called()
        native.assert_not_called()

    def test_operating_system_errors_do_not_disclose_values(self):
        with self.assertRaises(core.OperatorError) as caught:
            self.observe(snapshots=[OSError('SECRET')])
        self.assertEqual(str(caught.exception), 'EFFECTIVE_IO')
        self.assertTrue(caught.exception.__suppress_context__)


if __name__ == '__main__':
    unittest.main()
