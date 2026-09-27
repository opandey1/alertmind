"""Selected stop-effect policy and composition: no real bus, signal or service."""
from contextlib import contextmanager, ExitStack
from dataclasses import asdict, FrozenInstanceError
import errno
import inspect
from itertools import chain, repeat
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_core as core
from siem.rbac.broker_tls import operator_maintenance_effects as m
from siem.rbac.broker_tls import operator_maintenance_control as control
from siem.rbac.broker_tls import operator_maintenance_manager as manager
import test_broker_tls_maintenance_control as control_tests
import test_broker_tls_maintenance_manager as manager_tests


def values():
    result = dict(Id=m.state.UNIT, Names=[m.state.UNIT], Following='', LoadState='loaded',
        ActiveState='active', SubState='running', NeedDaemonReload=False, Job=[0, '/'],
        Transient=False, RefuseManualStop=False, ExecStopEx=[], ExecStopPostEx=[],
        ControlPID=0, KillMode='control-group', KillSignal=15, FinalKillSignal=9,
        SendSIGKILL=True, SendSIGHUP=False, TimeoutStopFailureMode='terminate')
    result.update({n: [] for n in m.EDGES})
    result.update({n: 'none' for n in m.ACTIONS})
    return result


def reply(group, data):
    return ('\n'.join(json.dumps({'type': t, 'data': data[n]})
                      for n, t in m.GROUPS[group]) + '\n').encode()


class MaintenanceEffectsTests(unittest.TestCase):
    @contextmanager
    def fixture(self, first=None, second=None):
        first = values() if first is None else first
        second = first if second is None else second
        with ExitStack() as stack:
            f = dict(checkpoint=Mock(return_value=None), clock=Mock(return_value=1_000_000_000),
                     query=Mock(side_effect=[reply(g, v) for v in (first, second) for g in m.GROUPS]))
            stack.enter_context(patch.object(m.fs, '_platform'))
            f['tool'] = stack.enter_context(patch.object(m.service, '_check_tool'))
            stack.enter_context(patch.object(m, '_clock', f['clock']))
            stack.enter_context(patch.object(m.time, 'CLOCK_BOOTTIME', 7, create=True))
            stack.enter_context(patch.object(m.time, 'clock_gettime_ns', create=True))
            stack.enter_context(patch.object(m, '_query', f['query']))
            yield f

    def assert_error(self, code, callback):
        with self.assertRaisesRegex(core.OperatorError, '^' + code + '$'):
            callback()

    def observe(self, **changes):
        with self.fixture(dict(values(), **changes)):
            return m.observe_maintenance_stop_effects()

    def test_exact_allowlisted_fields_and_interfaces(self):
        self.assertEqual(m.GROUPS['Unit'], (
            ('Id', 's'), ('Names', 'as'), ('Following', 's'), ('LoadState', 's'),
            ('ActiveState', 's'), ('SubState', 's'), ('NeedDaemonReload', 'b'),
            ('Job', '(uo)'), ('Transient', 'b'), ('RefuseManualStop', 'b'),
            ('RequiredBy', 'as'), ('RequisiteOf', 'as'), ('BoundBy', 'as'), ('ConsistsOf', 'as'),
            ('PropagatesStopTo', 'as'), ('OnFailure', 'as'), ('OnSuccess', 'as'),
            ('TriggeredBy', 'as'), ('Triggers', 'as'), ('UpheldBy', 'as'),
            ('FailureAction', 's'), ('SuccessAction', 's'), ('StartLimitAction', 's'),
            ('JobTimeoutAction', 's')))
        self.assertEqual(m.GROUPS['Service'], (
            ('ExecStopEx', 'a(sasasttttuii)'), ('ExecStopPostEx', 'a(sasasttttuii)'),
            ('ControlPID', 'u'), ('KillMode', 's'), ('KillSignal', 'i'), ('FinalKillSignal', 'i'),
            ('SendSIGKILL', 'b'), ('SendSIGHUP', 'b'), ('TimeoutStopFailureMode', 's')))

    def test_valid_observation_is_immutable_minimized_and_not_authority(self):
        result = self.observe()
        self.assertEqual(result.passes, 2)
        self.assertTrue(result.selected_hooks_empty and result.review_required)
        for key, value in asdict(result).items():
            if key.endswith(('_proven', '_authorized')):
                self.assertIs(value, False, key)
        with self.assertRaises(FrozenInstanceError):
            result.startup_authorized = True
        self.assertNotIn('wazuh-dashboard', repr(result))

    def test_two_complete_fresh_reads_and_checkpoint_bracketing(self):
        with self.fixture() as f:
            m._check('before_mask', checkpoint=f['checkpoint'])
            self.assertEqual([c.args for c in f['query'].call_args_list],
                             [('Unit',), ('Service',)] * 2)
            self.assertGreaterEqual(f['checkpoint'].call_count, 10)
            f['tool'].assert_called_once_with()

    def test_each_selected_dependency_edge_is_refused(self):
        for name in m.EDGES:
            with self.subTest(name=name):
                self.assert_error('EFFECTS_EDGES', lambda: self.observe(**{name: ['PRIVATE.service']}))

    def test_each_emergency_action_is_refused(self):
        for name in m.ACTIONS:
            for action in ('reboot', 'poweroff', 'exit', 'unknown', ''):
                with self.subTest(name=name, action=action):
                    self.assert_error('EFFECTS_ACTIONS', lambda: self.observe(**{name: action}))

    def test_stop_hooks_and_hook_arguments_are_never_executed_or_logged(self):
        row = ['/PRIVATE/program', ['PRIVATE_ARG'], [], 0, 0, 0, 0, 0, 0, 0]
        for name in ('ExecStopEx', 'ExecStopPostEx'):
            with patch.object(m.subprocess, 'Popen') as spawn:
                self.assert_error('EFFECTS_HOOKS', lambda: self.observe(**{name: [row]}))
                spawn.assert_not_called()

    def test_identity_alias_transient_and_following_are_refused(self):
        for name, bad in (('Id', 'other.service'), ('Names', []),
                          ('Names', [m.state.UNIT, 'other.service']),
                          ('Following', 'other.service'), ('Transient', True)):
            self.assert_error('EFFECTS_IDENTITY', lambda: self.observe(**{name: bad}))

    def test_unloaded_transitional_job_control_pid_and_refused_stop_fail(self):
        for changes in (dict(LoadState='not-found'), dict(LoadState='error'),
                        dict(ActiveState='activating'), dict(SubState='start-post'),
                        dict(Job=[2, '/job/2']), dict(Job=[0, '/job/2']),
                        dict(ControlPID=100), dict(RefuseManualStop=True)):
            self.assert_error('EFFECTS_STATE', lambda: self.observe(**changes))

    def test_all_stable_state_pairs_and_masked_unit_can_be_read(self):
        for load in ('loaded', 'masked'):
            for active, sub in (('active', 'running'), ('inactive', 'dead'), ('failed', 'failed')):
                self.observe(LoadState=load, ActiveState=active, SubState=sub)

    def test_reload_pending_allowed_only_between_disk_mask_and_reload(self):
        for phase in m.PHASES:
            with self.fixture(dict(values(), LoadState='masked', NeedDaemonReload=True)) as f:
                call = lambda: m._check(phase, checkpoint=f['checkpoint'])
                if phase == 'before_reload':
                    self.assertIsNone(call())
                else:
                    self.assert_error('EFFECTS_RELOAD_PENDING', call)

    def test_stop_phase_requires_masked_loaded_metadata(self):
        with self.fixture() as f:
            self.assert_error('EFFECTS_MASK_STATE', lambda: m._check('before_stop', checkpoint=f['checkpoint']))
        with self.fixture(dict(values(), LoadState='masked')) as f:
            self.assertIsNone(m._check('before_stop', checkpoint=f['checkpoint']))

    def test_each_kill_policy_override_fails(self):
        for name, bad in (('KillMode', 'process'), ('KillMode', 'mixed'), ('KillMode', 'none'),
                          ('KillSignal', 9), ('FinalKillSignal', 6), ('SendSIGKILL', False),
                          ('SendSIGHUP', True), ('TimeoutStopFailureMode', 'abort'),
                          ('TimeoutStopFailureMode', 'kill')):
            self.assert_error('EFFECTS_KILL_POLICY', lambda: self.observe(**{name: bad}))

    def test_equal_summary_does_not_hide_raw_snapshot_drift(self):
        with self.fixture(values(), dict(values(), ActiveState='inactive', SubState='dead')):
            self.assert_error('EFFECTS_CHANGED', m.observe_maintenance_stop_effects)

    def test_second_pass_policy_violation_refused(self):
        with self.fixture(values(), dict(values(), OnSuccess=['PRIVATE.service'])):
            self.assert_error('EFFECTS_EDGES', m.observe_maintenance_stop_effects)

    def test_phase_and_callback_are_not_caller_approval(self):
        with self.fixture() as f:
            for bad in (True, None, 'after_start'):
                self.assert_error('EFFECTS_PHASE', lambda: m._check(bad, checkpoint=f['checkpoint']))
            for bad in (True, None, 'approved'):
                self.assert_error('EFFECTS_CHECKPOINT', lambda: m._check('before_mask', checkpoint=bad))
            f['checkpoint'].return_value = True
            self.assert_error('EFFECTS_CHECKPOINT', lambda: m._check('before_mask', checkpoint=f['checkpoint']))
            f['query'].assert_not_called()

    def test_checkpoint_exception_sanitized_and_interrupt_preserved(self):
        with self.fixture() as f:
            f['checkpoint'].side_effect = ValueError('PRIVATE')
            self.assert_error('EFFECTS_CHECKPOINT', lambda: m._check('before_mask', checkpoint=f['checkpoint']))
            f['checkpoint'].side_effect = KeyboardInterrupt()
            with self.assertRaises(KeyboardInterrupt):
                m._check('before_mask', checkpoint=f['checkpoint'])
            f['query'].assert_not_called()

    def test_caller_pid_and_thread_drift_refused(self):
        for target, name in ((m.os, 'getpid'), (m.threading, 'get_native_id')):
            with self.fixture(), patch.object(target, name, side_effect=[100, 101]):
                self.assert_error('EFFECTS_OWNER', m.observe_maintenance_stop_effects)

    def test_timeout_backward_clock_and_late_success_refused(self):
        for now in (0, 31_000_000_000):
            with self.fixture() as f:
                f['clock'].side_effect = chain([1_000_000_000], repeat(now))
                self.assert_error('EFFECTS_TIMEOUT', m.observe_maintenance_stop_effects)
        with self.fixture() as f:
            old = iter(f['query'].side_effect)
            def query(*a, **kw):
                raw = next(old)
                if f['query'].call_count == 4:
                    f['clock'].return_value = 31_000_000_000
                return raw
            f['query'].side_effect = query
            self.assert_error('EFFECTS_TIMEOUT', m.observe_maintenance_stop_effects)

    def test_tool_and_os_failures_are_fixed_and_prevent_queries(self):
        with self.fixture() as f:
            f['tool'].side_effect = OSError(errno.EACCES, 'PRIVATE')
            self.assert_error('FS_ACCESS', m.observe_maintenance_stop_effects)
            f['query'].assert_not_called()

    def test_parser_size_framing_duplicates_and_encoding(self):
        raw = reply('Unit', values())
        self.assertEqual(m.parse_properties(raw, 'Unit'), m.parse_properties(raw[:-1], 'Unit'))
        for bad in (b'', '', bytearray(raw), b'x' * (m.MAX_REPLY + 1)):
            self.assert_error('EFFECTS_SIZE', lambda: m.parse_properties(bad, 'Unit'))
        for bad in (raw + b'\n', raw + b'{}\n', b'{}\n', raw.replace(b'{', b'{"extra":1,', 1)):
            self.assert_error('EFFECTS_SHAPE', lambda: m.parse_properties(bad, 'Unit'))
        for bad in (raw.replace(b'{', b'{"type":"s",', 1),
                    raw.replace(b'wazuh', b'\xff', 1), raw.replace(b'false', b'NaN', 1)):
            self.assert_error('EFFECTS_JSON', lambda: m.parse_properties(bad, 'Unit'))

    def test_parser_does_not_coerce_signals_booleans_jobs_or_hook_shapes(self):
        for group, name, bad in (('Service', 'KillSignal', True), ('Service', 'KillSignal', 2**31),
                ('Service', 'KillSignal', -(2**31)-1), ('Service', 'KillSignal', '15'),
                ('Service', 'SendSIGKILL', 1), ('Unit', 'Job', [True, '/']),
                ('Unit', 'Names', 'one'), ('Unit', 'Id', 'bad\x00value'),
                ('Service', 'ExecStopEx', [['not-a-full-row']])):
            raw = reply(group, dict(values(), **{name: bad}))
            self.assert_error('EFFECTS_SHAPE', lambda: m.parse_properties(raw, group))

    def test_missing_query_property_fails_without_loading_or_fallback(self):
        with self.fixture() as f:
            f['query'].side_effect = core.OperatorError('EFFECTS_QUERY')
            self.assert_error('EFFECTS_QUERY', m.observe_maintenance_stop_effects)
            self.assertEqual(f['query'].call_count, 1)

    def test_public_observer_has_no_target_override_or_approval(self):
        self.assertEqual(len(inspect.signature(m.observe_maintenance_stop_effects).parameters), 0)
        source = inspect.getsource(m)
        for forbidden in ('systemctl', 'LoadUnit', 'StopUnit', 'StartUnit', 'os.kill(',
                          'os.unlink(', 'os.symlink(', '__main__'):
            self.assertNotIn(forbidden, source)

    @contextmanager
    def transport(self, chunks, code=0, wait=None):
        proc = Mock()
        proc.stdout.fileno.return_value = 19
        proc.poll.return_value = None
        proc.wait.side_effect = [code, 0] if wait is None else wait
        selector = Mock()
        selector.select.return_value = [(1, 1)]
        with patch.object(m.subprocess, 'Popen', return_value=proc) as spawn, patch.object(
                m.selectors, 'DefaultSelector') as factory, patch.object(m.os, 'read', side_effect=chunks), patch.object(
                m, '_clock', return_value=1_000_000_000) as clock:
            factory.return_value.__enter__.return_value = selector
            yield proc, spawn, selector, clock

    def test_transport_is_fixed_bounded_read_only_closed_and_clean(self):
        for group in m.GROUPS:
            with self.transport([b'ok', b'']) as (proc, spawn, selector, clock):
                self.assertEqual(m._query(group, checkpoint=lambda: None), b'ok')
                args, kw = spawn.call_args
                self.assertEqual(args[0], ['/usr/bin/busctl', '--system', '--json=short', '--no-pager',
                    '--timeout=5', '--auto-start=no', '--allow-interactive-authorization=no', 'get-property',
                    'org.freedesktop.systemd1', m.state.OBJECT, 'org.freedesktop.systemd1.' + group,
                    *(n for n, _ in m.GROUPS[group])])
                self.assertEqual(kw, dict(stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL, shell=False, close_fds=True,
                    cwd='/', env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}))
                proc.stdout.close.assert_called_once_with()
                self.assertTrue(all(c.args[0] <= .25 for c in selector.select.call_args_list))

    def test_transport_bad_target_never_spawns(self):
        with patch.object(m.subprocess, 'Popen') as spawn:
            for group in (None, 'Manager', 'Unit;stop', True):
                self.assert_error('EFFECTS_TARGET', lambda: m._query(group, checkpoint=lambda: None))
            spawn.assert_not_called()

    def test_transport_oversize_nonzero_and_timeout_cleanup(self):
        for chunks, code, error in (([b'x' * (m.MAX_REPLY + 1)], 0, 'EFFECTS_SIZE'),
                                     ([b''], 1, 'EFFECTS_QUERY')):
            with self.transport(chunks, code) as (proc, *_):
                self.assert_error(error, lambda: m._query('Unit', checkpoint=lambda: None))
                proc.kill.assert_called_once_with()
                proc.stdout.close.assert_called_once_with()
        with self.transport([]) as (proc, spawn, selector, clock):
            selector.select.return_value = []
            clock.side_effect = [1_000_000_000, 1_000_000_000, 6_000_000_000]
            self.assert_error('EFFECTS_TIMEOUT', lambda: m._query('Unit', checkpoint=lambda: None))
            proc.kill.assert_called_once_with()

    def test_transport_spawn_read_wait_and_cleanup_errors_are_sanitized(self):
        with patch.object(m, '_clock', return_value=0), patch.object(m.subprocess, 'Popen',
                side_effect=OSError(errno.EIO, 'PRIVATE')):
            self.assert_error('EFFECTS_QUERY', lambda: m._query('Unit', checkpoint=lambda: None))
        with self.transport([OSError(errno.EIO, 'PRIVATE')]):
            self.assert_error('EFFECTS_QUERY', lambda: m._query('Unit', checkpoint=lambda: None))
        with self.transport([b''], wait=[subprocess.TimeoutExpired('PRIVATE', 5), 0]):
            self.assert_error('EFFECTS_TIMEOUT', lambda: m._query('Unit', checkpoint=lambda: None))
        with self.transport([b''], wait=[0, subprocess.TimeoutExpired('PRIVATE', 1)]) as (proc, *_):
            self.assert_error('EFFECTS_CLEANUP', lambda: m._query('Unit', checkpoint=lambda: None))
            proc.stdout.close.assert_called_once_with()

    def test_transport_revoked_checkpoint_kills_and_reaps_child(self):
        with self.transport([]) as (proc, *_):
            checkpoint = Mock(side_effect=[None, core.OperatorError('REVOKED')])
            self.assert_error('REVOKED', lambda: m._query('Unit', checkpoint=checkpoint))
            proc.kill.assert_called_once_with()
            proc.wait.assert_called_once_with(timeout=1)

    def test_transport_late_success_and_interrupt_never_escape_cleanup(self):
        with self.transport([b'']) as (proc, spawn, selector, clock):
            clock.side_effect = [1_000_000_000] * 3 + [6_000_000_000]
            self.assert_error('EFFECTS_TIMEOUT', lambda: m._query('Unit', checkpoint=lambda: None))
            proc.stdout.close.assert_called_once_with()
        with self.transport([KeyboardInterrupt()]) as (proc, *_):
            with self.assertRaises(KeyboardInterrupt):
                m._query('Unit', checkpoint=lambda: None)
            proc.kill.assert_called_once_with()
            proc.stdout.close.assert_called_once_with()

    def test_pre_mask_effects_failure_prevents_every_mutation(self):
        with control_tests.MaintenanceControlTests().fixture() as f:
            f['_check'].side_effect = core.OperatorError('EFFECTS_EDGES')
            self.assert_error('EFFECTS_EDGES', lambda: control._inhibit(boundary_checkpoint=f['boundary']))
            f['_prepare_at'].assert_not_called()
            f['_sequence'].assert_not_called()
            f['open'].assert_not_called()

    def test_effects_preflight_is_inside_all_controls_before_mask(self):
        with control_tests.MaintenanceControlTests().fixture() as f:
            def check(phase, *, checkpoint):
                self.assertEqual(phase, 'before_mask')
                self.assertEqual(f['active'], ['namespace', 'cooperative', 'package'])
                f['_prepare_at'].assert_not_called()
                checkpoint()
            f['_check'].side_effect = check
            control._inhibit(boundary_checkpoint=f['boundary'])
            f['_check'].assert_called_once()

    def test_pre_reload_failure_prevents_manager_action(self):
        with manager_tests.MaintenanceManagerTests().fixture() as f:
            f['effects'].side_effect = core.OperatorError('EFFECTS_HOOKS')
            self.assert_error('EFFECTS_HOOKS', lambda: manager._sequence(checkpoint=f['checkpoint']))
            f['action'].assert_not_called()

    def test_post_reload_effect_drift_prevents_stop_and_observers(self):
        with manager_tests.MaintenanceManagerTests().fixture() as f:
            f['effects'].side_effect = [None, core.OperatorError('EFFECTS_ACTIONS')]
            self.assert_error('EFFECTS_ACTIONS', lambda: manager._sequence(checkpoint=f['checkpoint']))
            self.assertEqual([c.args for c in f['action'].call_args_list], [('reload',)])
            f['tree'].assert_not_called()
            f['census'].assert_not_called()

    def test_three_phases_are_connected_without_a_replayable_receipt(self):
        sequence = manager._sequence
        events = []
        with manager_tests.MaintenanceManagerTests().fixture() as mf, control_tests.MaintenanceControlTests().fixture() as f:
            f['_sequence'].side_effect = sequence
            def effect(phase, *, checkpoint):
                checkpoint()
                events.append(phase)
            f['_check'].side_effect = effect
            mf['action'].side_effect = lambda action, **kw: events.append(action)
            control._inhibit(boundary_checkpoint=f['boundary'])
        self.assertEqual(events, ['before_mask', 'before_reload', 'reload', 'before_stop', 'stop'])

    def test_real_effects_collector_runs_in_private_composition_at_every_phase(self):
        sequence, check = manager._sequence, m._check
        before = values()
        pending = dict(before, NeedDaemonReload=True)
        masked = dict(before, LoadState='masked')
        replies = [reply(g, v) for v in (before, before, pending, pending, masked, masked)
                   for g in m.GROUPS]
        with manager_tests.MaintenanceManagerTests().fixture(), control_tests.MaintenanceControlTests().fixture() as f:
            f['_sequence'].side_effect = sequence
            f['_check'].side_effect = check
            with patch.object(m, '_clock', return_value=1_000_000_000), patch.object(
                    m, '_query', side_effect=replies) as query:
                result = control._inhibit(boundary_checkpoint=f['boundary'])
            self.assertEqual(query.call_count, 12)
            self.assertFalse(result.mutation_authorized or result.startup_authorized)


if __name__ == '__main__':
    unittest.main()
