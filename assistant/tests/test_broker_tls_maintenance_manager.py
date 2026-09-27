"""Offline manager sequencing: all native readers and systemctl calls are mocked."""
from contextlib import contextmanager, ExitStack
from dataclasses import asdict, FrozenInstanceError, replace
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
from siem.rbac.broker_tls import operator_maintenance_manager as m
from test_broker_tls_maintenance_state import values

BOOT = '7463f15f-0c87-4f03-94d8-c71adc722a9d'
MASK = (True, ('fresh-private-token',))


def tree(**changes):
    return replace(m.cg.MaintenanceCgroupObservation(BOOT, 1000, 0, True, False, True, False),
                   **changes)


def processes(**changes):
    return replace(m.census.MaintenanceProcessObservation(BOOT, 1000, 0, 40, 0, 0, 0, 0, True),
                   **changes)


class MaintenanceManagerTests(unittest.TestCase):
    @contextmanager
    def fixture(self):
        events = []
        readers = {
            'mask': Mock(return_value=MASK), 'manager': Mock(return_value=values()),
            'tree': Mock(side_effect=lambda: (events.append('tree'), tree())[1]),
            'census': Mock(side_effect=lambda: (events.append('census'), processes())[1]),
            'boot': Mock(return_value=BOOT), 'clock': Mock(return_value=1_000_000_000),
            'action': Mock(side_effect=lambda action, **_: events.append(action)),
            'checkpoint': Mock(return_value=None), 'events': events,
            'effects': Mock(return_value=None),
        }
        with ExitStack() as stack:
            for target, name, mock in (
                (m, '_boot_id', readers['boot']), (m, '_clock', readers['clock']),
                (m, '_run_action', readers['action']), (m.state, '_read_mask', readers['mask']),
                (m.state, '_read_manager', readers['manager']),
                (m.cg, 'observe_maintenance_cgroup', readers['tree']),
                (m.census, 'observe_maintenance_processes', readers['census']),
                (m.effects, '_check', readers['effects']),
            ):
                stack.enter_context(patch.object(target, name, mock))
            stack.enter_context(patch.object(m.state.service, '_check_tool'))
            stack.enter_context(patch.object(m.time, 'CLOCK_BOOTTIME', 7, create=True))
            stack.enter_context(patch.object(m.time, 'clock_gettime_ns', create=True))
            yield readers

    def sequence(self, f):
        return m._sequence(checkpoint=f['checkpoint'])

    def assert_error(self, code, callback):
        with self.assertRaises(core.OperatorError) as caught:
            callback()
        self.assertEqual(str(caught.exception), code)

    def test_public_entry_refuses_before_any_io_even_with_environment_claim(self):
        with (patch.dict(os.environ, {'ALERTMIND_MAINTENANCE_APPROVED': 'true'}),
              patch.object(m, '_sequence') as sequence, patch.object(m.os, 'open') as opened,
              patch.object(m.subprocess, 'Popen') as spawned):
            self.assert_error('MANAGER_NOT_RELEASED', m.establish_maintenance_inhibition)
        sequence.assert_not_called()
        opened.assert_not_called()
        spawned.assert_not_called()

    def test_noncallable_checkpoint_refused_before_readers(self):
        with self.fixture() as f:
            for invalid in (None, True, 'approved'):
                self.assert_error('MANAGER_CHECKPOINT', lambda: m._sequence(checkpoint=invalid))
            f['boot'].assert_not_called()
            f['action'].assert_not_called()

    def test_checkpoint_true_is_not_authorization(self):
        with self.fixture() as f:
            f['checkpoint'].return_value = True
            self.assert_error('MANAGER_CHECKPOINT', lambda: self.sequence(f))
            f['action'].assert_not_called()

    def test_checkpoint_exception_is_sanitized(self):
        with self.fixture() as f:
            f['checkpoint'].side_effect = RuntimeError('PRIVATE checkpoint data')
            self.assert_error('MANAGER_CHECKPOINT', lambda: self.sequence(f))
            f['mask'].assert_not_called()

    def test_owner_pid_or_thread_change_refused(self):
        for target, attribute in ((m.os, 'getpid'), (m.threading, 'get_native_id')):
            with self.subTest(attribute=attribute), self.fixture() as f:
                with patch.object(target, attribute, side_effect=[100, 100, 101]):
                    self.assert_error('MANAGER_OWNER', lambda: self.sequence(f))
                f['action'].assert_not_called()

    def test_order_is_reload_mask_readback_stop_tree_census_tree(self):
        with self.fixture() as f:
            def action(name, **kwargs):
                self.assertEqual(set(kwargs), {'checkpoint'})
                self.assertGreaterEqual(f['manager'].call_count, 2 if name == 'reload' else 4)
                kwargs['checkpoint']()
                f['events'].append(name)
            f['action'].side_effect = action
            result = self.sequence(f)
            self.assertEqual(f['events'], ['reload', 'stop', 'tree', 'census', 'tree'])
            self.assertEqual(f['manager'].call_count, 8)
            self.assertEqual(result.process_leaders_examined, 40)
            self.assertEqual(result.boot_id, BOOT)

    def test_result_is_immutable_minimized_and_never_authorizes(self):
        with self.fixture() as f:
            result = self.sequence(f)
        for name, value in asdict(result).items():
            if name.endswith(('_proven', '_authorized', '_tested')):
                self.assertIs(value, False, name)
        self.assertTrue(result.review_required)
        self.assertEqual(result.coverage_policy, 'leader-credential-or-packaged-node-v1')
        self.assertNotIn('fresh-private-token', repr(result))
        with self.assertRaises(FrozenInstanceError):
            result.startup_authorized = True

    def test_active_running_is_stopped_only_after_effective_mask(self):
        initial = dict(values(), LoadState='loaded', NeedDaemonReload=True,
                       ActiveState='active', SubState='running', MainPID=123)
        masked = dict(initial, LoadState='masked', NeedDaemonReload=False)
        with self.fixture() as f:
            f['manager'].side_effect = [initial] * 2 + [masked] * 2 + [values()] * 4
            self.sequence(f)
            self.assertEqual(f['events'][:2], ['reload', 'stop'])

    def test_missing_mask_never_reloads(self):
        with self.fixture() as f:
            f['mask'].return_value = (False, ())
            self.assert_error('MANAGER_MASK', lambda: self.sequence(f))
            f['action'].assert_not_called()

    def test_replaced_mask_after_reload_never_stops(self):
        with self.fixture() as f:
            def action(*_, **__):
                f['mask'].return_value = (True, ('replaced',))
            f['action'].side_effect = action
            self.assert_error('MANAGER_MASK_CHANGED', lambda: self.sequence(f))
            self.assertEqual(f['action'].call_count, 1)

    def test_boot_change_refused_without_second_action(self):
        with self.fixture() as f:
            f['action'].side_effect = lambda *a, **k: setattr(f['boot'], 'return_value', 'new-boot')
            self.assert_error('MANAGER_BOOT', lambda: self.sequence(f))
            self.assertEqual(f['action'].call_count, 1)

    def test_suspend_budget_and_backwards_clock_fail_closed(self):
        for now in (0, 1_000_000_000 + m.MAX_SEQUENCE_NS):
            with self.subTest(now=now), self.fixture() as f:
                f['clock'].side_effect = [1_000_000_000, now]
                self.assert_error('MANAGER_SEQUENCE_TIMEOUT', lambda: self.sequence(f))
                f['action'].assert_not_called()

    def test_manager_jobs_triggers_transitions_or_wrong_group_stop_before_reload(self):
        bad = [dict(Job=[1, '/job/1']), dict(Job=[0, '/job/1']),
               dict(TriggeredBy=['other.socket']), dict(ActiveState='activating'),
               dict(ControlGroup='/other.slice'), dict(Id='other.service'), dict(LoadState='not-found')]
        for changes in bad:
            with self.subTest(changes=changes), self.fixture() as f:
                f['manager'].return_value = dict(values(), **changes)
                self.assert_error('MANAGER_STATE', lambda: self.sequence(f))
                f['action'].assert_not_called()

    def test_manager_snapshot_race_refused(self):
        with self.fixture() as f:
            f['manager'].side_effect = [values(), dict(values(), MainPID=99)]
            self.assert_error('MANAGER_STATE_CHANGED', lambda: self.sequence(f))
            f['action'].assert_not_called()

    def test_successful_reload_exit_does_not_substitute_for_effective_mask(self):
        for changes in (dict(LoadState='loaded'), dict(UnitFileState='masked-runtime'),
                        dict(NeedDaemonReload=True)):
            with self.subTest(changes=changes), self.fixture() as f:
                f['manager'].side_effect = [values()] * 2 + [dict(values(), **changes)] * 2 + [values()] * 4
                self.assert_error('MANAGER_MASK_STATE', lambda: self.sequence(f))
                self.assertEqual(f['action'].call_count, 1)

    def test_reload_failure_never_stops_or_observes_census(self):
        with self.fixture() as f:
            f['action'].side_effect = core.OperatorError('MANAGER_ACTION_FAILED')
            self.assert_error('MANAGER_ACTION_FAILED', lambda: self.sequence(f))
            self.assertEqual(f['action'].call_count, 1)
            f['census'].assert_not_called()

    def test_stop_failure_never_accepts_even_an_inactive_manager(self):
        with self.fixture() as f:
            f['action'].side_effect = [None, core.OperatorError('MANAGER_ACTION_TIMEOUT')]
            self.assert_error('MANAGER_ACTION_TIMEOUT', lambda: self.sequence(f))
            self.assertEqual(f['action'].call_count, 2)
            f['tree'].assert_not_called()

    def test_stop_exit_zero_with_residual_pid_or_active_state_rejected(self):
        for changes in (dict(MainPID=3), dict(ControlPID=3),
                        dict(ActiveState='active', SubState='running')):
            with self.subTest(changes=changes), self.fixture() as f:
                f['manager'].side_effect = [values()] * 4 + [dict(values(), **changes)]
                self.assert_error('CGROUP_MANAGER_STATE', lambda: self.sequence(f))
                f['tree'].assert_not_called()

    def test_unavailable_masked_service_properties_fail_without_load_or_unmask(self):
        with self.fixture() as f:
            f['manager'].side_effect = [values()] * 2 + [core.OperatorError('MAINTENANCE_QUERY')]
            self.assert_error('MAINTENANCE_QUERY', lambda: self.sequence(f))
            self.assertEqual([c.args[0] for c in f['action'].call_args_list], ['reload'])

    def test_absent_or_failed_stopped_unit_is_accepted_only_with_empty_observers(self):
        with self.fixture() as f:
            f['manager'].return_value = dict(values(), ActiveState='failed', SubState='failed')
            f['tree'].side_effect = None
            f['tree'].return_value = tree(unit_cgroup_present=False, cgroup_frozen=None)
            self.sequence(f)
            self.assertEqual(f['tree'].call_count, 2)

    def test_nonempty_or_frozen_tree_never_runs_census(self):
        for changes in (dict(unit_tree_populated=True), dict(unit_tree_empty_observed=False),
                        dict(cgroup_frozen=True)):
            with self.subTest(changes=changes), self.fixture() as f:
                f['tree'].side_effect = None
                f['tree'].return_value = tree(**changes)
                self.assert_error('MANAGER_CGROUP_BUSY', lambda: self.sequence(f))
                f['census'].assert_not_called()

    def test_tree_repopulated_after_census_rejected(self):
        with self.fixture() as f:
            f['tree'].side_effect = [tree(), tree(unit_tree_populated=True)]
            self.assert_error('MANAGER_CGROUP_BUSY', lambda: self.sequence(f))

    def test_tree_presence_change_refused(self):
        with self.fixture() as f:
            f['tree'].side_effect = [tree(), tree(unit_cgroup_present=False, cgroup_frozen=None)]
            self.assert_error('MANAGER_CGROUP_CHANGED', lambda: self.sequence(f))

    def test_all_census_match_classes_and_missing_alignment_fail_closed(self):
        bad = [dict(service_identity_matches=1), dict(packaged_node_path_matches=1),
               dict(matched_in_unit=1), dict(matched_outside_unit=1),
               dict(visible_pid1_alignment_observed=False), dict(process_leaders_examined=0),
               dict(matched_outside_unit=False)]
        for changes in bad:
            with self.subTest(changes=changes), self.fixture() as f:
                f['census'].side_effect = None
                f['census'].return_value = processes(**changes)
                self.assert_error('MANAGER_CENSUS_BUSY', lambda: self.sequence(f))
                self.assertEqual(f['tree'].call_count, 1)

    def test_wrong_observation_type_or_boot_rejected(self):
        for item in (asdict(tree()), tree(boot_id='different')):
            with self.subTest(item=item), self.fixture() as f:
                f['tree'].side_effect = None
                f['tree'].return_value = item
                self.assert_error('MANAGER_OBSERVATION', lambda: self.sequence(f))

    def test_stale_future_overlong_and_malformed_observation_timing_rejected(self):
        changes = [dict(captured_boottime_ms=999), dict(captured_boottime_ms=1001),
                   dict(collection_elapsed_ms=-1), dict(collection_elapsed_ms=30001),
                   dict(collection_elapsed_ms=1), dict(captured_boottime_ms=True)]
        for change in changes:
            with self.subTest(change=change), self.fixture() as f:
                f['tree'].side_effect = None
                f['tree'].return_value = tree(**change)
                self.assert_error('MANAGER_OBSERVATION_TIME', lambda: self.sequence(f))

    def test_census_result_is_freshly_checked_too(self):
        with self.fixture() as f:
            f['census'].side_effect = None
            f['census'].return_value = processes(captured_boottime_ms=0)
            self.assert_error('MANAGER_OBSERVATION_TIME', lambda: self.sequence(f))

    def test_final_manager_change_refused(self):
        with self.fixture() as f:
            f['manager'].side_effect = [values()] * 6 + [dict(values(), ControlGroup=m.cg.CGROUP_NAME)] * 2
            self.assert_error('MANAGER_STATE_CHANGED', lambda: self.sequence(f))

    def test_final_checkpoint_revocation_refused(self):
        with self.fixture() as f:
            def check():
                if f['manager'].call_count == 8:
                    raise ValueError('PRIVATE revocation')
            f['checkpoint'].side_effect = check
            self.assert_error('MANAGER_CHECKPOINT', lambda: self.sequence(f))

    def test_census_error_aborts_without_retry_or_recovery_action(self):
        with self.fixture() as f:
            f['census'].side_effect = core.OperatorError('CENSUS_CHANGED')
            self.assert_error('CENSUS_CHANGED', lambda: self.sequence(f))
            self.assertEqual([c.args[0] for c in f['action'].call_args_list], ['reload', 'stop'])
            self.assertEqual(f['census'].call_count, 1)

    def test_native_read_error_does_not_leak_path(self):
        with self.fixture() as f:
            f['boot'].side_effect = PermissionError('PRIVATE path')
            with self.assertRaises(core.OperatorError) as caught:
                self.sequence(f)
            self.assertNotIn('PRIVATE', str(caught.exception))
            f['action'].assert_not_called()

    @contextmanager
    def child(self):
        proc = Mock()
        proc.wait.return_value = 0
        proc.poll.return_value = 0
        with (patch.object(m.subprocess, 'Popen', return_value=proc) as spawn,
              patch.object(m, '_clock', return_value=0) as clock,
              patch.object(m.fs, '_platform'), patch.object(m.fs, '_read_root_owned') as tool):
            yield proc, spawn, clock, tool

    def test_actions_use_only_fixed_allowlisted_argv_and_closed_fds(self):
        for action, tail in (('reload', ['daemon-reload']),
                             ('stop', ['--job-mode=fail', 'stop', m.state.UNIT])):
            with self.subTest(action=action), self.child() as (proc, spawn, _, tool):
                check = Mock(return_value=None)
                m._run_action(action, checkpoint=check)
                spawn.assert_called_once_with(
                    ['/usr/bin/systemctl', '--system', '--no-ask-password', '--no-pager'] + tail,
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    shell=False, close_fds=True, cwd='/', env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
                tool.assert_called_once_with(('usr', 'bin', 'systemctl'), 16 * 1024 * 1024)
                self.assertGreaterEqual(check.call_count, 4)
                proc.kill.assert_not_called()
                self.assertEqual(proc.wait.call_args.kwargs, {'timeout': 1})

    def test_unknown_actions_never_spawn(self):
        with self.child() as (_, spawn, _, _):
            for action in ('start', 'restart', 'unmask', 'cancel', 'kill', 'stop other.service', None, True):
                self.assert_error('MANAGER_ACTION', lambda: m._run_action(action, checkpoint=lambda: None))
            spawn.assert_not_called()

    def test_tool_check_failure_prevents_spawn(self):
        with self.child() as (_, spawn, _, tool):
            tool.side_effect = PermissionError('PRIVATE tool path')
            self.assert_error('MANAGER_ACTION_FAILED', lambda: m._run_action('reload', checkpoint=lambda: None))
            spawn.assert_not_called()

    def test_client_nonzero_exit_is_not_accepted(self):
        with self.child() as (proc, spawn, _, _):
            proc.wait.return_value = 1
            self.assert_error('MANAGER_ACTION_FAILED', lambda: m._run_action('stop', checkpoint=lambda: None))
            self.assertEqual(spawn.call_count, 1)

    def test_spawn_failure_is_sanitized_without_cleanup_of_an_unknown_child(self):
        with self.child() as (proc, spawn, _, _):
            spawn.side_effect = OSError('PRIVATE executable detail')
            self.assert_error('MANAGER_ACTION_FAILED', lambda: m._run_action('stop', checkpoint=lambda: None))
            proc.kill.assert_not_called()
            proc.wait.assert_not_called()

    def test_checkpoint_revocation_after_child_success_still_fails(self):
        with self.child() as (proc, spawn, _, _):
            check = Mock(side_effect=[None, None, None, core.OperatorError('MANAGER_CHECKPOINT')])
            self.assert_error('MANAGER_CHECKPOINT', lambda: m._run_action('stop', checkpoint=check))
            self.assertEqual(spawn.call_count, 1)
            self.assertEqual(proc.wait.call_count, 2)  # wait and cleanup, no second action

    def test_bounded_wait_rechecks_and_does_not_resubmit(self):
        with self.child() as (proc, spawn, _, _):
            proc.wait.side_effect = [subprocess.TimeoutExpired('PRIVATE', .25), 0, 0]
            check = Mock(return_value=None)
            m._run_action('stop', checkpoint=check)
            self.assertEqual(spawn.call_count, 1)
            self.assertEqual(proc.wait.call_count, 3)
            self.assertGreaterEqual(check.call_count, 5)

    def test_action_deadlines_kill_reap_client_without_undo_or_retry(self):
        for action, seconds in (('reload', 30), ('stop', 60)):
            with self.subTest(action=action), self.child() as (proc, spawn, clock, _):
                proc.wait.side_effect = [subprocess.TimeoutExpired('PRIVATE', .25), 0]
                proc.poll.return_value = None
                clock.side_effect = [0, 0, seconds * 1_000_000_000]
                self.assert_error('MANAGER_ACTION_TIMEOUT', lambda: m._run_action(action, checkpoint=lambda: None))
                proc.kill.assert_called_once_with()
                self.assertEqual(spawn.call_count, 1)
                self.assertEqual(proc.wait.call_args.kwargs, {'timeout': 1})

    def test_late_success_is_timeout_not_success(self):
        with self.child() as (_, _, clock, _):
            clock.side_effect = [0, 0, 60_000_000_000]
            self.assert_error('MANAGER_ACTION_TIMEOUT', lambda: m._run_action('stop', checkpoint=lambda: None))

    def test_keyboard_interrupt_kills_client_but_is_not_swallowed(self):
        with self.child() as (proc, spawn, _, _):
            proc.poll.return_value = None
            check = Mock(side_effect=[None, None, KeyboardInterrupt()])
            with self.assertRaises(KeyboardInterrupt):
                m._run_action('reload', checkpoint=check)
            proc.kill.assert_called_once_with()
            self.assertEqual(spawn.call_count, 1)

    def test_cleanup_failure_blocks_success(self):
        with self.child() as (proc, _, _, _):
            proc.wait.side_effect = [0, subprocess.TimeoutExpired('PRIVATE', 1)]
            self.assert_error('MANAGER_ACTION_CLEANUP', lambda: m._run_action('reload', checkpoint=lambda: None))

    def test_boot_reader_fixed_path_equal_passes_and_close(self):
        mock_tree = Mock()
        mock_tree.read.return_value = (BOOT.encode() + b'\n', ('stamp',))
        with (patch.object(m.os, 'open', return_value=10) as opened,
              patch.object(m.os, 'close') as closed,
              patch.object(m.os, 'O_DIRECTORY', 1, create=True),
              patch.object(m.os, 'O_NOFOLLOW', 2, create=True),
              patch.object(m.os, 'O_CLOEXEC', 4, create=True),
              patch.object(m.cg, '_Tree', return_value=mock_tree)):
            self.assertEqual(m._boot_id(), BOOT)
        self.assertEqual(opened.call_args.args[0], '/')
        self.assertEqual(mock_tree.read.call_count, 2)
        mock_tree.read.assert_called_with(m.cg.BOOT_PARTS, 37)
        mock_tree.verify.assert_called_once_with()
        closed.assert_called_once_with(10)

    def test_boot_reader_change_refused_and_descriptor_closed(self):
        mock_tree = Mock()
        mock_tree.read.side_effect = [(BOOT.encode() + b'\n', (1,)), (b'changed', (2,))]
        with (patch.object(m.os, 'open', return_value=10), patch.object(m.os, 'close') as closed,
              patch.object(m.os, 'O_DIRECTORY', 1, create=True),
              patch.object(m.os, 'O_NOFOLLOW', 2, create=True),
              patch.object(m.os, 'O_CLOEXEC', 4, create=True),
              patch.object(m.cg, '_Tree', return_value=mock_tree)):
            self.assert_error('MANAGER_BOOT', m._boot_id)
        closed.assert_called_once_with(10)


if __name__ == '__main__':
    unittest.main()
