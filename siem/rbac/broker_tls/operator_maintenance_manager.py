"""Private reload/stop/readback sequencing; NOT a released maintenance executor.

The public entry refuses before I/O. The private seam assumes a FUTURE trusted
controller already owns downtime, host/namespace, writer/start-path and lock
controls. A checkpoint is not authorization. No CLI or planner dispatch exists.
"""
from contextlib import ExitStack
from dataclasses import dataclass, field
import os
import subprocess
import threading
import time

from . import operator_core as core
from . import operator_fs as fs
from . import operator_maintenance_cgroup as cg
from . import operator_maintenance_processes as census
from . import operator_maintenance_state as state

SYSTEMCTL = '/usr/bin/systemctl'
MAX_SEQUENCE_NS = 180_000_000_000
ACTION_SECONDS = {'reload': 30, 'stop': 60}  # Candidate limits, not VM measurements.
POLL_SECONDS = 0.25


@dataclass(frozen=True)
class MaintenanceManagerResult:
    boot_id: str
    collection_elapsed_ms: int
    process_leaders_examined: int
    manager_reload_completed: bool = field(default=True, init=False)
    stop_request_completed: bool = field(default=True, init=False)
    masked_stopped_manager_observed: bool = field(default=True, init=False)
    unit_tree_empty_observed: bool = field(default=True, init=False)
    candidate_census_empty_observed: bool = field(default=True, init=False)
    coverage_policy: str = field(default=census.COVERAGE_POLICY, init=False)
    host_namespace_proven: bool = field(default=False, init=False)
    process_quiescence_proven: bool = field(default=False, init=False)
    exclusive_control_proven: bool = field(default=False, init=False)
    atomic_snapshot_proven: bool = field(default=False, init=False)
    reboot_persistence_tested: bool = field(default=False, init=False)
    mutation_authorized: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)
    review_required: bool = field(default=True, init=False)


def _clock():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def _boot_id():
    with ExitStack() as stack:
        root = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        stack.callback(os.close, root)
        tree = cg._Tree(root, stack)
        first = tree.read(cg.BOOT_PARTS, 37)
        core.require(tree.read(cg.BOOT_PARTS, 37) == first, 'MANAGER_BOOT')
        tree.verify()
        result = cg._boot(first[0])
    return result


def _run_action(action, *, checkpoint):
    """Fixed systemctl client, no shell/output capture; never cancel manager jobs.

    Killing a timed-out client does NOT cancel a submitted systemd transaction.
    Failure therefore leaves unknown manager state; do not retry automatically,
    remove the persistent mask, or start anything. A future controller must
    freshly reconcile state under its held controls before recovery.
    """
    core.require(type(action) is str and action in ACTION_SECONDS, 'MANAGER_ACTION')
    command = [SYSTEMCTL, '--system', '--no-ask-password', '--no-pager']
    command += (['daemon-reload'] if action == 'reload' else
                ['--job-mode=fail', 'stop', state.UNIT])
    proc = None
    try:
        checkpoint()
        # Metadata only, like the busctl reader: NOT package authenticity,
        # native dependency closure, or protection against a hostile root.
        fs._platform()
        fs._read_root_owned(('usr', 'bin', 'systemctl'), 16 * 1024 * 1024)
        checkpoint()
        started = _clock()
        deadline = started + ACTION_SECONDS[action] * 1_000_000_000
        proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, shell=False, close_fds=True,
                                cwd='/', env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        while True:
            checkpoint()
            now = _clock()
            core.require(started <= now < deadline, 'MANAGER_ACTION_TIMEOUT')
            try:
                status = proc.wait(timeout=min(POLL_SECONDS, (deadline - now) / 1_000_000_000))
            except subprocess.TimeoutExpired:
                continue
            checkpoint()
            core.require(started <= _clock() < deadline, 'MANAGER_ACTION_TIMEOUT')
            core.require(status == 0, 'MANAGER_ACTION_FAILED')
            break
    except OSError:
        raise core.OperatorError('MANAGER_ACTION_FAILED') from None
    finally:
        if proc is not None:
            try:
                if proc.poll() is None:
                    proc.kill()  # Only our systemctl child, never Dashboard/PID 1.
                proc.wait(timeout=1)
            except (OSError, subprocess.TimeoutExpired):
                raise core.OperatorError('MANAGER_ACTION_CLEANUP') from None


def _admissible_manager(value, *, masked=False, stopped=False):
    # Internal strict property-reader output only, not caller claims.
    core.require(value['Id'] == state.UNIT and value['LoadState'] in ('loaded', 'masked')
                 and value['Job'] == [0, '/'] and value['TriggeredBy'] == []
                 and (value['ActiveState'], value['SubState']) in
                     (('active', 'running'), ('inactive', 'dead'), ('failed', 'failed'))
                 and value['ControlGroup'] in ('', cg.CGROUP_NAME), 'MANAGER_STATE')
    if masked:
        core.require(value['LoadState'] == 'masked' and value['UnitFileState'] == 'masked'
                     and value['NeedDaemonReload'] is False, 'MANAGER_MASK_STATE')
    if stopped:
        cg._manager_ready(value)


def _sequence(*, checkpoint):
    """Private test/controller seam; no saved observation/result is accepted.

    Controller prerequisites are deliberately NOT inferred here. In particular,
    launching children under the existing no-fork lock contracts needs reviewed
    integration. Reload is manager-wide (including generators); stop can run
    unit hooks and propagate dependency jobs. Those effects need native review.
    The public entry stays closed until the full composition is authorized.
    """
    core.require(callable(checkpoint), 'MANAGER_CHECKPOINT')
    owner = os.getpid(), threading.get_native_id()

    def owner_check():
        core.require((os.getpid(), threading.get_native_id()) == owner, 'MANAGER_OWNER')
        try:
            answer = checkpoint()
        except Exception:
            raise core.OperatorError('MANAGER_CHECKPOINT') from None
        core.require(answer is None, 'MANAGER_CHECKPOINT')
        core.require((os.getpid(), threading.get_native_id()) == owner, 'MANAGER_OWNER')

    try:
        owner_check()
        state.service._check_tool()
        core.require(hasattr(time, 'CLOCK_BOOTTIME') and hasattr(time, 'clock_gettime_ns'),
                     'MANAGER_PLATFORM')
        started = previous = _clock()
        boot = _boot_id()
        mask = state._read_mask()
        core.require(mask[0] is True, 'MANAGER_MASK')

        def check():
            nonlocal previous
            owner_check()
            core.require(_boot_id() == boot, 'MANAGER_BOOT')
            core.require(state._read_mask() == mask, 'MANAGER_MASK_CHANGED')
            now = _clock()
            core.require(previous <= now and 0 <= now - started < MAX_SEQUENCE_NS,
                         'MANAGER_SEQUENCE_TIMEOUT')
            previous = now

        def manager(*, masked=False, stopped=False):
            check()
            first = state._read_manager()
            _admissible_manager(first, masked=masked, stopped=stopped)
            core.require(state._read_manager() == first, 'MANAGER_STATE_CHANGED')
            check()
            return first

        def observation(reader, kind):
            check()
            before = _clock() // 1_000_000
            item = reader()
            after = _clock() // 1_000_000
            check()
            core.require(type(item) is kind and item.boot_id == boot, 'MANAGER_OBSERVATION')
            core.require(type(item.captured_boottime_ms) is int
                         and type(item.collection_elapsed_ms) is int
                         and before <= item.captured_boottime_ms <= after
                         and 0 <= item.collection_elapsed_ms <= 30000
                         and item.captured_boottime_ms + item.collection_elapsed_ms <= after,
                         'MANAGER_OBSERVATION_TIME')
            return item

        manager()
        _run_action('reload', checkpoint=check)
        manager(masked=True)
        _run_action('stop', checkpoint=check)
        terminal = manager(masked=True, stopped=True)

        def empty_tree():
            item = observation(cg.observe_maintenance_cgroup, cg.MaintenanceCgroupObservation)
            core.require(item.unit_tree_empty_observed is True and item.unit_tree_populated is False
                         and item.cgroup_frozen in (None, False), 'MANAGER_CGROUP_BUSY')
            return item

        first_tree = empty_tree()
        processes = observation(census.observe_maintenance_processes, census.MaintenanceProcessObservation)
        core.require(processes.visible_pid1_alignment_observed is True
                     and type(processes.process_leaders_examined) is int
                     and processes.process_leaders_examined > 0
                     and all(type(n) is int and n == 0 for n in (
                         processes.service_identity_matches, processes.packaged_node_path_matches,
                         processes.matched_in_unit, processes.matched_outside_unit)),
                     'MANAGER_CENSUS_BUSY')
        last_tree = empty_tree()
        core.require(first_tree.unit_cgroup_present == last_tree.unit_cgroup_present,
                     'MANAGER_CGROUP_CHANGED')
        core.require(manager(masked=True, stopped=True) == terminal, 'MANAGER_STATE_CHANGED')
        check()
        return MaintenanceManagerResult(boot, (previous - started) // 1_000_000,
                                        processes.process_leaders_examined)
    except OSError as error:
        raise core.OperatorError(fs._os_error_code(error)) from None


def establish_maintenance_inhibition():
    """Unreleased: no receipt, environment flag or caller boolean enables I/O."""
    raise core.OperatorError('MANAGER_NOT_RELEASED')
