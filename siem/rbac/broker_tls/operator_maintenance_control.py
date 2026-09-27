"""Private held-control composition, NOT owner/host approval or a live executor.

The public entry refuses before I/O. This composes existing primitives, not a
security sandbox: intended-host/runtime trust, downtime approval and continuous
noncooperating writer/start-path control must come from a future trusted launch.
"""
from contextlib import contextmanager, ExitStack
from dataclasses import dataclass, field
import os
import threading
import time

from . import operator_core as core
from . import operator_fs as fs
from . import operator_maintenance_inhibit as disk
from . import operator_maintenance_lock as cooperative
from . import operator_maintenance_manager as manager
from . import operator_maintenance_namespaces as namespaces
from . import operator_maintenance_packages as packages

# Do not silently extend the namespace primitive's existing 30-second window.
# This outer deadline is stricter than the standalone manager's 180s budget.
MAX_WINDOW_NS = 30_000_000_000


def _clock():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


@dataclass(frozen=True)
class MaintenanceControlResult:
    boot_id: str
    collection_elapsed_ms: int
    mask_created: bool
    process_leaders_examined: int
    scoped_sequence_completed: bool = field(default=True, init=False)
    controls_released: bool = field(default=True, init=False)
    cooperative_lock_held_during_sequence: bool = field(default=True, init=False)
    package_barrier_held_during_sequence: bool = field(default=True, init=False)
    visible_pid1_alignment_observed: bool = field(default=True, init=False)
    host_namespace_proven: bool = field(default=False, init=False)
    noncooperating_writers_excluded: bool = field(default=False, init=False)
    process_quiescence_proven: bool = field(default=False, init=False)
    exclusive_control_proven: bool = field(default=False, init=False)
    package_transaction_authorized: bool = field(default=False, init=False)
    mutation_authorized: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)
    review_required: bool = field(default=True, init=False)


class _Window:
    """Lifetime-only private handle; never passed to a child or serialized."""
    def __init__(self, boundary_checkpoint):
        core.require(callable(boundary_checkpoint), 'CONTROL_BOUNDARY')
        self._boundary = boundary_checkpoint
        self._owner = os.getpid(), threading.get_native_id()
        self._started = self._previous = _clock()
        self._handles = []
        self._namespace_key = None
        self._namespace_elapsed = -1
        self._active, self._checking = True, False

    def __repr__(self):
        return '<private maintenance control window>'

    def _lifetime(self):
        core.require((os.getpid(), threading.get_native_id()) == self._owner, 'CONTROL_OWNER')
        now = _clock()
        core.require(self._previous <= now and 0 <= now - self._started < MAX_WINDOW_NS,
                     'CONTROL_TIMEOUT')
        self._previous = now
        return now

    def checkpoint(self):
        core.require(self._active, 'CONTROL_CLOSED')
        core.require(not self._checking, 'CONTROL_REENTRANT')
        self._checking = True
        try:
            self._lifetime()
            try:
                answer = self._boundary()
            except Exception:
                raise core.OperatorError('CONTROL_BOUNDARY') from None
            core.require(answer is None, 'CONTROL_BOUNDARY')
            self._lifetime()
            for handle, kind in self._handles:
                observation = handle.checkpoint()
                now = self._lifetime()
                core.require(type(observation) is kind, 'CONTROL_OBSERVATION')
                if kind is namespaces.MaintenanceNamespaceObservation:
                    key = observation.boot_id, observation.captured_boottime_ms
                    # Native namespace reader supplies the boot syntax. No
                    # external observation is accepted by this private seam.
                    core.require(type(key[1]) is int and self._started // 1_000_000 <= key[1]
                                 and type(observation.window_elapsed_ms) is int
                                 and self._namespace_elapsed <= observation.window_elapsed_ms
                                 and 0 <= observation.window_elapsed_ms <= 30000
                                 and key[1] + observation.window_elapsed_ms <= now // 1_000_000,
                                 'CONTROL_NAMESPACE_TIME')
                    core.require(self._namespace_key in (None, key), 'CONTROL_NAMESPACE_CHANGED')
                    self._namespace_key = key
                    self._namespace_elapsed = observation.window_elapsed_ms
        finally:
            self._checking = False
        # None is the internal checkpoint contract, not an approval token.


@contextmanager
def _hold_controls(*, boundary_checkpoint):
    """Fixed acquisition/unwind order; no argument selects resources or actions.

    The trusted boundary callback must check owner/host/runtime and external
    update/start controls. A no-op callback does not provide any of those facts.
    Child exceptions and failed successful-exit checks unwind all acquired
    resources; no partial observation, restart or retry is returned.
    """
    core.require(callable(boundary_checkpoint), 'CONTROL_BOUNDARY')
    fs._platform()
    core.require(hasattr(time, 'CLOCK_BOOTTIME') and hasattr(time, 'clock_gettime_ns'),
                 'CONTROL_PLATFORM')
    window = _Window(boundary_checkpoint)
    try:
        with ExitStack() as stack:
            for factory, kind in (
                (namespaces.hold_maintenance_namespaces, namespaces.MaintenanceNamespaceObservation),
                (cooperative.hold_maintenance_lock, cooperative.MaintenanceLockObservation),
                (packages.hold_maintenance_package_locks, packages.MaintenancePackageLockObservation),
            ):
                window.checkpoint()
                handle = stack.enter_context(factory())
                window._handles.append((handle, kind))
                window.checkpoint()
            try:
                yield window
                window.checkpoint()
            finally:
                # Captured checkpoints cannot outlive the protected body.
                window._active = False
        window._lifetime()  # Late/failed cleanup cannot yield a success result.
    finally:
        window._active = False


def _inhibit(*, boundary_checkpoint):
    """Compose disk then manager while all controls are held; no live release.

    Only the existing fixed busctl readers and reload/stop systemctl children
    are permitted. They close unrelated FDs before exec, have no pass_fds or
    preexec_fn, never receive handles and are waited/reaped. Raw fork, dup/pass,
    controller exec, arbitrary children and package transactions remain forbidden.
    An unfinished manager job after client failure requires fresh reconciliation;
    releasing advisory resources never removes the persistent mask.
    """
    try:
        with _hold_controls(boundary_checkpoint=boundary_checkpoint) as window:
            window.checkpoint()
            with ExitStack() as stack:
                root = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                stack.callback(os.close, root)
                window.checkpoint()
                prepared = disk._prepare_at(root, checkpoint=window.checkpoint)
                core.require(type(prepared) is disk.MaintenanceMaskResult, 'CONTROL_DISK_RESULT')
                window.checkpoint()
                observed = manager._sequence(checkpoint=window.checkpoint)
                core.require(type(observed) is manager.MaintenanceManagerResult, 'CONTROL_MANAGER_RESULT')
                window.checkpoint()
                core.require(observed.boot_id == window._namespace_key[0], 'CONTROL_BOOT')
            window.checkpoint()
        # No result escapes if root close, any context's exit checks/cleanup or
        # the final whole-window lifetime check fails. These are historical
        # observations, not a still-held lock or a permit for subsequent work.
        return MaintenanceControlResult(observed.boot_id,
            (window._previous - window._started) // 1_000_000,
            prepared.mask_created, observed.process_leaders_examined)
    except OSError as error:
        raise core.OperatorError(fs._os_error_code(error)) from None


def run_maintenance_inhibition():
    """Unreleased: data, caller booleans or environment cannot enable execution."""
    raise core.OperatorError('CONTROL_NOT_RELEASED')
