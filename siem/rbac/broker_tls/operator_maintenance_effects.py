"""Selected loaded-unit stop effects, not complete dependency/generator review.

Fixed read-only busctl requests. No unit loading, path traversal, hook execution,
manager mutation or authorization. Raw commands and related-unit names stay
private. Requires an externally trusted host/runtime and continuous controls.
"""
from dataclasses import dataclass, field
import json
import os
import selectors
import subprocess
import threading
import time

from . import operator_core as core
from . import operator_fs as fs
from . import operator_maintenance_state as state
from . import operator_service as service

EDGES = ('RequiredBy', 'RequisiteOf', 'BoundBy', 'ConsistsOf', 'PropagatesStopTo',
         'OnFailure', 'OnSuccess', 'TriggeredBy', 'Triggers', 'UpheldBy')
ACTIONS = ('FailureAction', 'SuccessAction', 'StartLimitAction', 'JobTimeoutAction')
GROUPS = {
    'Unit': (('Id', 's'), ('Names', 'as'), ('Following', 's'), ('LoadState', 's'),
             ('ActiveState', 's'), ('SubState', 's'), ('NeedDaemonReload', 'b'),
             ('Job', '(uo)'), ('Transient', 'b'), ('RefuseManualStop', 'b'))
            + tuple((n, 'as') for n in EDGES) + tuple((n, 's') for n in ACTIONS),
    'Service': (('ExecStopEx', 'a(sasasttttuii)'), ('ExecStopPostEx', 'a(sasasttttuii)'),
                ('ControlPID', 'u'), ('KillMode', 's'), ('KillSignal', 'i'),
                ('FinalKillSignal', 'i'), ('SendSIGKILL', 'b'), ('SendSIGHUP', 'b'),
                ('TimeoutStopFailureMode', 's')),
}
PHASES = ('before_mask', 'before_reload', 'before_stop')
MAX_REPLY = 64 * 1024
QUERY_SECONDS = 5
MAX_WINDOW_NS = 30_000_000_000


def _clock():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        core.require(key not in result, 'EFFECTS_JSON')
        result[key] = value
    return result


def parse_properties(raw, group):
    """Strict ordered LF records; unsupported/missing properties never default."""
    core.require(type(group) is str and group in GROUPS, 'EFFECTS_TARGET')
    core.require(type(raw) is bytes and 0 < len(raw) <= MAX_REPLY, 'EFFECTS_SIZE')
    try:
        lines = raw.split(b'\n')
        if lines[-1] == b'':
            lines.pop()
        core.require(len(lines) == len(GROUPS[group]), 'EFFECTS_SHAPE')
        values = {}
        for line, (name, signature) in zip(lines, GROUPS[group]):
            item = json.loads(line.decode('utf-8'), object_pairs_hook=_pairs,
                              parse_constant=lambda _: core.require(False, 'EFFECTS_JSON'))
            core.require(type(item) is dict and set(item) == {'type', 'data'}
                         and item['type'] == signature, 'EFFECTS_SHAPE')
            value = item['data']
            valid = (type(value) is int and -(2**31) <= value < 2**31
                     if signature == 'i' else state._valid(value, signature))
            core.require(valid, 'EFFECTS_SHAPE')
            values[name] = value
        return values
    except (ValueError, UnicodeError, RecursionError):
        raise core.OperatorError('EFFECTS_JSON') from None


def _query(group, *, checkpoint):
    core.require(type(group) is str and group in GROUPS, 'EFFECTS_TARGET')
    command = [service.BUSCTL, '--system', '--json=short', '--no-pager', '--timeout=5',
               '--auto-start=no', '--allow-interactive-authorization=no', 'get-property',
               'org.freedesktop.systemd1', state.OBJECT,
               'org.freedesktop.systemd1.' + group, *(n for n, _ in GROUPS[group])]
    proc = None
    try:
        checkpoint()
        started = _clock()
        deadline = started + QUERY_SECONDS * 1_000_000_000
        proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, shell=False, close_fds=True,
                                cwd='/', env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        data = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while True:
                checkpoint()
                now = _clock()
                core.require(started <= now < deadline, 'EFFECTS_TIMEOUT')
                if not selector.select(min(0.25, (deadline - now) / 1_000_000_000)):
                    continue
                checkpoint()
                chunk = os.read(proc.stdout.fileno(), min(4096, MAX_REPLY + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                core.require(len(data) <= MAX_REPLY, 'EFFECTS_SIZE')
        checkpoint()
        now = _clock()
        core.require(started <= now < deadline, 'EFFECTS_TIMEOUT')
        core.require(proc.wait(timeout=(deadline - now) / 1_000_000_000) == 0, 'EFFECTS_QUERY')
        checkpoint()
        core.require(started <= _clock() < deadline, 'EFFECTS_TIMEOUT')
        return bytes(data)
    except subprocess.TimeoutExpired:
        raise core.OperatorError('EFFECTS_TIMEOUT') from None
    except OSError:
        raise core.OperatorError('EFFECTS_QUERY') from None
    finally:
        if proc is not None:
            try:
                if proc.poll() is None:
                    proc.kill()
                proc.wait(timeout=1)
            except (OSError, subprocess.TimeoutExpired):
                raise core.OperatorError('EFFECTS_CLEANUP') from None
            finally:
                if proc.stdout is not None:
                    proc.stdout.close()


def _constrain(values, phase):
    core.require(values['Id'] == state.UNIT and values['Names'] == [state.UNIT]
                 and values['Following'] == '' and values['Transient'] is False,
                 'EFFECTS_IDENTITY')
    core.require(values['LoadState'] in ('loaded', 'masked')
                 and (values['ActiveState'], values['SubState']) in
                     (('active', 'running'), ('inactive', 'dead'), ('failed', 'failed'))
                 and values['Job'] == [0, '/'] and values['ControlPID'] == 0
                 and values['RefuseManualStop'] is False, 'EFFECTS_STATE')
    if phase != 'before_reload':
        core.require(values['NeedDaemonReload'] is False, 'EFFECTS_RELOAD_PENDING')
    if phase == 'before_stop':
        core.require(values['LoadState'] == 'masked', 'EFFECTS_MASK_STATE')
    core.require(all(values[n] == [] for n in EDGES), 'EFFECTS_EDGES')
    core.require(all(values[n] == 'none' for n in ACTIONS), 'EFFECTS_ACTIONS')
    core.require(values['ExecStopEx'] == [] and values['ExecStopPostEx'] == [], 'EFFECTS_HOOKS')
    # Conservative candidate, not an assertion about the installed version.
    core.require(values['KillMode'] == 'control-group' and values['KillSignal'] == 15
                 and values['FinalKillSignal'] == 9 and values['SendSIGKILL'] is True
                 and values['SendSIGHUP'] is False
                 and values['TimeoutStopFailureMode'] == 'terminate', 'EFFECTS_KILL_POLICY')


@dataclass(frozen=True)
class MaintenanceEffectsObservation:
    collection_elapsed_ms: int
    passes: int = field(default=2, init=False)
    selected_hooks_empty: bool = field(default=True, init=False)
    selected_edges_empty: bool = field(default=True, init=False)
    selected_actions_none: bool = field(default=True, init=False)
    selected_kill_policy_matches: bool = field(default=True, init=False)
    complete_dependency_effects_proven: bool = field(default=False, init=False)
    generator_effects_proven: bool = field(default=False, init=False)
    package_lock_compatibility_proven: bool = field(default=False, init=False)
    atomic_snapshot_proven: bool = field(default=False, init=False)
    continuous_control_proven: bool = field(default=False, init=False)
    mutation_authorized: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)
    review_required: bool = field(default=True, init=False)


def _collect(phase, *, checkpoint):
    core.require(type(phase) is str and phase in PHASES, 'EFFECTS_PHASE')
    core.require(callable(checkpoint), 'EFFECTS_CHECKPOINT')
    owner = os.getpid(), threading.get_native_id()
    try:
        fs._platform()
        core.require(hasattr(time, 'CLOCK_BOOTTIME') and hasattr(time, 'clock_gettime_ns'),
                     'EFFECTS_PLATFORM')
        started = previous = _clock()

        def check():
            nonlocal previous
            core.require((os.getpid(), threading.get_native_id()) == owner, 'EFFECTS_OWNER')
            try:
                answer = checkpoint()
            except Exception:
                raise core.OperatorError('EFFECTS_CHECKPOINT') from None
            core.require(answer is None, 'EFFECTS_CHECKPOINT')
            core.require((os.getpid(), threading.get_native_id()) == owner, 'EFFECTS_OWNER')
            now = _clock()
            core.require(previous <= now and 0 <= now - started < MAX_WINDOW_NS, 'EFFECTS_TIMEOUT')
            previous = now

        check()
        service._check_tool()
        snapshots = []
        for _ in range(2):
            values = {}
            for group in GROUPS:
                check()
                values.update(parse_properties(_query(group, checkpoint=check), group))
                check()
            _constrain(values, phase)
            snapshots.append(values)
        core.require(snapshots[0] == snapshots[1], 'EFFECTS_CHANGED')
        check()  # Includes child cleanup; no private raw snapshot escapes.
        return MaintenanceEffectsObservation((previous - started) // 1_000_000)
    except OSError as error:
        raise core.OperatorError(fs._os_error_code(error)) from None


def _check(phase, *, checkpoint):
    """Private fresh check, never accept a cached receipt or supplied values."""
    _collect(phase, checkpoint=checkpoint)


def observe_maintenance_stop_effects():
    """Read-only candidate; no CLI or live invocation is released by this code."""
    return _collect('before_mask', checkpoint=lambda: None)
