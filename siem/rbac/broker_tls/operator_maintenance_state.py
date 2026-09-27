"""Read-only maintenance observations, NOT a maintenance admission decision.

Fixed persistent-mask metadata and fixed systemd Properties.Get calls only.
No CLI, configuration writes, unit loading, stop/start or planner adapter.
Requires an already trusted root/Linux caller, OS, busctl and Python context.
An inactive unit with zero main/control PIDs does not prove process quiescence.
This module is outside the guard capsule and must not be used as a start permit.
"""
from contextlib import ExitStack
from dataclasses import dataclass, field
import json
import os
import re
import selectors
import stat
import subprocess
import time

from . import operator_core as core
from . import operator_fs as fs
from . import operator_python_paths as paths
from . import operator_service as service

MASK_PARENT = ('etc', 'systemd', 'system')
UNIT = 'wazuh-dashboard.service'
OBJECT = '/org/freedesktop/systemd1/unit/wazuh_2ddashboard_2eservice'
MAX_REPLY = 16384
QUERY_TIMEOUT = 5
MAX_COLLECTION_MS = 30000  # Candidate limit, not a measured native guarantee.
GROUPS = {
    'Unit': (('Id', 's'), ('LoadState', 's'), ('UnitFileState', 's'),
             ('ActiveState', 's'), ('SubState', 's'), ('NeedDaemonReload', 'b'),
             ('Job', '(uo)'), ('TriggeredBy', 'as')),
    'Service': (('MainPID', 'u'), ('ControlPID', 'u'), ('ControlGroup', 's')),
}


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        core.require(key not in result, 'MAINTENANCE_JSON')
        result[key] = value
    return result


def _valid(value, signature):
    if signature == '(uo)':
        return (type(value) is list and len(value) == 2
                and service._valid(value[0], 'u') and type(value[1]) is str
                and re.fullmatch(r'/(?:[A-Za-z0-9_]+(?:/[A-Za-z0-9_]+)*)?', value[1]) is not None)
    return service._valid(value, signature)


def parse_properties(raw, group):
    """Strict bounded busctl records. Parsed private values are not log output."""
    core.require(type(group) is str and group in GROUPS, 'MAINTENANCE_TARGET')
    core.require(type(raw) is bytes and 0 < len(raw) <= MAX_REPLY, 'MAINTENANCE_SIZE')
    try:
        lines = raw.split(b'\n')
        if lines[-1] == b'':
            lines.pop()
        core.require(len(lines) == len(GROUPS[group]), 'MAINTENANCE_SHAPE')
        values = {}
        for line, (name, signature) in zip(lines, GROUPS[group]):
            item = json.loads(line.decode('utf-8'), object_pairs_hook=_pairs,
                              parse_constant=lambda _: core.require(False, 'MAINTENANCE_JSON'))
            core.require(type(item) is dict and set(item) == {'type', 'data'}
                         and item['type'] == signature and _valid(item['data'], signature),
                         'MAINTENANCE_SHAPE')
            values[name] = item['data']
        return values
    except (ValueError, UnicodeError, RecursionError):
        raise core.OperatorError('MAINTENANCE_JSON') from None


def _query(group):
    # Separate allowlist: the steady-state observer deliberately rejects masked
    # units and requests configuration we do not need. Do not widen its contract.
    core.require(type(group) is str and group in GROUPS, 'MAINTENANCE_TARGET')
    command = [service.BUSCTL, '--system', '--json=short', '--no-pager', '--timeout=5',
               '--auto-start=no', '--allow-interactive-authorization=no', 'get-property',
               'org.freedesktop.systemd1', OBJECT, 'org.freedesktop.systemd1.' + group,
               *(name for name, _ in GROUPS[group])]
    proc = None
    try:
        deadline = time.monotonic() + QUERY_TIMEOUT
        proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, shell=False, close_fds=True,
                                cwd='/', env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        data = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                core.require(remaining > 0 and selector.select(remaining), 'MAINTENANCE_TIMEOUT')
                chunk = os.read(proc.stdout.fileno(), min(4096, MAX_REPLY + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                core.require(len(data) <= MAX_REPLY, 'MAINTENANCE_SIZE')
        core.require(proc.wait(timeout=max(0, deadline - time.monotonic())) == 0,
                     'MAINTENANCE_QUERY')
        return bytes(data)
    except subprocess.TimeoutExpired:
        raise core.OperatorError('MAINTENANCE_TIMEOUT') from None
    except OSError:
        raise core.OperatorError('MAINTENANCE_QUERY') from None
    finally:
        if proc is not None:
            try:
                if proc.poll() is None:
                    proc.kill()
                proc.wait(timeout=1)
            except (OSError, subprocess.TimeoutExpired):
                raise core.OperatorError('MAINTENANCE_CLEANUP') from None
            finally:
                if proc.stdout is not None:
                    proc.stdout.close()


def _mask_at(root_fd):
    """Private fixed-name reader. Root fd is / in production, temporary in tests.

    Never follow the mask symlink or read a unit/device payload. Hold and check
    all ancestors; permit exactly the root-owned /dev/null symlink as evidence.
    Other root-owned symlinks/regular files are negative observations, including
    an empty regular unit (which systemd can also treat as masked). No fallback.
    """
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    with ExitStack() as stack:
        root_before = os.fstat(root_fd)
        fs._trusted(root_before, True, ((0, 0),))
        parent, records = root_fd, []
        for name in MASK_PARENT:
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            fs._trusted(before, True, ((0, 0),))
            opened = os.open(name, flags, dir_fd=parent)
            stack.callback(os.close, opened)
            core.require(fs._stamp(before) == fs._stamp(os.fstat(opened)), 'FS_CHANGED')
            records.append((parent, name, opened, before))
            parent = opened
        try:
            leaf = os.stat(UNIT, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            leaf = None
        target, null_stamp = None, None
        if leaf is not None:
            core.require((leaf.st_uid, leaf.st_gid) == (0, 0), 'FS_METADATA')
            if stat.S_ISLNK(leaf.st_mode):
                target = os.readlink(UNIT, dir_fd=parent)
                core.require(type(target) is str and len(target) <= 4096, 'MAINTENANCE_MASK_TARGET')
                if target == '/dev/null':
                    null_stamp = paths._null_anchor_at(root_fd)
                core.require(target == os.readlink(UNIT, dir_fd=parent), 'FS_CHANGED')
            else:
                fs._trusted(leaf, False, ((0, 0),))
            core.require(fs._stamp(leaf) == fs._stamp(os.stat(
                UNIT, dir_fd=parent, follow_symlinks=False)), 'FS_CHANGED')
        else:
            try:
                os.stat(UNIT, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise core.OperatorError('FS_CHANGED')
        for held_parent, name, opened, before in reversed(records):
            core.require(fs._stamp(before) == fs._stamp(os.fstat(opened)) == fs._stamp(
                os.stat(name, dir_fd=held_parent, follow_symlinks=False)), 'FS_CHANGED')
        core.require(fs._stamp(root_before) == fs._stamp(os.fstat(root_fd)), 'FS_CHANGED')
        # Private comparison token includes negative state and all held metadata.
        token = (fs._stamp(root_before), tuple(fs._stamp(r[3]) for r in records),
                 None if leaf is None else fs._stamp(leaf), target, null_stamp)
        return target == '/dev/null' and null_stamp is not None, token


def _read_mask():
    with ExitStack() as stack:
        root_fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        stack.callback(os.close, root_fd)
        return _mask_at(root_fd)


def _read_manager():
    values = {}
    for group in GROUPS:
        values.update(parse_properties(_query(group), group))
    core.require(values['Id'] == UNIT, 'MAINTENANCE_IDENTITY')
    return values


@dataclass(frozen=True)
class MaintenanceStateObservation:
    persistent_mask_present: bool
    manager_reports_persistent_mask: bool
    persistent_inhibition_observed: bool
    manager_reports_stopped: bool
    reload_pending: bool
    job_pending: bool
    tracked_pid_present: bool
    control_group_named: bool
    trigger_count: int
    collection_elapsed_ms: int
    passes: int = field(default=2, init=False)
    process_quiescence_proven: bool = field(default=False, init=False)
    exclusive_control_proven: bool = field(default=False, init=False)
    atomic_snapshot_proven: bool = field(default=False, init=False)
    review_required: bool = field(default=True, init=False)
    mutation_authorized: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)


def observe_maintenance_state():
    """Collect fresh fixed observations, not caller-supplied receipts or truth.

    Disk observations bracket two complete manager reads. Equality detects
    visible changes, not ABA, an atomic snapshot, a lock or future durability.
    Unit garbage collection/unavailable Service properties fail closed; we never
    load or unmask the unit to read it. No process/cgroup enumeration is claimed.
    Not convertible to the planner's dashboard_stopped=True or an execution gate.
    """
    started = time.monotonic_ns()
    try:
        service._check_tool()  # Includes root/Linux and fixed executable metadata.
        core.require(all(hasattr(os, n) for n in ('O_PATH', 'major', 'minor'))
                     and os.readlink in os.supports_dir_fd, 'MAINTENANCE_PLATFORM')
        first_mask = _read_mask()
        first = _read_manager()
        second = _read_manager()
        last_mask = _read_mask()
        core.require(first == second and first_mask == last_mask, 'MAINTENANCE_CHANGED')
        elapsed = (time.monotonic_ns() - started) // 1000000
        core.require(0 <= elapsed <= MAX_COLLECTION_MS, 'MAINTENANCE_TIMEOUT')
        manager_mask = second['LoadState'] == 'masked' and second['UnitFileState'] == 'masked'
        reload_pending = second['NeedDaemonReload']
        job = second['Job'][0] != 0
        pid = second['MainPID'] != 0 or second['ControlPID'] != 0
        stopped = ((second['ActiveState'], second['SubState']) in
                   (('inactive', 'dead'), ('failed', 'failed')) and not (job or pid or reload_pending)
                   and second['LoadState'] in ('loaded', 'masked'))
        return MaintenanceStateObservation(first_mask[0], manager_mask,
            first_mask[0] and manager_mask and not reload_pending, stopped,
            reload_pending, job, pid, bool(second['ControlGroup']),
            len(second['TriggeredBy']), elapsed)
    except OSError as error:
        raise core.OperatorError(fs._os_error_code(error)) from None
