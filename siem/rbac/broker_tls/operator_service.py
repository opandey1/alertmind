"""Read-only systemd configuration observations; NOT runtime/startup approval.

Fixed local busctl Properties.Get calls only. Raw arguments/environment remain
private in memory. No CLI, unit loading/reload/start/stop, Node or broker call.
The host OS, busctl/libraries and Python launch/import environment are trusted.
"""
from dataclasses import dataclass, field
import json
import os
from pathlib import PurePosixPath
import re
import selectors
import subprocess
import time

from . import operator_core as core
from . import operator_fs as fs

BUSCTL = '/usr/bin/busctl'
UNIT = 'wazuh-dashboard.service'
OBJECT = '/org/freedesktop/systemd1/unit/wazuh_2ddashboard_2eservice'
MAX_REPLY = 256 * 1024
TIMEOUT = 5
GROUPS = {
    'Unit': (('Id', 's'), ('LoadState', 's'), ('ActiveState', 's'),
             ('FragmentPath', 's'), ('DropInPaths', 'as'), ('NeedDaemonReload', 'b')),
    'Service': (('ExecStartEx', 'a(sasasttttuii)'), ('Environment', 'as'),
                ('EnvironmentFiles', 'a(sb)'), ('PassEnvironment', 'as'),
                ('UnsetEnvironment', 'as'), ('User', 's'), ('Group', 's'),
                ('WorkingDirectory', 's'), ('RootDirectory', 's'), ('RootImage', 's'),
                ('MainPID', 'u'), ('ExecMainStartTimestampMonotonic', 't')),
}
RISK_NAMES = frozenset(('NODE_OPTIONS', 'NODE_PATH', 'NODE_HOME', 'NODE',
                        'LD_PRELOAD', 'LD_LIBRARY_PATH', 'PATH'))


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        core.require(key not in result, 'SERVICE_JSON')
        result[key] = value
    return result


def _string(value):
    return type(value) is str and not re.search(r'[\x00-\x1f\x7f\ud800-\udfff]', value)


def _strings(value):
    return type(value) is list and all(_string(v) for v in value)


def _valid(value, signature):
    if signature in ('u', 't'):
        return type(value) is int and 0 <= value < 2 ** (32 if signature == 'u' else 64)
    if signature == 's':
        return _string(value)
    if signature == 'b':
        return type(value) is bool
    if signature == 'as':
        return _strings(value)
    if type(value) is not list:
        return False
    if signature == 'a(sb)':
        return all(type(v) is list and len(v) == 2 and _string(v[0])
                   and type(v[1]) is bool for v in value)
    if signature == 'a(sasasttttuii)':
        for row in value:
            if not (type(row) is list and len(row) == 10 and _string(row[0])
                    and _strings(row[1]) and _strings(row[2])):
                return False
            for n, bits, signed in zip(row[3:], (64, 64, 64, 64, 32, 32, 32),
                                       (False, False, False, False, False, True, True)):
                lower = -(2 ** (bits - 1)) if signed else 0
                upper = 2 ** (bits - int(signed))
                if type(n) is not int or not lower <= n < upper:
                    return False
        return True
    return False


def parse_properties(raw, group):
    """Private-data parser for ordered busctl get-property JSON lines."""
    core.require(type(group) is str and group in GROUPS, 'SERVICE_TARGET')
    core.require(type(raw) is bytes and 0 < len(raw) <= MAX_REPLY, 'SERVICE_SIZE')
    try:
        # busctl JSON records are LF-delimited, not Unicode-line-delimited.
        lines = raw.split(b'\n')
        if lines[-1] == b'':
            lines.pop()
        core.require(len(lines) == len(GROUPS[group]), 'SERVICE_SHAPE')
        result = {}
        for line, (name, signature) in zip(lines, GROUPS[group]):
            obj = json.loads(line.decode('utf-8'), object_pairs_hook=_pairs,
                             parse_constant=lambda _: core.require(False, 'SERVICE_JSON'))
            core.require(type(obj) is dict and set(obj) == {'type', 'data'}
                         and obj['type'] == signature and _valid(obj['data'], signature), 'SERVICE_SHAPE')
            result[name] = obj['data']
        return result
    except (ValueError, UnicodeError, RecursionError):
        raise core.OperatorError('SERVICE_JSON') from None


def _query(group):
    """Bounded pipe read, finite wait, fixed command and clean child environment."""
    core.require(type(group) is str and group in GROUPS, 'SERVICE_TARGET')
    command = [BUSCTL, '--system', '--json=short', '--no-pager', '--timeout=5',
               '--auto-start=no', '--allow-interactive-authorization=no', 'get-property',
               'org.freedesktop.systemd1', OBJECT, 'org.freedesktop.systemd1.' + group,
               *(name for name, _ in GROUPS[group])]
    proc = None
    try:
        deadline = time.monotonic() + TIMEOUT
        proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, shell=False, close_fds=True,
                                cwd='/', env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        data = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                core.require(remaining > 0 and selector.select(remaining), 'SERVICE_TIMEOUT')
                chunk = os.read(proc.stdout.fileno(), min(65536, MAX_REPLY + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                core.require(len(data) <= MAX_REPLY, 'SERVICE_SIZE')
        core.require(proc.wait(timeout=max(0, deadline - time.monotonic())) == 0, 'SERVICE_QUERY')
        return bytes(data)
    except subprocess.TimeoutExpired:
        raise core.OperatorError('SERVICE_TIMEOUT') from None
    except OSError:
        raise core.OperatorError('SERVICE_QUERY') from None
    finally:
        if proc is not None:
            try:
                if proc.poll() is None:
                    proc.kill()
                proc.wait(timeout=1)
            except (OSError, subprocess.TimeoutExpired):
                raise core.OperatorError('SERVICE_CLEANUP') from None
            finally:
                if proc.stdout is not None:
                    proc.stdout.close()


@dataclass(frozen=True)
class ServiceObservation:
    active_state: str
    exec_start_count: int
    configured_executable: str
    exec_flags_present: bool
    environment_entries: int
    runtime_override_named: bool
    environment_files: int
    pass_environment_entries: int
    unset_environment_entries: int
    service_user_matches: bool
    service_group_matches: bool
    working_directory_matches: bool
    alternate_root_present: bool
    fragment_present: bool
    dropin_count: int
    passes: int = field(default=2, init=False)
    selected_runtime_proven: bool = field(default=False, init=False)
    effective_environment_proven: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)


def _summarize(values):
    core.require(values['Id'] == UNIT and values['LoadState'] == 'loaded', 'SERVICE_IDENTITY')
    core.require(values['NeedDaemonReload'] is False, 'SERVICE_RELOAD_PENDING')
    active = values['ActiveState']
    core.require(active in ('active', 'inactive', 'failed'), 'SERVICE_TRANSITION')
    rows = values['ExecStartEx']
    kind = 'other'
    if len(rows) == 1:
        kind = {core.NODE: 'packaged_node', core.BASE + 'bin/opensearch-dashboards':
                'dashboard_wrapper'}.get(rows[0][0], 'other')
    names = set()
    for entry in values['Environment']:
        name, sep, _ = entry.partition('=')
        core.require(sep and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name), 'SERVICE_ENVIRONMENT')
        core.require(name not in names, 'SERVICE_ENVIRONMENT')
        names.add(name)
    return ServiceObservation(active, len(rows), kind, any(row[2] for row in rows),
        len(names), bool(names & RISK_NAMES), len(values['EnvironmentFiles']),
        len(values['PassEnvironment']), len(values['UnsetEnvironment']),
        values['User'] == 'wazuh-dashboard', values['Group'] == 'wazuh-dashboard',
        values['WorkingDirectory'] == core.BASE.rstrip('/'),
        bool(values['RootDirectory'] or values['RootImage']), bool(values['FragmentPath']),
        len(values['DropInPaths']))


def _check_tool():
    fs._platform()
    path = PurePosixPath(BUSCTL)
    core.require(path.is_absolute() and str(path) == BUSCTL, 'SERVICE_TARGET')
    try:
        # Root-owned regular tool file/ancestors, NOT authenticity or
        # dependency proof. The host OS toolchain is an explicit trust assumption.
        fs._read_root_owned(path.parts[1:], 16 * 1024 * 1024)
    except OSError as error:
        raise core.OperatorError(fs._os_error_code(error)) from None


def _read_configuration():
    # Private data; callers must establish _check_tool first and never log it.
    values = {}
    for group in GROUPS:
        values.update(parse_properties(_query(group), group))
    _summarize(values)
    return values


def observe_service_configuration():
    """Fresh manager properties, not on-disk unit parsing or process attestation.

    Does not load an absent unit. No caller-selected executable, unit or property.
    Two equal snapshots are not atomic and do not prevent later reconfiguration.
    Returns counts/fixed labels only; do not log intermediate parser return values.
    """
    _check_tool()
    snapshots = []
    for _ in range(2):
        snapshots.append(_read_configuration())
    core.require(snapshots[0] == snapshots[1], 'SERVICE_CHANGED')
    return _summarize(snapshots[1])
