"""Read-only check of systemd's manager-wide exported environment.

The Manager.Environment property is only one source of a service's environment.
This module neither starts the Dashboard nor approves its eventual process
environment. Raw property values remain private and are never returned.
"""
from dataclasses import dataclass, field
import json
import re

from . import operator_core as core
from . import operator_service as service


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        core.require(key not in result, 'MANAGER_ENV_FORMAT')
        result[key] = value
    return result


def _parse(raw):
    core.require(type(raw) is bytes and 0 < len(raw) <= service.MAX_REPLY,
                 'MANAGER_ENV_SIZE')
    try:
        lines = raw.split(b'\n')
        if lines[-1] == b'':
            lines.pop()
        core.require(len(lines) == 1, 'MANAGER_ENV_SHAPE')
        obj = json.loads(lines[0].decode('utf-8'), object_pairs_hook=_pairs,
                         parse_constant=lambda _: core.require(False, 'MANAGER_ENV_FORMAT'))
        core.require(type(obj) is dict and set(obj) == {'type', 'data'}
                     and obj['type'] == 'as' and service._valid(obj['data'], 'as'),
                     'MANAGER_ENV_SHAPE')
        names = set()
        for entry in obj['data']:
            name, sep, _ = entry.partition('=')
            core.require(sep and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name)
                         and name not in names, 'MANAGER_ENV_ENTRY')
            names.add(name)
        return obj['data']
    except (ValueError, UnicodeError, RecursionError):
        raise core.OperatorError('MANAGER_ENV_FORMAT') from None


@dataclass(frozen=True)
class ManagerEnvironmentObservation:
    global_manager_environment_empty: bool = field(default=True, init=False)
    passes: int = field(default=2, init=False)
    unit_environment_proven: bool = field(default=False, init=False)
    wrapper_environment_proven: bool = field(default=False, init=False)
    effective_environment_proven: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)


def observe_manager_environment():
    """Accept only two equal, empty Manager.Environment replies.

    A nonempty export requires separate review, regardless of variable name.
    Equal snapshots do not make the property atomic or prevent later changes.
    Unit-specific, manager-process/PAM and wrapper-created variables are not
    established here. No caller-supplied target, environment or credential.
    """
    service._check_tool()
    first = _parse(service._query_manager_environment())
    second = _parse(service._query_manager_environment())
    core.require(first == second, 'MANAGER_ENV_CHANGED')
    core.require(not second, 'MANAGER_ENV_PRESENT')
    return ManagerEnvironmentObservation()
