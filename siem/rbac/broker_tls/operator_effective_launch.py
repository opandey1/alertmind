"""Post-start, read-only observation of a fixed Dashboard Node launch shape.

The running Dashboard must already exist. This is not a pre-start guard, a
complete environment inspection, or permission to start/restart the service.
Raw argv and environment values never appear in diagnostics or results.
"""
from dataclasses import dataclass, field

from . import operator_core as core
from . import operator_fs as fs
from . import operator_node_options as options
from . import operator_process as process
from . import operator_service as service


PREFIX = (b'--no-warnings', b'--max-http-header-size=65536')
ENTRYPOINT = (core.BASE + 'src/cli/dist').encode('ascii')
REQUIRED_ENV = {
    b'OSD_PATH_CONF': b'/etc/wazuh-dashboard',
    b'OSD_NODE_OPTS_PREFIX': b'--no-warnings --max-http-header-size=65536',
    b'OSD_USE_NODE_JS_FILE_PATH': b'/src/cli/dist',
    b'NODE_ENV': b'production',
}
DENIED_ENV = frozenset((
    b'NODE', b'NODE_HOME', b'OSD_NODE_HOME', b'OSD_NODE_OPTS',
    b'BASH_ENV', b'ENV', b'IFS', b'CDPATH', b'GLOBIGNORE',
    b'SHELLOPTS', b'BASHOPTS', b'GREP_OPTIONS',
))
DENIED_PREFIXES = (b'LD_', b'NODE_', b'OSD_', b'OPENSSL_', b'SSL_')


def _check_argv(raw, option_count):
    core.require(type(option_count) is int and option_count in (1, 2), 'EFFECTIVE_POLICY')
    args = process._nul_fields(raw)
    fixed = (core.NODE.encode('ascii'),) + PREFIX
    if option_count == 1:
        permitted = (fixed + (options.REQUIRED.encode('ascii'), ENTRYPOINT),)
    else:
        warn = options.REQUIRED.encode('ascii')
        heap = b'--max-old-space-size=4096'
        permitted = (fixed + (warn, heap, ENTRYPOINT),
                     fixed + (heap, warn, ENTRYPOINT))
    core.require(tuple(args) in permitted, 'EFFECTIVE_ARGV')
    return len(args)


def _check_environment(raw):
    fields = process._nul_fields(raw, environment=True)
    values = {name: value for name, _, value in (entry.partition(b'=') for entry in fields)}
    core.require(all(values.get(name) == expected for name, expected in REQUIRED_ENV.items()),
                 'EFFECTIVE_ENV')
    core.require(all(name not in DENIED_ENV and
                     not (name.startswith(DENIED_PREFIXES) and name not in REQUIRED_ENV)
                     for name in values), 'EFFECTIVE_ENV')
    return len(fields)


@dataclass(frozen=True)
class EffectiveLaunchObservation:
    argument_count: int
    environment_entries: int
    process_passes: int = field(default=2, init=False)
    option_policy_passes: int = field(default=2, init=False)
    reviewed_argv_shape_observed: bool = field(default=True, init=False)
    reviewed_environment_keys_observed: bool = field(default=True, init=False)
    process_executable_matches_pin: bool = field(default=True, init=False)
    actual_config_source_proven: bool = field(default=False, init=False)
    external_utility_resolution_proven: bool = field(default=False, init=False)
    complete_effective_environment_proven: bool = field(default=False, init=False)
    loaded_code_proven: bool = field(default=False, init=False)
    prestart_applicable: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)


def observe_effective_launch():
    """Compare bounded process snapshots against pinned Node launch expectations.

    Two equal observations are not atomic and do not attest a later state.
    Never start an unguarded Dashboard merely to make this observer usable.
    """
    service._check_tool()
    try:
        before = options.observe_node_options()
        core.require(type(before) is options.NodeOptionsObservation, 'EFFECTIVE_POLICY')
        identity = fs._identity()
        anchor = process._anchor()
        snapshots = []
        for _ in range(2):
            snapshots.append(process._native_snapshot(anchor['MainPID'], identity))
            core.require(process._anchor() == anchor, 'PROCESS_CHANGED')
        core.require(snapshots[0] == snapshots[1], 'PROCESS_CHANGED')
        argument_count = _check_argv(snapshots[1].cmdline, before.option_count)
        environment_entries = _check_environment(snapshots[1].environment)
        core.require(options.observe_node_options() == before, 'EFFECTIVE_CHANGED')
        core.require(process._anchor() == anchor, 'PROCESS_CHANGED')
        return EffectiveLaunchObservation(argument_count, environment_entries)
    except OSError:
        raise core.OperatorError('EFFECTIVE_IO') from None
