"""Fixed launch-file byte observations, not script execution or startup approval.

Pins were derived from the already approved exact Dashboard .deb. This adds no
caller-selected path, manifest override, shell/Node execution or write. Private
manager snapshots are never returned. Trusted Python/OS assumptions are shared
with operator_service/operator_fs; deployment wiring remains separate.
"""
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from . import operator_core as core
from . import operator_fs as fs
from . import operator_runtime as runtime
from . import operator_service as service

WRAPPER = core.BASE + 'bin/opensearch-dashboards'
CHECKS = (
    core.FileCheck(WRAPPER,
        '30993e61fae26ab0c7d73836fd510f1c9a54e9110a7e9c63edc9cbaff505f9d5', 939, 939),
    core.FileCheck(core.BASE + 'bin/use_node',
        'e1ec334650c93f2a4869cd679f2ff5a434a580f2c9b0e15cc4ef4f826803c464', 3531, 3531),
    core.FileCheck(core.BASE + 'src/cli/dist.js',
        '3425aafe16f4e139902826a4b929c61e74f930f2e7ef08cf7fe123cb81b7eefe', 1187, 1187),
)
# Visibility only: not a safe-environment allowlist or all possible influences.
WRAPPER_ENV_NAMES = frozenset(('OSD_NODE_HOME', 'NODE_HOME', 'NODE_OPTIONS',
    'OSD_NODE_OPTS', 'OSD_NODE_OPTS_PREFIX', 'OSD_PATH_CONF',
    'OSD_USE_NODE_JS_FILE_PATH', 'LOCALBASE', 'NODE_ENV',
    'NODE_PATH', 'PATH', 'LD_PRELOAD', 'LD_LIBRARY_PATH'))


def _configuration():
    values = service._read_configuration()
    # Host paths are not sufficient for a chroot/image configured unit.
    core.require(not values['RootDirectory'] and not values['RootImage'], 'LAUNCH_NAMESPACE')
    return values


@dataclass(frozen=True)
class LaunchObservation:
    configured_wrapper_path: bool
    configured_wrapper_argv_only: bool
    explicit_execution_flags: bool
    wrapper_environment_override_named: bool
    checked_files: int = field(default=3, init=False)
    passes: int = field(default=2, init=False)
    service_reads: int = field(default=3, init=False)
    package_reads: int = field(default=3, init=False)
    launch_bytes_match_pins: bool = field(default=True, init=False)
    selected_runtime_proven: bool = field(default=False, init=False)
    effective_environment_proven: bool = field(default=False, init=False)
    dependency_resolution_proven: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)


def observe_launch_files():
    """Read only three fixed paths; works with an inactive loaded service.

    Does not inspect environment-file contents, shell utilities, module lookup,
    other namespaces, all unit properties or a running process. Two equal reads
    do not stop later edits. Never use this result alone to permit a startup.
    """
    service._check_tool()
    try:
        identity = fs._identity()
        package = runtime.read_package_identity()
        config = _configuration()
        for _ in range(2):
            for check in CHECKS:
                raw = fs._read_native(PurePosixPath(check.path).parts[1:], check.limit, identity)
                core.require(type(raw) is bytes and len(raw) == check.size
                             and len(raw) <= check.limit, 'LAUNCH_SIZE')
                core.require(core.sha(raw) == check.digest, 'LAUNCH_DIGEST')
            core.require(runtime.read_package_identity() == package, 'PACKAGE_CHANGED')
            core.require(_configuration() == config, 'LAUNCH_CHANGED')
        rows = config['ExecStartEx']
        wrapper = len(rows) == 1 and rows[0][0] == WRAPPER
        names = {entry.partition('=')[0] for entry in config['Environment']}
        return LaunchObservation(wrapper, wrapper and rows[0][1] == [WRAPPER],
            any(row[2] for row in rows), bool(names & WRAPPER_ENV_NAMES))
    except OSError as error:
        raise core.OperatorError(fs._os_error_code(error)) from None
