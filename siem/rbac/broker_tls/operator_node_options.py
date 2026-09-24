"""Read-only policy for a fixed conffile and pinned scripts, not startup approval.

The pinned use_node script uses grep -v ^# and xargs, then unquoted shell
expansion. Accept a deliberately small option grammar; never source the file
or execute the wrapper, shell utilities or Node to inspect their behavior.
"""
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from . import operator_core as core
from . import operator_fs as fs
from . import operator_launch as launch
from . import operator_manager_environment as manager_env
from . import operator_runtime as runtime
from . import operator_service as service
from . import operator_unit_sources as unit_sources

CONFIG_PARTS = ('etc', 'wazuh-dashboard')
OPTIONS_PARTS = CONFIG_PARTS + ('node.options',)
MAX_OPTIONS = 16384
# Stock active option plus the exact example shipped commented-out in 4.14.7-1.
# Deliberately not all Node options or a general memory/performance approval.
ALLOWED = frozenset(('--unhandled-rejections=warn', '--max-old-space-size=4096'))
REQUIRED = '--unhandled-rejections=warn'
USE_NODE_PATH = core.BASE + 'bin/use_node'
USE_NODE_CHECK = launch.CHECKS[1]
WRAPPER_PATH = launch.WRAPPER
WRAPPER_CHECK = launch.CHECKS[0]
# Source-derived from the exact 4.14.7-1 .deb. The digest pins the entire
# wrapper; these lines force a new review if a future pin changes its dispatch.
WRAPPER_LINES = (
    (14, b'SCRIPT="$0"'),
    (29, b'OSD_HOME="$(cd "$(dirname "${SCRIPT}")/.."; pwd)"'),
    (31, b'OSD_PATH_CONF="/etc/wazuh-dashboard" OSD_NODE_OPTS_PREFIX="--no-warnings --max-http-header-size=65536" OSD_USE_NODE_JS_FILE_PATH=/src/cli/dist NODE_ENV=production exec ${OSD_HOME}/bin/use_node "${@}"'),
)
# Exact line sentinels are a review tripwire if the package pin is updated.
# The complete pinned digest, not these lines alone, identifies the script.
PIPELINE_LINES = (
    (48, b'CONFIG_DIR=${OSD_PATH_CONF:-"OSD_HOME/config"}'),
    (94, b'if [ -f "${CONFIG_DIR}/node.options" ]; then'),
    (95, b'  OSD_NODE_OPTS="$(grep -v ^# < ${CONFIG_DIR}/node.options | xargs)"'),
    (99, b'if [ ! -z "$OSD_USE_NODE_JS_FILE_PATH" ]; then'),
    (100, b'  NODE_OPTIONS="$OSD_NODE_OPTS_PREFIX $OSD_NODE_OPTS $NODE_OPTIONS"'),
    (101, b'  exec "${NODE}" ${NODE_OPTIONS} "${OSD_HOME}${OSD_USE_NODE_JS_FILE_PATH}" "${@}"'),
    (102, b'elif [ $# -ne 0 ]; then'),
    (103, b'  NODE_OPTIONS="$OSD_NODE_OPTS_PREFIX $OSD_NODE_OPTS $NODE_OPTIONS"'),
    (104, b'  exec "${NODE}" ${NODE_OPTIONS} "${@}"'),
)


def parse_node_options(raw):
    """Return only an option count; fixed errors never include input values.

    LF only. Comments must start in column zero, as in the vendor's grep.
    Active lines are exact individual tokens. No shell/xargs parsing emulation.
    """
    core.require(type(raw) is bytes and 0 < len(raw) <= MAX_OPTIONS, 'NODE_OPTIONS_SIZE')
    core.require(all(c in (9, 10) or 32 <= c <= 126 for c in raw), 'NODE_OPTIONS_FORMAT')
    tokens = set()
    for line in raw.decode('ascii').split('\n'):
        if line.startswith('#') or not line.strip(' \t'):
            continue
        core.require(line in ALLOWED, 'NODE_OPTIONS_OPTION')
        core.require(line not in tokens, 'NODE_OPTIONS_DUPLICATE')
        tokens.add(line)
    core.require(REQUIRED in tokens, 'NODE_OPTIONS_REQUIRED')
    return len(tokens)


def _config_owners(parts, identity):
    fs._components(parts, allow_empty=True)
    # Narrow configuration-tree exception; do not broaden fs.VENDOR or the
    # root-only certificate/manifest readers to accommodate this conffile.
    return ((0, 0), identity) if parts[:len(CONFIG_PARTS)] == CONFIG_PARTS else ((0, 0),)


def _read_options(identity):
    return fs._read_root(OPTIONS_PARTS, MAX_OPTIONS, lambda parts: _config_owners(parts, identity))


def _read_use_node(identity):
    core.require(USE_NODE_CHECK.path == USE_NODE_PATH and USE_NODE_CHECK.limit == USE_NODE_CHECK.size,
                 'NODE_PIPELINE_TARGET')
    return fs._read_native(PurePosixPath(USE_NODE_PATH).parts[1:], USE_NODE_CHECK.limit, identity)


def _read_wrapper(identity):
    core.require(WRAPPER_CHECK.path == WRAPPER_PATH and WRAPPER_CHECK.limit == WRAPPER_CHECK.size,
                 'NODE_WRAPPER_TARGET')
    return fs._read_native(PurePosixPath(WRAPPER_PATH).parts[1:], WRAPPER_CHECK.limit, identity)


def _check_wrapper(raw):
    core.require(WRAPPER_CHECK.path == WRAPPER_PATH and WRAPPER_CHECK.limit == WRAPPER_CHECK.size,
                 'NODE_WRAPPER_TARGET')
    core.require(type(raw) is bytes and len(raw) == WRAPPER_CHECK.size, 'NODE_WRAPPER_SIZE')
    core.require(core.sha(raw) == WRAPPER_CHECK.digest, 'NODE_WRAPPER_DIGEST')
    lines = raw.split(b'\n')
    core.require(all(len(lines) >= number and lines[number - 1] == expected
                     for number, expected in WRAPPER_LINES), 'NODE_WRAPPER_CONTRACT')


def _check_use_node(raw):
    core.require(USE_NODE_CHECK.path == USE_NODE_PATH and USE_NODE_CHECK.limit == USE_NODE_CHECK.size,
                 'NODE_PIPELINE_TARGET')
    core.require(type(raw) is bytes and len(raw) == USE_NODE_CHECK.size, 'NODE_PIPELINE_SIZE')
    core.require(core.sha(raw) == USE_NODE_CHECK.digest, 'NODE_PIPELINE_DIGEST')
    lines = raw.split(b'\n')
    core.require(all(len(lines) >= number and lines[number - 1] == expected
                     for number, expected in PIPELINE_LINES), 'NODE_PIPELINE_CONTRACT')


def _require_empty_manager_export():
    # Reuse the fixed-property, bounded query and private parser. Do not
    # return an environment entry or echo one in a diagnostic.
    core.require(not manager_env._parse(service._query_manager_environment()),
                 'MANAGER_ENV_PRESENT')


@dataclass(frozen=True)
class NodeOptionsObservation:
    option_count: int
    checked_files: int = field(default=3, init=False)
    passes: int = field(default=2, init=False)
    service_reads: int = field(default=3, init=False)
    package_reads: int = field(default=3, init=False)
    manager_export_reads: int = field(default=2, init=False)
    content_policy_passed: bool = field(default=True, init=False)
    queried_unit_sources_constrained: bool = field(default=True, init=False)
    manager_global_export_empty: bool = field(default=True, init=False)
    wrapper_bytes_match_pin: bool = field(default=True, init=False)
    wrapper_literal_config_assignment: bool = field(default=True, init=False)
    wrapper_literal_prefix_assignment: bool = field(default=True, init=False)
    launcher_bytes_match_pin: bool = field(default=True, init=False)
    source_contract_passed: bool = field(default=True, init=False)
    selected_source_proven: bool = field(default=False, init=False)
    effective_prefix_proven: bool = field(default=False, init=False)
    effective_environment_proven: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)


def observe_node_options():
    """Bracket pinned files with exact unit and manager-export observations.

    Constrains only queried unit sources and the manager's exported block.
    Proves wrapper literals, not that the conffile is selected at runtime.
    Does not read manager-process/generated/complete process environment or
    prove the effective prefix. Never executes scripts. Equal snapshots are
    not atomic and cannot prevent later edits.
    """
    service._check_tool()
    try:
        identity = fs._identity()
        package = runtime.read_package_identity()
        config = launch._configuration()
        unit_sources._constrain(config)
        _require_empty_manager_export()
        previous = None
        for _ in range(2):
            _check_wrapper(_read_wrapper(identity))
            _check_use_node(_read_use_node(identity))
            raw = _read_options(identity)
            count = parse_node_options(raw)
            core.require(previous is None or raw == previous, 'NODE_OPTIONS_CHANGED')
            previous = raw
            core.require(runtime.read_package_identity() == package, 'PACKAGE_CHANGED')
            current = launch._configuration()
            unit_sources._constrain(current)
            core.require(current == config, 'NODE_OPTIONS_CHANGED')
        _require_empty_manager_export()
        return NodeOptionsObservation(count)
    except OSError as error:
        raise core.OperatorError(fs._os_error_code(error)) from None
