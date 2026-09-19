"""Read-only policy for one fixed conffile, NOT effective launch authorization.

The shipped wrapper uses grep -v ^# and xargs, then unquoted shell expansion.
Accept a deliberately small grammar with no quoting/expansion ambiguities;
never source the file or execute the wrapper/Node to inspect its behavior.
"""
from dataclasses import dataclass, field

from . import operator_core as core
from . import operator_fs as fs
from . import operator_launch as launch
from . import operator_runtime as runtime
from . import operator_service as service

CONFIG_PARTS = ('etc', 'wazuh-dashboard')
OPTIONS_PARTS = CONFIG_PARTS + ('node.options',)
MAX_OPTIONS = 16384
# Stock active option plus the exact example shipped commented-out in 4.14.7-1.
# Deliberately not all Node options or a general memory/performance approval.
ALLOWED = frozenset(('--unhandled-rejections=warn', '--max-old-space-size=4096'))
REQUIRED = '--unhandled-rejections=warn'


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


@dataclass(frozen=True)
class NodeOptionsObservation:
    option_count: int
    checked_files: int = field(default=1, init=False)
    passes: int = field(default=2, init=False)
    service_reads: int = field(default=3, init=False)
    package_reads: int = field(default=3, init=False)
    content_policy_passed: bool = field(default=True, init=False)
    selected_source_proven: bool = field(default=False, init=False)
    effective_environment_proven: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)


def observe_node_options():
    """Bracket two fixed-file reads with package and private manager snapshots.

    Does not follow OSD_PATH_CONF or EnvironmentFiles, read inherited/process
    environment, or establish that this file is selected. Works when the service
    is inactive; invokes only the existing bounded read-only busctl adapter.
    File/service/package equality is not atomic and cannot prevent later edits.
    """
    service._check_tool()
    try:
        identity = fs._identity()
        package = runtime.read_package_identity()
        config = launch._configuration()
        previous = None
        for _ in range(2):
            raw = _read_options(identity)
            count = parse_node_options(raw)
            core.require(previous is None or raw == previous, 'NODE_OPTIONS_CHANGED')
            previous = raw
            core.require(runtime.read_package_identity() == package, 'PACKAGE_CHANGED')
            core.require(launch._configuration() == config, 'NODE_OPTIONS_CHANGED')
        return NodeOptionsObservation(count)
    except OSError as error:
        raise core.OperatorError(fs._os_error_code(error)) from None
