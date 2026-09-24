"""Point-in-time check for direct axios shadows, not module resolution proof.

The pinned patched client imports axios by package name. Node can resolve a
nearer node_modules/axios before the packaged root copy. This observer checks
the fixed nearer candidates and root file alternatives, then pins the client
and root package JSON.
It does not execute Node, inspect every transitive import or authorize startup.
"""
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from . import operator_bootstrap as bootstrap
from . import operator_core as core
from . import operator_fs as fs
from . import operator_runtime as runtime

SHADOW_PARENTS = tuple(core.BASE + suffix for suffix in (
    'plugins/wazuhCore/server/services',
    'plugins/wazuhCore/server',
    'plugins/wazuhCore',
    'plugins',
))
SHADOW_NAMES = ('axios', 'axios.js', 'axios.json', 'axios.node')
SHADOW_TARGETS = tuple(
    (parent, ('node_modules', name))
    for parent in SHADOW_PARENTS for name in SHADOW_NAMES
) + tuple(
    (core.BASE.rstrip('/'), ('node_modules', name))
    for name in SHADOW_NAMES[1:]
)
ROOT_AXIOS = core.BASE + 'node_modules/axios/package.json'
PINNED = (core.CLIENT, ROOT_AXIOS)


def _checks(manifest):
    found = {check.path: check for check in core.installed_checks(manifest)}
    core.require(all(path in found and found[path].size is not None for path in PINNED),
                 'DEPENDENCY_MANIFEST')
    return tuple(found[path] for path in PINNED)


@dataclass(frozen=True)
class DependencyObservation:
    direct_shadow_candidates_absent: bool = field(default=True, init=False)
    shadow_candidate_count: int = field(default=len(SHADOW_TARGETS), init=False)
    pinned_files_checked: int = field(default=len(PINNED), init=False)
    passes: int = field(default=2, init=False)
    package_reads: int = field(default=3, init=False)
    root_axios_selected_proven: bool = field(default=False, init=False)
    transitive_resolution_proven: bool = field(default=False, init=False)
    effective_environment_proven: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)


def observe_direct_axios_shadow():
    """Reject fixed nearer package paths and root file alternatives.

    Equal passes do not prevent later edits in the service-owned plugin tree.
    NODE_PATH, preload hooks, alternate loaded code and transitive resolution
    remain outside this observation. No raw file or path list is returned.
    """
    fs._platform()
    try:
        identity = fs._identity()
        first = bootstrap.load_bootstrap()
        checks = _checks(first.manifest)
        reader = fs.InstalledReader(first.manifest)
        package = runtime.read_package_identity()
        for _ in range(2):
            for parent, child in SHADOW_TARGETS:
                parts = PurePosixPath(parent).parts[1:]
                core.require(fs._absent_native(parts, child, identity),
                             'DEPENDENCY_SHADOW')
            for check in checks:
                raw = reader(check.path, check.limit)
                core.require(type(raw) is bytes and len(raw) == check.size,
                             'DEPENDENCY_SIZE')
                core.require(core.sha(raw) == check.digest, 'DEPENDENCY_DIGEST')
            core.require(runtime.read_package_identity() == package, 'PACKAGE_CHANGED')
        final = bootstrap.load_bootstrap()
        core.require(final.manifest == first.manifest
                     and final.certificate_pem == first.certificate_pem,
                     'DEPENDENCY_BOOTSTRAP_CHANGED')
        return DependencyObservation()
    except OSError as error:
        raise core.OperatorError(fs._os_error_code(error)) from None
