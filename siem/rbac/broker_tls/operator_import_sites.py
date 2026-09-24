"""Offline shadow check from every pinned package code-file directory.

This over-approximates possible CommonJS import sites for declared package
dependencies. It does not discover executed imports or attest Node resolution.
"""
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from . import operator_bootstrap as bootstrap
from . import operator_core as core
from . import operator_dependency_graph as graph
from . import operator_fs as fs
from . import operator_runtime as runtime

CODE_SUFFIXES = ('.js', '.cjs', '.mjs', '.node')
MAX_CODE_FILES = 256
MAX_SITE_DIRS = 128
MAX_SITE_PAIRS = 256
MAX_SHADOWS = 768


def _inventory(manifest):
    checks = core.installed_checks(manifest)
    client, packages = graph._package_checks(manifest)
    sources = {}
    sites = {root: set() for root in packages}
    for check in checks:
        if not (check.path.startswith(core.BASE + 'node_modules/')
                and check.path.endswith(CODE_SUFFIXES)):
            continue
        owners = [root for root in packages if check.path.startswith(root + '/')]
        core.require(len(owners) > 0 and check.size is not None, 'SITE_MANIFEST')
        owner = max(owners, key=len)
        sources[check.path] = check
        sites[owner].add(str(PurePosixPath(check.path).parent))
    core.require(1 <= len(sources) <= MAX_CODE_FILES
                 and all(sites.values())
                 and sum(map(len, sites.values())) <= MAX_SITE_DIRS,
                 'SITE_MANIFEST')
    return client, packages, tuple(sources[path] for path in sorted(sources)), sites


def _plan_sites(packages, dependencies, sites):
    """Over-approximate declared bare imports from all pinned code locations."""
    package_count, edge_count, package_shadows = graph._plan(packages, dependencies)
    expected = {}
    for root in sorted(packages):
        for name in dependencies[root]:
            selected = next((slot for slot in graph._slots(root, name)
                             if slot in packages), None)
            core.require(selected is not None, 'SITE_MISSING')
            expected[root, name] = selected
    core.require(set(sites) == set(packages) and all(sites.values()), 'SITE_MANIFEST')
    shadows = set(package_shadows)
    core.require(len(shadows) <= MAX_SHADOWS, 'SITE_LIMIT')
    pairs = 0
    for root in sorted(sites):
        for site in sorted(sites[root]):
            core.require(site == root or site.startswith(root + '/'), 'SITE_MANIFEST')
            for name in dependencies[root]:
                pairs += 1
                core.require(pairs <= MAX_SITE_PAIRS, 'SITE_LIMIT')
                earlier = []
                selected = None
                for slot in graph._slots(site, name):
                    if slot in packages:
                        selected = slot
                        break
                    earlier.append(slot)
                core.require(selected is not None, 'SITE_MISSING')
                core.require(selected == expected[root, name], 'SITE_SELECTION')
                for slot in earlier:
                    parent = str(PurePosixPath(slot).parent.parent)
                    base = PurePosixPath(slot).name
                    shadows.update((parent, ('node_modules', base + suffix))
                                   for suffix in graph.SUFFIXES)
                parent = str(PurePosixPath(selected).parent.parent)
                shadows.update((parent, ('node_modules', name + suffix))
                               for suffix in graph.SUFFIXES[1:])
                core.require(len(shadows) <= MAX_SHADOWS, 'SITE_LIMIT')
    return package_count, edge_count, sum(map(len, sites.values())), pairs, tuple(sorted(shadows))


@dataclass(frozen=True)
class SiteObservation:
    declared_packages_checked: int
    declared_edges_checked: int
    pinned_code_files_checked: int
    distinct_code_directories_checked: int
    site_dependency_pairs_checked: int
    shadow_candidates_checked: int
    passes: int = field(default=2, init=False)
    pinned_code_sites_observed: bool = field(default=True, init=False)
    executed_imports_proven: bool = field(default=False, init=False)
    unlisted_code_absent_proven: bool = field(default=False, init=False)
    actual_node_resolution_proven: bool = field(default=False, init=False)
    loaded_code_proven: bool = field(default=False, init=False)
    effective_environment_proven: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)


def observe_pinned_import_sites():
    """Reject shadows at pinned code-file directories, twice and fail closed.

    Code may still import dynamically, originate in unlisted files or change
    after inspection. This is not a complete dependency or startup guard.
    """
    fs._platform()
    try:
        identity = fs._identity()
        first = bootstrap.load_bootstrap()
        client, packages, sources, sites = _inventory(first.manifest)
        reader = fs.InstalledReader(first.manifest)
        package = runtime.read_package_identity()
        previous = None
        for _ in range(2):
            graph._read_pinned(reader, client)
            dependencies = {
                root: graph._metadata(graph._read_pinned(reader, check),
                                      PurePosixPath(root).name)
                for root, check in sorted(packages.items())
            }
            for check in sources:
                graph._read_pinned(reader, check)
            current = _plan_sites(packages, dependencies, sites)
            core.require(previous is None or current == previous, 'SITE_CHANGED')
            previous = current
            for parent, child in current[4]:
                core.require(fs._absent_native(PurePosixPath(parent).parts[1:],
                                               child, identity), 'SITE_SHADOW')
            core.require(runtime.read_package_identity() == package, 'PACKAGE_CHANGED')
        final = bootstrap.load_bootstrap()
        core.require(final.manifest == first.manifest
                     and final.certificate_pem == first.certificate_pem,
                     'SITE_BOOTSTRAP_CHANGED')
        return SiteObservation(previous[0], previous[1], len(sources), previous[2],
                               previous[3], len(previous[4]))
    except OSError as error:
        raise core.OperatorError(fs._os_error_code(error)) from None
