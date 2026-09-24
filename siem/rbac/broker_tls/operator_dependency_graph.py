"""Bounded, point-in-time declared axios dependency-graph observation.

This follows only package.json ``dependencies`` in the pinned candidate
inventory. It rejects CommonJS file/directory candidates in search slots
starting at each package root, NOT at the actual importing file's directory.
It does not execute Node or prove actual imports, self-resolution or loaded code.
"""
from dataclasses import dataclass, field
import json
from pathlib import PurePosixPath
import re

from . import operator_bootstrap as bootstrap
from . import operator_core as core
from . import operator_dependency as direct
from . import operator_fs as fs
from . import operator_runtime as runtime

ROOT = core.BASE + 'node_modules/axios'
MAX_PACKAGES = 64
MAX_EDGES = 256
MAX_SHADOWS = 512
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]*\Z')
SUFFIXES = ('', '.js', '.json', '.node')


def _package_checks(manifest):
    checks = core.installed_checks(manifest)
    packages = {}
    client = None
    for check in checks:
        if check.path == core.CLIENT:
            client = check
        if not check.path.startswith(core.BASE + 'node_modules/') or not check.path.endswith('/package.json'):
            continue
        root = check.path.removesuffix('/package.json')
        parts = PurePosixPath(root).parts
        core.require(len(parts) >= 2 and parts[-2] == 'node_modules'
                     and NAME.fullmatch(parts[-1]) is not None
                     and check.size is not None, 'GRAPH_MANIFEST')
        packages[root] = check
    core.require(client is not None and client.size is not None
                 and ROOT in packages and 1 <= len(packages) <= MAX_PACKAGES,
                 'GRAPH_MANIFEST')
    return client, packages


def _read_pinned(reader, check):
    raw = reader(check.path, check.limit)
    core.require(type(raw) is bytes and len(raw) == check.size, 'GRAPH_SIZE')
    core.require(core.sha(raw) == check.digest, 'GRAPH_DIGEST')
    return raw


def _metadata(raw, expected_name):
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=core.unique,
                           parse_constant=core.reject_constant)
    except (ValueError, UnicodeError, RecursionError, core.OperatorError):
        raise core.OperatorError('GRAPH_METADATA') from None
    core.require(type(value) is dict and value.get('name') == expected_name,
                 'GRAPH_METADATA')
    dependencies = value.get('dependencies', {})
    core.require(type(dependencies) is dict and len(dependencies) <= MAX_EDGES
                 and all(type(name) is str and NAME.fullmatch(name) is not None
                         and type(version) is str and len(version) <= 256
                         for name, version in dependencies.items()), 'GRAPH_METADATA')
    return tuple(sorted(dependencies))


def _slots(root, name):
    """Package-root-origin search slots within BASE, not actual import sites."""
    for directory in (PurePosixPath(root), *PurePosixPath(root).parents):
        if directory.name == 'node_modules':
            continue
        if str(directory) == core.BASE.rstrip('/'):
            yield str(directory / 'node_modules' / name)
            return
        if not str(directory).startswith(core.BASE):
            break
        yield str(directory / 'node_modules' / name)
    raise core.OperatorError('GRAPH_PATH')


def _plan(packages, dependencies):
    """Return the declared reachable graph and its unique shadow targets."""
    roots = frozenset(packages)
    core.require(roots == frozenset(dependencies) and ROOT in roots, 'GRAPH_MANIFEST')
    seen = set()
    edges = []
    shadows = set(direct.SHADOW_TARGETS)

    def visit(root):
        if root in seen:
            return
        seen.add(root)
        for name in dependencies[root]:
            candidates = []
            selected = None
            for candidate in _slots(root, name):
                if candidate in roots:
                    selected = candidate
                    break
                candidates.append(candidate)
            core.require(selected is not None, 'GRAPH_MISSING')
            edges.append((root, name, selected))
            core.require(len(edges) <= MAX_EDGES, 'GRAPH_LIMIT')
            for candidate in candidates:
                parent = str(PurePosixPath(candidate).parent.parent)
                base = PurePosixPath(candidate).name
                shadows.update((parent, ('node_modules', base + suffix)) for suffix in SUFFIXES)
            # LOAD_AS_FILE precedes LOAD_AS_DIRECTORY at the selected slot.
            parent = str(PurePosixPath(selected).parent.parent)
            shadows.update((parent, ('node_modules', name + suffix))
                           for suffix in SUFFIXES[1:])
            core.require(len(shadows) <= MAX_SHADOWS, 'GRAPH_LIMIT')
            visit(selected)

    visit(ROOT)
    core.require(seen == roots, 'GRAPH_ORPHAN')
    return len(seen), len(edges), tuple(sorted(shadows))


@dataclass(frozen=True)
class GraphObservation:
    declared_packages_checked: int
    declared_edges_checked: int
    shadow_candidates_checked: int
    passes: int = field(default=2, init=False)
    declared_graph_and_shadows_observed: bool = field(default=True, init=False)
    package_root_search_only: bool = field(default=True, init=False)
    import_sites_proven: bool = field(default=False, init=False)
    actual_node_resolution_proven: bool = field(default=False, init=False)
    loaded_code_proven: bool = field(default=False, init=False)
    effective_environment_proven: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)


def observe_declared_axios_graph():
    """Observe pinned declared dependencies and absent nearer candidates twice.

    A nested importer can have nearer paths than its package root; those and
    dynamic imports are outside this observation. This is not a stable snapshot
    of the service-owned plugin tree or startup approval.
    """
    fs._platform()
    try:
        identity = fs._identity()
        first = bootstrap.load_bootstrap()
        client, packages = _package_checks(first.manifest)
        reader = fs.InstalledReader(first.manifest)
        package = runtime.read_package_identity()
        previous = None
        for _ in range(2):
            _read_pinned(reader, client)
            dependencies = {
                root: _metadata(_read_pinned(reader, check), PurePosixPath(root).name)
                for root, check in sorted(packages.items())
            }
            current = _plan(packages, dependencies)
            core.require(previous is None or current == previous, 'GRAPH_CHANGED')
            previous = current
            for parent, child in current[2]:
                parts = PurePosixPath(parent).parts[1:]
                core.require(fs._absent_native(parts, child, identity), 'GRAPH_SHADOW')
            core.require(runtime.read_package_identity() == package, 'PACKAGE_CHANGED')
        final = bootstrap.load_bootstrap()
        core.require(final.manifest == first.manifest
                     and final.certificate_pem == first.certificate_pem,
                     'GRAPH_BOOTSTRAP_CHANGED')
        return GraphObservation(previous[0], previous[1], len(previous[2]))
    except OSError as error:
        raise core.OperatorError(fs._os_error_code(error)) from None
