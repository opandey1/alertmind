"""Read-only closure check for files inside the pinned axios package roots.

An extra file inside a selected package can be imported without appearing in
the candidate manifest. This checks the installed file names and metadata via
held, no-follow directory descriptors. It neither executes Node nor locks the
service-owned tree against subsequent edits.
"""
from contextlib import ExitStack
from dataclasses import dataclass, field
import os
from pathlib import PurePosixPath
import stat

from . import operator_bootstrap as bootstrap
from . import operator_core as core
from . import operator_dependency_graph as graph
from . import operator_fs as fs
from . import operator_runtime as runtime

MAX_ENTRIES = 8192
MAX_DEPTH = 64


def _plan(manifest):
    checks = core.installed_checks(manifest)
    _, packages = graph._package_checks(manifest)
    roots = tuple(sorted(packages))
    outer = tuple(root for root in roots if not any(
        root.startswith(other + '/') for other in roots if other != root))
    files = frozenset(PurePosixPath(check.path).parts[1:] for check in checks
                      if check.path.startswith(core.BASE + 'node_modules/'))
    root_parts = tuple(PurePosixPath(root).parts[1:] for root in roots)
    outer_parts = tuple(PurePosixPath(root).parts[1:] for root in outer)
    core.require(files and all(any(path[:len(prefix)] == prefix for prefix in root_parts)
                               for path in files), 'FILE_SET_MANIFEST')
    core.require(all(any(path[:len(prefix)] == prefix for prefix in outer_parts)
                     for path in files), 'FILE_SET_MANIFEST')
    for path in files:
        fs._components(path)
    return roots, outer, files


def _walk_at(root_fd, root_parts, expected, owners_for, budget):
    """Inspect one package root below a held FD; the caller owns root_fd.

    This private primitive accepts a test tree. Production uses only `/` and
    manifest-derived fixed roots. It never follows a discovered symlink.
    """
    fs._components(root_parts)
    core.require(type(expected) is frozenset and expected, 'FILE_SET_MANIFEST')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    with ExitStack() as stack:
        root_before = os.fstat(root_fd)
        fs._trusted(root_before, True, owners_for(()))
        ancestors = []
        parent = root_fd
        parts = ()
        for name in root_parts:
            parts += (name,)
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            fs._trusted(before, True, owners_for(parts))
            opened = os.open(name, flags, dir_fd=parent)
            stack.callback(os.close, opened)
            core.require(fs._stamp(before) == fs._stamp(os.fstat(opened)), 'FILE_SET_CHANGED')
            ancestors.append((parent, name, opened, before))
            parent = opened

        found = {}
        regular_files = set()
        def scan(directory, path, depth):
            core.require(depth <= MAX_DEPTH, 'FILE_SET_LIMIT')
            initial = os.fstat(directory)
            fs._trusted(initial, True, owners_for(path))
            found[path] = fs._stamp(initial)
            budget[1] += 1
            core.require(budget[1] <= MAX_ENTRIES, 'FILE_SET_LIMIT')
            with os.scandir(directory) as entries:
                for entry in entries:
                    name = entry.name
                    fs._components((name,))
                    budget[0] += 1
                    core.require(budget[0] <= MAX_ENTRIES, 'FILE_SET_LIMIT')
                    child = path + (name,)
                    before = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    # Never use DirEntry's cached type or path. The fresh stat
                    # and a no-follow open are the only type/identity evidence.
                    is_dir = stat.S_ISDIR(before.st_mode)
                    fs._trusted(before, is_dir, owners_for(child))
                    if is_dir:
                        opened = os.open(name, flags, dir_fd=directory)
                        try:
                            core.require(fs._stamp(before) == fs._stamp(os.fstat(opened)),
                                         'FILE_SET_CHANGED')
                            scan(opened, child, depth + 1)
                            core.require(fs._stamp(before) == fs._stamp(os.fstat(opened))
                                         == fs._stamp(os.stat(name, dir_fd=directory,
                                                              follow_symlinks=False)),
                                         'FILE_SET_CHANGED')
                        finally:
                            os.close(opened)
                    else:
                        core.require(child in expected, 'FILE_SET_UNLISTED')
                        opened = os.open(name, os.O_RDONLY | os.O_NOFOLLOW |
                                         os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
                        try:
                            core.require(fs._stamp(before) == fs._stamp(os.fstat(opened))
                                         == fs._stamp(os.stat(name, dir_fd=directory,
                                                              follow_symlinks=False)),
                                         'FILE_SET_CHANGED')
                        finally:
                            os.close(opened)
                        found[child] = fs._stamp(before)
                        regular_files.add(child)
            core.require(fs._stamp(initial) == fs._stamp(os.fstat(directory)),
                         'FILE_SET_CHANGED')

        scan(parent, root_parts, 0)
        core.require(regular_files == expected, 'FILE_SET_MISSING')
        for held_parent, name, opened, before in reversed(ancestors):
            core.require(fs._stamp(before) == fs._stamp(os.fstat(opened))
                         == fs._stamp(os.stat(name, dir_fd=held_parent,
                                              follow_symlinks=False)),
                         'FILE_SET_CHANGED')
        core.require(fs._stamp(root_before) == fs._stamp(os.fstat(root_fd)),
                     'FILE_SET_CHANGED')
        return found


def _walk_native(root, expected, identity, budget):
    parts = PurePosixPath(root).parts[1:]
    core.require(root.startswith(core.BASE + 'node_modules/'), 'FILE_SET_TARGET')
    fs._components(parts)
    with ExitStack() as stack:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        stack.callback(os.close, fd)
        return _walk_at(fd, parts, expected,
                        lambda path: fs._owners(path, identity), budget)


@dataclass(frozen=True)
class FileSetObservation:
    package_roots_checked: int
    outer_roots_scanned: int
    manifest_files_seen: int
    directory_entries_seen: int
    directories_seen: int
    passes: int = field(default=2, init=False)
    package_root_file_set_observed: bool = field(default=True, init=False)
    file_bytes_verified: bool = field(default=False, init=False)
    unlisted_files_outside_package_roots_excluded: bool = field(default=False, init=False)
    actual_node_resolution_proven: bool = field(default=False, init=False)
    loaded_code_proven: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)


def observe_package_file_set():
    """Two bounded scans of selected package roots; no VM mutation or start.

    The result is a point-in-time file-set observation, not an atomic snapshot.
    Other Dashboard package trees and external Node lookup paths are outside it.
    """
    fs._platform()
    core.require(os.scandir in os.supports_fd, 'FILE_SET_PLATFORM')
    try:
        identity = fs._identity()
        first = bootstrap.load_bootstrap()
        roots, outer, files = _plan(first.manifest)
        package = runtime.read_package_identity()
        previous = None
        counts = None
        for _ in range(2):
            budget = [0, 0]
            observed = {}
            for root in outer:
                prefix = PurePosixPath(root).parts[1:]
                selected = frozenset(path for path in files if path[:len(prefix)] == prefix)
                core.require(selected, 'FILE_SET_MANIFEST')
                observed.update(_walk_native(root, selected, identity, budget))
            core.require(previous is None or observed == previous, 'FILE_SET_CHANGED')
            previous, counts = observed, budget
            core.require(runtime.read_package_identity() == package, 'PACKAGE_CHANGED')
        final = bootstrap.load_bootstrap()
        core.require((final.manifest, final.certificate_pem)
                     == (first.manifest, first.certificate_pem), 'FILE_SET_BOOTSTRAP_CHANGED')
        return FileSetObservation(len(roots), len(outer), len(files), counts[0], counts[1])
    except OSError as error:
        raise core.OperatorError(fs._os_error_code(error)) from None
