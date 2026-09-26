"""Dormant selected-import filename checks, not a resolver or startup guard.

Requires a separately trusted root/Linux caller. No directory enumeration,
payload reads, subject execution, cache repair, process launch or writes.
Two metadata passes cannot attest earlier imports or lock future selection.
"""
from contextlib import ExitStack
from dataclasses import dataclass, field
import os

from . import operator_core as core
from . import operator_fs as fs
from . import operator_python_import_state as imports
from . import operator_python_path_importers as importers
from . import operator_python_policy as policy


def _parts(path):
    core.require(type(path) is str and path.startswith('/'), 'PY_CANDIDATE_POLICY')
    parts = tuple(path.split('/')[1:])
    fs._components(parts)
    return parts


def _candidate_policy():
    """Fixed selected names, both directory roots and declared package paths.

    Conservative: reject all non-selected peers, including later fallbacks
    and bare same-name directories, not only the first competing regular file.
    Existing __pycache__ entries are NOT sourceless FileFinder candidates.
    """
    rows = imports.SELECTED_MODULES
    origins = {_parts(origin) for _, origin, _ in rows}
    packages = {name: _parts(origin)[:-1] for name, origin, package in rows if package}
    roots = tuple(_parts(path) for path in imports.SEARCH_PATH[1:])
    suffixes = tuple(s for group in importers.SUFFIX_GROUPS for s in group)
    candidates = set()
    for name, _, package in rows:
        parent, dot, tail = name.rpartition('.')
        search = (packages[parent],) if dot else roots
        tail = tail if dot else name
        for root in search:
            candidates.add(root + (tail,))
            candidates.update(root + (tail + suffix,) for suffix in suffixes)
        if package:
            candidates.update(packages[name] + ('__init__' + suffix,) for suffix in suffixes)
    core.require(len(rows) == len(origins) == 50 and origins <= candidates, 'PY_CANDIDATE_POLICY')
    alternates = candidates - origins - set(packages.values())
    directories = {()}
    for parent in roots + tuple(path[:-1] for path in origins):
        directories.update(parent[:n] for n in range(1, len(parent) + 1))
    for path in origins | alternates:
        fs._components(path)
        core.require(path[:-1] in directories, 'PY_CANDIDATE_POLICY')
    return (tuple(sorted(origins)), tuple(sorted(alternates)),
            tuple(sorted(directories, key=lambda parts: (len(parts), parts))))


EXPECTED_PARTS, ALTERNATE_PARTS, DIRECTORY_PARTS = _candidate_policy()
EXTENSION_PARTS = _parts(policy.MAPPED_FILES[1].path)


def _root_owners(_parts):
    return ((0, 0),)


def _directory_recheck(handles, stamps):
    for parts in reversed(DIRECTORY_PARTS):
        fd = handles[parts]
        core.require(fs._stamp(os.fstat(fd)) == stamps[parts], 'FS_CHANGED')
        if parts:
            named = os.stat(parts[-1], dir_fd=handles[parts[:-1]], follow_symlinks=False)
            core.require(fs._stamp(named) == stamps[parts], 'FS_CHANGED')


def _snapshot(handles, owners_for):
    expected = []
    for parts in EXPECTED_PARTS:
        value = os.stat(parts[-1], dir_fd=handles[parts[:-1]], follow_symlinks=False)
        fs._trusted(value, False, owners_for(parts))
        core.require((value.st_size == policy.MAPPED_FILES[1].size if parts == EXTENSION_PARTS
                      else 0 < value.st_size <= policy.SOURCE_LIMIT), 'PY_CANDIDATE_SIZE')
        expected.append(fs._stamp(value))
    for parts in ALTERNATE_PARTS:
        try:
            os.stat(parts[-1], dir_fd=handles[parts[:-1]], follow_symlinks=False)
        except FileNotFoundError:
            continue
        # Includes dangling symlinks, FIFOs and directories; never open them.
        raise core.OperatorError('PY_CANDIDATE_PRESENT')
    return tuple(expected)


def _observe_at(root_fd, owners_for):
    """Private temporary-tree seam; public entry always anchors / as root."""
    with ExitStack() as stack:
        root = os.fstat(root_fd)
        fs._trusted(root, True, owners_for(()))
        handles, stamps = {(): root_fd}, {(): fs._stamp(root)}
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        for parts in DIRECTORY_PARTS[1:]:
            parent = handles[parts[:-1]]
            value = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
            fs._trusted(value, True, owners_for(parts))
            fd = os.open(parts[-1], flags, dir_fd=parent)
            stack.callback(os.close, fd)
            core.require(fs._stamp(value) == fs._stamp(os.fstat(fd)), 'FS_CHANGED')
            handles[parts], stamps[parts] = fd, fs._stamp(value)
        first = _snapshot(handles, owners_for)
        _directory_recheck(handles, stamps)
        second = _snapshot(handles, owners_for)
        core.require(first == second, 'PY_CANDIDATE_CHANGED')
        _directory_recheck(handles, stamps)


@dataclass(frozen=True)
class PythonCandidateObservation:
    selected_module_count: int = field(default=len(EXPECTED_PARTS), init=False)
    alternate_name_count: int = field(default=len(ALTERNATE_PARTS), init=False)
    passes: int = field(default=2, init=False)
    selected_origins_regular: bool = field(default=True, init=False)
    selected_alternate_names_absent: bool = field(default=True, init=False)
    on_disk_bytes_proven: bool = field(default=False, init=False)
    complete_import_coverage_proven: bool = field(default=False, init=False)
    effective_cache_redirection_proven: bool = field(default=False, init=False)
    actual_resolution_proven: bool = field(default=False, init=False)
    loaded_code_proven: bool = field(default=False, init=False)
    atomic_snapshot_proven: bool = field(default=False, init=False)
    runtime_trusted: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)


def observe_python_import_candidates():
    """Check fixed selected filenames twice while holding required directories.

    No configurable path/root/reader, observed-name auto-learning or pin refresh.
    Requires source/package/extension origins to exist as trusted regular files;
    byte pins and effective import/cache state remain separate checks. ZIP input,
    unselected modules, built-in/frozen machinery and private guard imports are
    outside this filename policy. This code cannot bootstrap its own trust.
    """
    try:
        fs._platform()
        with ExitStack() as stack:
            root_fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            stack.callback(os.close, root_fd)
            _observe_at(root_fd, _root_owners)
        return PythonCandidateObservation()
    except OSError as error:
        raise core.OperatorError(fs._os_error_code(error)) from None
