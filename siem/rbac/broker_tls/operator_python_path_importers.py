"""Dormant, candidate-specific path-import metadata checks; no resolution.

Requires an already trusted interpreter/caller. Current bootstrap objects are
mutable references, not independently authenticated code. Never invoke a hook,
finder or loader, fill/clear caches, import missing subjects or grant startup.
"""
from dataclasses import dataclass, field
from types import CodeType, FunctionType

from . import operator_core as core
from . import operator_fs as fs
from . import operator_python_import_state as imports


# Proposed release-build Linux x86-64 policy, NOT measured by gates B2/C2.
SUFFIX_GROUPS = (('.cpython-314-x86_64-linux-gnu.so', '.abi3.so', '.so'),
                 ('.py',), ('.pyc',))
LOADER_NAMES = ('ExtensionFileLoader', 'SourceFileLoader', 'SourcelessFileLoader')
DIRECTORY_PATHS = imports.SEARCH_PATH[1:] + tuple(
    origin.rsplit('/', 1)[0] for _, origin, package in imports.SELECTED_MODULES if package)
ZIP_PATH = imports.SEARCH_PATH[0]
MAX_DIRECTORY_ENTRIES = 8192
FINDER_FIELDS = frozenset(('path', '_loaders', '_path_mtime', '_path_cache', '_relaxed_path_cache'))


def _pairs(value, classes, refs, *, flattened=False):
    expected = (tuple((suffix, cls) for cls, suffixes in zip(classes, SUFFIX_GROUPS)
                      for suffix in suffixes) if flattened else tuple(zip(classes, SUFFIX_GROUPS)))
    core.require(type(value) is (list if flattened else tuple) and len(value) == len(expected),
                 'PY_PATH_LOADERS')
    refs.append(value)
    for actual, wanted in zip(value, expected):
        core.require(type(actual) is tuple and len(actual) == 2, 'PY_PATH_LOADERS')
        refs.append(actual)
        if flattened:
            core.require(type(actual[0]) is str and actual[0] == wanted[0] and actual[1] is wanted[1],
                         'PY_PATH_LOADERS')
        else:
            core.require(actual[0] is wanted[0], 'PY_PATH_LOADERS')
            imports._strings(actual[1], wanted[1], 'PY_PATH_LOADERS')
            refs.append(actual[1])


def _hook(hook, finder_class, external, classes, refs):
    # Inspect the descriptor without binding/calling FileFinder.path_hook.
    factory_descriptor = vars(finder_class).get('path_hook')
    core.require(type(factory_descriptor) is classmethod, 'PY_PATH_HOOK')
    factory = factory_descriptor.__func__
    core.require(type(factory) is FunctionType and factory.__globals__ is external, 'PY_PATH_HOOK')
    nested = tuple(code for code in factory.__code__.co_consts
                   if type(code) is CodeType and code.co_name == 'path_hook_for_FileFinder')
    core.require(len(nested) == 1 and type(hook) is FunctionType and hook.__code__ is nested[0] and
                 hook.__globals__ is external and hook.__defaults__ is None and
                 hook.__kwdefaults__ is None and not hook.__dict__, 'PY_PATH_HOOK')
    core.require(hook.__code__.co_freevars == ('cls', 'loader_details') and
                 type(hook.__closure__) is tuple and len(hook.__closure__) == 2, 'PY_PATH_HOOK')
    cells = hook.__closure__
    core.require(cells[0].cell_contents is finder_class, 'PY_PATH_HOOK')
    _pairs(cells[1].cell_contents, classes, refs)
    refs.extend((factory_descriptor, factory, factory.__code__, nested[0], hook,
                 hook.__closure__, cells[0], cells[1]))


def _directory_cache(value):
    core.require(type(value) is set and len(value) <= MAX_DIRECTORY_ENTRIES, 'PY_PATH_DIRECTORY_CACHE')
    core.require(all(type(name) is str and 0 < len(name) <= 255 and
                     '/' not in name and '\0' not in name and name not in ('.', '..') for name in value),
                 'PY_PATH_DIRECTORY_CACHE')
    return tuple(sorted(value))


def _capture():
    imports._settings()
    host = imports.sys
    modules = host.modules
    core.require(type(modules) is dict and 2 <= len(modules) <= imports.MAX_MODULES, 'PY_PATH_MODULES')
    external_module, zip_module = modules.get('_frozen_importlib_external'), modules.get('zipimport')
    external, zipdict = imports._module_dict(external_module), imports._module_dict(zip_module)
    finder_class, zip_class = external.get('FileFinder'), zipdict.get('zipimporter')
    classes = tuple(external.get(name) for name in LOADER_NAMES)
    core.require(all(type(cls) is type for cls in (finder_class, zip_class) + classes), 'PY_PATH_CLASSES')
    hooks, cache = host.path_hooks, host.path_importer_cache
    core.require(type(hooks) is list and len(hooks) == 2 and hooks[0] is zip_class, 'PY_PATH_HOOKS')
    refs = [modules, external_module, zip_module, external, zipdict, finder_class, zip_class,
            *classes, hooks, cache]
    _hook(hooks[1], finder_class, external, classes, refs)
    core.require(type(cache) is dict and len(cache) <= len(DIRECTORY_PATHS) + 1, 'PY_PATH_CACHE')
    core.require(all(type(path) is str and path in DIRECTORY_PATHS + (ZIP_PATH,) for path in cache),
                 'PY_PATH_CACHE_KEY')
    # Entries may be absent after legitimate invalidation; never populate them.
    # An existing ZIP entry must be the negative-cache sentinel, not a finder.
    records = []
    for path in sorted(cache):
        finder = cache[path]
        if path == ZIP_PATH:
            core.require(finder is None, 'PY_PATH_ZIP_CACHE')
            records.append((path, None, ()))
            continue
        core.require(type(finder) is finder_class, 'PY_PATH_FINDER')
        fd = object.__getattribute__(finder, '__dict__')
        core.require(type(fd) is dict and all(type(key) is str for key in fd) and
                     fd.keys() == FINDER_FIELDS, 'PY_PATH_FINDER_FIELDS')
        core.require(type(fd['path']) is str and fd['path'] == path, 'PY_PATH_FINDER_PATH')
        _pairs(fd['_loaders'], classes, refs, flattened=True)
        mtime = fd['_path_mtime']
        core.require(type(mtime) in (int, float) and -1 <= mtime < float('inf'), 'PY_PATH_DIRECTORY_CACHE')
        names = _directory_cache(fd['_path_cache'])
        relaxed = _directory_cache(fd['_relaxed_path_cache'])
        core.require(not relaxed, 'PY_PATH_DIRECTORY_CACHE')  # candidate is Linux, case-sensitive
        refs.extend((finder, fd, fd['_path_cache'], fd['_relaxed_path_cache']))
        records.append((path, mtime, names))
    return tuple(refs), tuple(records)


@dataclass(frozen=True)
class PythonPathImporterObservation:
    cached_path_count: int
    passes: int = field(default=2, init=False)
    candidate_hook_metadata_matches: bool = field(default=True, init=False)
    cached_finder_metadata_matches: bool = field(default=True, init=False)
    hook_code_authenticated: bool = field(default=False, init=False)
    directory_contents_proven: bool = field(default=False, init=False)
    bytecode_exclusion_proven: bool = field(default=False, init=False)
    complete_module_inventory_proven: bool = field(default=False, init=False)
    actual_resolution_proven: bool = field(default=False, init=False)
    atomic_snapshot_proven: bool = field(default=False, init=False)
    runtime_trusted: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)


def observe_python_path_importers():
    """Compare bounded current metadata twice; no imports or cache repair.

    This candidate accepts only the standard ZIP/FileFinder hook shape and
    cached finders for the two stdlib roots and six selected package paths.
    Optional/missing cache keys need no resolution. Directory caches contain
    filenames, not proof of filesystem contents, and .pyc loaders remain part
    of the default machinery. This is not proof of source-only execution.
    """
    fs._platform()
    try:
        first, second = _capture(), _capture()
    except (AttributeError, KeyError, TypeError, ValueError, RuntimeError):
        raise core.OperatorError('PY_PATH_STATE') from None
    core.require(len(first[0]) == len(second[0]) and
                 all(old is new for old, new in zip(first[0], second[0])) and first[1] == second[1],
                 'PY_PATH_CHANGED')
    return PythonPathImporterObservation(len(second[1]))
