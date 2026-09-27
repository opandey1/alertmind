"""Dormant in-process import-state observations, not runtime attestation.

The caller/interpreter must already be trusted. Mutable sys/module metadata
cannot prove which bytes executed. No imports of missing subjects, finder or
loader calls, file reads, environment changes, process launch or activation.
"""
from dataclasses import dataclass, field
import sys
from types import ModuleType

from . import operator_core as core
from . import operator_fs as fs
from . import operator_python_policy as policy


SEARCH_PATH = ('/usr/lib/python314.zip', '/usr/lib/python3.14',
               '/usr/lib/python3.14/lib-dynload')
CACHE_PREFIX = '/dev/null/alertmind-c2'
FLAG_VALUES = (('isolated', 1), ('ignore_environment', 1), ('no_site', 1),
               ('no_user_site', 1), ('dont_write_bytecode', 1), ('optimize', 0))
MAX_MODULES = 1024
# C1 source paths encode their B2 dotted names; __init__.py denotes a package.
SELECTED_MODULES = (('_hashlib', policy.MAPPED_FILES[1].path, False),) + tuple(
    (pin.path.removeprefix('/usr/lib/python3.14/').removesuffix('/__init__.py')
     .removesuffix('.py').replace('/', '.'), pin.path, pin.path.endswith('/__init__.py'))
    for pin in policy.SOURCE_FILES)


def _strings(value, expected, code):
    core.require(type(value) is list and len(value) == len(expected) and
                 all(type(item) is str for item in value) and tuple(value) == expected, code)


def _module_dict(module):
    # Exact type avoids executing a custom object's properties/__getattr__.
    core.require(type(module) is ModuleType, 'PY_IMPORT_MODULE')
    return vars(module)


def _settings():
    version = sys.version_info
    core.require(type(sys.platform) is str and sys.platform == 'linux' and
                 type(sys.executable) is str and sys.executable == '/usr/bin/python3.14' and
                 isinstance(version, tuple) and len(version) == 5 and
                 all(type(version[i]) is int for i in (0, 1, 2, 4)) and
                 type(version[3]) is str and tuple(version) == (3, 14, 4, 'final', 0) and
                 type(sys.implementation.name) is str and sys.implementation.name == 'cpython' and
                 type(sys.implementation.cache_tag) is str and
                 sys.implementation.cache_tag == 'cpython-314', 'PY_IMPORT_RUNTIME')
    for name, expected in FLAG_VALUES:
        value = getattr(sys.flags, name, None)
        core.require(type(value) is int and value == expected, 'PY_IMPORT_FLAGS')
    core.require(getattr(sys.flags, 'safe_path', None) is True and
                 sys.dont_write_bytecode is True, 'PY_IMPORT_FLAGS')
    _strings(sys.orig_argv, policy.CANDIDATE_ARGV, 'PY_IMPORT_ARGV')
    _strings(sys.argv, (policy.CANDIDATE_ARGV[-1],), 'PY_IMPORT_ARGV')
    _strings(sys.path, SEARCH_PATH, 'PY_IMPORT_PATH')
    core.require(type(sys.pycache_prefix) is str and sys.pycache_prefix == CACHE_PREFIX and
                 type(sys._xoptions) is dict and len(sys._xoptions) == 1 and
                 type(sys._xoptions.get('pycache_prefix')) is str and
                 sys._xoptions['pycache_prefix'] == CACHE_PREFIX, 'PY_IMPORT_CACHE_PREFIX')


def _check_finders(finders, held_finder, code):
    """Allow only defaults, or the exact entry-defined held deny-finder first.

    Full registry/table checks belong to the entry before and after this call.
    No finder is removed, invoked or accepted by its display name alone.
    """
    meta = sys.meta_path
    core.require(type(meta) is list, code)
    if held_finder is None:
        core.require(len(meta) == 3 and all(a is b for a, b in zip(meta, finders)), code)
        return
    main = _module_dict(sys.modules.get('__main__'))
    cls = main.get('_DenyHeldFallback')
    core.require(type(cls) is type and type(held_finder) is cls and
                 main.get('__file__') == policy.CANDIDATE_ARGV[-1] and
                 len(meta) == 4 and meta[0] is held_finder and
                 all(a is b for a, b in zip(meta[1:], finders)), code)
    fields = object.__getattribute__(held_finder, '__dict__')
    function = vars(cls).get('find_spec')
    core.require(type(fields) is dict and not fields and
                 type(function) is type(lambda: None) and function.__globals__ is main and
                 function.__code__.co_filename == policy.CANDIDATE_ARGV[-1], code)


def _capture(held_finder=None):
    _settings()
    modules = sys.modules
    core.require(type(modules) is dict and len(SELECTED_MODULES) <= len(modules) <= MAX_MODULES,
                 'PY_IMPORT_MODULE_TABLE')
    builtin = _module_dict(modules.get('_frozen_importlib'))
    external = _module_dict(modules.get('_frozen_importlib_external'))
    helpers = (builtin.get('ModuleSpec'), external.get('SourceFileLoader'),
               external.get('ExtensionFileLoader'))
    finders = (builtin.get('BuiltinImporter'), builtin.get('FrozenImporter'), external.get('PathFinder'))
    core.require(all(type(item) is type for item in helpers + finders), 'PY_IMPORT_MACHINERY')
    # Compare objects, not attacker-supplied finder class-name strings.
    _check_finders(finders, held_finder, 'PY_IMPORT_META_PATH')
    records = []
    for name, origin, package in SELECTED_MODULES:
        module = modules.get(name)
        md = _module_dict(module)
        spec = md.get('__spec__')
        core.require(type(spec) is helpers[0], 'PY_IMPORT_SPEC')
        sd = vars(spec)
        core.require(type(md.get('__name__')) is str and md['__name__'] == name and
                     type(sd.get('name')) is str and sd['name'] == name, 'PY_IMPORT_NAME')
        core.require(type(md.get('__file__')) is str and md['__file__'] == origin and
                     type(sd.get('origin')) is str and sd['origin'] == origin and
                     sd.get('_set_fileattr') is True, 'PY_IMPORT_ORIGIN')
        loader = sd.get('loader')
        source = origin.endswith('.py')
        core.require(type(loader) is helpers[1 if source else 2] and md.get('__loader__') is loader,
                     'PY_IMPORT_LOADER')
        ld = vars(loader)
        core.require(type(ld.get('name')) is str and ld['name'] == name and
                     type(ld.get('path')) is str and ld['path'] == origin, 'PY_IMPORT_LOADER')
        cached = CACHE_PREFIX + origin[:-3] + '.cpython-314.pyc' if source else None
        # Do not call ModuleSpec.cached: inspect already-materialized metadata.
        # C2's diagnostic called that property, not evidence that code was read.
        for value in (md.get('__cached__'), sd.get('_cached')):
            core.require((value is None if cached is None else type(value) is str and value == cached),
                         'PY_IMPORT_CACHE_PATH')
        if package:
            expected_path = (origin.rsplit('/', 1)[0],)
            _strings(md.get('__path__'), expected_path, 'PY_IMPORT_PACKAGE_PATH')
            _strings(sd.get('submodule_search_locations'), expected_path, 'PY_IMPORT_PACKAGE_PATH')
        else:
            core.require(md.get('__path__') is None and sd.get('submodule_search_locations') is None,
                         'PY_IMPORT_PACKAGE_PATH')
        if '.' in name:
            parent, child = name.rsplit('.', 1)
            core.require(_module_dict(modules.get(parent)).get(child) is module, 'PY_IMPORT_PARENT_BINDING')
        # Retain object references between passes, so ID reuse cannot disguise
        # replacement. Comparisons below use identity, never user equality.
        records.append((module, spec, loader))
    return (modules, len(modules), helpers + finders, tuple(records))


@dataclass(frozen=True)
class PythonImportObservation:
    observed_module_count: int
    selected_module_count: int = field(default=50, init=False)
    passes: int = field(default=2, init=False)
    reported_settings_match: bool = field(default=True, init=False)
    selected_origin_metadata_matches: bool = field(default=True, init=False)
    complete_module_inventory_proven: bool = field(default=False, init=False)
    import_hooks_and_cache_proven: bool = field(default=False, init=False)
    selected_code_bytes_proven: bool = field(default=False, init=False)
    loader_environment_proven: bool = field(default=False, init=False)
    native_resolution_proven: bool = field(default=False, init=False)
    atomic_snapshot_proven: bool = field(default=False, init=False)
    runtime_trusted: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)


def observe_python_import_state(*, held_finder=None):
    """Check current candidate state twice; never repair or preload a module.

    All 50 selected file-backed modules must already exist in sys.modules.
    This is not a whitelist for remaining built-in/frozen/private modules,
    path_hooks or path_importer_cache, nor proof of earlier or future imports.
    Metadata can be forged by an already compromised interpreter. The caller
    must arrange and review initialization separately before any deployment.
    """
    fs._platform()
    try:
        first = _capture() if held_finder is None else _capture(held_finder)
        second = _capture() if held_finder is None else _capture(held_finder)
    except (AttributeError, TypeError, ValueError, RuntimeError):
        raise core.OperatorError('PY_IMPORT_STATE') from None
    same = first[0] is second[0] and first[1] == second[1]
    same = same and all(a is b for a, b in zip(first[2], second[2]))
    same = same and all(all(a is b for a, b in zip(old, new)) for old, new in zip(first[3], second[3]))
    core.require(same, 'PY_IMPORT_CHANGED')
    return PythonImportObservation(second[1])
