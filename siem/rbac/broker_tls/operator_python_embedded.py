"""Dormant built-in/frozen metadata checks; NOT embedded-code attestation.

Requires an already trusted caller/interpreter and preloaded subjects. The B2
diagnostic supplies names/origins/files, not alias identity or loader metadata.
Those extra constraints are candidate CPython 3.14.4 policy, pending native
acceptance. No subject imports, finder/loader calls, file reads or repairs.
"""
from dataclasses import dataclass, field

from . import operator_core as core
from . import operator_fs as fs
from . import operator_python_import_state as imports


BUILTIN_NAMES = (
    '_abc', '_ast', '_blake2', '_codecs', '_collections', '_contextvars',
    '_functools', '_imp', '_io', '_json', '_locale', '_opcode', '_operator',
    '_posixsubprocess', '_signal', '_sre', '_stat', '_struct', '_thread',
    '_tokenize', '_types', '_warnings', '_weakref', 'binascii', 'builtins',
    'errno', 'fcntl', 'grp', 'itertools', 'marshal', 'math', 'posix', 'pwd',
    'select', 'sys', 'time',
)
# sys.modules key, module.__name__, spec.name, __package__, informational file.
# Frozen informational files are NOT evidence that these source files executed.
FROZEN_MODULES = (
    ('_collections_abc', 'collections.abc', '_collections_abc', '', '_collections_abc.py'),
    ('_frozen_importlib', 'importlib._bootstrap', '_frozen_importlib', 'importlib', 'importlib/_bootstrap.py'),
    ('_frozen_importlib_external', 'importlib._bootstrap_external', '_frozen_importlib_external', 'importlib', 'importlib/_bootstrap_external.py'),
    ('abc', 'abc', 'abc', '', 'abc.py'),
    ('codecs', 'codecs', 'codecs', '', 'codecs.py'),
    ('collections.abc', 'collections.abc', '_collections_abc', '', '_collections_abc.py'),
    ('genericpath', 'genericpath', 'genericpath', '', 'genericpath.py'),
    ('importlib._bootstrap', 'importlib._bootstrap', '_frozen_importlib', 'importlib', 'importlib/_bootstrap.py'),
    ('importlib._bootstrap_external', 'importlib._bootstrap_external', '_frozen_importlib_external', 'importlib', 'importlib/_bootstrap_external.py'),
    ('importlib.machinery', 'importlib.machinery', 'importlib.machinery', 'importlib', 'importlib/machinery.py'),
    ('io', 'io', 'io', '', 'io.py'),
    ('ntpath', 'ntpath', 'ntpath', '', 'ntpath.py'),
    ('os', 'os', 'os', '', 'os.py'),
    ('os.path', 'posixpath', 'posixpath', '', 'posixpath.py'),
    ('posixpath', 'posixpath', 'posixpath', '', 'posixpath.py'),
    ('stat', 'stat', 'stat', '', 'stat.py'),
    ('zipimport', 'zipimport', 'zipimport', '', 'zipimport.py'),
)
ALIASES = (('_collections_abc', 'collections.abc'),
           ('_frozen_importlib', 'importlib._bootstrap'),
           ('_frozen_importlib_external', 'importlib._bootstrap_external'),
           ('posixpath', 'os.path'))
MACHINERY_NAMES = ('ModuleSpec', 'BuiltinImporter', 'FrozenImporter',
                   'PathFinder', 'SourceFileLoader', 'ExtensionFileLoader')


def _text(value, expected, code):
    core.require(type(value) is str and value == expected, code)


def _capture(held_finder=None):
    imports._settings()
    host = imports.sys
    modules = host.modules
    core.require(type(modules) is dict and 53 <= len(modules) <= imports.MAX_MODULES,
                 'PY_EMBED_TABLE')
    core.require(modules.get('sys') is host, 'PY_EMBED_SYS')
    builtin = imports._module_dict(modules.get('_frozen_importlib'))
    external = imports._module_dict(modules.get('_frozen_importlib_external'))
    helpers = tuple(builtin.get(name) for name in MACHINERY_NAMES[:3]) + tuple(
        external.get(name) for name in MACHINERY_NAMES[3:])
    core.require(all(type(item) is type for item in helpers), 'PY_EMBED_MACHINERY')
    finders = (helpers[1], helpers[2], helpers[3])
    imports._check_finders(finders, held_finder, 'PY_EMBED_MACHINERY')
    names = host.builtin_module_names
    core.require(type(names) is tuple and 36 <= len(names) <= imports.MAX_MODULES and
                 all(type(name) is str and 0 < len(name) <= 128 for name in names) and
                 len(set(names)) == len(names) and all(name in names for name in BUILTIN_NAMES),
                 'PY_EMBED_BUILTINS')
    rows = tuple((name, name, name, '', None, 'built-in') for name in BUILTIN_NAMES) + tuple(
        (*row[:4], '/usr/lib/python3.14/' + row[4], 'frozen') for row in FROZEN_MODULES)
    refs = []
    for key, module_name, spec_name, package, path, origin in rows:
        module = modules.get(key)
        md = imports._module_dict(module)
        spec = md.get('__spec__')
        core.require(type(spec) is helpers[0], 'PY_EMBED_SPEC')
        sd = vars(spec)  # Never call lazy spec properties or module __getattr__.
        _text(md.get('__name__'), module_name, 'PY_EMBED_NAME')
        _text(sd.get('name'), spec_name, 'PY_EMBED_NAME')
        _text(md.get('__package__'), package, 'PY_EMBED_PACKAGE')
        _text(sd.get('origin'), origin, 'PY_EMBED_ORIGIN')
        core.require(sd.get('_set_fileattr') is False, 'PY_EMBED_ORIGIN')
        if path is None:
            core.require(md.get('__file__') is None, 'PY_EMBED_FILE')
        else:
            _text(md.get('__file__'), path, 'PY_EMBED_FILE')
        core.require(md.get('__cached__') is None and sd.get('_cached') is None,
                     'PY_EMBED_CACHE')
        core.require(md.get('__path__') is None and sd.get('submodule_search_locations') is None,
                     'PY_EMBED_PACKAGE')
        loader = helpers[1 if origin == 'built-in' else 2]
        core.require(md.get('__loader__') is loader and sd.get('loader') is loader,
                     'PY_EMBED_LOADER')
        parent = None
        if '.' in key:
            parent_key, child = key.rsplit('.', 1)
            parent = modules.get(parent_key)
            core.require(imports._module_dict(parent).get(child) is module, 'PY_EMBED_PARENT')
        refs.append((module, spec, loader, parent))
    for original, alias in ALIASES:
        core.require(modules[original] is modules[alias], 'PY_EMBED_ALIAS')
    machinery = imports._module_dict(modules['importlib.machinery'])
    core.require(all(machinery.get(name) is helper for name, helper in zip(MACHINERY_NAMES, helpers)),
                 'PY_EMBED_MACHINERY')
    return modules, len(modules), names, helpers, tuple(refs)


@dataclass(frozen=True)
class PythonEmbeddedObservation:
    observed_module_count: int
    selected_module_keys: int = field(default=53, init=False)
    alias_pairs: int = field(default=4, init=False)
    passes: int = field(default=2, init=False)
    selected_metadata_matches: bool = field(default=True, init=False)
    complete_module_inventory_proven: bool = field(default=False, init=False)
    embedded_code_proven: bool = field(default=False, init=False)
    bootstrap_code_proven: bool = field(default=False, init=False)
    native_resolution_proven: bool = field(default=False, init=False)
    atomic_snapshot_proven: bool = field(default=False, init=False)
    runtime_trusted: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)


def observe_python_embedded_modules(*, held_finder=None):
    """Observe 36 built-in and 17 frozen keys twice; never preload subjects.

    This is selected metadata/alias coverage, NOT a whole-table allowlist or
    proof of bootstrap/embedded code. __main__, guard-private and other modules
    remain outside the observation. Equal passes are not an atomic snapshot.
    """
    fs._platform()
    try:
        first = _capture() if held_finder is None else _capture(held_finder)
        second = _capture() if held_finder is None else _capture(held_finder)
    except (AttributeError, KeyError, TypeError, ValueError, RuntimeError):
        raise core.OperatorError('PY_EMBED_STATE') from None
    same = first[0] is second[0] and first[1:3] == second[1:3]
    same = same and all(a is b for a, b in zip(first[3], second[3]))
    same = same and len(first[4]) == len(second[4]) and all(
        all(a is b for a, b in zip(old, new)) for old, new in zip(first[4], second[4]))
    core.require(same, 'PY_EMBED_CHANGED')
    return PythonEmbeddedObservation(second[1])
