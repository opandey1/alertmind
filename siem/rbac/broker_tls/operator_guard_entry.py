"""Candidate isolated pre-start entry boundary; deliberately NOT deployable.

This standalone script has no project imports. A future reviewed installer may
copy it into a root-controlled tree and invoke it with an approved, pinned
interpreter in isolated/no-site/no-bytecode mode. It always exits nonzero:
there is no guard decision or systemd drop-in in this package.

Post-load metadata checks cannot authenticate code that Python already read.
The service unit, interpreter, standard library and installation transaction
must be trusted and reviewed before this entrypoint can form a real guard.
"""
from contextlib import ExitStack, contextmanager
import hashlib
import os
import stat
import sys


CANDIDATE_ROOT = '/usr/local/libexec/alertmind-broker-tls'
ENTRY_PATH = CANDIDATE_ROOT + '/guard_entry.py'
ENTRY_PARTS = ('usr', 'local', 'libexec', 'alertmind-broker-tls', 'guard_entry.py')
MAX_ENTRY_BYTES = 65536
# Exact LF source bytes for the pre-start observer closure only. These are
# independently reviewable source pins, not an installation or import permit.
# Post-start process/effective-launch modules are deliberately excluded.
PINNED_MODULES = (
    ('operator_core.py', 8270, 'c23eaacf814ee628bc891a50e92eeb36909bdabdf1a52f50a1183bcd9b967d93'),
    ('operator_fs.py', 9682, '5274bbdecf3b8298a27e5e946b1268e1bbce602cb9d00e2e94cb4e5d4124cb2a'),
    ('operator_bootstrap.py', 3504, '5c4bda2fcb7aa0925f584ce597ae153451dee24d8c46b45a3198a299acdd5e4f'),
    ('operator_runtime.py', 4683, 'e017007b65d68657182f72970c4ea8234e965f7507faea1bc5e568e7afb9bb1a'),
    ('operator_service.py', 11720, 'f4969eb0266eec2b9e37f7e4a0fb3ea8e5f34144f9b07ccf2b88ed5a956fc6a6'),
    ('operator_launch.py', 3905, '53a011104156555b5b06e29245344c99ae234b1590cbf53572c90ab3b635e709'),
    ('operator_unit_sources.py', 5448, '1a0c61056b67825363bfa5fe5114d7704abcc19f35aa81a4289b4cf198bc2c7d'),
    ('operator_manager_environment.py', 2873, '612add757241d6bb44492b5d2972f542e152c16a94edaa09b51e4447519b28e6'),
    ('operator_node_options.py', 8382, '1bce69283c7c7d35bb5d2f17c236adf1afb596b20fe03738b1e0acb50b990289'),
    ('operator_dependency.py', 3736, '0fe2c4cbc86e56b08f3904cdff92a0905df750b2401a1b205926fe92ddeaa2eb'),
    ('operator_dependency_graph.py', 7380, '9ca314b9c4c15dc5a2f666d1164b4dee33cd0f8c4ccd5690c25000d4a9e04dbc'),
    ('operator_import_sites.py', 6425, '716a3a2b12ac26d99241b1e16716d5315e8dda5897482e3e76715ff7415534a8'),
    ('operator_file_set.py', 8964, 'f6819927f88de7030b47d5e2fdee690f514fda82e42b0a16326431a2e334f180'),
)
# Additional runtime-observer closure, loaded only by the explicit full phase.
# The original thirteen-source capsule remains available to offline tests.
RUNTIME_MODULES = (
    ('operator_python_policy.py', 18363, 'e33d3d01e9a37d02b0089d8c3f8b48f99fc1c3d1ca3ae7aea2ee7a54011dafd8'),
    ('operator_python_runtime.py', 6794, '00a7605556455d8f64d8cbc207f830b59dda4945e15cb11f821d1f915509541c'),
    ('operator_python_paths.py', 5434, 'afc604fdf5f2974c137a35bf8a9ae6fd927736387ad2e107a12af0718a2bd6a9'),
    ('operator_python_import_state.py', 9624, 'd2e10b725d5044a7c817e38c46f98cde22b0c5980f9d69ce1188051717d40a2a'),
    ('operator_python_path_importers.py', 8077, '745a134ba8fe89fb020659dfdf3d5e193c17e3a9b8dd2ba4f4f79fd94c2a9e68'),
    ('operator_python_candidates.py', 6857, '40cbadcfaa259808e32053d3702aad2e2e95c3f71ab4822514023c4f1cfef699'),
    ('operator_python_embedded.py', 8113, 'ad118dc2f7c33f5589db897781ca1d04e5d4baca3014b2e2c04a70eb9c826f40'),
    ('operator_python_native.py', 11575, '55cb17c982adfc18e9dc63e8c47945116aed9ed668112f88b0427a3d13b2ed46'),
)


def _bundle_pins(runtime):
    _require(type(runtime) is bool, 'GUARD_TABLE_PHASE')
    return PINNED_MODULES + RUNTIME_MODULES if runtime else PINNED_MODULES


def _held_keys(runtime):
    return frozenset((HELD_PACKAGE,) + tuple(
        HELD_PACKAGE + '.' + name[:-3] for name, _, _ in _bundle_pins(runtime)))


HELD_PACKAGE = '_alertmind_guard_held'
# Candidate prepared-table policy from the accepted B2/C1 name sets, not a
# measured guard launch. Keep literal here: importing a policy module would
# itself change the entry's closed module table. Tests cross-check the sets.
STDLIB_MODULE_KEYS = (
    '_abc', '_ast', '_blake2', '_codecs', '_collections',
    '_collections_abc', '_contextvars', '_frozen_importlib', '_frozen_importlib_external', '_functools',
    '_hashlib', '_imp', '_io', '_json', '_locale',
    '_opcode', '_opcode_metadata', '_operator', '_posixsubprocess', '_py_warnings',
    '_signal', '_sre', '_stat', '_struct', '_thread',
    '_tokenize', '_types', '_warnings', '_weakref', '_weakrefset',
    'abc', 'annotationlib', 'ast', 'base64', 'binascii',
    'builtins', 'codecs', 'collections', 'collections.abc', 'contextlib',
    'copy', 'copyreg', 'dataclasses', 'dis', 'encodings',
    'encodings.aliases', 'encodings.utf_8', 'enum', 'errno', 'fcntl',
    'fnmatch', 'functools', 'genericpath', 'glob', 'grp',
    'hashlib', 'importlib', 'importlib._bootstrap', 'importlib._bootstrap_external', 'importlib.machinery',
    'inspect', 'io', 'itertools', 'json', 'json.decoder',
    'json.encoder', 'json.scanner', 'keyword', 'linecache', 'locale',
    'marshal', 'math', 'ntpath', 'opcode', 'operator',
    'os', 'os.path', 'pathlib', 'pathlib._os', 'posix',
    'posixpath', 'pwd', 're', 're._casefix', 're._compiler',
    're._constants', 're._parser', 'reprlib', 'select', 'selectors',
    'signal', 'stat', 'struct', 'subprocess', 'sys',
    'threading', 'time', 'token', 'tokenize', 'types',
    'warnings', 'weakref', 'zipimport',
)
MODULE_ALIASES = (('_collections_abc', 'collections.abc'),
                  ('_frozen_importlib', 'importlib._bootstrap'),
                  ('_frozen_importlib_external', 'importlib._bootstrap_external'),
                  ('os.path', 'posixpath'))
PREPARED_MODULE_KEYS = frozenset(STDLIB_MODULE_KEYS + ('__main__',))
HELD_MODULE_KEYS = frozenset((HELD_PACKAGE,) + tuple(
    HELD_PACKAGE + '.' + name[:-3] for name, _, _ in PINNED_MODULES))
# Same ordered direct roots as B2, including its first `import sys`. Importing
# these can execute stdlib/native code: external launch/runtime trust is a
# prerequisite, not something the preparation step establishes.
PREPARATION_ROOTS = (
    'sys', 'base64', 'binascii', 'contextlib', 'dataclasses', 'errno', 'grp',
    'hashlib', 'json', 'os', 'pathlib', 'pwd', 're', 'selectors', 'stat',
    'subprocess', 'time', 'types',
)
PREPARATION_SEARCH_PATH = ('/usr/lib/python314.zip', '/usr/lib/python3.14',
                           '/usr/lib/python3.14/lib-dynload')
PREPARATION_ARGV = ('/usr/bin/python3.14', '-I', '-S', '-B', '-X',
                    'pycache_prefix=/dev/null/alertmind-c2', ENTRY_PATH)
PREPARATION_ENV = (('HOME', '/nonexistent'), ('LC_ALL', 'C'), ('PATH', '/usr/bin:/bin'))


class GuardLaunchError(Exception):
    """Fixed diagnostic codes only, never supplier paths or values."""


def _require(condition, code):
    if not condition:
        raise GuardLaunchError(code)


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _trusted(info, directory):
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    _require(kind(info.st_mode) and info.st_uid == 0 and info.st_gid == 0
             and not info.st_mode & 0o6022, 'GUARD_PATH')
    if not directory:
        _require(info.st_nlink == 1 and 0 < info.st_size <= MAX_ENTRY_BYTES,
                 'GUARD_PATH')


def _check_isolation():
    """Require an isolated root Python process before any project import.

    This cannot undo linker/interpreter inputs already consumed at process
    creation. A future unit policy must inspect those sources separately.
    """
    _require(sys.platform == 'linux' and hasattr(os, 'geteuid') and
             os.geteuid() == 0 and all(hasattr(os, name) for name in
             ('O_NOFOLLOW', 'O_DIRECTORY', 'O_CLOEXEC', 'O_NONBLOCK')) and
             os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd
             and os.stat in os.supports_follow_symlinks
             and os.scandir in os.supports_fd,
             'GUARD_PLATFORM')
    flags = sys.flags
    _require(all(getattr(flags, name, None) == 1 for name in
                 ('isolated', 'ignore_environment', 'no_site',
                  'dont_write_bytecode')), 'GUARD_ISOLATION')
    _require(sys.argv == [ENTRY_PATH], 'GUARD_ARGUMENTS')
    _require(all(type(path) is str and path.startswith('/') and
                 path != CANDIDATE_ROOT for path in sys.path),
             'GUARD_IMPORT_PATH')


def _check_entry_at(root_fd):
    """No-follow, descriptor-relative metadata recheck of the fixed entry.

    root_fd is private test isolation only. This is after Python has loaded the
    script, so it is NOT an executable trust anchor or an atomic file lock.
    """
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    with ExitStack() as stack:
        root_before = os.fstat(root_fd)
        _trusted(root_before, True)
        parent = root_fd
        records = []
        for index, name in enumerate(ENTRY_PARTS):
            directory = index < len(ENTRY_PARTS) - 1
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            _trusted(before, directory)
            opened = os.open(name, flags | (os.O_DIRECTORY if directory else os.O_NONBLOCK),
                             dir_fd=parent)
            stack.callback(os.close, opened)
            _require(_stamp(before) == _stamp(os.fstat(opened)), 'GUARD_CHANGED')
            records.append((parent, name, opened, before))
            parent = opened
        for parent, name, opened, before in reversed(records):
            _require(_stamp(before) == _stamp(os.fstat(opened)) ==
                     _stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                     'GUARD_CHANGED')
        _require(_stamp(root_before) == _stamp(os.fstat(root_fd)), 'GUARD_CHANGED')


def _read_exact(fd, expected_size):
    """Bounded descriptor read; short reads do not imply EOF."""
    chunks = []
    total = 0
    while total <= expected_size:
        requested = min(8192, expected_size + 1 - total)
        chunk = os.read(fd, requested)
        _require(type(chunk) is bytes and len(chunk) <= requested,
                 'GUARD_BUNDLE_SIZE')
        if not chunk:
            break
        total += len(chunk)
        chunks.append(chunk)
    _require(total == expected_size, 'GUARD_BUNDLE_SIZE')
    return b''.join(chunks)


def _scan_exact_names(fd, expected):
    """Bounded directory enumeration without buffering untrusted entries."""
    names = set()
    # A new open file description avoids inheriting a prior scan's directory
    # offset; scanning twice through the same fd can otherwise miss entries.
    scan_fd = os.open('.', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                      os.O_CLOEXEC, dir_fd=fd)
    try:
        _require(_stamp(os.fstat(scan_fd)) == _stamp(os.fstat(fd)),
                 'GUARD_CHANGED')
        with os.scandir(scan_fd) as entries:
            for item in entries:
                name = item.name
                _require(type(name) is str and name in expected and name not in names,
                         'GUARD_BUNDLE_SET')
                names.add(name)
    finally:
        os.close(scan_fd)
    _require(names == expected, 'GUARD_BUNDLE_SET')


def _verify_bundle_at(root_fd, *, runtime=False):
    """Return held verified bytes; NEVER import or execute the source set.

    The fixed pins bind to LF repository source, not an installer or a live
    package. This is a point-in-time check after entry code has already run.
    """
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with ExitStack() as stack:
        root_before = os.fstat(root_fd)
        _trusted(root_before, True)
        parent = root_fd
        records = []
        for name in ENTRY_PARTS[:-1]:
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            _trusted(before, True)
            opened = os.open(name, directory_flags, dir_fd=parent)
            stack.callback(os.close, opened)
            _require(_stamp(before) == _stamp(os.fstat(opened)), 'GUARD_CHANGED')
            records.append((parent, name, opened, before))
            parent = opened
        pins = _bundle_pins(runtime)
        expected_names = {'guard_entry.py'} | {name for name, _, _ in pins}
        _scan_exact_names(parent, expected_names)
        sources = []
        for name, size, digest in pins:
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            _trusted(before, False)
            _require(before.st_size == size, 'GUARD_BUNDLE_SIZE')
            opened = os.open(name, file_flags, dir_fd=parent)
            stack.callback(os.close, opened)
            _require(_stamp(before) == _stamp(os.fstat(opened)), 'GUARD_CHANGED')
            raw = _read_exact(opened, size)
            _require(hashlib.sha256(raw).hexdigest() == digest,
                     'GUARD_BUNDLE_DIGEST')
            sources.append((name, raw))
            _require(_stamp(before) == _stamp(os.fstat(opened)) ==
                     _stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                     'GUARD_CHANGED')
        try:
            _scan_exact_names(parent, expected_names)
        except GuardLaunchError:
            raise GuardLaunchError('GUARD_CHANGED') from None
        for ancestor, name, opened, before in reversed(records):
            _require(_stamp(before) == _stamp(os.fstat(opened)) ==
                     _stamp(os.stat(name, dir_fd=ancestor, follow_symlinks=False)),
                     'GUARD_CHANGED')
        _require(_stamp(root_before) == _stamp(os.fstat(root_fd)), 'GUARD_CHANGED')
        return tuple(sources)


def _compile_verified_bundle(sources, *, runtime=False):
    """Compile exact held bytes without reopening a path or executing them."""
    pins = _bundle_pins(runtime)
    _require(type(sources) is tuple and len(sources) == len(pins),
             'GUARD_COMPILE_SET')
    compiled = []
    for received, (name, size, digest) in zip(sources, pins):
        _require(type(received) is tuple and len(received) == 2 and
                 received[0] == name and type(received[1]) is bytes,
                 'GUARD_COMPILE_SET')
        raw = received[1]
        _require(len(raw) == size and hashlib.sha256(raw).hexdigest() == digest,
                 'GUARD_COMPILE_BYTES')
        try:
            code = compile(raw, '<alertmind-guard>/' + name, 'exec',
                           flags=0, dont_inherit=True, optimize=0)
        except (SyntaxError, ValueError, TypeError, OverflowError, MemoryError):
            raise GuardLaunchError('GUARD_COMPILE') from None
        compiled.append((name, code))
    return tuple(compiled)


class _DenyHeldFallback:
    """Never resolve an unregistered private module through ambient finders."""

    def find_spec(self, fullname, path=None, target=None):
        if fullname == HELD_PACKAGE or fullname.startswith(HELD_PACKAGE + '.'):
            raise ImportError('GUARD_IMPORT_DENIED')
        return None


@contextmanager
def _loaded_verified_bundle(sources, *, runtime=False):
    """Execute only held, rechecked bytes in a temporary private namespace.

    The connected candidate calls this after preparation and verified source
    acquisition. Interpreter, standard-library and import-path trust must be
    established externally first. Neither a sandbox nor a startup decision.
    """
    compiled = _compile_verified_bundle(sources, runtime=runtime)
    # In the connected path, types is already in the prepared module table.
    from types import ModuleType

    prefix = HELD_PACKAGE + '.'
    _require(not any(name == HELD_PACKAGE or name.startswith(prefix)
                     for name in sys.modules), 'GUARD_LOAD_COLLISION')
    original_finders = tuple(sys.meta_path)
    finder = _DenyHeldFallback()
    loaded = {}
    try:
        sys.meta_path.insert(0, finder)
        package = ModuleType(HELD_PACKAGE)
        package.__path__ = ()  # No filesystem search location.
        package.__package__ = HELD_PACKAGE
        loaded[HELD_PACKAGE] = package
        sys.modules[HELD_PACKAGE] = package
        for name, code in compiled:
            stem = name[:-3]
            fullname = prefix + stem
            module = ModuleType(fullname)
            module.__package__ = HELD_PACKAGE
            module.__file__ = code.co_filename
            loaded[fullname] = module
            sys.modules[fullname] = module
            setattr(package, stem, module)
            exec(code, module.__dict__)
            _require(sys.modules.get(HELD_PACKAGE) is package and
                     sys.modules.get(fullname) is module and
                     tuple(sys.meta_path) == (finder,) + original_finders and
                     all(sys.modules.get(key) is value for key, value in loaded.items()) and
                     not any(key.startswith(prefix) and key not in loaded
                             for key in sys.modules), 'GUARD_LOAD_DRIFT')
        yield loaded
    except BaseException:
        raise GuardLaunchError('GUARD_LOAD') from None
    finally:
        # The private prefix was empty on entry; leave no half-loaded modules.
        for name in tuple(sys.modules):
            if name == HELD_PACKAGE or name.startswith(prefix):
                del sys.modules[name]
        sys.meta_path[:] = original_finders


def _table_keys(table, expected):
    _require(type(table) is dict and len(table) == len(expected), 'GUARD_TABLE_SET')
    # Check types before hashing/comparing any supplier key to an expected key.
    _require(all(type(key) is str and 0 < len(key) <= 128 for key in table),
             'GUARD_TABLE_KEY')
    _require(table.keys() == expected, 'GUARD_TABLE_SET')


def _table_module(module):
    _require(type(module) is type(sys), 'GUARD_TABLE_MODULE')
    return vars(module)


def _table_text(value, expected, code):
    _require(type(value) is str and value == expected, code)


def _table_capture(modules, held, loaded, runtime=False):
    held_keys = _held_keys(runtime)
    expected = PREPARED_MODULE_KEYS | held_keys if held else PREPARED_MODULE_KEYS
    _table_keys(modules, expected)
    records = tuple((key, modules[key]) for key in sorted(expected))
    for _, module in records:
        _table_module(module)
    for a, b in MODULE_ALIASES:
        _require(modules[a] is modules[b], 'GUARD_TABLE_ALIAS')
    # Only those four alias pairs may share module identity. Do not allow an
    # unrelated key to disguise a missing module by pointing at another one.
    allowed = {frozenset(pair) for pair in MODULE_ALIASES}
    for index, (key, module) in enumerate(records):
        for other_key, other in records[:index]:
            _require(module is not other or frozenset((key, other_key)) in allowed,
                     'GUARD_TABLE_ALIAS')
    main = _table_module(modules['__main__'])
    builtin = _table_module(modules['_frozen_importlib'])
    external = _table_module(modules['_frozen_importlib_external'])
    builtins = _table_module(modules['builtins'])
    _table_text(main.get('__name__'), '__main__', 'GUARD_TABLE_ENTRY')
    _table_text(main.get('__file__'), ENTRY_PATH, 'GUARD_TABLE_ENTRY')
    _require(all(main.get(key) is None for key in
                 ('__spec__', '__package__', '__cached__', '__path__')), 'GUARD_TABLE_ENTRY')
    _require(main.get('__builtins__') is modules['builtins'] or
             main.get('__builtins__') is builtins, 'GUARD_TABLE_BINDING')
    source_class = external.get('SourceFileLoader')
    loader = main.get('__loader__')
    _require(type(source_class) is type and type(loader) is source_class,
             'GUARD_TABLE_LOADER')
    loader_fields = vars(loader)
    _table_keys(loader_fields, frozenset(('name', 'path')))
    _table_text(loader_fields['name'], '__main__', 'GUARD_TABLE_LOADER')
    _table_text(loader_fields['path'], ENTRY_PATH, 'GUARD_TABLE_LOADER')
    for name in ('sys', 'os', 'stat', 'hashlib'):
        _require(main.get(name) is modules[name], 'GUARD_TABLE_BINDING')
    context = _table_module(modules['contextlib'])
    for name in ('ExitStack', 'contextmanager'):
        _require(context.get(name) is not None and main.get(name) is context[name],
                 'GUARD_TABLE_BINDING')
    meta = _table_module(modules['sys']).get('meta_path')
    defaults = (builtin.get('BuiltinImporter'), builtin.get('FrozenImporter'), external.get('PathFinder'))
    _require(all(type(item) is type for item in defaults) and type(meta) is list and
             len(meta) == (4 if held else 3) and
             all(a is b for a, b in zip(meta[1:] if held else meta, defaults)), 'GUARD_TABLE_FINDER')
    refs = [modules, main, builtins, source_class, loader, loader_fields, meta, *defaults,
            context['ExitStack'], context['contextmanager']]
    if held:
        _table_keys(loaded, held_keys)
        _require(all(loaded[key] is modules[key] for key in held_keys), 'GUARD_TABLE_REGISTRY')
        package = _table_module(modules[HELD_PACKAGE])
        fields = frozenset(('__name__', '__doc__', '__package__', '__loader__', '__spec__', '__path__')) | frozenset(
            name[:-3] for name, _, _ in _bundle_pins(runtime))
        _table_keys(package, fields)
        _table_text(package.get('__name__'), HELD_PACKAGE, 'GUARD_TABLE_HELD')
        _table_text(package.get('__package__'), HELD_PACKAGE, 'GUARD_TABLE_HELD')
        _require(type(package.get('__path__')) is tuple and not package['__path__'] and
                 all(package.get(key) is None for key in ('__doc__', '__loader__', '__spec__')),
                 'GUARD_TABLE_HELD')
        for name, _, _ in _bundle_pins(runtime):
            stem = name[:-3]
            key = HELD_PACKAGE + '.' + stem
            module = modules[key]
            md = _table_module(module)
            _table_text(md.get('__name__'), key, 'GUARD_TABLE_HELD')
            _table_text(md.get('__package__'), HELD_PACKAGE, 'GUARD_TABLE_HELD')
            _table_text(md.get('__file__'), '<alertmind-guard>/' + name, 'GUARD_TABLE_HELD')
            _require(all(md.get(attr) is None for attr in
                         ('__loader__', '__spec__', '__cached__', '__path__')) and
                     md.get('__builtins__') is builtins and package.get(stem) is module,
                     'GUARD_TABLE_HELD')
        finder = meta[0]
        finder_class = main.get('_DenyHeldFallback')
        _require(type(finder_class) is type and type(finder) is finder_class, 'GUARD_TABLE_FINDER')
        fd = object.__getattribute__(finder, '__dict__')
        _require(type(fd) is dict and not fd, 'GUARD_TABLE_FINDER')
        definition = vars(finder_class)
        _table_text(definition.get('__module__'), '__main__', 'GUARD_TABLE_FINDER')
        function = definition.get('find_spec')  # Inspect, never bind/invoke.
        _require(type(function) is type(lambda: None) and function.__globals__ is main and
                 function.__code__.co_filename == ENTRY_PATH and function.__closure__ is None and
                 type(function.__defaults__) is tuple and len(function.__defaults__) == 2 and
                 all(value is None for value in function.__defaults__) and function.__kwdefaults__ is None and
                 not function.__dict__, 'GUARD_TABLE_FINDER')
        refs.extend((loaded, package, finder, fd, finder_class, function, function.__code__))
        _table_keys(loaded, held_keys)
        _require(all(loaded[key] is modules[key] for key in held_keys), 'GUARD_TABLE_REGISTRY')
    else:
        _require(loaded is None, 'GUARD_TABLE_PHASE')
    _table_keys(modules, expected)
    _require(all(modules[key] is module for key, module in records), 'GUARD_TABLE_CHANGED')
    return tuple(refs) + tuple(module for _, module in records)


def _check_module_table(modules, *, held=False, loaded=None, runtime=False):
    """Pure table policy, also applied at connected entry phase boundaries.

    Prepared: 103 selected stdlib keys plus direct-file __main__. Held: also
    exactly the private package and 13 pinned children, matching the loader's
    supplied registry. Partial/extra tables never auto-select another phase.
    Checks twice without importing, invoking a finder, mutating, or reading a
    live sys.modules table itself. Returns None, NOT a startup decision.

    The full observation path adds eight pinned runtime children. Mutable
    metadata and a supplied registry cannot attest executed bytes, freshness,
    bootstrap provenance, stdlib internals or an atomic process snapshot.
    """
    _require(type(held) is bool, 'GUARD_TABLE_PHASE')
    try:
        first = _table_capture(modules, held, loaded, runtime)
        second = _table_capture(modules, held, loaded, runtime)
    except (AttributeError, KeyError, TypeError, ValueError, RuntimeError):
        raise GuardLaunchError('GUARD_TABLE_STATE') from None
    _require(len(first) == len(second) and all(a is b for a, b in zip(first, second)),
             'GUARD_TABLE_CHANGED')


def _preparation_strings(value, expected, code):
    _require(type(value) is list and len(value) == len(expected) and
             all(type(item) is str for item in value) and tuple(value) == expected, code)


def _preparation_settings():
    _check_isolation()
    version = sys.version_info
    _require(isinstance(version, tuple) and len(version) == 5 and
             all(type(version[i]) is int for i in (0, 1, 2, 4)) and
             type(version[3]) is str and tuple(version) == (3, 14, 4, 'final', 0),
             'GUARD_PREP_RUNTIME')
    _table_text(sys.executable, '/usr/bin/python3.14', 'GUARD_PREP_RUNTIME')
    _table_text(sys.implementation.name, 'cpython', 'GUARD_PREP_RUNTIME')
    _table_text(sys.implementation.cache_tag, 'cpython-314', 'GUARD_PREP_RUNTIME')
    for name, expected in (('isolated', 1), ('ignore_environment', 1), ('no_site', 1),
                           ('no_user_site', 1), ('dont_write_bytecode', 1), ('optimize', 0)):
        value = getattr(sys.flags, name, None)
        _require(type(value) is int and value == expected, 'GUARD_PREP_FLAGS')
    _require(sys.flags.safe_path is True and sys.dont_write_bytecode is True, 'GUARD_PREP_FLAGS')
    _preparation_strings(sys.orig_argv, PREPARATION_ARGV, 'GUARD_PREP_ARGV')
    _preparation_strings(sys.argv, (ENTRY_PATH,), 'GUARD_PREP_ARGV')
    _preparation_strings(sys.path, PREPARATION_SEARCH_PATH, 'GUARD_PREP_PATH')
    _table_text(sys.pycache_prefix, '/dev/null/alertmind-c2', 'GUARD_PREP_CACHE')
    _table_keys(sys._xoptions, frozenset(('pycache_prefix',)))
    _table_text(sys._xoptions['pycache_prefix'], '/dev/null/alertmind-c2', 'GUARD_PREP_CACHE')
    # Observe, never clear/repair the environment after the ELF loader ran.
    _require(len(os.environ) == len(PREPARATION_ENV), 'GUARD_PREP_ENV')
    environment = dict(os.environ)
    _require(all(type(k) is str and type(v) is str for k, v in environment.items())
             and environment == dict(PREPARATION_ENV), 'GUARD_PREP_ENV')
    _table_text(os.getcwd(), '/', 'GUARD_PREP_CWD')


def _preparation_capture():
    _preparation_settings()
    modules = sys.modules
    _require(type(modules) is dict and 0 < len(modules) <= len(PREPARED_MODULE_KEYS),
             'GUARD_PREP_SET')
    _require(all(type(key) is str and 0 < len(key) <= 128 and key in PREPARED_MODULE_KEYS for key in modules),
             'GUARD_PREP_SET')
    records = tuple((key, modules[key]) for key in sorted(modules))
    for _, module in records:
        _table_module(module)
    # Existing bindings cannot be displaced by preparation. No held/private
    # namespace is permitted at this phase and nothing is deleted to make it fit.
    main = _table_module(modules['__main__'])
    _require(main is globals() and modules['sys'] is sys and
             modules['os'] is os and modules['stat'] is stat and modules['hashlib'] is hashlib,
             'GUARD_PREP_BINDING')
    _table_text(main.get('__name__'), '__main__', 'GUARD_PREP_ENTRY')
    _table_text(main.get('__file__'), ENTRY_PATH, 'GUARD_PREP_ENTRY')
    _require(all(main.get(key) is None for key in ('__spec__', '__package__', '__cached__', '__path__')),
             'GUARD_PREP_ENTRY')
    context = _table_module(modules['contextlib'])
    _require(context.get('ExitStack') is ExitStack and context.get('contextmanager') is contextmanager,
             'GUARD_PREP_BINDING')
    _require(main.get('__builtins__') is modules['builtins'] or
             main.get('__builtins__') is _table_module(modules['builtins']), 'GUARD_PREP_BINDING')
    builtin = _table_module(modules['_frozen_importlib'])
    external = _table_module(modules['_frozen_importlib_external'])
    source_class, loader = external.get('SourceFileLoader'), main.get('__loader__')
    _require(type(source_class) is type and type(loader) is source_class, 'GUARD_PREP_ENTRY')
    _table_keys(vars(loader), frozenset(('name', 'path')))
    _table_text(vars(loader)['name'], '__main__', 'GUARD_PREP_ENTRY')
    _table_text(vars(loader)['path'], ENTRY_PATH, 'GUARD_PREP_ENTRY')
    finders = (builtin.get('BuiltinImporter'), builtin.get('FrozenImporter'), external.get('PathFinder'))
    meta = sys.meta_path
    _require(all(type(f) is type for f in finders) and type(meta) is list and len(meta) == 3 and
             all(a is b for a, b in zip(meta, finders)), 'GUARD_PREP_FINDER')
    imports = _table_module(modules['builtins']).get('__import__')
    _require(type(imports) is type(len) and imports is __import__, 'GUARD_PREP_IMPORT')
    hooks = sys.path_hooks
    _require(type(hooks) is list and len(hooks) == 2 and
             hooks[0] is _table_module(modules['zipimport']).get('zipimporter') and
             type(hooks[0]) is type and type(hooks[1]) is type(lambda: None), 'GUARD_PREP_HOOK')
    # These are current identities, NOT authenticated loader/hook function code.
    return modules, records, (meta, *finders, imports, hooks, *hooks, source_class, loader)


def _preparation_transition(before, after):
    _require(before[0] is after[0] and len(before[2]) == len(after[2]) and
             all(a is b for a, b in zip(before[2], after[2])) and
             all(after[0].get(key) is module for key, module in before[1]), 'GUARD_PREP_CHANGED')


def _import_preparation_root(name):
    # Private seam for fixture tests, not a callback in the initializer API.
    _require(type(name) is str and name in PREPARATION_ROOTS, 'GUARD_PREP_ROOT')
    return __import__(name, globals(), globals(), (), 0)


def _prepare_stdlib():
    """Fixed preparation, NOT an external trust anchor or a permit.

    A trusted launcher must establish the reviewed interpreter, sources, native
    inputs and clean environment BEFORE running this entry. These imports can
    execute source/native code through the current machinery. In-process checks
    cannot make an untrusted interpreter safe or undo earlier loader execution.

    Check launch/state before and after each of the eighteen B2 root imports;
    retain prior module identities and permit only the fixed prepared set to
    grow. Finish with the existing exact 104-key table policy. Do not import a
    private capsule, invoke its observers, adjust paths/hooks/cache/environment,
    or issue startup authority. On failure, abandon the process; no retry or
    partial-import cleanup is attempted. The connected launch calls this before
    loading private sources; the compile-only helper does not call it.
    """
    try:
        state = _preparation_capture()
        for name in PREPARATION_ROOTS:
            try:
                module = _import_preparation_root(name)
            except BaseException:
                # Even a subject-raised GuardLaunchError is untrusted text.
                raise GuardLaunchError('GUARD_PREP_FAILED') from None
            following = _preparation_capture()
            _preparation_transition(state, following)
            _require(type(module) is type(sys) and following[0].get(name) is module,
                     'GUARD_PREP_RESULT')
            state = following
        _check_module_table(sys.modules)
        final = _preparation_capture()
        _preparation_transition(state, final)
        _require(len(final[1]) == len(PREPARED_MODULE_KEYS), 'GUARD_PREP_SET')
    except GuardLaunchError:
        raise
    except BaseException:
        # Imports may throw SystemExit or contain private filesystem diagnostics.
        # Do not expose the original exception, trigger recovery, or continue.
        raise GuardLaunchError('GUARD_PREP_FAILED') from None


def _check_entry():
    _check_isolation()
    try:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY |
                     os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            _check_entry_at(fd)
            # Retained compile-only helper, not the connected main() path.
            # It must never execute the capsule or prepare the interpreter.
            _compile_verified_bundle(_verify_bundle_at(fd))
        finally:
            os.close(fd)
    except OSError:
        raise GuardLaunchError('GUARD_IO') from None


def _phase_state(loaded):
    """Full held-phase check; never remove the deny-finder for an observer."""
    _preparation_settings()
    _require(vars(sys.modules['__main__']) is globals(), 'GUARD_PHASE_ENTRY')
    _check_module_table(sys.modules, held=True, loaded=loaded, runtime=True)
    return _table_capture(sys.modules, True, loaded, True)


def _same_phase(before, after):
    _require(len(before) == len(after) and all(a is b for a, b in zip(before, after)),
             'GUARD_PHASE_CHANGED')


def _fields(true='', false='', **values):
    """Explicit result contracts, never inferred from an observer's defaults."""
    return {**{name: True for name in true.split()},
            **{name: False for name in false.split()}, **values}


# A non-authorizing result policy, NOT a service-start decision. These are
# exact pinned observer contracts; unknown fields/classes/versions need review.
# Tuples denote a strict typed range/choice, not Python's bool==int equality.
_RESULT_CONTRACTS = {
    'operator_python_paths': ('PythonPathObservation', _fields(
        'fixed_optional_inputs_absent null_anchor_matches',
        'complete_search_path_proven effective_cache_redirection_proven '
        'loader_environment_proven native_resolution_proven loaded_code_proven '
        'atomic_snapshot_proven runtime_trusted startup_authorized',
        file_passes=2, absent_input_count=2)),
    'operator_python_runtime': ('PythonRuntimeObservation', _fields(
        'on_disk_byte_pins_match on_disk_source_pins_match',
        'source_origins_verified package_file_ownership_verified package_authenticity_proven '
        'native_resolution_proven atomic_snapshot_proven loaded_code_proven '
        'effective_environment_proven runtime_trusted startup_authorized',
        packages=tuple, mapped_file_count=9, generated_cache_count=1,
        source_file_count=49, file_passes=2, package_reads=3)),
    'operator_python_candidates': ('PythonCandidateObservation', _fields(
        'selected_origins_regular selected_alternate_names_absent',
        'on_disk_bytes_proven complete_import_coverage_proven effective_cache_redirection_proven '
        'actual_resolution_proven loaded_code_proven atomic_snapshot_proven '
        'runtime_trusted startup_authorized',
        selected_module_count=50, alternate_name_count=514, passes=2)),
    'operator_python_native': ('PythonNativeObservation', _fields(
        'mapped_backing_pins_match',
        'native_resolution_proven loaded_memory_proven symbol_bindings_proven '
        'package_authenticity_proven atomic_snapshot_proven runtime_trusted startup_authorized',
        file_count=9, byte_passes=2, maps_reads=4)),
    'operator_python_path_importers': ('PythonPathImporterObservation', _fields(
        'candidate_hook_metadata_matches cached_finder_metadata_matches',
        'hook_code_authenticated directory_contents_proven bytecode_exclusion_proven '
        'complete_module_inventory_proven actual_resolution_proven atomic_snapshot_proven '
        'runtime_trusted startup_authorized',
        cached_path_count=('range', 0, 9), passes=2)),
    'operator_python_import_state': ('PythonImportObservation', _fields(
        'reported_settings_match selected_origin_metadata_matches',
        'complete_module_inventory_proven import_hooks_and_cache_proven selected_code_bytes_proven '
        'loader_environment_proven native_resolution_proven atomic_snapshot_proven '
        'runtime_trusted startup_authorized',
        observed_module_count=126, selected_module_count=50, passes=2)),
    'operator_python_embedded': ('PythonEmbeddedObservation', _fields(
        'selected_metadata_matches',
        'complete_module_inventory_proven embedded_code_proven bootstrap_code_proven '
        'native_resolution_proven atomic_snapshot_proven runtime_trusted startup_authorized',
        observed_module_count=126, selected_module_keys=53, alias_pairs=4, passes=2)),
    'operator_bootstrap': ('Bootstrap', _fields(false='startup_authorized',
        manifest=('bytes', 1, 524288), certificate_pem=('bytes', 1, 65536),
        checked_files=2, passes=2)),
    'operator_runtime': ('RuntimeObservation', _fields(
        false='selected_runtime_proven startup_authorized',
        package='package', packaged_node_version='18.19.0', runtime_passes=2, package_reads=3)),
    'operator_service': ('ServiceObservation', _fields(
        'service_user_matches service_group_matches working_directory_matches fragment_present',
        'exec_flags_present runtime_override_named alternate_root_present '
        'selected_runtime_proven effective_environment_proven startup_authorized',
        # Visibility only: neither active/inactive/failed proves startup inhibition.
        active_state=('choice', 'active', 'inactive', 'failed'), exec_start_count=1,
        configured_executable='dashboard_wrapper', environment_entries=0,
        environment_files=0, pass_environment_entries=0, unset_environment_entries=0,
        dropin_count=0, passes=2)),
    'operator_launch': ('LaunchObservation', _fields(
        'configured_wrapper_path configured_wrapper_argv_only launch_bytes_match_pins',
        'explicit_execution_flags inline_wrapper_environment_override_named '
        'selected_runtime_proven effective_environment_proven dependency_resolution_proven '
        'startup_authorized', checked_files=3, passes=2, service_reads=3, package_reads=3)),
    'operator_unit_sources': ('UnitSourcesObservation', _fields(
        'exact_wrapper_argv auxiliary_commands_empty explicit_unit_environment_empty '
        'pam_session_disabled exec_search_path_empty dynamic_user_disabled '
        'directory_environment_sources_empty queried_descriptor_inputs_empty '
        'queried_trigger_edges_empty queried_credential_metadata_empty',
        'manager_inheritance_proven embedded_credential_sources_proven '
        'selected_config_source_proven effective_environment_proven startup_authorized',
        # Reported systemd HOME/LOGNAME/SHELL behavior, not complete environment proof.
        login_variables_enabled=bool, passes=2, service_reads=2)),
    'operator_manager_environment': ('ManagerEnvironmentObservation', _fields(
        'global_manager_environment_empty',
        'unit_environment_proven wrapper_environment_proven effective_environment_proven '
        'startup_authorized', passes=2)),
    'operator_node_options': ('NodeOptionsObservation', _fields(
        'content_policy_passed queried_unit_sources_constrained manager_global_export_empty '
        'wrapper_bytes_match_pin wrapper_literal_config_assignment wrapper_literal_prefix_assignment '
        'launcher_bytes_match_pin source_contract_passed',
        'selected_source_proven effective_prefix_proven effective_environment_proven startup_authorized',
        option_count=('range', 1, 2), checked_files=3, passes=2, service_reads=3,
        package_reads=3, manager_export_reads=2)),
    'operator_dependency': ('DependencyObservation', _fields(
        'direct_shadow_candidates_absent',
        'root_axios_selected_proven transitive_resolution_proven effective_environment_proven '
        'startup_authorized', shadow_candidate_count=19, pinned_files_checked=2,
        passes=2, package_reads=3)),
    'operator_dependency_graph': ('GraphObservation', _fields(
        'declared_graph_and_shadows_observed package_root_search_only',
        'import_sites_proven actual_node_resolution_proven loaded_code_proven '
        'effective_environment_proven startup_authorized',
        declared_packages_checked=26, declared_edges_checked=35,
        shadow_candidates_checked=238, passes=2)),
    'operator_import_sites': ('SiteObservation', _fields(
        'pinned_code_sites_observed',
        'executed_imports_proven unlisted_code_absent_proven actual_node_resolution_proven '
        'loaded_code_proven effective_environment_proven startup_authorized',
        declared_packages_checked=26, declared_edges_checked=35, pinned_code_files_checked=153,
        distinct_code_directories_checked=46, site_dependency_pairs_checked=89,
        shadow_candidates_checked=478, passes=2)),
    'operator_file_set': ('FileSetObservation', _fields(
        'package_root_file_set_observed',
        'file_bytes_verified unlisted_files_outside_package_roots_excluded '
        'actual_node_resolution_proven loaded_code_proven startup_authorized',
        package_roots_checked=26, outer_roots_scanned=('range', 1, 26), manifest_files_seen=267,
        directory_entries_seen=('range', 267, 8192), directories_seen=('range', 26, 8192), passes=2)),
    'operator_core': (None, _fields('byte_integrity_passed',
        'startup_authorized live_acceptance', checked_files=270, passes=2)),
}

_PYTHON_PACKAGE_RESULTS = (
    ('python3.14-minimal', '3.14.4-1ubuntu0.2'),
    ('libpython3.14-minimal', '3.14.4-1ubuntu0.2'),
    ('libc6', '2.43-2ubuntu2.4'), ('libssl3t64', '3.5.5-1ubuntu3.5'),
    ('libexpat1', '2.7.4-1ubuntu0.2'),
    ('zlib1g', '1:1.3.dfsg+really1.3.1-1ubuntu3.1'), ('libzstd1', '1.5.7+dfsg-3'),
)


def _result_shape(module, name, result, fields):
    """Exact pinned class/dict, never duck-typed or truthiness-based evidence."""
    if name is None:
        _require(type(result) is dict and result.keys() == fields.keys(), 'GUARD_RESULT_SHAPE')
        return dict(result)
    cls = getattr(module, name)
    _require(type(result) is cls and cls.__dataclass_fields__.keys() == fields.keys(),
             'GUARD_RESULT_SHAPE')
    _require(vars(result).keys() <= fields.keys(), 'GUARD_RESULT_SHAPE')
    return {key: getattr(result, key) for key in fields}


def _result_values(values, fields):
    for key, rule in fields.items():
        value = values[key]
        if rule is bool or rule is tuple:
            valid = type(value) is rule
        elif type(rule) is tuple and rule[0] == 'range':
            valid = type(value) is int and rule[1] <= value <= rule[2]
        elif type(rule) is tuple and rule[0] == 'bytes':
            valid = type(value) is bytes and rule[1] <= len(value) <= rule[2]
        elif type(rule) is tuple and rule[0] == 'choice':
            valid = type(value) is str and value in rule[1:]
        elif rule == 'package':
            continue  # Validated with the exact held PackageIdentity below.
        else:
            valid = type(value) is type(rule) and value == rule
        _require(valid, 'GUARD_RESULT_VALUE')


def _check_observation(loaded, stem, result):
    """Return a private immutable comparison snapshot, never a permit/receipt.

    No I/O, report replay, auto-learning, source imports or diagnostics carrying
    observation data. Exact bytes still come from the independently pinned
    observers; a well-shaped forged record is not live evidence.
    """
    _require(type(stem) is str and stem in _RESULT_CONTRACTS, 'GUARD_RESULT_KIND')
    module = loaded[HELD_PACKAGE + '.' + stem]
    name, fields = _RESULT_CONTRACTS[stem]
    values = _result_shape(module, name, result, fields)
    _result_values(values, fields)
    if stem == 'operator_runtime':
        expected = dict(version='4.14.7-1', architecture='amd64',
                        selection=('choice', 'install', 'hold'))
        package = _result_shape(module, 'PackageIdentity', values['package'], expected)
        _result_values(package, expected)
        values['package'] = tuple(package.items())
    elif stem == 'operator_python_runtime':
        packages = values['packages']
        _require(len(packages) == len(_PYTHON_PACKAGE_RESULTS), 'GUARD_RESULT_VALUE')
        snapshots = []
        for record, (package_name, version) in zip(packages, _PYTHON_PACKAGE_RESULTS):
            expected = dict(name=package_name, version=version, architecture='amd64',
                            selection=('choice', 'install', 'hold'))
            package = _result_shape(module, 'PackageRecord', record, expected)
            _result_values(package, expected)
            snapshots.append(tuple(package.items()))
        values['packages'] = tuple(snapshots)
    elif stem == 'operator_file_set':
        # Every visited directory except the outer roots is also an entry.
        # Extra empty directories remain allowed by the existing bounded walk.
        _require(values['directory_entries_seen'] == values['manifest_files_seen']
                 + values['directories_seen'] - values['outer_roots_scanned'],
                 'GUARD_RESULT_COUNTS')
    return tuple(values.items())


def _observe_held(loaded):
    """One fixed observation sequence. Results never become startup authority.

    The external OS/launcher is the trust anchor, not an input Boolean or a
    saved report. Private bootstrap data stays local. Every observer is bracketed
    by full held-table/launch checks; Python checks bracket broker checks too.
    """
    baseline = _phase_state(loaded)
    def module(stem):
        return loaded[HELD_PACKAGE + '.' + stem]
    snapshots = {}
    def checked(stem, method, *args, **kwargs):
        _same_phase(baseline, _phase_state(loaded))
        result = getattr(module(stem), method)(*args, **kwargs)
        snapshot = _check_observation(loaded, stem, result)
        # Cache invalidation may legitimately change the count; both snapshots
        # still undergo their own full observer/policy checks. No auto-repair.
        if stem != 'operator_python_path_importers':
            code = {'operator_bootstrap': 'GUARD_PHASE_BOOTSTRAP',
                    'operator_runtime': 'GUARD_PHASE_PACKAGE'}.get(stem, 'GUARD_RESULT_CHANGED')
            _require(stem not in snapshots or snapshots[stem] == snapshot, code)
            snapshots[stem] = snapshot
        _same_phase(baseline, _phase_state(loaded))
        return result
    def python_checks():
        for stem, method in (
            ('operator_python_paths', 'observe_python_path_inputs'),
            ('operator_python_runtime', 'observe_python_runtime'),
            ('operator_python_candidates', 'observe_python_import_candidates'),
            ('operator_python_native', 'observe_python_native'),
            ('operator_python_path_importers', 'observe_python_path_importers'),
        ):
            checked(stem, method)
        finder = sys.meta_path[0]  # Exact entry-defined object checked above.
        checked('operator_python_import_state', 'observe_python_import_state',
                held_finder=finder)
        checked('operator_python_embedded', 'observe_python_embedded_modules',
                held_finder=finder)

    python_checks()
    core = module('operator_core')
    first = checked('operator_bootstrap', 'load_bootstrap')
    package = checked('operator_runtime', 'observe_package_runtime', first.manifest)
    for stem, method in (
        ('operator_service', 'observe_service_configuration'),
        ('operator_launch', 'observe_launch_files'),
        ('operator_unit_sources', 'observe_unit_sources'),
        ('operator_manager_environment', 'observe_manager_environment'),
        ('operator_node_options', 'observe_node_options'),
        ('operator_dependency', 'observe_direct_axios_shadow'),
        ('operator_dependency_graph', 'observe_declared_axios_graph'),
        ('operator_import_sites', 'observe_pinned_import_sites'),
        ('operator_file_set', 'observe_package_file_set'),
    ):
        checked(stem, method)
    # Compare installed bytes against the selected on-disk contract; passing
    # NODE is NOT a claim that a live broker selected it (no PID in pre-start).
    checked('operator_core', 'verify_installed_bytes', first.manifest,
            module('operator_fs').InstalledReader(first.manifest),
            package_version=package.package.version, selected_node=core.NODE)
    checked('operator_bootstrap', 'load_bootstrap')
    checked('operator_runtime', 'observe_package_runtime', first.manifest)
    python_checks()
    _same_phase(baseline, _phase_state(loaded))


def _observe_launch():
    """Fixed root-controlled launch target, still NOT a production permit.

    Requires the separately trusted OS and generated launcher's pre-exec checks.
    A root caller bypassing that launcher is outside the trust model. No token,
    environment switch or CLI flag can assert bootstrap trust to this routine.
    """
    _preparation_settings()
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        _check_entry_at(fd)
        sources = _verify_bundle_at(fd, runtime=True)
    finally:
        os.close(fd)
    _prepare_stdlib()
    prepared = tuple(sys.modules.items())
    table = sys.modules
    with _loaded_verified_bundle(sources, runtime=True) as loaded:
        _require(sys.modules is table and all(sys.modules.get(k) is v for k, v in prepared),
                 'GUARD_PHASE_CHANGED')
        _observe_held(loaded)
    _preparation_settings()
    _check_module_table(sys.modules)
    _require(sys.modules is table and all(sys.modules.get(k) is v for k, v in prepared),
             'GUARD_PHASE_CHANGED')


def main():
    """Always fail closed: no installed guard or startup permit exists yet."""
    try:
        _observe_launch()
    except GuardLaunchError:
        print('GUARD_OBSERVATION_FAILED', file=sys.stderr)
        return 1
    except BaseException:
        print('GUARD_UNEXPECTED', file=sys.stderr)
        return 1
    print('GUARD_NOT_READY', file=sys.stderr)
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
