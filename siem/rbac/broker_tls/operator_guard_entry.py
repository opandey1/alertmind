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
HELD_PACKAGE = '_alertmind_guard_held'


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


def _verify_bundle_at(root_fd):
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
        expected_names = {'guard_entry.py'} | {name for name, _, _ in PINNED_MODULES}
        _scan_exact_names(parent, expected_names)
        sources = []
        for name, size, digest in PINNED_MODULES:
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


def _compile_verified_bundle(sources):
    """Compile exact held bytes without reopening a path or executing them."""
    _require(type(sources) is tuple and len(sources) == len(PINNED_MODULES),
             'GUARD_COMPILE_SET')
    compiled = []
    for received, (name, size, digest) in zip(sources, PINNED_MODULES):
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
def _loaded_verified_bundle(sources):
    """Execute only held, rechecked bytes in a temporary private namespace.

    This offline candidate is not called by the entrypoint: interpreter,
    standard-library and import-path trust must be established first. It is
    neither a sandbox nor a startup decision.
    """
    compiled = _compile_verified_bundle(sources)
    # Import types only after the entry and descriptor checks in _check_entry.
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


def _check_entry():
    _check_isolation()
    try:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY |
                     os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            _check_entry_at(fd)
            # Keep execution disabled until the interpreter, stdlib and import
            # system are independently trusted. The tested loader is dormant.
            _compile_verified_bundle(_verify_bundle_at(fd))
        finally:
            os.close(fd)
    except OSError:
        raise GuardLaunchError('GUARD_IO') from None


def main():
    """Always fail closed: no installed guard or startup permit exists yet."""
    try:
        _check_entry()
    except GuardLaunchError as error:
        print(str(error), file=sys.stderr)
        return 1
    except Exception:
        print('GUARD_UNEXPECTED', file=sys.stderr)
        return 1
    print('GUARD_NOT_READY', file=sys.stderr)
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
