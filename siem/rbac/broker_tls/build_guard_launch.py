"""Offline reproducible launcher renderer. No installation or subprocess API.

Build tooling is trusted developer code, not part of the privileged capsule.
render_launch_candidate() returns bytes for review only. There is no execution
CLI, runtime pin discovery, caller-selected path or force/skip option.
"""
import hashlib
from pathlib import Path
import re

from . import operator_guard_entry as entry
from . import operator_python_policy as policy
from . import operator_python_candidates as candidates


LAUNCH_PATH = '/usr/local/libexec/alertmind-broker-tls-launch'
BASE = Path(__file__).resolve().parent


def _require(value):
    if not value:
        raise ValueError('GUARD_LAUNCH_BUILD')


def launch_records():
    """Bind current reviewed entry bytes plus exact literal capsule/runtime pins."""
    records = [(p.path, p.size, p.size, p.sha256) for p in policy.MAPPED_FILES]
    cache = policy.LOADER_CACHE
    records.append((cache.path, cache.size, cache.size, cache.sha256))
    records.extend((p.path, policy.SOURCE_LIMIT, 0, p.sha256) for p in policy.SOURCE_FILES)
    raw = (BASE / 'operator_guard_entry.py').read_bytes()
    _require(0 < len(raw) <= entry.MAX_ENTRY_BYTES and b'\r' not in raw and raw.endswith(b'\n'))
    records.append((entry.ENTRY_PATH, len(raw), len(raw), hashlib.sha256(raw).hexdigest()))
    for name, size, digest in entry._bundle_pins(True):
        raw = (BASE / name).read_bytes()
        _require(len(raw) == size and b'\r' not in raw and raw.endswith(b'\n') and
                 hashlib.sha256(raw).hexdigest() == digest)
        records.append((entry.CANDIDATE_ROOT + '/' + name, size, size, digest))
    _require(len(records) == 81 and len({r[0] for r in records}) == len(records))
    for path, limit, size, digest in records:
        _require(re.fullmatch(r'/[A-Za-z0-9_./-]+', path) and '..' not in path.split('/') and
                 type(limit) is int and 0 < limit <= 16 * 1024 * 1024 and
                 type(size) is int and 0 <= size <= limit and re.fullmatch('[0-9a-f]{64}', digest))
    return tuple(records)


def absent_paths():
    # No alternate selected Python imports, global loader injection or ZIP input.
    # Reject the hwcaps tree conservatively, not by learning new mapped libraries.
    return tuple(sorted({'/' + '/'.join(parts) for parts in candidates.ALTERNATE_PARTS} | {
        '/etc/ld.so.preload', '/usr/lib/python314.zip',
        '/usr/lib/x86_64-linux-gnu/glibc-hwcaps',
    }))


def loader_links():
    # Canonical C3 objects were hashed above. Resolve required ELF interpreter
    # and SONAME spelling without executing the loader or ldd.
    return (('/lib64/ld-linux-x86-64.so.2', policy.MAPPED_FILES[2].path),) + tuple(
        ('/usr/lib/x86_64-linux-gnu/' + pin.soname, pin.path)
        for pin in policy.MAPPED_FILES[3:] if pin.soname)


def render_launch_candidate():
    raw = (BASE / 'guard_launch.sh.in').read_bytes()
    _require(b'\r' not in raw and raw.endswith(b'\n'))
    text = raw.decode('ascii')
    replacements = {
        '@FILES@': '\n'.join(' '.join(map(str, row)) for row in launch_records()),
        '@ABSENT@': '\n'.join(absent_paths()),
        '@LINKS@': '\n'.join(' '.join(pair) for pair in loader_links()),
    }
    for token, value in replacements.items():
        _require(text.count(token) == 1)
        text = text.replace(token, value)
    _require('@' not in text and len(text) < 128 * 1024)
    return text.encode('ascii')
