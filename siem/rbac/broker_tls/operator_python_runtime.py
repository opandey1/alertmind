"""Dormant Linux on-disk Python runtime observer; NOT runtime attestation.

Reads only the fixed dpkg status database, nine C3-pinned files and generated
loader cache. No commands, NSS, network, report replay, writes or launch. The
calling interpreter/import environment must already be trusted separately.
This adapter is not installed, in the guard capsule, or called by the guard.
"""
from dataclasses import dataclass, field
import hashlib
import re

from . import operator_core as core
from . import operator_fs as fs
from . import operator_python_policy as policy


STATUS_PARTS = ('var', 'lib', 'dpkg', 'status')
MAX_STATUS = 32 * 1024 * 1024
MAX_STATUS_LINES = 250000
IDENTITY_FIELDS = frozenset(('package', 'status', 'version', 'architecture'))
# dpkg's status Package field is unqualified; C3's search output may include
# :amd64. Retain a single amd64 version for each of the seven base names.
PACKAGE_PINS = tuple(dict.fromkeys(
    (item.package.split(':')[0], 'amd64', item.version) for item in policy.MAPPED_FILES))


@dataclass(frozen=True)
class PackageRecord:
    name: str
    architecture: str
    version: str
    selection: str


def parse_package_records(raw):
    """Read seven selected package identities from bounded deb822-style bytes.

    Foreign architectures are separate records, not an amd64 substitute. A
    hold is allowed only with ok/installed state and is compared across passes.
    Other fields never enter returned identities or diagnostic messages.
    """
    core.require(type(raw) is bytes and 0 < len(raw) <= MAX_STATUS, 'PY_PACKAGE_SIZE')
    try:
        text = raw.decode('utf-8').replace('\r\n', '\n')
    except UnicodeError:
        raise core.OperatorError('PY_PACKAGE_FORMAT') from None
    core.require(not re.search(r'[\x00-\x08\x0b-\x1f\x7f]', text) and
                 text.count('\n') <= MAX_STATUS_LINES, 'PY_PACKAGE_FORMAT')
    expected = {(name, arch): version for name, arch, version in PACKAGE_PINS}
    selected_names = {name for name, _ in expected}
    fields, found, previous = {}, {}, None
    for line in text.split('\n') + ['']:
        core.require(len(line) <= 65536, 'PY_PACKAGE_FORMAT')
        if not line.strip(' \t'):
            name = fields.get('package')
            if name in selected_names:
                arch = fields.get('architecture')
                core.require(type(arch) is str and re.fullmatch(r'[a-z0-9][a-z0-9-]*', arch),
                             'PY_PACKAGE_FORMAT')
                key = (name, arch)
                if key in expected:
                    core.require(key not in found, 'PY_PACKAGE_AMBIGUOUS')
                    core.require(fields.get('version') == expected[key], 'PY_PACKAGE_VERSION')
                    state = fields.get('status')
                    core.require(state in ('install ok installed', 'hold ok installed'),
                                 'PY_PACKAGE_NOT_INSTALLED')
                    found[key] = PackageRecord(name, arch, expected[key], state.split(' ')[0])
            fields, previous = {}, None
            continue
        if line[0] in ' \t':
            core.require(previous is not None and previous not in IDENTITY_FIELDS, 'PY_PACKAGE_FORMAT')
            continue
        key, colon, value = line.partition(':')
        core.require(bool(colon) and re.fullmatch(r'[!-9;-~]+', key)
                     and not key.startswith(('#', '-')), 'PY_PACKAGE_FORMAT')
        key = key.lower()
        core.require(key not in fields, 'PY_PACKAGE_DUPLICATE')
        core.require(len(fields) < 256, 'PY_PACKAGE_FORMAT')
        fields[key] = value.strip(' \t') if key in IDENTITY_FIELDS else None
        previous = key
    core.require(set(found) == set(expected), 'PY_PACKAGE_MISSING')
    return tuple(found[(name, arch)] for name, arch, _ in PACKAGE_PINS)


def _read_fixed(parts, limit):
    # Private plumbing only. Public observe_python_runtime accepts no reader,
    # path, manifest, alternate root, username or observed digest override.
    try:
        fs._platform()
        return fs._read_root_owned(parts, limit)
    except OSError as error:
        raise core.OperatorError(fs._os_error_code(error)) from None


def _package_records():
    return parse_package_records(_read_fixed(STATUS_PARTS, MAX_STATUS))


@dataclass(frozen=True)
class PythonRuntimeObservation:
    packages: tuple
    mapped_file_count: int = field(default=9, init=False)
    generated_cache_count: int = field(default=1, init=False)
    file_passes: int = field(default=2, init=False)
    package_reads: int = field(default=3, init=False)
    on_disk_byte_pins_match: bool = field(default=True, init=False)
    source_origins_verified: bool = field(default=False, init=False)
    package_file_ownership_verified: bool = field(default=False, init=False)
    package_authenticity_proven: bool = field(default=False, init=False)
    native_resolution_proven: bool = field(default=False, init=False)
    atomic_snapshot_proven: bool = field(default=False, init=False)
    loaded_code_proven: bool = field(default=False, init=False)
    effective_environment_proven: bool = field(default=False, init=False)
    runtime_trusted: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)


def observe_python_runtime():
    """Bracket two fixed byte-pin passes with three fresh package-status reads.

    Each root-only no-follow read uses the existing descriptor-relative
    primitive, including before/open/after metadata and ancestor rechecks.
    Pins are maximum AND exact sizes; no shell/ELF parser or C3 transcript is
    consulted. Bytes are discarded after each digest check, not executed.

    Equal observations do not lock updates, attest loaded code or prove a
    coherent cross-file snapshot. This code cannot bootstrap its own trust.
    """
    packages = _package_records()
    pins = policy.MAPPED_FILES + (policy.LOADER_CACHE,)
    for _ in range(2):
        for pin in pins:
            raw = _read_fixed(tuple(pin.path.split('/')[1:]), pin.size)
            core.require(type(raw) is bytes and len(raw) == pin.size, 'PY_RUNTIME_SIZE')
            core.require(hashlib.sha256(raw).hexdigest() == pin.sha256, 'PY_RUNTIME_DIGEST')
        core.require(_package_records() == packages, 'PY_PACKAGE_CHANGED')
    return PythonRuntimeObservation(packages)
