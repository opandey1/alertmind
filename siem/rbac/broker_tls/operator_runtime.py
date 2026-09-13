"""Fresh installed-package/on-disk runtime observations, NOT launch attestation.

No subprocess, CLI, network or write. Reads the fixed root-owned dpkg status
database and the two independently pinned packaged runtime files. Never executes
Node and never treats a package registry entry as package authenticity proof.
"""
from dataclasses import dataclass, field
import re

from . import operator_core as core
from . import operator_fs as fs

STATUS_PARTS = ('var', 'lib', 'dpkg', 'status')
MAX_STATUS = 32 * 1024 * 1024
PACKAGE = 'wazuh-dashboard'
ARCHITECTURE = 'amd64'
IDENTITY_FIELDS = frozenset(('package', 'status', 'version', 'architecture'))


@dataclass(frozen=True)
class PackageIdentity:
    version: str
    architecture: str
    selection: str


def parse_package_status(raw):
    """Strict bounded deb822-style database parsing; no raw fields in errors.

    Field names are case-insensitive; duplicates and ambiguous target stanzas
    fail closed. Continuations of descriptive fields are ignored, never mistaken
    for Package/Status headers. The four identity fields must be single-line.
    This is a format-specific reader, not a general deb822 implementation.
    """
    core.require(type(raw) is bytes and 0 < len(raw) <= MAX_STATUS, 'PACKAGE_STATUS_SIZE')
    try:
        text = raw.decode('utf-8').replace('\r\n', '\n')
    except UnicodeError:
        raise core.OperatorError('PACKAGE_STATUS_FORMAT') from None
    core.require(not re.search(r'[\x00-\x08\x0b-\x1f\x7f]', text), 'PACKAGE_STATUS_FORMAT')
    fields, matches, previous = {}, [], None
    for line in text.split('\n') + ['']:
        if not line.strip(' \t'):
            if fields.get('package') == PACKAGE:
                matches.append(fields)
                core.require(len(matches) == 1, 'PACKAGE_STATUS_AMBIGUOUS')
            fields, previous = {}, None
            continue
        if line[0] in ' \t':
            core.require(previous is not None and previous not in IDENTITY_FIELDS, 'PACKAGE_STATUS_FORMAT')
            continue
        key, colon, value = line.partition(':')
        core.require(bool(colon) and re.fullmatch(r'[!-9;-~]+', key)
                     and not key.startswith(('#', '-')), 'PACKAGE_STATUS_FORMAT')
        key = key.lower()
        core.require(key not in fields, 'PACKAGE_STATUS_DUPLICATE')
        fields[key] = value.strip(' \t') if key in IDENTITY_FIELDS else None
        previous = key
    core.require(len(matches) == 1, 'PACKAGE_STATUS_MISSING')
    target = matches[0]
    core.require(target.get('version') == core.PACKAGE_VERSION, 'PACKAGE_VERSION')
    core.require(target.get('architecture') == ARCHITECTURE, 'PACKAGE_ARCHITECTURE')
    status = target.get('status')
    core.require(status in ('install ok installed', 'hold ok installed'), 'PACKAGE_NOT_INSTALLED')
    return PackageIdentity(target['version'], target['architecture'], status.split(' ')[0])


def read_package_identity():
    """Fresh fixed-path read; root-only metadata and no NSS/process execution."""
    try:
        fs._platform()
        raw = fs._read_root_owned(STATUS_PARTS, MAX_STATUS)
    except OSError as error:
        raise core.OperatorError(fs._os_error_code(error)) from None
    return parse_package_status(raw)


@dataclass(frozen=True)
class RuntimeObservation:
    package: PackageIdentity
    packaged_node_version: str
    runtime_passes: int = field(default=2, init=False)
    package_reads: int = field(default=3, init=False)
    selected_runtime_proven: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)


def observe_package_runtime(manifest):
    """Validate pins before IO; bracket two runtime passes with package reads.

    The manifest may be taken from load_bootstrap(). No observed package version,
    file path or reader can be supplied by an operator. Caller/import environment
    remains trusted. This does not inspect service launch, environment, modules,
    Python trust, live processes, architecture of the host or certificate validity.
    """
    reader = fs.InstalledReader(manifest)
    checks = {check.path: check for check in core.installed_checks(manifest)}
    identity = read_package_identity()
    for _ in range(2):
        for path in (core.NODE, core.HEADER):
            check = checks[path]
            raw = reader(path, check.limit)
            core.require(type(raw) is bytes and len(raw) <= check.limit, 'RUNTIME_SIZE')
            core.require(core.sha(raw) == check.digest, 'RUNTIME_DIGEST')
        core.require(read_package_identity() == identity, 'PACKAGE_CHANGED')
    return RuntimeObservation(identity, core.CONTRACT['packaged_node_version'])
