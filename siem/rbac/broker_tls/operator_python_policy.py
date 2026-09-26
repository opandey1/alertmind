"""Offline Python runtime metadata/launch policy; NOT a startup guard.

Pins come from owner-reported C3 metadata, not independent package provenance.
Functions compare caller-supplied data only: no filesystem, subprocess, network,
environment lookup or mutation. Matching an old report cannot verify a live host.
This module is deliberately outside the dormant guard's pinned source capsule.
"""
from dataclasses import dataclass, field
import re


POLICY_VERSION = 1
MAX_REPORT_BYTES = 16384
PATH_LIST_SHA256 = '0b112d9d770034238714593a83cc70c81cf232c2c7601d917e736b28e452e9ba'


class PythonPolicyError(Exception):
    """Fixed codes only; never echo supplied paths, environment or report text."""


def _require(condition, code):
    if not condition:
        raise PythonPolicyError(code)


@dataclass(frozen=True)
class MappedFile:
    path: str
    sha256: str
    size: int
    package: str
    version: str
    needed: tuple
    soname: str | None


@dataclass(frozen=True)
class LoaderCache:
    path: str
    sha256: str
    size: int


# Exact public values transcribed from the owner's C3 report. No pin refresh on
# mismatch: a package update needs a new observation and a reviewed policy change.
MAPPED_FILES = (
    MappedFile('/usr/bin/python3.14',
               '52e0a13e60a981d8c4b6478be2ba5176f69da07948a056bf49cf6f077e30cb41',
               7477160, 'python3.14-minimal', '3.14.4-1ubuntu0.2',
               ('libm.so.6', 'libz.so.1', 'libexpat.so.1', 'libc.so.6'), None),
    MappedFile('/usr/lib/python3.14/lib-dynload/_hashlib.cpython-314-x86_64-linux-gnu.so',
               'f57bc22cc1b6f3b48c43778634af1a7e79c5ae0632350fa5144d050c7848112c',
               64448, 'libpython3.14-minimal:amd64', '3.14.4-1ubuntu0.2',
               ('libcrypto.so.3', 'libc.so.6'), None),
    MappedFile('/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2',
               'bda779ea9e9ad234f60315477d7cfd0bdde861cd8ddd9df8cdaf62f18c4cec14',
               254864, 'libc6:amd64', '2.43-2ubuntu2.4', (), 'ld-linux-x86-64.so.2'),
    MappedFile('/usr/lib/x86_64-linux-gnu/libc.so.6',
               '85e64f97e348786a8fb4d9f3d52fec289e2fb86bba20f0731dfe61990525e0f7',
               2190608, 'libc6:amd64', '2.43-2ubuntu2.4',
               ('ld-linux-x86-64.so.2',), 'libc.so.6'),
    MappedFile('/usr/lib/x86_64-linux-gnu/libcrypto.so.3',
               '7cf7da0a671c553b7140d40ed0ee8f07d12d0fceedff87c930d1918d205b106f',
               6386528, 'libssl3t64:amd64', '3.5.5-1ubuntu3.5',
               ('libz.so.1', 'libzstd.so.1', 'libc.so.6'), 'libcrypto.so.3'),
    MappedFile('/usr/lib/x86_64-linux-gnu/libexpat.so.1.11.2',
               '2e5f66e2784c2746775567ff9916f6e7503182a8f1f2deb8ca729dfc1463849f',
               186704, 'libexpat1:amd64', '2.7.4-1ubuntu0.2',
               ('libc.so.6',), 'libexpat.so.1'),
    MappedFile('/usr/lib/x86_64-linux-gnu/libm.so.6',
               '1c488db6f4fe8cecb72456bc018de000b7a9b539c2994864b0416b5e8371b3d8',
               1198376, 'libc6:amd64', '2.43-2ubuntu2.4',
               ('libc.so.6', 'ld-linux-x86-64.so.2'), 'libm.so.6'),
    MappedFile('/usr/lib/x86_64-linux-gnu/libz.so.1.3.1',
               '47b61967895b30e8c0c6818dd633ffeb87711cf637c688f981896f0dd84ce23b',
               121272, 'zlib1g:amd64', '1:1.3.dfsg+really1.3.1-1ubuntu3.1',
               ('libc.so.6',), 'libz.so.1'),
    MappedFile('/usr/lib/x86_64-linux-gnu/libzstd.so.1.5.7',
               '060eeb79531d435306665fd78329d8a9dd579f95876c5960bb67937825362a80',
               796824, 'libzstd1:amd64', '1.5.7+dfsg-3',
               ('libc.so.6',), 'libzstd.so.1'),
)
LOADER_CACHE = LoaderCache('/etc/ld.so.cache',
                          'eab8c2e19e049bc84bbd2bd03d03adad92139ca7b1503f39b6b98e0a50456d4e',
                          70231)

# Candidate argv/environment DATA ONLY. Retain C2's deliberately non-traversable
# cache prefix rather than inventing another cache location. No exec API exists.
# The guard script path is proposed, not installed or authorized for root use.
CANDIDATE_ARGV = (
    '/usr/bin/python3.14', '-I', '-S', '-B', '-X',
    'pycache_prefix=/dev/null/alertmind-c2',
    '/usr/local/libexec/alertmind-broker-tls/guard_entry.py',
)
CANDIDATE_ENVIRONMENT = (('HOME', '/nonexistent'), ('LC_ALL', 'C'),
                         ('PATH', '/usr/bin:/bin'))


@dataclass(frozen=True)
class ReportedMetadataMatch:
    file_count: int = field(default=9, init=False)
    package_count: int = field(default=7, init=False)
    declared_dependency_edges: int = field(default=15, init=False)
    report_matches_pins: bool = field(default=True, init=False)
    live_host_checked: bool = field(default=False, init=False)
    package_authenticity_proven: bool = field(default=False, init=False)
    native_resolution_proven: bool = field(default=False, init=False)
    runtime_trusted: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)


@dataclass(frozen=True)
class LaunchCandidateMatch:
    candidate_matches: bool = field(default=True, init=False)
    effective_environment_proven: bool = field(default=False, init=False)
    runtime_trusted: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)


def compare_metadata(files, cache):
    """Compare fixed-order metadata values, never observe or authenticate files.

    The types are intentionally exact: bool must not pass for integer size,
    custom equality must not bypass pins, and caller collections stay bounded.
    """
    _require(type(files) is tuple and len(files) == len(MAPPED_FILES),
             'PY_METADATA_FILES')
    for actual, expected in zip(files, MAPPED_FILES):
        _require(type(actual) is MappedFile, 'PY_METADATA_FORMAT')
        for value in (actual.path, actual.sha256, actual.package, actual.version):
            _require(type(value) is str and 0 < len(value) <= 256, 'PY_METADATA_FORMAT')
        _require(type(actual.size) is int and 0 < actual.size <= 33554432,
                 'PY_METADATA_FORMAT')
        _require(type(actual.needed) is tuple and len(actual.needed) <= 8 and
                 all(type(name) is str and 0 < len(name) <= 128 for name in actual.needed),
                 'PY_METADATA_FORMAT')
        _require(actual.soname is None or
                 (type(actual.soname) is str and 0 < len(actual.soname) <= 128),
                 'PY_METADATA_FORMAT')
        _require(actual == expected, 'PY_METADATA_DRIFT')
    _require(type(cache) is LoaderCache and type(cache.path) is str and
             type(cache.sha256) is str and type(cache.size) is int,
             'PY_METADATA_FORMAT')
    _require(cache == LOADER_CACHE, 'PY_LOADER_CACHE_DRIFT')
    return ReportedMetadataMatch()


_FILE_LINE = re.compile(
    r'FILE ([0-9]{2}) sha256=([0-9a-f]{64}) bytes=([1-9][0-9]{0,7}) '
    r'package=([a-z0-9+.:_-]+) version=([A-Za-z0-9.+:~_-]+) path=(/[A-Za-z0-9._/-]+)')
_ELF_LINE = re.compile(r'ELF ([0-9]{2}) (NEEDED|SONAME) ([A-Za-z0-9._+-]+)')
_CACHE_LINE = re.compile(
    r'LOADER_CACHE sha256=([0-9a-f]{64}) bytes=([1-9][0-9]{0,7}) path=/etc/ld.so.cache')
REPORT_STOP = ('STOP: Gate C3 metadata only; no native-closure, '
               'package-authenticity or root-run guard authorization.')


def check_c3_report(raw):
    """Strict, bounded C3 transcript reader, with LF/CRLF portability only.

    Requires all nine FILE records, their ELF entries, the cache, summary and
    final non-authorizing STOP. Arbitrary text, duplicates and partial runs fail.
    A matching transcript is replayable historical evidence, NOT a live check.
    """
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_REPORT_BYTES, 'PY_REPORT_SIZE')
    try:
        text = raw.decode('ascii').replace('\r\n', '\n')
    except UnicodeError:
        raise PythonPolicyError('PY_REPORT_FORMAT') from None
    _require(text.endswith('\n') and
             all(ch == '\n' or ' ' <= ch <= '~' for ch in text), 'PY_REPORT_FORMAT')
    lines = text[:-1].split('\n')
    _require(12 <= len(lines) <= 64 and all(0 < len(line) <= 512 for line in lines),
             'PY_REPORT_FORMAT')
    _require(lines[0] == 'PASS fixed C2 path list: count=9 sha256=' + PATH_LIST_SHA256,
             'PY_REPORT_HEADER')
    files, cursor = [], 1
    for index in range(len(MAPPED_FILES)):
        row = _FILE_LINE.fullmatch(lines[cursor]) if cursor < len(lines) else None
        _require(row is not None and row[1] == f'{index:02d}', 'PY_REPORT_FORMAT')
        cursor += 1
        needed, soname = [], None
        while cursor < len(lines) and lines[cursor].startswith('ELF '):
            entry = _ELF_LINE.fullmatch(lines[cursor])
            _require(entry is not None and entry[1] == f'{index:02d}', 'PY_REPORT_FORMAT')
            if entry[2] == 'NEEDED':
                _require(soname is None and len(needed) < 8 and entry[3] not in needed,
                         'PY_REPORT_FORMAT')
                needed.append(entry[3])
            else:
                _require(soname is None, 'PY_REPORT_FORMAT')
                soname = entry[3]
            cursor += 1
        files.append(MappedFile(row[6], row[2], int(row[3]), row[4], row[5],
                                tuple(needed), soname))
    _require(len(lines) - cursor == 3, 'PY_REPORT_FORMAT')
    cache = _CACHE_LINE.fullmatch(lines[cursor])
    _require(cache is not None, 'PY_REPORT_FORMAT')
    _require(lines[cursor + 1] == 'PASS C3 metadata: mapped_files=9 packages=7 no_rpath_runpath=yes'
             and lines[cursor + 2] == REPORT_STOP, 'PY_REPORT_SUMMARY')
    return compare_metadata(tuple(files), LoaderCache('/etc/ld.so.cache', cache[1], int(cache[2])))


def check_candidate_launch(argv, environment):
    """Check proposed data without reading os.environ, launching or authorizing.

    The environment must be established BEFORE interpreter/ELF startup by a
    separately trusted launcher. Clearing it inside Python is too late. This
    function supplies no such launcher, unit wiring, import or metadata proof.
    """
    _require(type(argv) in (tuple, list) and len(argv) == len(CANDIDATE_ARGV) and
             all(type(arg) is str and len(arg) <= 256 for arg in argv), 'PY_LAUNCH_ARGV')
    _require(tuple(argv) == CANDIDATE_ARGV, 'PY_LAUNCH_ARGV')
    _require(type(environment) is dict and len(environment) == len(CANDIDATE_ENVIRONMENT) and
             all(type(key) is str and type(value) is str for key, value in environment.items()),
             'PY_LAUNCH_ENVIRONMENT')
    _require(environment == dict(CANDIDATE_ENVIRONMENT), 'PY_LAUNCH_ENVIRONMENT')
    return LaunchCandidateMatch()
