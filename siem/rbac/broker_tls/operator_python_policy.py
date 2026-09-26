"""Offline Python runtime metadata/launch policy; NOT a startup guard.

Pins come from owner-reported C1/C3 metadata, not independent package provenance.
Functions compare caller-supplied data only: no filesystem, subprocess, network,
environment lookup or mutation. Matching an old report cannot verify a live host.
This module is deliberately outside the dormant guard's pinned source capsule.
"""
from dataclasses import dataclass, field
import hashlib
import re


POLICY_VERSION = 2
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

# Source bytes reported at C1; not an exhaustive import closure. C1 did not
# record lengths, so this is a reviewable ceiling, NOT an observed exact size.
SOURCE_LIMIT = 1024 * 1024
SOURCE_PACKAGE = 'libpython3.14-minimal:amd64'
SOURCE_VERSION = '3.14.4-1ubuntu0.2'
C1_ORIGIN_MANIFEST_SHA256 = '6625b3d3dd24b51ceb4f4396d3eb21eada5fa2a7f87e8951cc3b7ceaded61c1d'


@dataclass(frozen=True)
class SourceFile:
    path: str
    sha256: str
    package: str = SOURCE_PACKAGE
    version: str = SOURCE_VERSION


SOURCE_FILES = (
    SourceFile('/usr/lib/python3.14/_opcode_metadata.py',
               'd9badc5ab19a66415e230bf8f4299491b2207d584981a92b6e7c447cfa1aeac3'),
    SourceFile('/usr/lib/python3.14/_py_warnings.py',
               '7728580177727fa3b295478cef4777a9d2a364c5cbd809efcea352db31144f85'),
    SourceFile('/usr/lib/python3.14/_weakrefset.py',
               '2dd7cb459d654fe78b00c5c47ee8e786c037ee77763304603f5e976dd62cbf81'),
    SourceFile('/usr/lib/python3.14/annotationlib.py',
               'e0726bf3334247b98070d1eed0a1257c1e27be1fc289aadabf2fd29f6b31b1ff'),
    SourceFile('/usr/lib/python3.14/ast.py',
               '5ea9a796353544bea0d706153516f04ef3d92be305d15a73238403837d77e34c'),
    SourceFile('/usr/lib/python3.14/base64.py',
               '202d288f0b6d25ed1b206640f86e934381e6766fa0496f6f8d87d9c1bf92cdef'),
    SourceFile('/usr/lib/python3.14/collections/__init__.py',
               'dbd563752a57c6633b7566b1e9c95bc8ea81df1a1d213b23f61c5335424e5af5'),
    SourceFile('/usr/lib/python3.14/contextlib.py',
               'c1e0d67b2007de11ae93cd36cf6faf38d9ab32656a832d592a49325eec579f96'),
    SourceFile('/usr/lib/python3.14/copy.py',
               '15154fde290d6e65b5007905689a47a9a5a724822c5e06eec35d9ffbb2a3aa69'),
    SourceFile('/usr/lib/python3.14/copyreg.py',
               '6376eb5722806396f5842997ac18add369ea9ac3ff4fcfe1460c41a088cac425'),
    SourceFile('/usr/lib/python3.14/dataclasses.py',
               'cd1435e8cd7b7fd8b0128e05c2583445ea3f76fb437b065d22cb7587206afca8'),
    SourceFile('/usr/lib/python3.14/dis.py',
               '17d4d9a9195c9ee5aa27a96f3e0871f9363fd501e3a64ef20cb1cc876d7ad553'),
    SourceFile('/usr/lib/python3.14/encodings/__init__.py',
               '2b708410495acf12a6fad9d2de928dd89e567537c253eaa2b51aaae578e96c59'),
    SourceFile('/usr/lib/python3.14/encodings/aliases.py',
               'e38fc524cc8b2355807921411c918c0d971419c4d6ba6147409785db42d257a3'),
    SourceFile('/usr/lib/python3.14/encodings/utf_8.py',
               'ba0cac060269583523ca9506473a755203037c57d466a11aa89a30a5f6756f3d'),
    SourceFile('/usr/lib/python3.14/enum.py',
               '982843c2dd6dbec992bfed44abe9ef5464be81876a180d977ccd1a69e26ec16d'),
    SourceFile('/usr/lib/python3.14/fnmatch.py',
               'ce582bc266922e4c682e2a85d72095124430a6bf58716c6f2537103480eae742'),
    SourceFile('/usr/lib/python3.14/functools.py',
               '046ec9660146db48862c7b22c78e2ef3818eaed6920e5cbf35f551ef09fec6cd'),
    SourceFile('/usr/lib/python3.14/glob.py',
               'e3c82e6f0a1fe9442d4c5625e68cb206228408f0342326f6f5c8f59112091b59'),
    SourceFile('/usr/lib/python3.14/hashlib.py',
               '88fa624821fbdee7eb2ef87c2437b207afe328cf117c7463367e2db5eb1af492'),
    SourceFile('/usr/lib/python3.14/importlib/__init__.py',
               '72b07de4133a7e39b2f6a7920465669aa04626f217e800779587bc0713fe002e'),
    SourceFile('/usr/lib/python3.14/inspect.py',
               '1da17a5ed9395af63cd76abf28967722d70341488e61f86d82634a659920ed73'),
    SourceFile('/usr/lib/python3.14/json/__init__.py',
               '95022d150a27a2bfd54ac21bfce35812c96b53c420bb7b018dcb573f13e52da0'),
    SourceFile('/usr/lib/python3.14/json/decoder.py',
               '302ce57cb6f411122d7ef2ad2997c1fc0f184849fab3f1f585752f18f2195c73'),
    SourceFile('/usr/lib/python3.14/json/encoder.py',
               'd68a4d04d2cfd95897498307f29349058b42c3f48ea6aa6739714a09200a7d01'),
    SourceFile('/usr/lib/python3.14/json/scanner.py',
               '572958017eae8842eeddd0e3d18d3c56cc0a197348224915e1d87ce937841764'),
    SourceFile('/usr/lib/python3.14/keyword.py',
               '18c2be738c04ad20ad375f6a71db34b3823c7f40b0340f5294d0e89f3c9b093b'),
    SourceFile('/usr/lib/python3.14/linecache.py',
               '692daec68e2a419adf46bafc0eb2f8a2fb36c482183fa1ac47e00fec440f7d7e'),
    SourceFile('/usr/lib/python3.14/locale.py',
               '0e90907424b4bef150b00feb1bef4687bacb416e6e3f2b463e0758ee34979fe4'),
    SourceFile('/usr/lib/python3.14/opcode.py',
               '1036d90c917bb27c540ac3205d22896ee747214df1f2682458ab915758e4fdf2'),
    SourceFile('/usr/lib/python3.14/operator.py',
               'a9f9910965c31f841caad0447ee47299ac539a371422aefe200c86c60f3b4697'),
    SourceFile('/usr/lib/python3.14/pathlib/__init__.py',
               'e82f9063fa8081136d04d27a79ba6fa44085ccb7ac78077e1095afce77f2a071'),
    SourceFile('/usr/lib/python3.14/pathlib/_os.py',
               '61e844988e54bdf47c0b11ad2b3fd961f058bb370793428f4c6868bd40cab6f2'),
    SourceFile('/usr/lib/python3.14/re/__init__.py',
               '741a9de729ed8207bfa19db990f8826f1bf3661f33d0970a80c08cd1338ebc35'),
    SourceFile('/usr/lib/python3.14/re/_casefix.py',
               '1b12d9136f23db6c3f6f26053fefc15ca964b886838c7b9c1fabf8d2efc1e5c8'),
    SourceFile('/usr/lib/python3.14/re/_compiler.py',
               'd49f30cf9a1dbae33b200ed8befd9d0ce3ac612783a10ac35196536f98923e91'),
    SourceFile('/usr/lib/python3.14/re/_constants.py',
               '42253b3181b81aad6c46392f44a0ab26dcfa31feea411296f43ba16616a1ab0b'),
    SourceFile('/usr/lib/python3.14/re/_parser.py',
               'e57bd194a2d42398355ae7c1ccc2ddfb78421dd431eb81e3809dbe8ca9057dc4'),
    SourceFile('/usr/lib/python3.14/reprlib.py',
               'b04872e10d76252e44eae50cc785eb0fe478491afc4d7f0825a93f82b2eaba5f'),
    SourceFile('/usr/lib/python3.14/selectors.py',
               '4b8a60cfbb619d080f87dffe1578372e56e8c0ac826f043224a154cf7b77606d'),
    SourceFile('/usr/lib/python3.14/signal.py',
               '0363c964c90ac0b3e515de5749205e6e6454051a1211058375d84d91eab6071a'),
    SourceFile('/usr/lib/python3.14/struct.py',
               '50c14e55f94957804c1e45e975fedbe8e86f7e1dbb745b150370ff681155370a'),
    SourceFile('/usr/lib/python3.14/subprocess.py',
               '6628ffdd65c093a6c08cae01ffe82877d3ced515aac9e7be0cff16512c30a7d9'),
    SourceFile('/usr/lib/python3.14/threading.py',
               '5323909624ec2165e70b6d31333e4191b63d383d2dc5a7d7d516a3475ea2b7e3'),
    SourceFile('/usr/lib/python3.14/token.py',
               '61d4270311099c8a0c0b2e45fb363fd1c4e347a720bcc25f682b63dc28c34234'),
    SourceFile('/usr/lib/python3.14/tokenize.py',
               '65ba1bacdc42e768382208ff27f3001ee77d9d61aafba686c67652d22b84b330'),
    SourceFile('/usr/lib/python3.14/types.py',
               'fcfdd1c5ae56a9c35f207743d774e236da0153bf78e6e4629193a8e0e9438a6b'),
    SourceFile('/usr/lib/python3.14/warnings.py',
               '142225786de63c593f1c9abdacf5b4fc0b05dd847f6bed0ebb4b4aa2d4d93b02'),
    SourceFile('/usr/lib/python3.14/weakref.py',
               '5e5f727a19a858cb4c56dbaf3e0a138ded02fb954a9a58a840a0764216ae9522'),
)


def check_source_bytes(index, raw):
    """Compare one fixed source pin; no import, execution or path fallback.

    C1 is historical owner evidence. Matching bytes cannot establish that
    Python selected this source instead of cached, frozen or shadowing code.
    """
    _require(type(index) is int and 0 <= index < len(SOURCE_FILES), 'PY_SOURCE_INDEX')
    _require(type(raw) is bytes and 0 < len(raw) <= SOURCE_LIMIT, 'PY_SOURCE_SIZE')
    _require(hashlib.sha256(raw).hexdigest() == SOURCE_FILES[index].sha256,
             'PY_SOURCE_DIGEST')


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
