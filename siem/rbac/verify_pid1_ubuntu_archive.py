"""Offline, unprivileged Ubuntu archive-chain check for a PID 1 *candidate*.

This tool never downloads, installs, imports AlertMind's operator modules or
touches a VM. It consumes four public local files: an independently obtained
archive keyring, InRelease, Packages.xz and the exact systemd .deb. Passing
does not approve an installed-image pin or authorize manager operations.
"""
import argparse
import hashlib
import json
import lzma
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

SUITE = 'resolute-updates'
VERSION = '259.5-0ubuntu3.4'
ARCH = 'amd64'
SIGNER = 'F6ECB3762474EDA9D21B7022871920D1991BC93C'
INDEX_REL = 'main/binary-amd64/Packages.xz'
DEB_REL = 'pool/main/s/systemd/systemd_259.5-0ubuntu3.4_amd64.deb'
DEB_NAME = Path(DEB_REL).name
IMAGE_REL = 'usr/lib/systemd/systemd'
_HEX = re.compile(r'[0-9a-f]{64}\Z')
_FIELD = re.compile(rb'[A-Za-z][A-Za-z0-9-]{0,79}\Z')
_HASH_LINE = re.compile(rb' ([0-9a-f]{64}) +([0-9]+) +([^\s]+)\Z')
LIMITS = {'InRelease': 2 * 1024 * 1024,
          'Packages.xz': 16 * 1024 * 1024,
          DEB_NAME: 16 * 1024 * 1024,
          'ubuntu-archive-keyring.gpg': 2 * 1024 * 1024}
MAX_PACKAGES = 32 * 1024 * 1024
MAX_IMAGE = 32 * 1024 * 1024
MAX_TAR_LIST = 4 * 1024 * 1024


class Stop(Exception):
    """Fixed, non-sensitive failure code for an unapproved verification run."""


def require(condition, code):
    if not condition:
        raise Stop(code)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_fixed(path, limit):
    """Bound a regular input and reject obvious replacement during one read."""
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= limit,
            'INPUT_METADATA')
    with path.open('rb') as handle:
        raw = handle.read(limit + 1)
        require(len(raw) <= limit and not handle.read(1), 'INPUT_SIZE')
    after = path.lstat()
    require(len(raw) == before.st_size and
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            'INPUT_CHANGED')
    return raw


def _command(executable, argv, *, input_bytes=None, limit):
    require(executable.is_absolute() and
            stat.S_ISREG(executable.lstat().st_mode), 'TOOL_PATH')
    result = subprocess.run([str(executable), *argv], input=input_bytes,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=30, check=False)
    require(result.returncode == 0 and len(result.stdout) <= limit and
            len(result.stderr) <= 1024 * 1024, 'TOOL_FAILED')
    return result


def _verified_release(gpgv, keyring, inrelease_bytes, *, signer=SIGNER):
    """Return gpgv-verified cleartext only for the reviewed archive signer."""
    result = _command(gpgv, ['--status-fd', '2', '--keyring', str(keyring),
                             '--output', '-', '--', '-'],
                      input_bytes=inrelease_bytes, limit=LIMITS['InRelease'])
    matches = re.findall(rb'^\[GNUPG:\] VALIDSIG ([0-9A-Fa-f]{40})\b',
                         result.stderr, re.MULTILINE)
    require(len(matches) == 1 and matches[0].decode('ascii').upper() == signer,
            'ARCHIVE_SIGNER')
    require(result.stdout, 'RELEASE_EMPTY')
    return result.stdout


def _header(lines, key):
    prefix = key + b': '
    found = [line[len(prefix):] for line in lines if line.startswith(prefix)]
    require(len(found) == 1, 'RELEASE_HEADER')
    return found[0]


def release_index(cleartext):
    """Read the one exact amd64 Packages.xz digest from signed Release text."""
    require(b'\0' not in cleartext and b'\r' not in cleartext and
            cleartext.endswith(b'\n'), 'RELEASE_FORMAT')
    lines = cleartext.splitlines()
    require(_header(lines, b'Origin') == b'Ubuntu' and
            _header(lines, b'Suite') == SUITE.encode() and
            _header(lines, b'Codename') == b'resolute' and
            _header(lines, b'Version') == b'26.04', 'RELEASE_IDENTITY')
    sections = [i for i, line in enumerate(lines) if line == b'SHA256:']
    require(len(sections) == 1, 'RELEASE_SHA256')
    found = []
    for line in lines[sections[0] + 1:]:
        if not line.startswith(b' '):
            break
        match = _HASH_LINE.fullmatch(line)
        require(match is not None, 'RELEASE_SHA256')
        if match[3] == INDEX_REL.encode():
            found.append((match[1].decode('ascii'), int(match[2])))
    require(len(found) == 1 and 0 < found[0][1] <= LIMITS['Packages.xz'],
            'RELEASE_INDEX')
    return found[0]


def _unxz(raw):
    """Decompress one complete XZ stream with a strict output bound."""
    dec = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
    out = bytearray()
    for offset in range(0, len(raw), 65536):
        require(not dec.eof, 'INDEX_XZ_TRAILING')
        out.extend(dec.decompress(raw[offset:offset + 65536],
                                  max_length=MAX_PACKAGES + 1 - len(out)))
        require(len(out) <= MAX_PACKAGES, 'INDEX_SIZE')
        while not dec.needs_input and not dec.eof:
            previous = len(out)
            out.extend(dec.decompress(b'', max_length=MAX_PACKAGES + 1 - len(out)))
            require(len(out) <= MAX_PACKAGES, 'INDEX_SIZE')
            require(len(out) > previous or dec.needs_input or dec.eof,
                    'INDEX_XZ_STALLED')
    require(dec.eof and not dec.unused_data, 'INDEX_XZ_INCOMPLETE')
    return bytes(out)


def _stanza(raw):
    fields = {}
    previous = None
    for line in raw.split(b'\n'):
        if line.startswith((b' ', b'\t')):
            require(previous is not None, 'INDEX_FIELDS')
            if previous in (b'package', b'version', b'architecture', b'filename',
                            b'size', b'sha256'):
                raise Stop('INDEX_FIELDS')
            continue
        name, separator, value = line.partition(b': ')
        require(separator and _FIELD.fullmatch(name) is not None,
                'INDEX_FIELDS')
        key = name.lower()
        require(key not in fields, 'INDEX_FIELDS')
        fields[key] = value
        previous = key
    return fields


def package_entry(xz_bytes):
    raw = _unxz(xz_bytes)
    require(raw.endswith(b'\n') and b'\r' not in raw and b'\0' not in raw,
            'INDEX_FORMAT')
    matches = []
    for block in raw.rstrip(b'\n').split(b'\n\n'):
        require(block, 'INDEX_FORMAT')
        item = _stanza(block)
        if item.get(b'package') == b'systemd' and item.get(b'version') == VERSION.encode() and \
                item.get(b'architecture') == ARCH.encode():
            matches.append(item)
    require(len(matches) == 1, 'INDEX_PACKAGE')
    item = matches[0]
    require(item.get(b'filename') == DEB_REL.encode() and
            item.get(b'sha256') is not None and
            _HEX.fullmatch(item[b'sha256'].decode('ascii')) is not None and
            item.get(b'size') is not None and item[b'size'].isdigit(),
            'INDEX_PACKAGE')
    size = int(item[b'size'])
    require(0 < size <= LIMITS[DEB_NAME], 'INDEX_PACKAGE')
    return item[b'sha256'].decode('ascii'), size


def _data_tar(deb):
    """Take exactly one data.tar member from the authenticated ar container."""
    require(deb.startswith(b'!<arch>\n'), 'DEB_AR')
    position = 8
    found = []
    while position < len(deb):
        require(position + 60 <= len(deb), 'DEB_AR')
        header = deb[position:position + 60]
        require(header[58:60] == b'`\n', 'DEB_AR')
        name = header[:16].strip().rstrip(b'/')
        size_text = header[48:58].strip()
        require(size_text.isdigit(), 'DEB_AR')
        size = int(size_text)
        start = position + 60
        end = start + size
        require(end <= len(deb), 'DEB_AR')
        if name in (b'data.tar.gz', b'data.tar.xz', b'data.tar.zst'):
            found.append(deb[start:end])
        if size % 2:
            require(end < len(deb) and deb[end:end + 1] == b'\n', 'DEB_AR')
        position = end + (size % 2)
    require(position == len(deb) and len(found) == 1 and found[0], 'DEB_AR')
    return found[0]


def extracted_image(bsdtar, data_tar):
    listing = _command(bsdtar, ['-tf', '-'], input_bytes=data_tar,
                       limit=MAX_TAR_LIST).stdout
    listing = listing.replace(b'\r\n', b'\n')  # Windows bsdtar text listing.
    require(b'\0' not in listing and b'\r' not in listing, 'TAR_LIST')
    names = listing.decode('utf-8').splitlines()
    selected = [name for name in names
                if name.removeprefix('./') == IMAGE_REL]
    require(len(selected) == 1, 'TAR_IMAGE')
    image = _command(bsdtar, ['-xOf', '-', selected[0]], input_bytes=data_tar,
                     limit=MAX_IMAGE).stdout
    require(0 < len(image) <= MAX_IMAGE, 'IMAGE_SIZE')
    return image


def verify_bundle(bundle, gpgv, bsdtar, expected_image_sha256,
                  expected_image_bytes):
    """Verify local chain and compare bytes; never attest the input's origin."""
    require(type(expected_image_sha256) is str and
            _HEX.fullmatch(expected_image_sha256) is not None,
            'CANDIDATE_DIGEST')
    require(type(expected_image_bytes) is int and
            0 < expected_image_bytes <= MAX_IMAGE, 'CANDIDATE_SIZE')
    require(bundle.is_absolute() and stat.S_ISDIR(bundle.lstat().st_mode),
            'BUNDLE_PATH')
    contents = {name: read_fixed(bundle / name, limit)
                for name, limit in LIMITS.items()}
    release = _verified_release(gpgv, bundle / 'ubuntu-archive-keyring.gpg',
                                contents['InRelease'])
    index_digest, index_size = release_index(release)
    xz = contents['Packages.xz']
    require(len(xz) == index_size and digest(xz) == index_digest,
            'INDEX_HASH')
    deb_digest, deb_size = package_entry(xz)
    deb = contents[DEB_NAME]
    require(len(deb) == deb_size and digest(deb) == deb_digest, 'DEB_HASH')
    image = extracted_image(bsdtar, _data_tar(deb))
    image_digest = digest(image)
    require(len(image) == expected_image_bytes, 'IMAGE_SIZE_MISMATCH')
    require(image_digest == expected_image_sha256, 'IMAGE_MISMATCH')
    return {'archive_signer_fingerprint': SIGNER,
            'inrelease_sha256': digest(contents['InRelease']),
            'packages_xz_sha256': digest(xz),
            'deb_sha256': digest(deb),
            'extracted_image_sha256': image_digest,
            'extracted_image_bytes': len(image),
            'candidate_image_bytes_match': True,
            'scope': 'offline local bundle comparison only',
            'trust_anchor_origin_independently_approved': False,
            'installed_clone_state_proven': False,
            'reference_approved': False,
            'mutation_authorized': False,
            'review_required': True}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--gpgv', type=Path, required=True)
    parser.add_argument('--bsdtar', type=Path, required=True)
    parser.add_argument('--candidate-sha256', required=True)
    parser.add_argument('--candidate-bytes', type=int, required=True)
    args = parser.parse_args(argv)
    try:
        # The verifier is never a privileged/VM program; fail closed on Unix.
        require(not hasattr(os, 'geteuid') or os.geteuid() != 0, 'ROOT_FORBIDDEN')
        result = verify_bundle(args.bundle, args.gpgv, args.bsdtar,
                               args.candidate_sha256, args.candidate_bytes)
    except (Stop, OSError, ValueError, lzma.LZMAError,
            subprocess.TimeoutExpired, UnicodeError) as error:
        code = str(error) if type(error) is Stop else 'VERIFIER_ERROR'
        print('STOP: ' + code, file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
