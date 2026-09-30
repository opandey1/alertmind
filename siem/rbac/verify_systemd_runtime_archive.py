"""Host-only signed Ubuntu manager/library artifact candidate, never a VM tool.

Consumes two exact .debs through one verified Release/Packages chain. Extracts
three fixed images to stdout only, then inspects supplied ELF metadata/literal
suffixes without executing downloaded bytes. No runtime or path admission.
"""
import argparse
import json
import lzma
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

from . import verify_pid1_ubuntu_archive as archive
from .inspect_systemd_elf import inspect_elf64

VERSION = archive.VERSION
LIB_NAME = 'libsystemd-shared_' + VERSION + '_amd64.deb'
PACKAGES = (
    ('systemd', archive.DEB_NAME),
    ('libsystemd-shared', LIB_NAME),
)
OBJECTS = (
    ('manager', 'systemd', archive.IMAGE_REL),
    ('core', 'libsystemd-shared', 'usr/lib/x86_64-linux-gnu/systemd/libsystemd-core-259.so'),
    ('shared', 'libsystemd-shared', 'usr/lib/x86_64-linux-gnu/systemd/libsystemd-shared-259.so'),
)
LITERALS = tuple('/' + '/'.join((prefix, 'systemd', leaf))
                 for leaf in ('system-generators', 'system-environment-generators')
                 for prefix in ('run', 'etc', 'usr/local/lib', 'usr/lib')) + (
    'SYSTEMD_GENERATOR_PATH', 'SYSTEMD_ENVIRONMENT_GENERATOR_PATH',
)
LIMITS = {**archive.LIMITS, LIB_NAME: 16 * 1024 * 1024}
_HEX = re.compile(rb'[0-9a-f]{64}')


def package_records(xz):
    raw = archive._unxz(xz)
    archive.require(raw.endswith(b'\n') and b'\r' not in raw and b'\0' not in raw,
                    'INDEX_FORMAT')
    selected = {name: [] for name, _ in PACKAGES}
    for block in raw.rstrip(b'\n').split(b'\n\n'):
        archive.require(block, 'INDEX_FORMAT')
        item = archive._stanza(block)
        name = item.get(b'package')
        if name in (b'systemd', b'libsystemd-shared') and \
                item.get(b'version') == VERSION.encode() and \
                item.get(b'architecture') == b'amd64':
            archive.require(re.search(rb'^source: [^\n]*\n[ \t]', block,
                                      re.MULTILINE | re.IGNORECASE) is None,
                            'RUNTIME_INDEX_PACKAGE')
            selected[name.decode()].append(item)
    records = []
    for name, filename in PACKAGES:
        found = selected[name]
        archive.require(len(found) == 1, 'RUNTIME_INDEX_PACKAGE')
        item = found[0]
        source = item.get(b'source', name.encode())
        archive.require(source in (b'systemd', b'systemd (' + VERSION.encode() + b')') and
                        item.get(b'filename') == b'pool/main/s/systemd/' + filename.encode() and
                        _HEX.fullmatch(item.get(b'sha256', b'')) is not None and
                        item.get(b'size', b'').isdigit() and
                        len(item[b'size']) <= 8, 'RUNTIME_INDEX_PACKAGE')
        size = int(item[b'size'])
        archive.require(0 < size <= LIMITS[filename], 'RUNTIME_INDEX_PACKAGE')
        records.append({'package': name, 'filename': filename,
                        'sha256': item[b'sha256'].decode(), 'bytes': size})
    return tuple(records)


def extracted_objects(bsdtar, contents):
    """Fixed stdout-only members, never filesystem extraction or discovery."""
    result = {}
    for package, filename in PACKAGES:
        compressed = archive._data_tar(contents[filename])
        listing = archive._command(bsdtar, ['-tf', '-'], input_bytes=compressed,
                                   limit=archive.MAX_TAR_LIST).stdout.replace(b'\r\n', b'\n')
        archive.require(b'\0' not in listing and b'\r' not in listing, 'RUNTIME_TAR_LIST')
        names = listing.decode('utf-8').splitlines()
        for role, owner, member in OBJECTS:
            if owner != package:
                continue
            selected = [name for name in names if name.removeprefix('./') == member]
            archive.require(len(selected) == 1, 'RUNTIME_TAR_MEMBER')
            raw = archive._command(bsdtar, ['-xOf', '-', selected[0]], input_bytes=compressed,
                                   limit=archive.MAX_IMAGE).stdout
            archive.require(0 < len(raw) <= archive.MAX_IMAGE, 'RUNTIME_IMAGE_SIZE')
            result[role] = raw
    return result


def verify_runtime_bundle(bundle, gpgv, bsdtar, candidate_sha256, candidate_bytes):
    archive.require(type(candidate_sha256) is str and
                    archive._HEX.fullmatch(candidate_sha256) is not None, 'CANDIDATE_DIGEST')
    archive.require(type(candidate_bytes) is int and
                    0 < candidate_bytes <= archive.MAX_IMAGE, 'CANDIDATE_SIZE')
    archive.require(bundle.is_absolute() and stat.S_ISDIR(bundle.lstat().st_mode), 'BUNDLE_PATH')
    contents = {name: archive.read_fixed(bundle / name, limit) for name, limit in LIMITS.items()}
    release = archive._verified_release(gpgv, bundle / 'ubuntu-archive-keyring.gpg',
                                        contents['InRelease'])
    sha, size = archive.release_index(release)
    xz = contents['Packages.xz']
    archive.require(len(xz) == size and archive.digest(xz) == sha, 'INDEX_HASH')
    records = package_records(xz)
    # Check BOTH packages before any archive member is processed.
    for record in records:
        deb = contents[record['filename']]
        archive.require(len(deb) == record['bytes'] and
                        archive.digest(deb) == record['sha256'], 'RUNTIME_DEB_HASH')
    images = extracted_objects(bsdtar, contents)
    archive.require(len(images['manager']) == candidate_bytes, 'IMAGE_SIZE_MISMATCH')
    archive.require(archive.digest(images['manager']) == candidate_sha256, 'IMAGE_MISMATCH')
    objects = []
    for role, package, member in OBJECTS:
        raw = images[role]
        elf = inspect_elf64(raw)
        archive.require(elf['elf_type'] == 'ET_DYN', 'RUNTIME_ELF_TYPE')
        if role == 'manager':
            archive.require(elf['interpreter'] == '/lib64/ld-linux-x86-64.so.2' and
                            elf['soname'] is None and
                            elf['needed'].count('libsystemd-core-259.so') == 1 and
                            elf['needed'].count('libsystemd-shared-259.so') == 1,
                            'RUNTIME_MANAGER_SHAPE')
        else:
            archive.require(elf['interpreter'] is None and
                            elf['soname'] == 'libsystemd-' + role + '-259.so',
                            'RUNTIME_LIBRARY_SHAPE')
        objects.append({'role': role, 'package': package, 'member': member,
                        'sha256': archive.digest(raw), 'bytes': len(raw), 'elf': elf})
    literals = [{'literal': literal, 'nul_terminated_suffix_counts':
                 {role: raw.count(literal.encode('ascii') + b'\0') for role, raw in images.items()}}
                for literal in LITERALS]
    return {'schema': 1, 'scope': 'offline Ubuntu runtime-artifact candidate only',
            'package_version': VERSION, 'architecture': 'amd64',
            'archive_signer_fingerprint': archive.SIGNER,
            'inrelease_sha256': archive.digest(contents['InRelease']),
            'packages_xz_sha256': archive.digest(xz),
            'keyring_sha256': archive.digest(contents['ubuntu-archive-keyring.gpg']),
            'packages': list(records), 'objects': objects, 'literal_observations': literals,
            'candidate_image_bytes_match': True,
            'trust_anchor_origin_independently_approved': False,
            'archive_metadata_freshness_proven': False, 'installed_state_proven': False,
            'loaded_runtime_proven': False, 'loader_resolution_proven': False,
            'dependency_closure_proven': False, 'compiled_vendor_path_semantics_proven': False,
            'effective_search_paths_proven': False, 'path_override_state_proven': False,
            'reference_approved': False, 'mutation_authorized': False,
            'startup_authorized': False, 'review_required': True}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--gpgv', type=Path, required=True)
    parser.add_argument('--bsdtar', type=Path, required=True)
    parser.add_argument('--candidate-sha256', required=True)
    parser.add_argument('--candidate-bytes', type=int, required=True)
    args = parser.parse_args(argv)
    try:
        archive.require(not hasattr(os, 'geteuid') or os.geteuid() != 0, 'ROOT_FORBIDDEN')
        result = verify_runtime_bundle(args.bundle, args.gpgv, args.bsdtar,
                                       args.candidate_sha256, args.candidate_bytes)
    except (archive.Stop, OSError, ValueError, lzma.LZMAError,
            subprocess.TimeoutExpired, UnicodeError) as error:
        code = str(error) if type(error) is archive.Stop else 'VERIFIER_ERROR'
        print('STOP: ' + code, file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
