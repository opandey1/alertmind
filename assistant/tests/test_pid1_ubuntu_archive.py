"""Offline archive-chain candidate checks; fixtures never touch a VM."""
from io import BytesIO
import hashlib
import lzma
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac import verify_pid1_ubuntu_archive as m

IMAGE = b'synthetic-systemd-image\n' * 6


def sha(value):
    return hashlib.sha256(value).hexdigest()


def release(index):
    return (b'Origin: Ubuntu\nLabel: Ubuntu\nSuite: resolute-updates\n'
            b'Version: 26.04\nCodename: resolute\nSHA256:\n ' +
            sha(index).encode() + b' ' + str(len(index)).encode() + b' ' +
            m.INDEX_REL.encode() + b'\n')


def ar_member(name, data):
    header = (f'{name + "/":<16}{"0":<12}{"0":<6}{"0":<6}'
              f'{"100644":<8}{len(data):<10}`\n').encode('ascii')
    assert len(header) == 60
    return header + data + (b'\n' if len(data) % 2 else b'')


def deb_with_image(image=IMAGE):
    stream = BytesIO()
    with tarfile.open(fileobj=stream, mode='w:gz') as archive:
        item = tarfile.TarInfo('./' + m.IMAGE_REL)
        item.size = len(image)
        archive.addfile(item, BytesIO(image))
    return (b'!<arch>\n' + ar_member('debian-binary', b'2.0\n') +
            ar_member('data.tar.gz', stream.getvalue()))


def index_for(deb):
    entry = (b'Package: systemd\nVersion: ' + m.VERSION.encode() +
             b'\nArchitecture: amd64\nFilename: ' + m.DEB_REL.encode() +
             b'\nSize: ' + str(len(deb)).encode() + b'\nSHA256: ' +
             sha(deb).encode() + b'\nDescription: fixture\n\n')
    return lzma.compress(entry, format=lzma.FORMAT_XZ)


class ArchiveVerifierTests(unittest.TestCase):
    def stop(self, code, call):
        with self.assertRaisesRegex(m.Stop, '^' + code + '$'):
            call()

    def test_release_exact_identity_and_unique_index(self):
        index = b'fixture'
        self.assertEqual(m.release_index(release(index)), (sha(index), len(index)))
        self.stop('RELEASE_IDENTITY', lambda: m.release_index(
            release(index).replace(b'resolute-updates', b'evil-updates')))
        self.stop('RELEASE_INDEX', lambda: m.release_index(
            release(index) + b' ' + sha(index).encode() + b' 7 ' +
            m.INDEX_REL.encode() + b'\n'))
        self.stop('RELEASE_SHA256', lambda: m.release_index(
            release(index) + b'SHA256:\n'))

    def test_index_package_identity_and_duplicate_rejection(self):
        deb = deb_with_image()
        xz = index_for(deb)
        self.assertEqual(m.package_entry(xz), (sha(deb), len(deb)))
        raw = lzma.decompress(xz)
        self.stop('INDEX_PACKAGE', lambda: m.package_entry(lzma.compress(raw + raw)))
        self.stop('INDEX_PACKAGE', lambda: m.package_entry(lzma.compress(
            raw.replace(b'Architecture: amd64', b'Architecture: arm64'))))
        self.stop('INDEX_FIELDS', lambda: m.package_entry(lzma.compress(
            raw.replace(b'SHA256: ', b'SHA256: bad\nSHA256: '))))

    def test_xz_is_single_bounded_stream(self):
        xz = index_for(deb_with_image())
        self.stop('INDEX_XZ_INCOMPLETE', lambda: m.package_entry(xz[:-5]))
        self.stop('INDEX_XZ_INCOMPLETE', lambda: m.package_entry(xz + b'garbage'))

    def test_ar_requires_one_complete_data_member(self):
        archive = deb_with_image()
        self.assertTrue(m._data_tar(archive))
        self.stop('DEB_AR', lambda: m._data_tar(archive[:-1]))
        self.stop('DEB_AR', lambda: m._data_tar(
            archive + ar_member('data.tar.gz', b'fake')))
        self.stop('DEB_AR', lambda: m._data_tar(b'not-an-ar'))

    @unittest.skipUnless(shutil.which('tar'), 'tar unavailable')
    def test_verified_metadata_chain_and_candidate_comparison(self):
        tar = Path(shutil.which('tar')).resolve()
        deb = deb_with_image()
        xz = index_for(deb)
        signed = release(xz)
        with tempfile.TemporaryDirectory() as folder:
            bundle = Path(folder)
            for name, value in (('InRelease', b'signed-envelope'),
                                ('Packages.xz', xz), (m.DEB_NAME, deb),
                                ('ubuntu-archive-keyring.gpg', b'keyring')):
                (bundle / name).write_bytes(value)
            with patch.object(m, '_verified_release', return_value=signed):
                result = m.verify_bundle(bundle, Path('/unused/gpgv'), tar,
                                         sha(IMAGE), len(IMAGE))
                self.assertEqual(result['extracted_image_sha256'], sha(IMAGE))
                self.assertFalse(result['reference_approved'])
                self.assertFalse(result['mutation_authorized'])
                self.assertFalse(result['trust_anchor_origin_independently_approved'])
                self.stop('IMAGE_MISMATCH', lambda: m.verify_bundle(
                    bundle, Path('/unused/gpgv'), tar, 'a' * 64, len(IMAGE)))
                self.stop('IMAGE_SIZE_MISMATCH', lambda: m.verify_bundle(
                    bundle, Path('/unused/gpgv'), tar, sha(IMAGE), len(IMAGE) + 1))
                (bundle / 'Packages.xz').write_bytes(xz[:-1] + b'0')
                self.stop('INDEX_HASH', lambda: m.verify_bundle(
                    bundle, Path('/unused/gpgv'), tar, sha(IMAGE), len(IMAGE)))
                (bundle / 'Packages.xz').write_bytes(xz)
                (bundle / m.DEB_NAME).write_bytes(deb[:-1] + b'0')
                self.stop('DEB_HASH', lambda: m.verify_bundle(
                    bundle, Path('/unused/gpgv'), tar, sha(IMAGE), len(IMAGE)))

    def test_symlink_input_or_invalid_candidate_fails(self):
        self.stop('CANDIDATE_DIGEST', lambda: m.verify_bundle(
            Path('/unused'), Path('/unused'), Path('/unused'), 'bad', 1))
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            source = base / 'source'
            source.write_bytes(b'content')
            link = base / 'link'
            try:
                link.symlink_to(source)
            except (OSError, NotImplementedError):
                self.skipTest('symlink creation unavailable')
            self.stop('INPUT_METADATA', lambda: m.read_fixed(link, 100))

    @unittest.skipUnless(shutil.which('gpg') and shutil.which('gpgv'),
                         'GnuPG tools unavailable')
    def test_actual_gpgv_clearsign_and_wrong_signer(self):
        gpg = Path(shutil.which('gpg')).resolve()
        gpgv = Path(shutil.which('gpgv')).resolve()
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            home = base / 'gnupg'
            home.mkdir()
            if os.name != 'nt':
                home.chmod(0o700)
            env = {**os.environ, 'GNUPGHOME': str(home)}

            def run(*args):
                result = subprocess.run([str(gpg), '--batch', '--yes',
                                         '--pinentry-mode', 'loopback', *args],
                                        env=env, capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr[:300])
                return result.stdout

            run('--passphrase', '', '--quick-generate-key',
                'Fixture <fixture@example.invalid>', 'ed25519', 'sign', '0')
            listing = run('--with-colons', '--fingerprint', '--list-keys')
            signer = next(line.split(b':')[9].decode('ascii') for line in
                          listing.splitlines() if line.startswith(b'fpr:'))
            keyring = base / 'keyring.gpg'
            keyring.write_bytes(run('--export', signer))
            plain = base / 'Release'
            plain.write_bytes(release(b'fixture'))
            signed = base / 'InRelease'
            run('--armor', '--clearsign', '--output', str(signed), str(plain))
            self.assertEqual(m._verified_release(gpgv, keyring, signed.read_bytes(),
                                                 signer=signer), plain.read_bytes())
            self.stop('ARCHIVE_SIGNER', lambda: m._verified_release(
                gpgv, keyring, signed.read_bytes(), signer='0' * 40))
            tampered = signed.read_bytes().replace(b'resolute-updates',
                                                   b'evil-updates')
            self.stop('TOOL_FAILED', lambda: m._verified_release(
                gpgv, keyring, tampered, signer=signer))


if __name__ == '__main__':
    unittest.main()
