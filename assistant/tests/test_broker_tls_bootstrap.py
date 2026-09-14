"""Bootstrap wiring with synthetic public bytes; no VM, credentials or network."""
import base64
import errno
import json
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_bootstrap as b
from siem.rbac.broker_tls import operator_core as core
from siem.rbac.broker_tls import operator_fs as f
if __package__:
    from .test_broker_tls_operator_fs import FakeFS, metadata
else:
    from test_broker_tls_operator_fs import FakeFS, metadata


def pem(der):
    return b'-----BEGIN CERTIFICATE-----\n' + base64.b64encode(der) + b'\n-----END CERTIFICATE-----\n'


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        # Tests pin exact opaque DER bytes; not an X.509 validity fixture.
        self.der = b'fixture-der-bytes'
        self.pem = pem(self.der)
        self.cert_patch = patch.object(b, 'CERTIFICATE_SHA256', core.sha(self.der))
        self.cert_patch.start()
        self.addCleanup(self.cert_patch.stop)
        self.files = {'original.cjs': b'old', 'candidate.cjs': b'new'}
        contract = dict(core.CONTRACT, original_sha256=core.sha(b'old'),
                        candidate_sha256=core.sha(b'new'))
        entries = {name: {'bytes': len(raw), 'sha256': core.sha(raw)} for name, raw in self.files.items()}
        contract['files_digest'] = core.sha(json.dumps(entries, sort_keys=True, separators=(',', ':')).encode())
        self.raw = json.dumps(dict(contract, files=entries)).encode()
        self.contract_patch = patch.object(core, 'CONTRACT', contract)
        self.contract_patch.start()
        self.addCleanup(self.contract_patch.stop)

    def test_production_pin_and_path_match_reviewed_candidate(self):
        # Inspect source because setUp deliberately replaces the fixture pin.
        source = Path(b.__file__).read_text(encoding='utf-8')
        pin = re.search(r"CERTIFICATE_SHA256 = '([0-9a-f]{64})'", source)[1]
        policy = (ROOT / 'siem/rbac/broker_tls/policy.cjs').read_text(encoding='utf-8')
        self.assertIn("const pin = '" + pin + "'", policy)
        self.assertIn("const path = '" + b.CERTIFICATE_PATH + "'", policy)
        self.assertEqual(b.CERTIFICATE_PATH, '/etc/alertmind/certs/alertmind-server-api.pem')
        self.assertIn("const paths = ['/', '/etc', '/etc/alertmind', '/etc/alertmind/certs', path];", policy)
        self.assertNotIn('/etc/wazuh-dashboard', policy)
        self.assertEqual(b.MANIFEST_PATH, '/etc/alertmind/broker-tls/manifest.json')
        self.assertEqual(set(b.FILES), {'manifest', 'certificate'})

    def test_certificate_dispatch_uses_independent_root_tree_not_vendor_reader(self):
        with patch.object(f, '_platform'), patch.object(f, '_identity') as identity, patch.object(
                f, '_read_native') as vendor, patch.object(f, '_read_root_owned', return_value=b'public') as read:
            self.assertEqual(b.read_bootstrap_file('certificate'), b'public')
            read.assert_called_once_with(('etc', 'alertmind', 'certs', 'alertmind-server-api.pem'), 65536)
            vendor.assert_not_called()
            identity.assert_not_called()

    def test_labels_rejected_before_filesystem_access(self):
        with patch.object(f, '_platform') as platform:
            for label in (None, [], b'manifest', '/etc/shadow', 'manifest/../certificate'):
                with self.subTest(label=label), self.assertRaisesRegex(core.OperatorError, '^BOOTSTRAP_TARGET$'):
                    b.read_bootstrap_file(label)
            platform.assert_not_called()

    def test_dispatch_requires_platform_and_root_only_reader_without_nss(self):
        with patch.object(f, '_platform') as platform, patch.object(f, '_identity') as identity, patch.object(
                f, '_read_root_owned', return_value=b'public') as read:
            for label, (path, limit) in b.FILES.items():
                self.assertEqual(b.read_bootstrap_file(label), b'public')
                read.assert_called_with(tuple(path.split('/')[1:]), limit)
            self.assertEqual(platform.call_count, 2)
            identity.assert_not_called()
        with patch.object(f, '_platform', side_effect=core.OperatorError('FS_ROOT_REQUIRED')), patch.object(
                f, '_read_root_owned') as read, self.assertRaisesRegex(core.OperatorError, '^FS_ROOT_REQUIRED$'):
            b.read_bootstrap_file('manifest')
        read.assert_not_called()

    def test_root_only_policy_rejects_service_owners_at_any_depth(self):
        with patch.object(f, '_read_root', return_value=b'ok') as root:
            self.assertEqual(f._read_root_owned(('etc', 'file'), 3), b'ok')
            policy = root.call_args.args[2]
            for parts in ((), f.VENDOR, f.VENDOR + ('file',)):
                self.assertEqual(policy(parts), ((0, 0),))
        for fd in (10, 11, 12):
            fs = FakeFS()
            fs.nodes[fd] = metadata(fd != 12, st_uid=126, st_gid=128)
            with patch.object(f, 'os', fs), self.assertRaisesRegex(core.OperatorError, '^FS_METADATA$'):
                f._read_at(10, ('dir', 'file'), 3, policy)
            fs.read.assert_not_called()

    def test_native_errors_are_static(self):
        for number, code in ((errno.ENOENT, 'FS_MISSING'), (errno.EACCES, 'FS_ACCESS'),
                             (errno.ELOOP, 'FS_SYMLINK'), (errno.ENOTDIR, 'FS_NOT_DIRECTORY'),
                             (errno.EIO, 'FS_IO')):
            with patch.object(f, '_platform'), patch.object(f, '_read_root_owned',
                    side_effect=OSError(number, 'SECRET')), self.assertRaises(core.OperatorError) as caught:
                b.read_bootstrap_file('manifest')
            self.assertEqual(str(caught.exception), code)
            self.assertTrue(caught.exception.__suppress_context__)
            self.assertIsNone(caught.exception.__cause__)

    def test_exact_certificate_pin_accepts_lf_crlf_and_no_final_newline(self):
        for raw in (self.pem, self.pem.replace(b'\n', b'\r\n'), self.pem.rstrip(b'\n')):
            b.verify_certificate_pin(raw)
        with self.assertRaisesRegex(core.OperatorError, '^BOOTSTRAP_CERT_PIN$'):
            b.verify_certificate_pin(pem(b'other'))

    def test_certificate_size_type_encoding_and_bundle_rejected(self):
        for raw in (b'', 'text', bytearray(self.pem), memoryview(self.pem), b'x' * (b.MAX_CERTIFICATE + 1)):
            with self.assertRaisesRegex(core.OperatorError, '^BOOTSTRAP_CERT_SIZE$'):
                b.verify_certificate_pin(raw)
        invalid = (self.pem + self.pem, b'prefix' + self.pem, self.pem + b'suffix',
                   self.pem.replace(b'CERTIFICATE', b'PRIVATE KEY'), self.pem.replace(b'Zml4', b'!ml4'),
                   pem(b'a').replace(b'YQ==', b'YR=='), pem(b'a').replace(b'YQ==', b'Y'), b'\xff')
        for raw in invalid:
            with self.subTest(raw=raw[:40]), self.assertRaisesRegex(core.OperatorError, '^BOOTSTRAP_CERT_PEM$'):
                b.verify_certificate_pin(raw)

    def test_composition_validates_two_passes_and_never_authorizes_start(self):
        with patch.object(b, 'read_bootstrap_file', side_effect=[self.raw, self.pem] * 2) as read:
            result = b.load_bootstrap()
        self.assertEqual([c.args[0] for c in read.call_args_list], ['manifest', 'certificate'] * 2)
        self.assertEqual(result.manifest, self.raw)
        self.assertEqual(result.certificate_pem, self.pem)
        self.assertEqual((result.checked_files, result.passes, result.startup_authorized), (2, 2, False))
        self.assertNotIn('fixture', repr(result))
        self.assertNotIn('CERTIFICATE', repr(result))
        self.assertNotIn('original.cjs', repr(result))
        with self.assertRaises(AttributeError):
            result.startup_authorized = True
        self.assertEqual(len(f.InstalledReader(result.manifest)._limits), 3)

    def test_manifest_failure_stops_before_certificate_read(self):
        with patch.object(b, 'read_bootstrap_file', return_value=b'{}') as read, self.assertRaisesRegex(
                core.OperatorError, '^MANIFEST_CONTRACT$'):
            b.load_bootstrap()
        self.assertEqual(read.call_count, 1)
        with patch.object(b, 'read_bootstrap_file', side_effect=[self.raw, pem(b'other')]) as read, self.assertRaisesRegex(
                core.OperatorError, '^BOOTSTRAP_CERT_PIN$'):
            b.load_bootstrap()
        self.assertEqual(read.call_count, 2)

    def test_second_pass_change_read_error_and_no_snapshot_claim(self):
        # Semantically valid bytes can still drift: pin-valid CRLF PEM or
        # whitespace-only manifest reserialization must fail exact pass equality.
        for values in ([self.raw, self.pem, self.raw + b' ', self.pem],
                       [self.raw, self.pem, self.raw, self.pem.replace(b'\n', b'\r\n')]):
            with patch.object(b, 'read_bootstrap_file', side_effect=values), self.assertRaisesRegex(
                    core.OperatorError, '^BOOTSTRAP_CHANGED$'):
                b.load_bootstrap()
        with patch.object(b, 'read_bootstrap_file', side_effect=[self.raw, self.pem,
                core.OperatorError('FS_CHANGED')]), self.assertRaisesRegex(core.OperatorError, '^FS_CHANGED$'):
            b.load_bootstrap()


if __name__ == '__main__':
    unittest.main()
