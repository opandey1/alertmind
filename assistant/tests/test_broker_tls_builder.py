"""No vendor download, Node process, TLS listener or credential in default CI."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('broker_tls_builder', ROOT / 'siem/rbac/broker_tls/build_candidate.py')
b = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(b)


class BrokerTLSBuilderTests(unittest.TestCase):
    def synthetic_source(self):
        # Structural fixture only, not represented as vendor source or proof.
        text = 'class ServerAPIClient {\n' + b.AGENT + '\n}\n'
        text += '// filler\n' * (193 - len(text.splitlines()))
        text += '//# sourceMappingURL=data:application/json;charset=utf-8;base64,e30=\n'
        return text.encode()

    def test_unrecognized_source_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SOURCE_HASH'):
            b.transform(b'not vendor code', b'policy')

    def test_structural_transform_removes_entire_map_and_inserts_policy(self):
        source = self.synthetic_source()
        with patch.object(b, 'CLIENT_SHA256', b.digest(source)):
            out = b.transform(source, b'// synthetic policy\n')
        self.assertNotIn(b'sourceMappingURL', out)
        self.assertNotIn(b'e30=', out)
        self.assertIn(b'// synthetic policy', out)
        self.assertIn(b'interceptors.request.use(policy.guard)', out)
        self.assertNotIn(b'rejectUnauthorized: false', out)

    def test_second_application_rejected(self):
        source = self.synthetic_source()
        with patch.object(b, 'CLIENT_SHA256', b.digest(source)):
            out = b.transform(source, b'// policy\n')
            with self.assertRaisesRegex(ValueError, 'SOURCE_HASH'):
                b.transform(out, b'// policy\n')

    def test_missing_map_fails_even_if_source_hash_is_bound(self):
        source = self.synthetic_source().replace(b'sourceMappingURL', b'changedMapLabel')
        with patch.object(b, 'CLIENT_SHA256', b.digest(source)):
            with self.assertRaisesRegex(ValueError, 'SOURCE_MAP'):
                b.transform(source, b'')

    def test_source_shape_mismatch_fails(self):
        source = self.synthetic_source().replace(b'rejectUnauthorized: false', b'rejectUnauthorized: true ')
        with patch.object(b, 'CLIENT_SHA256', b.digest(source)):
            with self.assertRaisesRegex(ValueError, 'SOURCE_SHAPE'):
                b.transform(source, b'')

    def test_existing_output_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            marker = p / 'keep'; marker.write_text('unchanged')
            with self.assertRaisesRegex(ValueError, 'OUTPUT_EXISTS'):
                b.build(p / 'absent.deb', p)
            self.assertEqual(marker.read_text(), 'unchanged')

    def test_bad_package_size_rejected_before_tar_parse(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'fake.deb'; p.write_bytes(b'bad')
            with self.assertRaisesRegex(ValueError, 'PACKAGE_SIZE'):
                b.archive_bytes(p)

    def test_same_size_bad_package_hash_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'fake.deb'; p.write_bytes(b'!<arch>\n')
            with patch.object(b, 'DEB_SIZE', 8):
                with self.assertRaisesRegex(ValueError, 'PACKAGE_HASH'):
                    b.archive_bytes(p)

    def test_policy_hash_matches_review_contract(self):
        contract = json.loads((b.HERE / 'contract.json').read_text())
        policy = (b.HERE / 'policy.cjs').read_bytes().replace(b'\r\n', b'\n')
        self.assertEqual(b.digest(policy), contract['policy_lf_sha256'])

    def test_error_adapter_preserves_http_contract_without_axios_objects(self):
        self.assertIn('status: error.response.status, data: error.response.data', b.REPLACEMENT)
        self.assertNotIn('safe.config', b.REPLACEMENT)
        self.assertNotIn('safe.request', b.REPLACEMENT)
        self.assertNotIn('safe.cause', b.REPLACEMENT)


if __name__ == '__main__':
    unittest.main()
