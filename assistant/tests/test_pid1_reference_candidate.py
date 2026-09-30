"""Pin historical reference-candidate agreement, never attest or collect it."""
from dataclasses import asdict, fields, replace
import hashlib
import inspect
import json
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_core as core
from siem.rbac.broker_tls import operator_maintenance_pid1_image as image
from siem.rbac.broker_tls import operator_maintenance_pid1_reference as reference

CANDIDATE = ROOT / 'evidence/rbac/pid1-image-reference-candidate-v1.json'
RECORD = CANDIDATE.with_suffix('.md')
ARCHIVE = ROOT / 'evidence/rbac/pid1-ubuntu-archive-host-smoke-2026-09-28.md'
NATIVE = ROOT / 'evidence/rbac/pid1-clone-observation-2026-09-30.md'
RAW_SHA = 'ae4d461b5666c1afc7ba59f0d24809ca2a3d42ea0debef3e7e525163c34e5978'
FINGERPRINT = '4d70f472c30b25dc3626dd3d27688cbc1327c6ebb7e0e9bf83842e96d0064c70'
ARCHIVE_SHA = '59bcbfda06525fe65f5ce605718b1cfdb127a16f85e75a6de491162766eedf91'
NATIVE_SHA = '6d2d6e0ecb3099430a0b4e11e53df5b30bd63a329dca506e98c387be31d31c3f'


def reported_result():
    # This reads a historical report, not a runtime receipt or freshness check.
    blocks = re.findall(r'```text\n(.*?)\n```', NATIVE.read_text(encoding='utf-8'), re.S)
    if len(blocks) != 1:
        raise AssertionError('Expected one retained diagnostic transcript')
    lines = [line for line in blocks[0].splitlines() if line.startswith('{')]
    if len(lines) != 1:
        raise AssertionError('Expected one retained JSON result')
    return json.loads(lines[0])


class Pid1ReferenceCandidateTests(unittest.TestCase):
    def retained_inventory(self):
        report = reported_result()
        self.assertEqual(set(report), {'candidate_fields_match', 'inventory',
            'reference_approved', 'runtime_authenticity_proven', 'scope', 'source_count'})
        self.assertIs(report['candidate_fields_match'], True)
        self.assertIs(report['reference_approved'], False)
        self.assertIs(report['runtime_authenticity_proven'], False)
        self.assertIs(type(report['source_count']), int)
        self.assertEqual(report['source_count'], 8)
        self.assertEqual(report['scope'], 'isolated-clone native diagnostic; not maintenance admission')
        values = report['inventory']
        self.assertIs(type(values), dict)
        init = {item.name for item in fields(image.Pid1ImageInventory) if item.init}
        self.assertTrue(init <= values.keys())
        current = image.Pid1ImageInventory(**{name: values[name] for name in init})
        # Never silently discard recorded false claims or reconstruct defaults
        # over a changed transcript. Exact field types matter (False != 0 here).
        expected = asdict(current)
        self.assertEqual(set(values), set(expected))
        for name, value in expected.items():
            self.assertIs(type(values[name]), type(value), name)
            self.assertEqual(values[name], value, name)
        return current

    def test_exact_candidate_bytes_schema_and_content_fingerprint(self):
        raw = CANDIDATE.read_bytes()
        self.assertEqual(len(raw), 234)
        self.assertTrue(raw.endswith(b'\n'))
        self.assertNotIn(b'\r', raw)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), RAW_SHA)
        value = reference.parse_pid1_image_reference(raw)
        canonical = json.dumps({'schema': 1, **asdict(value)}, sort_keys=True,
                               separators=(',', ':'), ensure_ascii=True).encode('ascii')
        self.assertEqual(raw, canonical + b'\n')
        self.assertEqual(reference.reference_fingerprint(value), FINGERPRINT)
        self.assertIn('evidence/rbac/pid1-image-reference-candidate-v1.json text eol=lf',
                      (ROOT / '.gitattributes').read_text(encoding='utf-8'))

    def test_historical_evidence_hashes_and_archive_image_not_package_hash(self):
        for path, expected in ((ARCHIVE, ARCHIVE_SHA), (NATIVE, NATIVE_SHA)):
            normalized = path.read_bytes().replace(b'\r\n', b'\n')
            self.assertEqual(hashlib.sha256(normalized).hexdigest(), expected, str(path))
        value = reference.parse_pid1_image_reference(CANDIDATE.read_bytes())
        archive = ARCHIVE.read_text(encoding='utf-8')
        self.assertIn('| extracted `usr/lib/systemd/systemd` | `' +
                      value.executable_sha256 + '` / 141,776 bytes |', archive)
        self.assertIn('`systemd_' + value.dpkg_claimed_version + '_amd64.deb`', archive)
        self.assertNotEqual(value.executable_sha256,
            '1b2eca56c5cfdbc1aca78591a68f94b7e1c996abd52095587069776b816b9dca')

    def test_recorded_complete_inventory_matches_without_native_collection(self):
        value = reference.parse_pid1_image_reference(CANDIDATE.read_bytes())
        with patch.object(image, 'observe_pid1_image_inventory',
                          side_effect=AssertionError('No native collection permitted')) as observer:
            result = reference.compare_pid1_image_reference(self.retained_inventory(), value)
        observer.assert_not_called()
        self.assertTrue(result.candidate_fields_match)
        self.assertEqual(result.reference_sha256, FINGERPRINT)
        self.assertEqual(result.observed_boot_id, '23419e71-1a7f-48c1-a8f9-dce98a1565c4')
        self.assertEqual(result.observed_pid1_start_ticks, 145)

    def test_recorded_match_cannot_be_promoted_to_approval_or_freshness(self):
        current = self.retained_inventory()
        value = reference.parse_pid1_image_reference(CANDIDATE.read_bytes())
        self.assertEqual(current.collection_elapsed_ms, 61)
        result = asdict(reference.compare_pid1_image_reference(current, value))
        for name in ('reference_provenance_verified', 'observation_authenticity_proven',
                     'package_authenticity_proven', 'observation_freshness_proven',
                     'effective_generator_paths_proven', 'mutation_authorized',
                     'startup_authorized'):
            self.assertIs(result[name], False)
        self.assertIs(result['review_required'], True)
        self.assertEqual(set(json.loads(CANDIDATE.read_bytes())), {
            'schema', 'candidate_path', 'package_name', 'architecture',
            'executable_sha256', 'dpkg_claimed_version'})

    def test_version_or_digest_drift_fails_without_refreshing_candidate(self):
        raw = CANDIDATE.read_bytes()
        value = reference.parse_pid1_image_reference(raw)
        current = self.retained_inventory()
        for changed in (replace(current, executable_sha256='0' * 64),
                        replace(current, dpkg_claimed_version='259.5-0ubuntu3.5')):
            with self.assertRaisesRegex(core.OperatorError, '^PID1_REF_MISMATCH$'):
                reference.compare_pid1_image_reference(changed, value)
        self.assertEqual(CANDIDATE.read_bytes(), raw)

    def test_candidate_cannot_embed_an_approval_field(self):
        for name in ('reference_approved', 'independent_review_approved',
                     'mutation_authorized', 'startup_authorized'):
            data = json.loads(CANDIDATE.read_bytes())
            data[name] = True
            with self.assertRaisesRegex(core.OperatorError, '^PID1_REF_SHAPE$'):
                reference.parse_pid1_image_reference(json.dumps(data).encode('ascii'))

    def test_review_deferral_record_and_no_live_candidate_wiring(self):
        text = RECORD.read_text(encoding='utf-8')
        for item in (RAW_SHA, FINGERPRINT, ARCHIVE_SHA, NATIVE_SHA,
                     'independent review deferred; no live wiring',
                     'not independent approval', 'All older review',
                     'not connected to the guard or maintenance controller',
                     'Do not auto-learn or refresh it', 'No further Gate 2A/2B/2C',
                     'dec7a77', '523995c', '7f7c6d5', '430c436'):
            self.assertIn(item, text)
        from siem.rbac.broker_tls import operator_maintenance_control as control
        self.assertNotIn('pid1_reference', inspect.getsource(control))
        # Committed evidence is not an implicit default or an installed allowlist.
        for path in (ROOT / 'siem/rbac/broker_tls').glob('*.py'):
            self.assertNotIn(CANDIDATE.name, path.read_text(encoding='utf-8'), str(path))
        plan = (ROOT / 'docs/runbooks/rbac-pid1-clone-provenance-plan.md').read_text(encoding='utf-8')
        self.assertIn('owner-authorized offline continuation', plan)
        self.assertIn('pid1-image-reference-candidate-v1.json', plan)


if __name__ == '__main__':
    unittest.main()
