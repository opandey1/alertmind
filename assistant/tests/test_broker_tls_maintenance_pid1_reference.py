"""Offline candidate reference comparison; no live PID or package reads."""
from dataclasses import FrozenInstanceError
import inspect
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_core as core
from siem.rbac.broker_tls import operator_maintenance_pid1_image as image
from siem.rbac.broker_tls import operator_maintenance_pid1_reference as m

BOOT = '00000000-0000-0000-0000-000000000001'
DIGEST = 'a' * 64  # Synthetic fixture, never an installed-image pin.
VERSION = '259.5-0ubuntu3.4'


def payload(**changes):
    result = dict(schema=1, candidate_path=image.IMAGE_PATH,
                  package_name='systemd', architecture='amd64',
                  executable_sha256=DIGEST, dpkg_claimed_version=VERSION)
    result.update(changes)
    return json.dumps(result, separators=(',', ':')).encode('utf-8')


def observation(**changes):
    result = dict(boot_id=BOOT, pid1_start_ticks=123,
                  executable_sha256=DIGEST, dpkg_claimed_version=VERSION,
                  collection_elapsed_ms=17)
    result.update(changes)
    return image.Pid1ImageInventory(**result)


class Pid1ReferenceTests(unittest.TestCase):
    def error(self, code, call):
        with self.assertRaisesRegex(core.OperatorError, '^' + code + '$'):
            call()

    def test_pure_module_is_not_wired_to_live_controller(self):
        from siem.rbac.broker_tls import operator_maintenance_control as control
        self.assertNotIn('pid1_reference', inspect.getsource(control))
        source = inspect.getsource(m)
        for forbidden in ('subprocess', 'os.', 'open(', 'eval(', 'exec('):
            self.assertNotIn(forbidden, source)

    def test_exact_reference_parses_and_has_stable_canonical_fingerprint(self):
        one = m.parse_pid1_image_reference(payload())
        two = m.parse_pid1_image_reference(json.dumps(json.loads(payload()),
                                        sort_keys=True, indent=2).encode('utf-8'))
        self.assertEqual(one, two)
        self.assertEqual(m.reference_fingerprint(one), m.reference_fingerprint(two))
        self.assertEqual(len(m.reference_fingerprint(one)), 64)

    def test_duplicate_or_extra_or_missing_fields_fail(self):
        duplicate = payload()[:-1] + b',"executable_sha256":"' + DIGEST.encode() + b'"}'
        self.error('PID1_REF_JSON', lambda: m.parse_pid1_image_reference(duplicate))
        self.error('PID1_REF_SHAPE', lambda: m.parse_pid1_image_reference(payload(extra='x')))
        missing = json.loads(payload())
        del missing['architecture']
        self.error('PID1_REF_SHAPE', lambda: m.parse_pid1_image_reference(
            json.dumps(missing).encode()))

    def test_wrong_schema_and_value_types_fail(self):
        for raw in (payload(schema=2), payload(schema=True)):
            self.error('PID1_REF_SHAPE', lambda raw=raw: m.parse_pid1_image_reference(raw))
        for raw in (payload(candidate_path='/tmp/systemd'), payload(package_name='other'),
                    payload(architecture='arm64'), payload(executable_sha256='A' * 64),
                    payload(executable_sha256='a' * 63),
                    payload(dpkg_claimed_version='bad version'),
                    payload(dpkg_claimed_version=123)):
            self.error('PID1_REF_VALUE', lambda raw=raw: m.parse_pid1_image_reference(raw))

    def test_malformed_oversized_or_nonfinite_json_fails_without_echo(self):
        for raw, code in ((b'', 'PID1_REF_SIZE'), (b' ' * 513, 'PID1_REF_SIZE'),
                          (b'\xff', 'PID1_REF_JSON'), (b'{', 'PID1_REF_JSON'),
                          (b'{"schema": NaN}', 'PID1_REF_JSON')):
            self.error(code, lambda raw=raw: m.parse_pid1_image_reference(raw))

    def test_reference_class_and_shape_cannot_be_extended(self):
        ref = m.parse_pid1_image_reference(payload())
        self.error('PID1_REF_SHAPE', lambda: m.reference_fingerprint(object()))
        object.__setattr__(ref, 'extra', 'x')
        self.error('PID1_REF_SHAPE', lambda: m.reference_fingerprint(ref))

    def test_matching_candidate_returns_only_non_authorizing_metadata(self):
        result = m.compare_pid1_image_reference(
            observation(), m.parse_pid1_image_reference(payload()))
        self.assertEqual(result.observed_boot_id, BOOT)
        self.assertEqual(result.observed_pid1_start_ticks, 123)
        self.assertTrue(result.candidate_fields_match)
        self.assertTrue(result.review_required)
        for name in ('reference_provenance_verified', 'observation_authenticity_proven',
                     'package_authenticity_proven', 'observation_freshness_proven',
                     'effective_generator_paths_proven', 'mutation_authorized',
                     'startup_authorized'):
            self.assertIs(getattr(result, name), False)
        with self.assertRaises(FrozenInstanceError):
            result.startup_authorized = True

    def test_image_or_version_drift_fails_closed(self):
        ref = m.parse_pid1_image_reference(payload())
        for current in (observation(executable_sha256='b' * 64),
                        observation(dpkg_claimed_version='259.5-0ubuntu3.5')):
            self.error('PID1_REF_MISMATCH', lambda current=current:
                       m.compare_pid1_image_reference(current, ref))

    def test_observation_cannot_be_wrong_type_or_extra_shaped(self):
        ref = m.parse_pid1_image_reference(payload())
        self.error('PID1_REF_OBSERVATION', lambda: m.compare_pid1_image_reference({}, ref))
        current = observation()
        object.__setattr__(current, 'extra', 'x')
        self.error('PID1_REF_OBSERVATION', lambda: m.compare_pid1_image_reference(current, ref))

    def test_observation_identity_digest_version_and_time_are_checked(self):
        ref = m.parse_pid1_image_reference(payload())
        for current in (observation(boot_id='bad'), observation(pid1_start_ticks=-1),
                        observation(pid1_start_ticks=True),
                        observation(collection_elapsed_ms=30000),
                        observation(collection_elapsed_ms=True),
                        observation(executable_sha256='A' * 64),
                        observation(dpkg_claimed_version='bad version')):
            self.error('PID1_REF_OBSERVATION', lambda current=current:
                       m.compare_pid1_image_reference(current, ref))

    def test_observation_false_claims_cannot_be_promoted(self):
        ref = m.parse_pid1_image_reference(payload())
        for name in m._FALSE_CLAIMS:
            current = observation()
            object.__setattr__(current, name, True)
            self.error('PID1_REF_OBSERVATION', lambda current=current:
                       m.compare_pid1_image_reference(current, ref))

    def test_observation_static_requirements_cannot_be_forged(self):
        ref = m.parse_pid1_image_reference(payload())
        for name, value in (('candidate_path', '/tmp/systemd'), ('passes', 1),
                            ('running_and_disk_bytes_matched', False),
                            ('local_dpkg_status_and_list_claim_matched', False),
                            ('review_required', False)):
            current = observation()
            object.__setattr__(current, name, value)
            self.error('PID1_REF_OBSERVATION', lambda current=current:
                       m.compare_pid1_image_reference(current, ref))

    def test_reference_input_is_validated_before_observation(self):
        self.error('PID1_REF_SHAPE', lambda: m.compare_pid1_image_reference(
            object(), object()))


if __name__ == '__main__':
    unittest.main()
