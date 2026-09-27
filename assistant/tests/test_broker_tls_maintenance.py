"""Synthetic maintenance policy only: no VM, package tool, filesystem or start."""
import ast
from copy import deepcopy
from dataclasses import asdict, replace
import itertools
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_maintenance as m
from siem.rbac.broker_tls import operator_guard_entry as entry

BOOT = '11111111-2222-3333-4444-555555555555'
OTHER_BOOT = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'


def document():
    # Deliberately synthetic: these are NOT production pins or VM evidence.
    return {'schema': 1, 'versions': {key: 'fixture-1' for key in m.VERSION_KEYS},
            'digests': {key: 'a' * 64 for key in m.DIGEST_KEYS}}


def baseline(data=None):
    return m.parse_baseline(json.dumps(document() if data is None else data).encode())


def alter(value, key, new):
    return m.Baseline(tuple((k, new if k == key else v) for k, v in value.versions),
                      tuple((k, new if k == key else v) for k, v in value.digests))


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.source = baseline()
        self.target = alter(alter(self.source, 'python_version', 'fixture-2'),
                            'python_binary_sha256', 'b' * 64)
        self.review = m.ReviewEvidence(m.baseline_fingerprint(self.source),
            m.baseline_fingerprint(self.target), 'e' * 64, True, True, True)
        self.observation = m.MaintenanceObservation(BOOT, 1000, True, True, True,
            m.baseline_fingerprint(self.source), True, self.source, True)

    def decide(self, observation=None, review=None, **kwargs):
        values = dict(current_boot_id=BOOT, now_monotonic_ms=1000)
        values.update(kwargs)
        result = m.next_maintenance_step(self.source, self.target,
            self.observation if observation is None else observation,
            self.review if review is None else review, **values)
        self.assertFalse(result.mutation_authorized)
        self.assertFalse(result.startup_authorized)
        self.assertTrue(result.review_required)
        return result.next_step

    def test_baseline_parser_roundtrip_canonical_order_and_newlines(self):
        doc = document()
        doc['versions'] = dict(reversed(tuple(doc['versions'].items())))
        doc['digests'] = dict(reversed(tuple(doc['digests'].items())))
        a = json.dumps(doc, indent=2).replace('\n', '\r\n').encode()
        self.assertEqual(m.parse_baseline(a), self.source)
        self.assertEqual(m.baseline_fingerprint(m.parse_baseline(a)), m.baseline_fingerprint(self.source))

    def test_schema_size_encoding_and_json_fail_closed(self):
        for raw in (None, '', bytearray(b'{}'), b'', b'x' * (m.MAX_BASELINE_BYTES + 1),
                    b'\xff', b'{} trailing', b'[' * 1500 + b']' * 1500, b'NaN', b'Infinity'):
            with self.subTest(raw=type(raw)), self.assertRaises(m.MaintenanceError):
                m.parse_baseline(raw)
        for version in (True, 1.0, '1', 0, 2, None):
            data = document()
            data['schema'] = version
            with self.assertRaisesRegex(m.MaintenanceError, '^BASELINE_SCHEMA$'):
                baseline(data)

    def test_duplicate_keys_rejected_at_every_level(self):
        raw = json.dumps(document()).encode()
        for old, new in ((b'"schema": 1', b'"schema": 1, "schema": 1'),
                          (b'"os_id": "fixture-1"', b'"os_id": "fixture-1", "os_id": "fixture-1"'),
                          (b'"loader_cache_sha256":', b'"loader_cache_sha256": "' + b'a' * 64 + b'", "loader_cache_sha256":')):
            with self.assertRaisesRegex(m.MaintenanceError, '^BASELINE_DUPLICATE$'):
                m.parse_baseline(raw.replace(old, new))

    def test_missing_extra_and_wrong_container_fields_rejected(self):
        for label in ('versions', 'digests'):
            for transform in (lambda d: d.pop(next(iter(d))), lambda d: d.update(extra='x')):
                data = document()
                transform(data[label])
                with self.assertRaises(m.MaintenanceError):
                    baseline(data)
            for value in ([], None, 'PRIVATE'):
                data = document()
                data[label] = value
                with self.assertRaises(m.MaintenanceError):
                    baseline(data)
        data = document()
        data['approved'] = True
        with self.assertRaises(m.MaintenanceError):
            baseline(data)

    def test_version_and_digest_values_strict_and_bounded(self):
        for label, values in (
            ('versions', ('', 'a' * 97, '../secret', 'PRIVATE\n', True, None, 1, 'é')),
            ('digests', ('', 'a' * 63, 'a' * 65, 'A' * 64, 'g' * 64, None, True, 1))):
            for key in document()[label]:
                for value in values:
                    data = document()
                    data[label][key] = value
                    with self.subTest(key=key), self.assertRaises(m.MaintenanceError):
                        baseline(data)

    def test_direct_baseline_construction_cannot_bypass_shape(self):
        for value in (SimpleNamespace(**asdict(self.source)),
                      replace(self.source, versions=list(self.source.versions)),
                      replace(self.source, versions=tuple(reversed(self.source.versions))),
                      replace(self.source, digests=self.source.digests[:-1]),
                      replace(self.source, versions=(('os_id', 'secret\n'),) + self.source.versions[1:])):
            with self.assertRaises(m.MaintenanceError):
                m.baseline_fingerprint(value)

    def test_each_component_change_changes_content_address_and_delta(self):
        self.assertEqual(len(m.VERSION_KEYS) + len(m.DIGEST_KEYS), 24)
        before = m.baseline_fingerprint(self.source)
        for key in m.VERSION_KEYS + m.DIGEST_KEYS:
            updated = alter(self.source, key, 'c' * 64 if key in m.DIGEST_KEYS else 'fixture-3')
            self.assertNotEqual(m.baseline_fingerprint(updated), before)
            self.assertEqual(m.changed_components(self.source, updated), (key,))
        self.assertEqual(m.changed_components(self.source, self.source), ())

    def test_candidate_new_versions_do_not_imply_approval(self):
        self.assertEqual(self.decide(review=replace(self.review, independent_review_passed=None)), 'HOLD_TARGET_REVALIDATION')
        self.assertEqual(self.decide(review=replace(self.review, native_validation_passed=False)), 'HOLD_TARGET_REVALIDATION')

    def test_independent_review_source_target_and_evidence_all_required(self):
        for key in ('source_baseline_sha256', 'target_baseline_sha256', 'evidence_sha256'):
            for value in ((None,) if key == 'evidence_sha256' else (None, 'f' * 64)):
                self.assertEqual(self.decide(review=replace(self.review, **{key: value})), 'HOLD_TARGET_REVALIDATION')
        for independent, native in itertools.product((None, False, True), repeat=2):
            result = self.decide(review=replace(self.review, independent_review_passed=independent,
                                                native_validation_passed=native))
            self.assertEqual(result, 'PLAN_UPGRADE_WHILE_INHIBITED' if independent is native is True else 'HOLD_TARGET_REVALIDATION')

    def test_freshness_bound_and_clock_regression(self):
        for now, expected in ((1000, 'PLAN_UPGRADE_WHILE_INHIBITED'),
                              (31000, 'PLAN_UPGRADE_WHILE_INHIBITED'),
                              (31001, 'HOLD_STALE_OBSERVATION'), (999, 'HOLD_STALE_OBSERVATION')):
            self.assertEqual(self.decide(now_monotonic_ms=now), expected)
        self.assertEqual(self.decide(current_boot_id=OTHER_BOOT), 'HOLD_STALE_OBSERVATION')

    def test_timestamp_boot_id_and_goal_type_validation(self):
        for value in (True, -1, 1.0, '1000', 2 ** 63):
            with self.assertRaises(m.MaintenanceError):
                self.decide(now_monotonic_ms=value)
            with self.assertRaises(m.MaintenanceError):
                self.decide(observation=replace(self.observation, captured_monotonic_ms=value))
        for value in (None, 'PRIVATE', BOOT.upper() + '\n', [], True):
            with self.assertRaises(m.MaintenanceError):
                self.decide(current_boot_id=value)
        for goal in (None, True, 'start', 'unmask', 'resume'):
            with self.assertRaisesRegex(m.MaintenanceError, '^MAINTENANCE_GOAL$'):
                self.decide(goal=goal)

    def test_every_gate_boolean_rejects_coercion(self):
        for subject, keys in ((self.observation, ('exclusive_control', 'persistent_inhibition',
                'dashboard_stopped', 'backup_verified', 'installed_metadata_verified')),
                (self.review, ('independent_review_passed', 'native_validation_passed', 'owner_downtime_approved'))):
            for key, value in itertools.product(keys, (1, 0, 'true', [], {})):
                args = {'observation' if subject is self.observation else 'review': replace(subject, **{key: value})}
                with self.subTest(key=key), self.assertRaises(m.MaintenanceError):
                    self.decide(**args)

    def test_optional_digests_reject_malformed_values(self):
        for value in (True, '', 'F' * 64, 'PRIVATE', '0' * 63):
            with self.assertRaises(m.MaintenanceError):
                self.decide(observation=replace(self.observation, backup_baseline_sha256=value))
            for key in ('source_baseline_sha256', 'target_baseline_sha256', 'evidence_sha256'):
                with self.assertRaises(m.MaintenanceError):
                    self.decide(review=replace(self.review, **{key: value}))

    def test_extra_record_fields_and_wrong_classes_fail_closed(self):
        for name, obj in (('observation', self.observation), ('review', self.review)):
            with self.assertRaisesRegex(m.MaintenanceError, '^MAINTENANCE_SHAPE$'):
                self.decide(**{name: SimpleNamespace(**asdict(obj))})
            invalid = deepcopy(obj)
            object.__setattr__(invalid, 'last_completed_step', 'START')
            with self.assertRaisesRegex(m.MaintenanceError, '^MAINTENANCE_SHAPE$'):
                self.decide(**{name: invalid})

    def test_owner_and_exclusive_control_precede_proposed_operations(self):
        for value in (None, False):
            self.assertEqual(self.decide(review=replace(self.review, owner_downtime_approved=value)), 'HOLD_OWNER_DOWNTIME_APPROVAL')
            self.assertEqual(self.decide(observation=replace(self.observation, exclusive_control=value)), 'HOLD_EXCLUSIVE_CONTROL')

    def test_inhibition_precedes_stop_and_every_package_or_restore_plan(self):
        for goal in ('upgrade', 'recover'):
            for value in (None, False):
                obs = replace(self.observation, persistent_inhibition=value, dashboard_stopped=False)
                self.assertEqual(self.decide(observation=obs, goal=goal), 'REQUIRE_PERSISTENT_INHIBITION_AND_REOBSERVE')
                self.assertEqual(self.decide(observation=replace(obs, persistent_inhibition=True), goal=goal), 'REQUIRE_STOPPED_DASHBOARD_AND_REOBSERVE')

    def test_missing_inventory_or_metadata_keeps_hold(self):
        for observation in (replace(self.observation, installed=None),
                            replace(self.observation, installed_metadata_verified=None),
                            replace(self.observation, installed_metadata_verified=False)):
            self.assertEqual(self.decide(observation=observation), 'HOLD_FRESH_INSTALLED_INVENTORY')

    def test_source_backup_bound_and_verified_before_both_directions(self):
        for goal in ('upgrade', 'recover'):
            for value in (None, m.baseline_fingerprint(self.target)):
                self.assertEqual(self.decide(observation=replace(self.observation, backup_baseline_sha256=value), goal=goal), 'HOLD_VERIFIED_SOURCE_BACKUP')
            for value in (False, None):
                self.assertEqual(self.decide(observation=replace(self.observation, backup_verified=value), goal=goal), 'HOLD_VERIFIED_SOURCE_BACKUP')

    def test_source_state_proposes_upgrade_but_never_executes(self):
        self.assertEqual(self.decide(), 'PLAN_UPGRADE_WHILE_INHIBITED')

    def test_target_state_keeps_inhibited_even_after_all_checks(self):
        self.assertEqual(self.decide(observation=replace(self.observation, installed=self.target)), 'TARGET_MATCHES_KEEP_INHIBITED')

    def test_unexpected_drift_never_auto_learned_or_overwritten(self):
        for key in m.VERSION_KEYS + m.DIGEST_KEYS:
            installed = alter(self.source, key, 'd' * 64 if key in m.DIGEST_KEYS else 'unexpected-9')
            for goal in ('upgrade', 'recover'):
                self.assertEqual(self.decide(observation=replace(self.observation, installed=installed), goal=goal), 'HOLD_UNREVIEWED_DRIFT')

    def test_mixed_upgrade_never_resumes_from_partial_match(self):
        mixed = alter(self.source, 'python_version', 'fixture-2')
        for goal in ('upgrade', 'recover'):
            self.assertEqual(self.decide(observation=replace(self.observation, installed=mixed), goal=goal), 'HOLD_PARTIAL_UPGRADE_FOR_RECOVERY')

    def test_recovery_does_not_require_failed_candidate_approval_or_restart(self):
        review = replace(self.review, native_validation_passed=False, independent_review_passed=False)
        self.assertEqual(self.decide(review=review, goal='recover'), 'SOURCE_RESTORED_KEEP_INHIBITED')
        self.assertEqual(self.decide(observation=replace(self.observation, installed=self.target), review=review, goal='recover'), 'PLAN_SOURCE_RESTORE_WHILE_INHIBITED')

    def test_interruption_before_each_prerequisite_rechecks_current_state(self):
        keys = ('exclusive_control', 'persistent_inhibition', 'dashboard_stopped',
                'backup_verified', 'installed_metadata_verified')
        for combination in itertools.product((False, None, True), repeat=len(keys)):
            result = self.decide(observation=replace(self.observation, **dict(zip(keys, combination))))
            if all(value is True for value in combination):
                self.assertEqual(result, 'PLAN_UPGRADE_WHILE_INHIBITED')
            else:
                self.assertNotIn(result, ('PLAN_UPGRADE_WHILE_INHIBITED', 'TARGET_MATCHES_KEEP_INHIBITED'))

    def test_post_reboot_reuse_holds_even_with_other_green_claims(self):
        self.assertEqual(self.decide(current_boot_id=OTHER_BOOT), 'HOLD_STALE_OBSERVATION')
        fresh = replace(self.observation, boot_id=OTHER_BOOT, persistent_inhibition=None)
        self.assertEqual(self.decide(observation=fresh, current_boot_id=OTHER_BOOT), 'REQUIRE_PERSISTENT_INHIBITION_AND_REOBSERVE')

    def test_noop_target_still_needs_review_and_keeps_inhibition(self):
        self.target = self.source
        self.review = replace(self.review, target_baseline_sha256=m.baseline_fingerprint(self.source))
        self.assertEqual(self.decide(), 'TARGET_MATCHES_KEEP_INHIBITED')
        self.assertEqual(self.decide(review=replace(self.review, native_validation_passed=None)), 'HOLD_TARGET_REVALIDATION')

    def test_source_target_and_observation_not_mutated(self):
        before = deepcopy((self.source, self.target, self.observation, self.review))
        self.decide()
        self.assertEqual(before, (self.source, self.target, self.observation, self.review))

    def test_sanitized_decision_has_no_values_commands_or_success_authority(self):
        result = m.next_maintenance_step(self.source, self.target, self.observation, self.review,
                                         current_boot_id=BOOT, now_monotonic_ms=1000)
        self.assertEqual(result.changed_components, ('python_version', 'python_binary_sha256'))
        self.assertEqual(set(asdict(result)), {'next_step', 'changed_components', 'review_required', 'mutation_authorized', 'startup_authorized'})
        text = repr(result)
        self.assertNotIn('fixture-', text)
        self.assertNotIn('a' * 64, text)
        self.assertNotIn(BOOT, text)
        with self.assertRaises(m.MaintenanceError) as caught:
            m.parse_baseline(b'{"PRIVATE SECRET":true}')
        self.assertNotIn('PRIVATE', str(caught.exception))

    def test_planner_has_no_io_cli_or_guard_capsule_integration(self):
        tree = ast.parse(Path(m.__file__).read_bytes())
        modules = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        modules.update(a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names)
        self.assertEqual(modules, {'dataclasses', 'hashlib', 'json', 're'})
        calls = {n.func.id for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        self.assertTrue(calls.isdisjoint({'open', 'exec', 'eval', 'compile', 'input', 'print', '__import__'}))
        attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        self.assertTrue(attrs.isdisjoint({'write_text', 'write_bytes', 'Popen', 'system', 'run', 'unlink'}))
        self.assertNotIn('operator_maintenance.py', {row[0] for row in entry._bundle_pins(True)})


if __name__ == '__main__':
    unittest.main()
