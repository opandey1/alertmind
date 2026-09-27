"""Offline connected result-policy tests. Fixtures are NOT live evidence."""
import ast
from copy import deepcopy
from dataclasses import fields
from io import StringIO
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

if __package__:
    from .test_broker_tls_guard_launch import entry, loaded_fixture, observation_fixture, ORDER
else:
    from test_broker_tls_guard_launch import entry, loaded_fixture, observation_fixture, ORDER


def changed(result, key, value):
    result = deepcopy(result)
    if type(result) is dict:
        result[key] = value
    else:
        object.__setattr__(result, key, value)
    return result


class GuardObservationTests(unittest.TestCase):
    def setUp(self):
        self.loaded, _ = loaded_fixture()

    def check(self, stem, result):
        return entry._check_observation(self.loaded, stem, result)

    def compose(self, **kwargs):
        loaded, calls = loaded_fixture(**kwargs)
        with patch.object(entry, '_phase_state', return_value=()):
            entry._observe_held(loaded)
        return calls

    def test_all_nineteen_contracts_accept_actual_result_classes(self):
        self.assertEqual(len(entry._RESULT_CONTRACTS), 19)
        for stem in entry._RESULT_CONTRACTS:
            result = observation_fixture(stem)
            snapshot = self.check(stem, result)
            self.assertIs(type(snapshot), tuple)
            self.assertIs(dict(snapshot)['startup_authorized'], False)

    def test_actual_held_classes_not_ambient_lookalikes(self):
        sources = tuple((n, (Path(entry.__file__).parent / n).read_bytes())
                        for n, _, _ in entry._bundle_pins(True))
        with entry._loaded_verified_bundle(sources, runtime=True) as loaded:
            stem = 'operator_python_paths'
            cls = loaded[entry.HELD_PACKAGE + '.' + stem].PythonPathObservation
            entry._check_observation(loaded, stem, cls())
            with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_RESULT_SHAPE$'):
                entry._check_observation(loaded, stem, observation_fixture(stem))

    def test_missing_unknown_or_duck_typed_results_fail(self):
        for stem in entry._RESULT_CONTRACTS:
            for result in (None, True, {}, NS(startup_authorized=False)):
                with self.subTest(stem=stem, result=type(result)), self.assertRaises(entry.GuardLaunchError):
                    self.check(stem, result)
        for stem in ('unknown', None, [], 'operator_process'):
            with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_RESULT_KIND$'):
                self.check(stem, object())

    def test_subclasses_and_extra_instance_fields_fail(self):
        for stem in entry._RESULT_CONTRACTS:
            result = observation_fixture(stem)
            with self.subTest(stem=stem), self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_RESULT_SHAPE$'):
                self.check(stem, changed(result, 'unreviewed', False))
            if type(result) is not dict:
                subclass = type('Unreviewed', (type(result),), {})
                other = object.__new__(subclass)
                vars(other).update(vars(result))
                with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_RESULT_SHAPE$'):
                    self.check(stem, other)

    def test_new_or_missing_declared_fields_require_review(self):
        for stem, (name, schema) in entry._RESULT_CONTRACTS.items():
            if name is None:
                continue
            cls = type(observation_fixture(stem))
            original = dict(cls.__dataclass_fields__)
            for new in ({**original, 'extra': None}, {k: v for k, v in original.items() if k != 'passes' and k != 'file_passes'}):
                if new == original:
                    continue
                with patch.object(cls, '__dataclass_fields__', new), self.assertRaisesRegex(
                        entry.GuardLaunchError, '^GUARD_RESULT_SHAPE$'):
                    self.check(stem, observation_fixture(stem))

    def test_every_boolean_flag_is_exact_not_truthy(self):
        for stem in entry._RESULT_CONTRACTS:
            result = observation_fixture(stem)
            values = result if type(result) is dict else {f.name: getattr(result, f.name) for f in fields(result)}
            for key, value in values.items():
                if type(value) is not bool:
                    continue
                bad = [int(value), 'true', None]
                if key != 'login_variables_enabled':
                    bad.append(not value)
                for item in bad:
                    with self.subTest(stem=stem, field=key, value=item), self.assertRaises(entry.GuardLaunchError):
                        self.check(stem, changed(result, key, item))

    def test_integer_fields_reject_bool_float_string_and_out_of_range(self):
        for stem, (_, schema) in entry._RESULT_CONTRACTS.items():
            result = observation_fixture(stem)
            for key, rule in schema.items():
                value = result[key] if type(result) is dict else getattr(result, key)
                if type(value) is not int:
                    continue
                bad = [True, float(value), str(value), -1, 999999]
                if type(rule) is int:
                    bad.append(value + 1)
                else:
                    bad += [rule[1] - 1, rule[2] + 1]
                for item in bad:
                    with self.subTest(stem=stem, field=key, value=item), self.assertRaises(entry.GuardLaunchError):
                        self.check(stem, changed(result, key, item))

    def test_unsafe_service_and_launch_observations_fail(self):
        for stem, changes in (
            ('operator_service', {'configured_executable': 'packaged_node', 'dropin_count': 1,
             'active_state': 'activating', 'environment_files': 1, 'environment_entries': 1,
             'service_user_matches': False, 'alternate_root_present': True}),
            ('operator_launch', {'configured_wrapper_path': False, 'configured_wrapper_argv_only': False,
             'explicit_execution_flags': True, 'inline_wrapper_environment_override_named': True})):
            for key, value in changes.items():
                with self.subTest(stem=stem, field=key), self.assertRaises(entry.GuardLaunchError):
                    self.check(stem, changed(observation_fixture(stem), key, value))

    def test_visibility_fields_do_not_claim_stopped_service_or_safe_environment(self):
        for state in ('active', 'inactive', 'failed'):
            snapshot = self.check('operator_service', changed(observation_fixture('operator_service'), 'active_state', state))
            self.assertIs(dict(snapshot)['startup_authorized'], False)
        for enabled in (True, False):
            snapshot = self.check('operator_unit_sources', changed(observation_fixture('operator_unit_sources'), 'login_variables_enabled', enabled))
            self.assertIs(dict(snapshot)['effective_environment_proven'], False)

    def test_optional_counts_keep_reviewed_bounds(self):
        for count in (0, 9):
            self.check('operator_python_path_importers', changed(observation_fixture('operator_python_path_importers'), 'cached_path_count', count))
        for count in (1, 2):
            self.check('operator_node_options', changed(observation_fixture('operator_node_options'), 'option_count', count))

    def test_file_tree_counts_must_agree_and_allow_extra_empty_directories(self):
        result = observation_fixture('operator_file_set')
        with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_RESULT_COUNTS$'):
            self.check('operator_file_set', changed(result, 'directory_entries_seen', 295))
        result = changed(changed(result, 'directory_entries_seen', 295), 'directories_seen', 54)
        self.check('operator_file_set', result)

    def test_bootstrap_bytes_bounded_without_echo_or_decoding(self):
        for key, limit in (('manifest', 524288), ('certificate_pem', 65536)):
            for value in (b'', b'X' * (limit + 1), 'PRIVATE', bytearray(b'PRIVATE'), None):
                with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_RESULT_VALUE$'):
                    self.check('operator_bootstrap', changed(observation_fixture('operator_bootstrap'), key, value))

    def test_package_versions_architectures_selections_and_shapes(self):
        for stem in ('operator_runtime', 'operator_python_runtime'):
            original = observation_fixture(stem)
            records = (original.package,) if stem == 'operator_runtime' else original.packages
            for index, record in enumerate(records):
                for key, value in (('version', 'UPGRADED'), ('architecture', 'arm64'),
                                   ('selection', 'deinstall'), ('selection', True), ('extra', False)):
                    altered = changed(record, key, value)
                    new = changed(original, 'package', altered) if stem == 'operator_runtime' else changed(
                        original, 'packages', records[:index] + (altered,) + records[index + 1:])
                    with self.subTest(stem=stem, index=index, key=key), self.assertRaises(entry.GuardLaunchError):
                        self.check(stem, new)
                # Legitimate hold is not a request to freeze security updates.
                altered = changed(record, 'selection', 'hold')
                new = changed(original, 'package', altered) if stem == 'operator_runtime' else changed(
                    original, 'packages', records[:index] + (altered,) + records[index + 1:])
                self.check(stem, new)

    def test_python_packages_exact_set_and_order_no_duplicates(self):
        result = observation_fixture('operator_python_runtime')
        for values in ((), list(result.packages), result.packages[:-1], result.packages * 2,
                       tuple(reversed(result.packages)), (result.packages[0],) * 7,
                       (NS(**vars(result.packages[0])),) + result.packages[1:]):
            with self.assertRaises(entry.GuardLaunchError):
                self.check('operator_python_runtime', changed(result, 'packages', values))

    def test_literal_string_contracts_do_not_accept_unknown_versions_or_names(self):
        # Do not derive this list from the policy: widening an exact rule to
        # a choice must not silently remove its negative test.
        for stem, key in (('operator_runtime', 'packaged_node_version'),
                          ('operator_service', 'configured_executable')):
            for value in ('unreviewed', None, True):
                with self.subTest(stem=stem, field=key), self.assertRaises(entry.GuardLaunchError):
                    self.check(stem, changed(observation_fixture(stem), key, value))

    def test_comparison_snapshot_does_not_alias_mutable_nested_record(self):
        result = observation_fixture('operator_python_runtime')
        before = self.check('operator_python_runtime', result)
        object.__setattr__(result.packages[0], 'selection', 'hold')
        after = self.check('operator_python_runtime', result)
        self.assertNotEqual(before, after)
        self.assertEqual(dict(dict(before)['packages'][0])['selection'], 'install')

    def test_every_connected_call_rejects_missing_result_before_next_observer(self):
        for index in range(len(ORDER)):
            loaded, calls = loaded_fixture(result_change=lambda i, s, r: None if i == index else r)
            with self.subTest(index=index), patch.object(entry, '_phase_state', return_value=()), self.assertRaises(entry.GuardLaunchError):
                entry._observe_held(loaded)
            self.assertEqual(tuple(c[0] for c in calls), ORDER[:index + 1])

    def test_every_connected_call_rejects_false_authority(self):
        for index in range(len(ORDER)):
            loaded, calls = loaded_fixture(result_change=lambda i, s, r: changed(r, 'startup_authorized', True) if i == index else r)
            with self.subTest(index=index), patch.object(entry, '_phase_state', return_value=()), self.assertRaises(entry.GuardLaunchError):
                entry._observe_held(loaded)
            self.assertEqual(len(calls), index + 1)

    def test_python_package_drift_across_phases_stops_even_if_each_is_acceptable(self):
        seen = 0
        def drift(index, stem, result):
            nonlocal seen
            if stem == 'operator_python_runtime':
                seen += 1
                if seen == 2:
                    record = changed(result.packages[0], 'selection', 'hold')
                    return changed(result, 'packages', (record,) + result.packages[1:])
            return result
        with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_RESULT_CHANGED$'):
            self.compose(result_change=drift)

    def test_legitimate_cache_invalidation_between_phases_not_repaired_or_rejected(self):
        calls = self.compose(result_change=lambda i, s, r: changed(r, 'cached_path_count', 0)
                             if s == 'operator_python_path_importers' and i > 7 else r)
        self.assertEqual(tuple(c[0] for c in calls), ORDER)

    def test_successful_connected_observations_still_exit_one(self):
        with patch.object(entry, '_observe_launch', side_effect=lambda: self.compose()), redirect_stderr(StringIO()) as output:
            self.assertEqual(entry.main(), 1)
        self.assertEqual(output.getvalue(), 'GUARD_NOT_READY\n')

    def test_rejection_diagnostics_are_fixed_and_private(self):
        def observe():
            self.compose(result_change=lambda i, s, r: changed(r, 'active_state', 'PRIVATE /secret value')
                         if s == 'operator_service' else r)
        with patch.object(entry, '_observe_launch', side_effect=observe), redirect_stderr(StringIO()) as output:
            self.assertEqual(entry.main(), 1)
        self.assertEqual(output.getvalue(), 'GUARD_OBSERVATION_FAILED\n')

    def test_entry_stays_within_preparation_import_and_size_contract(self):
        raw = Path(entry.__file__).read_bytes()
        self.assertLessEqual(len(raw), entry.MAX_ENTRY_BYTES)
        functions = {n.name: n for n in ast.parse(raw).body if isinstance(n, ast.FunctionDef)}
        for name in ('_fields', '_result_shape', '_result_values', '_check_observation'):
            self.assertFalse(any(isinstance(n, (ast.Import, ast.ImportFrom)) for n in ast.walk(functions[name])))


if __name__ == '__main__':
    unittest.main()
