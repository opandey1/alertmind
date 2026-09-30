"""Synthetic, pure selection contracts; no native collection or generators."""
from contextlib import ExitStack
from dataclasses import asdict, FrozenInstanceError, replace
import copy
import hashlib
import inspect
from itertools import product
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_core as core
from siem.rbac.broker_tls import operator_maintenance_control as control
from siem.rbac.broker_tls import operator_maintenance_generators as inventory
from siem.rbac.broker_tls import operator_maintenance_generator_selection as m


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    ensure_ascii=True).encode('ascii')).hexdigest()


def row(name='one', kind='executable_regular', size=None, mode=None, sha=None):
    size = (0 if kind == 'empty_regular' else 3) if size is None else size
    mode = (0o644 if kind in ('empty_regular', 'nonexecutable_regular')
            else 0o755) if mode is None else mode
    sha = (hashlib.sha256(b'').hexdigest() if size == 0 else 'a' * 64) if sha is None else sha
    return name, (kind, size, mode, 0, 0, sha), ()


def group(rows, paths):
    snapshot = tuple((bool(rows.get(i)), tuple(sorted(rows.get(i, ()))), ())
                     for i in range(4))
    return inventory._result(snapshot, 1, paths)


def catalog(unit=None, environment=None):
    unit = group(unit or {}, inventory.DIRECTORIES)
    environment = group(environment or {}, inventory.ENV_DIRECTORIES)
    sha = digest(dict(version=1, unit=unit.inventory_sha256,
                      environment=environment.inventory_sha256))
    return inventory.GeneratorCatalog(unit, environment, sha, 1)


def with_entries(value, entries):
    sha = digest(dict(version=1, directories=value.directories,
                      entries=[asdict(e) for e in entries]))
    return replace(value, entries=entries, inventory_sha256=sha)


class GeneratorSelectionTests(unittest.TestCase):
    def refuse(self, suffix, value):
        with self.assertRaisesRegex(core.OperatorError,
                                    '^GENERATOR_SELECTION_' + suffix + '$'):
            m.model_default_generator_selection(value)

    def test_exact_contract_and_single_pure_input(self):
        self.assertEqual(str(inspect.signature(m.model_default_generator_selection)), '(catalog)')
        self.assertEqual(m.CONTRACT, 'upstream-v259.5-regular-subset-v1')
        self.assertEqual(m.UPSTREAM_COMMIT, 'b3d8fc43e9cb531d958c17ef2cd93b374bc14e8a')

    def test_empty_catalog_is_candidate_not_empty_effect_proof(self):
        value = m.model_default_generator_selection(catalog())
        self.assertEqual(value.unit_candidates, ())
        self.assertEqual(value.environment_candidates, ())
        self.assertTrue(value.default_paths_assumed)
        self.assertTrue(value.regular_subset_only)
        self.assertFalse(value.generated_environment_proven)

    def test_first_executable_wins_over_lower_executable_and_mask(self):
        value = m.model_default_generator_selection(catalog({0: [row()], 1: [row()],
                                                              3: [row(kind='empty_regular')]}))
        self.assertEqual([r.decision for r in value.unit_rows],
                         ['candidate', 'shadowed_by_candidate', 'shadowed_by_candidate'])
        self.assertEqual([r.earlier_blocker for r in value.unit_rows], [None, 0, 0])
        self.assertEqual([r.directory for r in value.unit_candidates], [0])

    def test_nonexecutable_does_not_shadow_lower_executable(self):
        data = catalog({0: [row(kind='nonexecutable_regular')], 3: [row()]})
        self.assertEqual(data.unit.entries[1].earlier_same_name, (0,))
        value = m.model_default_generator_selection(data)
        self.assertEqual([r.decision for r in value.unit_rows], ['nonexecutable', 'candidate'])
        self.assertEqual(value.unit_candidates[0].directory, 3)
        self.assertIsNone(value.unit_candidates[0].earlier_blocker)

    def test_empty_regular_masks_even_without_any_execute_bit(self):
        for mode in (0o000, 0o644, 0o755):
            with self.subTest(mode=mode):
                value = m.model_default_generator_selection(catalog(
                    {0: [row(kind='empty_regular', mode=mode)], 3: [row()]}))
                self.assertEqual([r.decision for r in value.unit_rows],
                                 ['empty_mask', 'shadowed_by_empty_mask'])
                self.assertEqual(value.unit_rows[1].earlier_blocker, 0)
                self.assertEqual(value.unit_candidates, ())

    def test_nonexecutable_then_empty_then_executable(self):
        value = m.model_default_generator_selection(catalog(
            {0: [row(kind='nonexecutable_regular')], 1: [row(kind='empty_regular')],
             2: [row()]}))
        self.assertEqual([r.decision for r in value.unit_rows],
                         ['nonexecutable', 'empty_mask', 'shadowed_by_empty_mask'])
        self.assertEqual(value.unit_rows[2].earlier_blocker, 1)

    def test_classes_have_separate_name_precedence_and_candidates(self):
        value = m.model_default_generator_selection(catalog(
            {0: [row(kind='empty_regular')]}, {3: [row()]}))
        self.assertEqual(value.unit_candidates, ())
        self.assertEqual(value.environment_candidates[0].name, 'one')
        self.assertEqual(value.environment_candidates[0].directory, 3)

    def test_candidate_lists_ascii_sorted_not_directory_or_execution_order(self):
        data = {0: [row('z-last'), row('A-first')], 3: [row('b-middle')]}
        value = m.model_default_generator_selection(catalog(data, data))
        self.assertEqual([r.name for r in value.unit_rows], ['A-first', 'z-last', 'b-middle'])
        for result in (value.unit_candidates, value.environment_candidates):
            self.assertEqual([r.name for r in result], ['A-first', 'b-middle', 'z-last'])

    def test_256_priority_combinations_for_each_class(self):
        kinds = (None, 'empty_regular', 'executable_regular', 'nonexecutable_regular')
        for states in product(kinds, repeat=4):
            rows = {i: [row(kind=kind)] for i, kind in enumerate(states) if kind is not None}
            decisive = next((i for i, k in enumerate(states)
                             if k in ('empty_regular', 'executable_regular')), None)
            expected = ([] if decisive is None or states[decisive] == 'empty_regular'
                        else [decisive])
            value = m.model_default_generator_selection(catalog(rows, rows))
            for selected in (value.unit_candidates, value.environment_candidates):
                self.assertEqual([r.directory for r in selected], expected, states)

    def test_links_refused_including_shadowed_and_literal_dev_null(self):
        for kind in ('null_link_literal', 'unresolved_symlink'):
            for environment in (False, True):
                rows = {0: [row()], 3: [row(kind=kind)]}
                self.refuse('LINK_UNREVIEWED', catalog(environment=rows) if environment
                            else catalog(rows))

    def test_ambiguous_names_refused_without_silent_filtering(self):
        for name in ('.hidden', 'one~', 'one.dpkg-old', 'one.rpmnew', 'one.py',
                     '../one', 'a/b', 'a\\b', 'a:b', 'a b', 'a\x00b', 'caf\u00e9',
                     '', 'a' * 256, '_leading'):
            self.refuse('NAME_UNREVIEWED', catalog({0: [row(name)]}))

    def test_bounded_simple_basename_is_supported(self):
        value = m.model_default_generator_selection(catalog(
            {0: [row('0' + 'a' * 254), row('systemd-debug-generator')]}))
        self.assertEqual(len(value.unit_candidates), 2)

    def test_wrong_record_types_missing_and_extra_fields_refused(self):
        for bad in (None, {}, (), asdict(catalog())):
            self.refuse('SHAPE', bad)
        data = catalog()
        object.__setattr__(data, 'surprise', 'PRIVATE')
        self.refuse('SHAPE', data)
        data = catalog()
        object.__delattr__(data, 'catalog_sha256')
        self.refuse('SHAPE', data)
        self.refuse('SHAPE', replace(catalog(), unit=None))

    def test_all_declared_claims_and_passes_checked_with_exact_types(self):
        base = catalog({0: [row()]})
        for location in ('catalog', 'unit', 'environment'):
            target = base if location == 'catalog' else getattr(base, location)
            defaults = {name: val for name, val in asdict(target).items()
                        if name == 'passes' or type(val) is bool}
            for name, val in defaults.items():
                for changed in ((not val, int(val)) if type(val) is bool else (True, 3)):
                    data = copy.deepcopy(base)
                    obj = data if location == 'catalog' else getattr(data, location)
                    object.__setattr__(obj, name, changed)
                    self.refuse('CLAIMS', data)

    def test_wrong_paths_presence_and_path_order_refused(self):
        data = catalog({0: [row()]})
        paths = data.unit.directories
        for changed in (list(paths), paths[:-1], tuple(reversed(paths)),
                        (('/tmp/private', True),) + paths[1:],
                        ((paths[0][0], 1),) + paths[1:]):
            self.refuse('PATHS', replace(data, unit=replace(data.unit, directories=changed)))
        self.refuse('ORDER', replace(data, unit=replace(data.unit, directories=
                    ((paths[0][0], False),) + paths[1:])))

    def test_entries_order_duplicates_and_container_type_refused(self):
        data = catalog({0: [row('a'), row('b')], 3: [row('a')]})
        entries = data.unit.entries
        for changed in (list(entries), entries * 86):
            self.refuse('COUNT', replace(data, unit=replace(data.unit, entries=changed)))
        for changed in (tuple(reversed(entries[:2])), (entries[0], entries[0])):
            self.refuse('ORDER', replace(data, unit=with_entries(data.unit, changed)))

    def test_raw_precedence_is_recomputed_not_taken_as_selection(self):
        data = catalog({0: [row(kind='nonexecutable_regular')], 3: [row()]})
        for prior in ((), (1,), (False,), [0], (0, 0)):
            entries = (data.unit.entries[0], replace(data.unit.entries[1], earlier_same_name=prior))
            self.refuse('PRECEDENCE', replace(data, unit=with_entries(data.unit, entries)))

    def test_entry_indices_kinds_modes_sizes_owners_are_strict(self):
        data = catalog({0: [row()]})
        entry = data.unit.entries[0]
        cases = {'ENTRY': [('directory', True), ('directory', -1), ('directory', 4),
                           ('kind', None), ('kind', 'fifo')],
                 'METADATA': [('bytes', True), ('bytes', -1), ('bytes', 16 * 1024 * 1024 + 1),
                              ('mode', True), ('mode', -1), ('mode', 0o10000),
                              ('mode', 0o775), ('mode', 0o757), ('mode', 0o4755),
                              ('mode', 0o2755), ('uid', False), ('gid', False),
                              ('uid', 1000), ('gid', 1000)]}
        for suffix, changes in cases.items():
            for name, val in changes:
                with self.subTest(name=name, value=val):
                    bad = replace(entry, **{name: val})
                    self.refuse(suffix, replace(data, unit=with_entries(data.unit, (bad,))))

    def test_regular_classification_and_empty_content_hash_consistent(self):
        data = catalog({0: [row()]})
        entry = data.unit.entries[0]
        for bad in (replace(entry, kind='empty_regular'),
                    replace(entry, kind='nonexecutable_regular'),
                    replace(entry, mode=0o644),
                    replace(entry, bytes=0, kind='empty_regular')):
            self.refuse('ENTRY', replace(data, unit=with_entries(data.unit, (bad,))))

    def test_sha_shapes_inventory_and_catalog_content_binding(self):
        data = catalog({0: [row()]})
        for sha in (None, 'A' * 64, 'a' * 63, 'x' * 64):
            self.refuse('DIGEST', replace(data, catalog_sha256=sha))
            self.refuse('DIGEST', replace(data, unit=replace(data.unit, inventory_sha256=sha)))
            entry = replace(data.unit.entries[0], sha256=sha)
            self.refuse('ENTRY', replace(data, unit=with_entries(data.unit, (entry,))))
        self.refuse('DIGEST', replace(data, catalog_sha256='b' * 64))
        entry = replace(data.unit.entries[0], sha256='b' * 64)
        self.refuse('DIGEST', replace(data, unit=replace(data.unit, entries=(entry,))))
        changed_unit = with_entries(data.unit, (entry,))
        self.refuse('DIGEST', replace(data, unit=changed_unit))

    def test_elapsed_bounds_and_combined_window_consistency(self):
        data = catalog()
        for elapsed in (-1, True, 30_000, '1'):
            self.refuse('WINDOW', replace(data, collection_elapsed_ms=elapsed))
            self.refuse('WINDOW', replace(data, unit=replace(data.unit, collection_elapsed_ms=elapsed)))
        self.refuse('WINDOW', replace(data, environment=replace(data.environment,
                                                              collection_elapsed_ms=2)))

    def test_aggregate_count_and_bytes_cover_both_classes_and_shadowed_entries(self):
        rows = {0: [row('a%03d' % i) for i in range(129)]}
        self.refuse('COUNT', catalog(rows, rows))
        rows = {i: [row('same', size=inventory.MAX_FILE_BYTES)] for i in range(3)}
        self.refuse('BYTES', catalog(rows, rows))
        rows = {0: [row('a%03d' % i, size=inventory.MAX_FILE_BYTES) for i in range(5)]}
        self.refuse('BYTES', catalog(rows))

    def test_selection_digest_binds_contract_classes_rows_and_source(self):
        data = catalog({0: [row()]}, {3: [row('env')]})
        value = m.model_default_generator_selection(data)
        expected = digest(dict(version=1, contract=m.CONTRACT, upstream_commit=m.UPSTREAM_COMMIT,
                               catalog_sha256=data.catalog_sha256,
                               unit=[asdict(r) for r in value.unit_rows],
                               environment=[asdict(r) for r in value.environment_rows]))
        self.assertEqual(value.selection_sha256, expected)
        self.assertNotEqual(value.selection_sha256,
                            m.model_default_generator_selection(catalog(
                                {0: [row()]}, {3: [row('env', sha='b' * 64)]})).selection_sha256)

    def test_result_frozen_all_authority_flags_false_and_input_unchanged(self):
        data = catalog({0: [row()]})
        before = asdict(data)
        result = m.model_default_generator_selection(data)
        self.assertEqual(asdict(data), before)
        for name, val in asdict(result).items():
            if type(val) is bool:
                self.assertEqual(val, name in ('default_paths_assumed', 'regular_subset_only',
                                              'review_required'), name)
        with self.assertRaises(FrozenInstanceError):
            result.mutation_authorized = True
        with self.assertRaises(FrozenInstanceError):
            result.unit_rows[0].decision = 'approved'

    def test_supplied_self_consistent_records_are_not_authenticated(self):
        result = m.model_default_generator_selection(catalog(
            {0: [row('forged', sha='f' * 64)]}))
        self.assertEqual(result.unit_candidates[0].sha256, 'f' * 64)
        self.assertFalse(result.observation_authenticity_proven)
        self.assertFalse(result.observation_freshness_proven)
        self.assertFalse(result.installed_contract_proven)

    def test_no_io_collectors_or_controller_admission(self):
        data = catalog({0: [row()]})
        with ExitStack() as stack:
            mocks = [stack.enter_context(patch(target, side_effect=AssertionError('unexpected I/O')))
                     for target in ('builtins.open', 'os.open', 'subprocess.run')]
            for name in ('observe_maintenance_generators', 'observe_maintenance_environment_generators',
                         'observe_maintenance_generator_catalog', '_collect'):
                mocks.append(stack.enter_context(patch.object(inventory, name,
                                  side_effect=AssertionError('unexpected collection'))))
            m.model_default_generator_selection(data)
            with self.assertRaisesRegex(core.OperatorError, '^CONTROL_NOT_RELEASED$'):
                control.run_maintenance_inhibition()
            for mocked in mocks:
                mocked.assert_not_called()


if __name__ == '__main__':
    unittest.main()
