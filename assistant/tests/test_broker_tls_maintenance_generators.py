"""Inventory only: fake native seams and disposable Linux trees, never systemd."""
from contextlib import contextmanager, ExitStack
from dataclasses import asdict, FrozenInstanceError
import errno
import hashlib
import inspect
from itertools import chain, repeat
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_core as core
from siem.rbac.broker_tls import operator_maintenance_generators as m


def metadata(mode=stat.S_IFREG | 0o755, size=3, **changes):
    values = dict(st_dev=1, st_ino=2, st_mode=mode, st_uid=0, st_gid=0,
                  st_nlink=1, st_size=size, st_mtime_ns=1, st_ctime_ns=1)
    values.update(changes)
    return SimpleNamespace(**values)


def snapshot():
    return tuple((False, (), ('private_stamp',)) for _ in m.DIRECTORIES)


def environment_snapshot():
    return tuple((False, (), ('private_stamp',)) for _ in m.ENV_DIRECTORIES)


def row(name='one', kind='executable_regular', digest='a' * 64, mode=0o755):
    return (name, (kind, 3, mode, 0, 0, digest), ('private_stamp',))


class GeneratorInventoryTests(unittest.TestCase):
    def error(self, code, call):
        with self.assertRaisesRegex(core.OperatorError, '^' + code + '$'):
            call()

    @contextmanager
    def flags(self):
        with ExitStack() as stack:
            for name, value in (('O_NOFOLLOW', 131072), ('O_CLOEXEC', 524288),
                                ('O_DIRECTORY', 65536), ('O_NONBLOCK', 2048)):
                stack.enter_context(patch.object(m.os, name, getattr(os, name, value), create=True))
            yield

    @contextmanager
    def leaf(self, value=None, chunks=None):
        value = metadata() if value is None else value
        with self.flags(), ExitStack() as stack:
            mocks = {}
            for name, obj in dict(stat=Mock(return_value=value), fstat=Mock(return_value=value),
                                  open=Mock(return_value=99), close=Mock(),
                                  read=Mock(side_effect=[b'abc', b''] if chunks is None else chunks),
                                  readlink=Mock(return_value='/dev/null')).items():
                mocks[name] = stack.enter_context(patch.object(m.os, name, obj))
            yield mocks

    @contextmanager
    def collect(self):
        with self.flags(), ExitStack() as stack:
            stack.enter_context(patch.object(m.fs, '_platform'))
            stack.enter_context(patch.object(m.time, 'CLOCK_BOOTTIME', 7, create=True))
            stack.enter_context(patch.object(m.time, 'clock_gettime_ns', create=True))
            stack.enter_context(patch.object(m.os, 'supports_fd', {os.scandir}))
            stack.enter_context(patch.object(m.os, 'supports_dir_fd', {os.readlink}))
            f = dict(clock=Mock(return_value=1000), scan=Mock(return_value=snapshot()),
                     open=Mock(return_value=99), close=Mock())
            stack.enter_context(patch.object(m, '_clock', f['clock']))
            stack.enter_context(patch.object(m, '_scan_at', f['scan']))
            stack.enter_context(patch.object(m.os, 'open', f['open']))
            stack.enter_context(patch.object(m.os, 'close', f['close']))
            yield f

    def test_fixed_paths_order_and_no_public_overrides(self):
        self.assertEqual(tuple('/' + '/'.join(p) for p in m.DIRECTORIES), (
            '/run/systemd/system-generators', '/etc/systemd/system-generators',
            '/usr/local/lib/systemd/system-generators', '/usr/lib/systemd/system-generators'))
        self.assertEqual(str(inspect.signature(m.observe_maintenance_generators)), '()')

    def test_environment_paths_and_no_argument_entries_are_fixed(self):
        self.assertEqual(tuple('/' + '/'.join(p) for p in m.ENV_DIRECTORIES), (
            '/run/systemd/system-environment-generators',
            '/etc/systemd/system-environment-generators',
            '/usr/local/lib/systemd/system-environment-generators',
            '/usr/lib/systemd/system-environment-generators'))
        for function in (m.observe_maintenance_environment_generators,
                         m.observe_maintenance_generator_catalog):
            self.assertEqual(str(inspect.signature(function)), '()')

    def test_environment_inventory_has_own_names_and_digest(self):
        unit = m._result(snapshot(), 1)
        environment = m._result(environment_snapshot(), 1, m.ENV_DIRECTORIES)
        self.assertNotEqual(unit.directories, environment.directories)
        self.assertNotEqual(unit.inventory_sha256, environment.inventory_sha256)
        self.assertTrue(all('system-environment-generators' in p for p, _ in
                            environment.directories))

    def test_environment_precedence_is_separate_from_unit_names(self):
        one = ((True, (row('same'),), ()),) + environment_snapshot()[1:]
        two = (one[0], (True, (row('same'),), ())) + one[2:]
        environment = m._result(two, 0, m.ENV_DIRECTORIES)
        self.assertEqual([e.earlier_same_name for e in environment.entries], [(), (0,)])
        self.assertEqual(m._result(((True, (row('same'),), ()),) + snapshot()[1:], 0)
                         .entries[0].earlier_same_name, ())

    def test_empty_environment_directory_does_not_prove_empty_output(self):
        environment = m._result(environment_snapshot(), 0, m.ENV_DIRECTORIES)
        self.assertEqual(environment.entries, ())
        self.assertFalse(environment.effective_search_path_proven)
        self.assertFalse(environment.generator_effects_proven)

    def test_private_scope_rejects_arbitrary_paths_and_groups_before_io(self):
        with patch.object(m, '_directory_at') as walk:
            self.error('GENERATORS_SCOPE', lambda: m._scan_at(99, lambda: None,
                      (('tmp', 'PRIVATE'),)))
            walk.assert_not_called()
        with patch.object(m.fs, '_platform') as platform:
            self.error('GENERATORS_SCOPE', lambda: m._collect((m.ENV_DIRECTORIES,
                      m.DIRECTORIES)))
            platform.assert_not_called()

    def test_environment_only_observer_scans_its_four_paths_twice(self):
        with self.collect() as f:
            f['scan'].return_value = environment_snapshot()
            result = m.observe_maintenance_environment_generators()
            self.assertEqual(f['scan'].call_count, 2)
            self.assertTrue(all(c.args[2] is m.ENV_DIRECTORIES for c in f['scan'].call_args_list))
            self.assertEqual(result.directories[0][0],
                             '/run/systemd/system-environment-generators')

    def test_catalog_uses_one_root_and_orders_both_classes_each_pass(self):
        with self.collect() as f:
            f['scan'].side_effect = [snapshot(), environment_snapshot()] * 2
            result = m.observe_maintenance_generator_catalog()
            self.assertIsInstance(result, m.GeneratorCatalog)
            self.assertEqual([c.args[2] for c in f['scan'].call_args_list],
                             [m.DIRECTORIES, m.ENV_DIRECTORIES] * 2)
            self.assertEqual(f['open'].call_count, 1)
            f['close'].assert_called_once_with(99)
            self.assertEqual(result.unit.directories[0][0],
                             '/run/systemd/system-generators')
            self.assertEqual(result.environment.directories[0][0],
                             '/run/systemd/system-environment-generators')

    def test_catalog_shares_aggregate_budget_within_not_across_passes(self):
        with self.collect() as f:
            f['scan'].side_effect = [snapshot(), environment_snapshot()] * 2
            m.observe_maintenance_generator_catalog()
            a, b, c, d = [call.args[3] for call in f['scan'].call_args_list]
            self.assertIs(a, b)
            self.assertIs(c, d)
            self.assertIsNot(a, c)

    def test_environment_change_disposes_entire_catalog(self):
        with self.collect() as f:
            changed = ((False, (), ('changed',)),) + environment_snapshot()[1:]
            f['scan'].side_effect = [snapshot(), environment_snapshot(), snapshot(), changed]
            self.error('GENERATORS_CHANGED', m.observe_maintenance_generator_catalog)
            f['close'].assert_called_once_with(99)

    def test_unit_change_disposes_entire_catalog(self):
        with self.collect() as f:
            changed = ((False, (), ('changed',)),) + snapshot()[1:]
            f['scan'].side_effect = [snapshot(), environment_snapshot(), changed,
                                     environment_snapshot()]
            self.error('GENERATORS_CHANGED', m.observe_maintenance_generator_catalog)

    def test_first_class_failure_never_scans_second_class(self):
        with self.collect() as f:
            f['scan'].side_effect = core.OperatorError('PRIVATE_FAIL')
            self.error('PRIVATE_FAIL', m.observe_maintenance_generator_catalog)
            self.assertEqual(f['scan'].call_count, 1)
            f['close'].assert_called_once_with(99)

    def test_catalog_hash_binds_both_independent_inventory_hashes(self):
        with self.collect() as f:
            f['scan'].side_effect = [snapshot(), environment_snapshot()] * 2
            baseline = m.observe_maintenance_generator_catalog()
        unit_changed = ((True, (row('unit'),), ()),) + snapshot()[1:]
        env_changed = ((True, (row('environment'),), ()),) + environment_snapshot()[1:]
        for unit, environment in ((unit_changed, environment_snapshot()),
                                  (snapshot(), env_changed)):
            with self.collect() as f:
                f['scan'].side_effect = [unit, environment] * 2
                result = m.observe_maintenance_generator_catalog()
                self.assertNotEqual(result.catalog_sha256, baseline.catalog_sha256)
                self.assertNotEqual((result.unit.inventory_sha256,
                                     result.environment.inventory_sha256),
                                    (baseline.unit.inventory_sha256,
                                     baseline.environment.inventory_sha256))

    def test_catalog_flags_and_components_are_immutable_non_authorizing(self):
        with self.collect() as f:
            f['scan'].side_effect = [snapshot(), environment_snapshot()] * 2
            result = m.observe_maintenance_generator_catalog()
            for name, value in asdict(result).items():
                if name.endswith(('_proven', '_authorized', '_verified')):
                    self.assertIs(value, False, name)
            self.assertTrue(result.review_required)
            self.assertFalse(result.generated_environment_proven)
            self.assertEqual(result.passes, 2)
            with self.assertRaises(FrozenInstanceError):
                result.startup_authorized = True
            with self.assertRaises(FrozenInstanceError):
                result.environment.inventory_sha256 = 'tampered'

    def test_catalog_cleanup_failure_prevents_success(self):
        with self.collect() as f:
            f['scan'].side_effect = [snapshot(), environment_snapshot()] * 2
            f['close'].side_effect = OSError(errno.EIO, 'PRIVATE')
            self.error('FS_IO', m.observe_maintenance_generator_catalog)

    def test_catalog_path_count_and_byte_limits_cover_both_classes(self):
        for offset, code in ((0, 'GENERATORS_COUNT'), (1, 'GENERATORS_BYTES')):
            with self.collect() as f, patch.object(m, 'MAX_ENTRIES', 1), \
                    patch.object(m, 'MAX_TOTAL_BYTES', 1):
                def scan(_root, _check, paths, budget):
                    budget[offset] += 1
                    m.core.require(budget[offset] <= 1, code)
                    return snapshot() if paths is m.DIRECTORIES else environment_snapshot()
                f['scan'].side_effect = scan
                self.error(code, m.observe_maintenance_generator_catalog)
                self.assertEqual(f['scan'].call_count, 2)

    def test_environment_inventory_never_reads_or_emits_generated_values(self):
        source = inspect.getsource(m)
        self.assertNotIn('/run/systemd/generator', source)
        for forbidden in ('subprocess', 'os.environ', 'getenv(', 'exec(', 'eval('):
            self.assertNotIn(forbidden, source)

    def test_result_is_immutable_non_authorizing_and_minimized(self):
        result = m._result(snapshot(), 1)
        for name, value in asdict(result).items():
            if name.endswith(('_proven', '_authorized', '_verified')):
                self.assertIs(value, False, name)
        self.assertTrue(result.review_required)
        with self.assertRaises(FrozenInstanceError):
            result.startup_authorized = True
        self.assertNotIn('private_stamp', repr(result))

    def test_precedence_records_all_earlier_names_not_executability(self):
        snap = ((True, (row(kind='nonexecutable_regular', mode=0o644),), ()),
                (True, (row(kind='unresolved_symlink'),), ()),
                (True, (row(), row('two')), ()), (True, (row(),), ()))
        entries = m._result(snap, 0).entries
        self.assertEqual([e.earlier_same_name for e in entries], [(), (0,), (0, 1), (), (0, 1, 2)])
        self.assertEqual(entries[2].kind, 'executable_regular')

    def test_digest_deterministic_excludes_elapsed_and_inode_stamps(self):
        snap = snapshot()
        a = m._result(snap, 0)
        b = m._result(tuple((p, r, ('other',)) for p, r, _ in snap), 900)
        self.assertEqual(a.inventory_sha256, b.inventory_sha256)
        self.assertEqual(len(a.inventory_sha256), 64)

    def test_digest_binds_presence_name_kind_metadata_content_and_priority(self):
        base = ((True, (row(),), ()),) + snapshot()[1:]
        expected = m._result(base, 0).inventory_sha256
        for record in (row('changed'), row(kind='empty_regular'), row(digest='b' * 64), row(mode=0o644)):
            self.assertNotEqual(expected, m._result(((True, (record,), ()),) + base[1:], 0).inventory_sha256)
        self.assertNotEqual(expected, m._result(snapshot(), 0).inventory_sha256)
        self.assertNotEqual(expected, m._result((snapshot()[0], base[0]) + base[2:], 0).inventory_sha256)

    def test_path_names_reject_traversal_nonascii_and_controls(self):
        for name in ('..', '.', '/etc', 'a/b', 'a\\b', 'a:b', 'a b', 'a\n', 'é', 'x' * 256):
            with self.subTest(name=repr(name)), self.assertRaises(core.OperatorError):
                m._name(name)
        for name in ('systemd-ssh-generator', '.hidden', 'a.dpkg-new'):
            m._name(name)  # Inventory includes names manager may ignore.

    def test_regular_hash_streams_and_uses_nonfollow_nonblocking_cloexec(self):
        with self.leaf() as f:
            check = Mock()
            data, _ = m._leaf(4, 'one', [0, 0], check)
            self.assertEqual(data[0], 'executable_regular')
            self.assertEqual(data[-1], hashlib.sha256(b'abc').hexdigest())
            self.assertEqual(f['open'].call_args.kwargs, {'dir_fd': 4})
            flags = f['open'].call_args.args[1]
            self.assertEqual(flags, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            f['close'].assert_called_once_with(99)
            self.assertGreaterEqual(check.call_count, 6)

    def test_empty_and_nonexecutable_regular_remain_in_inventory(self):
        for size, mode, chunks, kind in ((0, 0o644, [b''], 'empty_regular'),
                                       (3, 0o644, [b'abc', b''], 'nonexecutable_regular')):
            with self.leaf(metadata(stat.S_IFREG | mode, size), chunks):
                data, _ = m._leaf(4, 'one', [0, 0], lambda: None)
                self.assertEqual(data[0], kind)

    def test_link_hash_is_text_not_target_bytes_and_never_opened(self):
        for target, kind in (('/dev/null', 'null_link_literal'),
                             ('../../PRIVATE', 'unresolved_symlink')):
            with self.leaf(metadata(stat.S_IFLNK | 0o777, len(target))) as f:
                f['readlink'].return_value = target
                data, _ = m._leaf(4, 'one', [0, 0], lambda: None)
                self.assertEqual(data[0], kind)
                self.assertEqual(data[-1], hashlib.sha256(target.encode()).hexdigest())
                self.assertNotIn('PRIVATE', repr(data))
                f['open'].assert_not_called()
                f['read'].assert_not_called()

    def test_link_owner_length_and_change_are_refused(self):
        for value, code in ((metadata(stat.S_IFLNK | 0o777, 9, st_uid=5), 'GENERATORS_OWNER'),
                            (metadata(stat.S_IFLNK | 0o777, 4097), 'GENERATORS_LINK'),
                            (metadata(stat.S_IFLNK | 0o777, 8), 'GENERATORS_LINK')):
            with self.leaf(value):
                self.error(code, lambda: m._leaf(4, 'one', [0, 0], lambda: None))

    def test_special_types_and_unsafe_file_owners_modes_never_open(self):
        for mode, uid, gid in ((stat.S_IFDIR | 0o755, 0, 0), (stat.S_IFIFO | 0o644, 0, 0),
                              (stat.S_IFCHR | 0o644, 0, 0), (stat.S_IFSOCK | 0o600, 0, 0),
                              (stat.S_IFREG | 0o777, 0, 0), (stat.S_IFREG | 0o4755, 0, 0),
                              (stat.S_IFREG | 0o755, 1, 0), (stat.S_IFREG | 0o755, 0, 1)):
            with self.leaf(metadata(mode, st_uid=uid, st_gid=gid)) as f:
                with self.assertRaises(core.OperatorError):
                    m._leaf(4, 'one', [0, 0], lambda: None)
                f['open'].assert_not_called()

    def test_file_and_aggregate_budgets_reject_before_open(self):
        with self.leaf(metadata(size=m.MAX_FILE_BYTES + 1)) as f:
            self.error('GENERATORS_SIZE', lambda: m._leaf(4, 'one', [0, 0], lambda: None))
            f['open'].assert_not_called()
        with self.leaf() as f:
            self.error('GENERATORS_BYTES', lambda: m._leaf(4, 'one', [0, m.MAX_TOTAL_BYTES], lambda: None))
            f['open'].assert_not_called()

    def test_short_or_growing_read_closes_fd(self):
        for chunks in ([b'ab', b''], [b'abcd']):
            with self.leaf(chunks=chunks) as f:
                self.error('GENERATORS_CHANGED', lambda: m._leaf(4, 'one', [0, 0], lambda: None))
                f['close'].assert_called_once_with(99)

    def test_descriptor_and_final_name_substitution_fail(self):
        for seam in ('fstat', 'stat'):
            with self.leaf() as f:
                f[seam].side_effect = ([metadata(st_ino=6)] if seam == 'fstat'
                                      else [metadata(), metadata(st_ino=6)])
                self.error('GENERATORS_CHANGED', lambda: m._leaf(4, 'one', [0, 0], lambda: None))
                f['close'].assert_called_once_with(99)

    def test_checkpoint_failure_during_read_closes_fd(self):
        with self.leaf() as f:
            check = Mock(side_effect=[None, core.OperatorError('STOP')])
            self.error('STOP', lambda: m._leaf(4, 'one', [0, 0], check))
            f['close'].assert_called_once_with(99)

    def test_fixed_four_directories_share_one_budget(self):
        with patch.object(m, '_directory_at', return_value=(False, (), ())) as walk:
            check = Mock()
            m._scan_at(99, check)
            self.assertEqual([c.args[1] for c in walk.call_args_list], list(m.DIRECTORIES))
            self.assertTrue(all(c.args[2] is walk.call_args_list[0].args[2] for c in walk.call_args_list))

    def test_missing_first_component_checked_twice_without_open(self):
        directory = metadata(stat.S_IFDIR | 0o755)
        with self.flags(), patch.object(m.os, 'fstat', return_value=directory), \
                patch.object(m.os, 'stat', side_effect=FileNotFoundError()), \
                patch.object(m.os, 'open') as opened:
            result = m._directory_at(4, m.DIRECTORIES[0], [0, 0], lambda: None)
            self.assertFalse(result[0])
            opened.assert_not_called()

    def test_partial_ancestor_open_failure_unwinds(self):
        directory = metadata(stat.S_IFDIR | 0o755)
        with self.flags(), patch.object(m.os, 'fstat', return_value=directory), \
                patch.object(m.os, 'stat', return_value=directory), \
                patch.object(m.os, 'open', side_effect=[5, PermissionError()]), \
                patch.object(m.os, 'close') as closed:
            with self.assertRaises(PermissionError):
                m._directory_at(4, m.DIRECTORIES[0], [0, 0], lambda: None)
            closed.assert_called_once_with(5)

    def test_duplicate_and_entry_budget_fail_before_leaf_read(self):
        directory = metadata(stat.S_IFDIR | 0o755)
        for names, limit, code in ((['same', 'same'], 256, 'GENERATORS_DUPLICATE'),
                                   (['one', 'two'], 1, 'GENERATORS_COUNT')):
            @contextmanager
            def entries(_fd):
                yield iter(SimpleNamespace(name=n) for n in names)
            with self.flags(), patch.object(m.os, 'fstat', return_value=directory), \
                    patch.object(m.os, 'stat', return_value=directory), \
                    patch.object(m.os, 'open', side_effect=[5, 6, 7]), \
                    patch.object(m.os, 'close') as closed, \
                    patch.object(m.os, 'scandir', side_effect=entries), \
                    patch.object(m, 'MAX_ENTRIES', limit), \
                    patch.object(m, '_leaf', return_value=(row()[1], m.fs._stamp(directory))) as leaf:
                self.error(code, lambda: m._directory_at(4, m.DIRECTORIES[0], [0, 0], lambda: None))
                self.assertEqual([c.args[0] for c in closed.call_args_list], [7, 6, 5])
                leaf.assert_not_called()

    def test_symlink_bytes_count_toward_total_and_changed_metadata_fails(self):
        value = metadata(stat.S_IFLNK | 0o777, 9)
        with self.leaf(value):
            self.error('GENERATORS_BYTES', lambda: m._leaf(4, 'one', [0, m.MAX_TOTAL_BYTES], lambda: None))
        with self.leaf(value) as f:
            f['stat'].side_effect = [value, metadata(stat.S_IFLNK | 0o777, 9, st_ino=3)]
            self.error('GENERATORS_CHANGED', lambda: m._leaf(4, 'one', [0, 0], lambda: None))

    def test_streaming_is_chunk_bounded(self):
        size = m.CHUNK + 1
        with self.leaf(metadata(size=size), [b'x' * m.CHUNK, b'x', b'']) as f:
            m._leaf(4, 'one', [0, 0], lambda: None)
            self.assertEqual([c.args[1] for c in f['read'].call_args_list], [m.CHUNK, 2, 1])

    def test_two_fresh_passes_one_root_and_cleanup(self):
        with self.collect() as f:
            m.observe_maintenance_generators()
            self.assertEqual(f['scan'].call_count, 2)
            self.assertEqual(f['open'].call_args.args[0], '/')
            f['close'].assert_called_once_with(99)

    def test_cross_pass_metadata_or_content_drift_rejected(self):
        with self.collect() as f:
            f['scan'].side_effect = [snapshot(), ((False, (), ('changed',)),) + snapshot()[1:]]
            self.error('GENERATORS_CHANGED', m.observe_maintenance_generators)
            f['close'].assert_called_once_with(99)

    def test_scan_failures_are_static_and_root_closed(self):
        with self.collect() as f:
            f['scan'].side_effect = PermissionError(errno.EACCES, 'PRIVATE_TARGET')
            self.error('FS_ACCESS', m.observe_maintenance_generators)
            f['close'].assert_called_once_with(99)

    def test_close_failure_prevents_result(self):
        with self.collect() as f:
            f['close'].side_effect = OSError(errno.EIO, 'PRIVATE')
            self.error('FS_IO', m.observe_maintenance_generators)

    def test_platform_failure_precedes_read(self):
        with self.collect() as f, patch.object(m.os, 'supports_fd', set()):
            self.error('GENERATORS_PLATFORM', m.observe_maintenance_generators)
            f['open'].assert_not_called()

    def test_clock_backward_deadline_and_expiry_after_cleanup_fail(self):
        for times in ([1000, 999], [1000, 1000 + m.MAX_WINDOW_NS],
                      [1000] * 4 + [1000 + m.MAX_WINDOW_NS]):
            with self.collect() as f:
                f['clock'].side_effect = chain(times, repeat(times[-1]))
                self.error('GENERATORS_TIMEOUT', m.observe_maintenance_generators)

    def test_process_and_native_thread_drift_fail(self):
        for module, name in ((m.os, 'getpid'), (m.threading, 'get_native_id')):
            with self.collect(), patch.object(module, name, side_effect=chain([1], repeat(2))):
                self.error('GENERATORS_CALLER', m.observe_maintenance_generators)

    def test_observer_not_connected_to_mutation_or_entry(self):
        from siem.rbac.broker_tls import operator_maintenance_control as control
        from siem.rbac.broker_tls import operator_maintenance_manager as manager
        self.assertNotIn('maintenance_generators', inspect.getsource(control))
        self.assertNotIn('maintenance_generators', inspect.getsource(manager))
        source = inspect.getsource(m)
        for forbidden in ('subprocess', 'exec(', 'eval(', 'ctypes', 'os.system', 'os.environ'):
            self.assertNotIn(forbidden, source)


@unittest.skipUnless(sys.platform == 'linux', 'Linux descriptor-relative fixture')
class GeneratorNativeTests(unittest.TestCase):
    @contextmanager
    def tree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            for parts in m.DIRECTORIES:
                root.joinpath(*parts).mkdir(parents=True, exist_ok=True)
                for depth in range(1, len(parts) + 1):
                    root.joinpath(*parts[:depth]).chmod(0o755)
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            trusted = m.fs._trusted
            def fixture_trust(value, is_dir, owners):
                normalized = SimpleNamespace(**{name: getattr(value, name) for name in
                    ('st_mode', 'st_uid', 'st_gid')})
                normalized.st_uid = normalized.st_gid = 0
                trusted(normalized, is_dir, owners)
            try:
                # Only owner normalization; retain actual modes, types and syscalls.
                with patch.object(m.fs, '_trusted', side_effect=fixture_trust):
                    yield root, fd
            finally:
                os.close(fd)

    def test_real_streaming_two_passes_and_no_execution(self):
        with self.tree() as (root, fd):
            target = root.joinpath(*m.DIRECTORIES[0], 'fixture')
            target.write_bytes(b'#!/bin/sh\nexit 73\n')
            target.chmod(0o755)
            a = m._scan_at(fd, lambda: None)
            b = m._scan_at(fd, lambda: None)
            self.assertEqual(a, b)
            self.assertEqual(a[0][1][0][1][-1], hashlib.sha256(target.read_bytes()).hexdigest())

    def test_absent_directory_is_distinct_and_reappearance_rejected(self):
        with self.tree() as (root, fd):
            target = root.joinpath(*m.DIRECTORIES[0])
            target.rmdir()
            self.assertFalse(m._scan_at(fd, lambda: None)[0][0])
            original = os.stat
            calls = [0]
            def race(name, **kwargs):
                if name == 'system-generators':
                    calls[0] += 1
                    if calls[0] == 2:
                        target.mkdir()
                return original(name, **kwargs)
            with patch.object(m.os, 'stat', side_effect=race):
                with self.assertRaisesRegex(core.OperatorError, '^GENERATORS_CHANGED$'):
                    m._directory_at(fd, m.DIRECTORIES[0], [0, 0], lambda: None)

    def test_ancestor_symlink_and_special_leaf_fail_without_following(self):
        with self.tree() as (root, fd):
            target = root.joinpath(*m.DIRECTORIES[0])
            os.mkfifo(target / 'fifo')
            with self.assertRaises(core.OperatorError):
                m._scan_at(fd, lambda: None)
            (target / 'fifo').unlink()
            target.rmdir()
            target.symlink_to(root / 'etc', target_is_directory=True)
            with self.assertRaises(core.OperatorError):
                m._scan_at(fd, lambda: None)

    def test_count_budget_includes_all_directories_and_shadowed_names(self):
        with self.tree() as (root, fd):
            for parts in m.DIRECTORIES:
                target = root.joinpath(*parts, 'same')
                target.write_bytes(b'')
                target.chmod(0o644)
            with patch.object(m, 'MAX_ENTRIES', 3):
                with self.assertRaisesRegex(core.OperatorError, '^GENERATORS_COUNT$'):
                    m._scan_at(fd, lambda: None)

    def test_directory_mutation_and_denied_access_do_not_become_absence(self):
        with self.tree() as (root, fd):
            target = root.joinpath(*m.DIRECTORIES[0])
            (target / 'one').write_bytes(b'x')
            (target / 'one').chmod(0o644)
            leaf = m._leaf
            def race(*args):
                result = leaf(*args)
                (target / 'new').write_bytes(b'x')
                return result
            with patch.object(m, '_leaf', side_effect=race):
                with self.assertRaisesRegex(core.OperatorError, '^GENERATORS_CHANGED$'):
                    m._scan_at(fd, lambda: None)
            with patch.object(m.os, 'stat', side_effect=PermissionError(errno.EACCES, 'private')):
                with self.assertRaises(PermissionError):
                    m._scan_at(fd, lambda: None)

    def test_repeated_success_and_failure_do_not_leak_descriptors(self):
        with self.tree() as (root, fd):
            target = root.joinpath(*m.DIRECTORIES[0], 'fixture')
            target.write_bytes(b'contents')
            target.chmod(0o644)
            count = len(os.listdir('/proc/self/fd'))
            for _ in range(3):
                m._scan_at(fd, lambda: None)
            target.chmod(0o666)
            for _ in range(3):
                with self.assertRaises(core.OperatorError):
                    m._scan_at(fd, lambda: None)
            self.assertEqual(len(os.listdir('/proc/self/fd')), count)

    def test_environment_class_uses_real_fd_walk_and_hashed_file(self):
        with self.tree() as (root, fd):
            directory = root.joinpath(*m.ENV_DIRECTORIES[0])
            directory.mkdir()
            directory.chmod(0o755)
            target = directory / '20-fixture'
            target.write_bytes(b'#!/bin/sh\nexit 79\n')
            target.chmod(0o755)
            a = m._scan_at(fd, lambda: None, m.ENV_DIRECTORIES)
            b = m._scan_at(fd, lambda: None, m.ENV_DIRECTORIES)
            self.assertEqual(a, b)
            self.assertEqual(m._result(a, 0, m.ENV_DIRECTORIES).entries[0].sha256,
                             hashlib.sha256(target.read_bytes()).hexdigest())

    def test_shared_budget_counts_environment_after_unit(self):
        with self.tree() as (root, fd):
            unit = root.joinpath(*m.DIRECTORIES[0], 'same')
            unit.write_bytes(b'')
            unit.chmod(0o644)
            directory = root.joinpath(*m.ENV_DIRECTORIES[0])
            directory.mkdir()
            directory.chmod(0o755)
            environment = directory / 'same'
            environment.write_bytes(b'')
            environment.chmod(0o644)
            budget = [0, 0]
            with patch.object(m, 'MAX_ENTRIES', 1):
                m._scan_at(fd, lambda: None, m.DIRECTORIES, budget)
                with self.assertRaisesRegex(core.OperatorError, '^GENERATORS_COUNT$'):
                    m._scan_at(fd, lambda: None, m.ENV_DIRECTORIES, budget)


if __name__ == '__main__':
    unittest.main()
