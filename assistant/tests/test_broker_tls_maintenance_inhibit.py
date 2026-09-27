"""Offline inhibition disk tests; public entry cannot touch real systemd files."""
from contextlib import contextmanager
from dataclasses import asdict, FrozenInstanceError
import errno
import inspect
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
from siem.rbac.broker_tls import operator_guard_entry as guard
from siem.rbac.broker_tls import operator_maintenance_inhibit as m
from test_broker_tls_maintenance_lock import LockFS, metadata

LEAF = m.PARENT + (m.UNIT,)


class InhibitFS(LockFS):
    def __init__(self):
        super().__init__()
        self.nodes = {m.PARENT[:n]: metadata(st_ino=n+1) for n in range(4)}
        self.fds = {10: ((), self.nodes[()])}
        self.O_PATH = 16
        self.target = m.TARGET
        self.events = []
        self.symlink = Mock(side_effect=self._symlink)
        self.readlink = Mock(side_effect=lambda name, *, dir_fd: self.target)
        self.fsync = Mock(side_effect=lambda fd: self.events.append(('sync', self.fds[fd][0])))

    def add_mask(self):
        self.nodes[LEAF] = metadata(stat.S_IFLNK | 0o777, st_ino=99, st_size=9)

    def _symlink(self, target, name, *, dir_fd):
        assert (target, self._path(name, dir_fd)) == (m.TARGET, LEAF)
        if LEAF in self.nodes:
            raise FileExistsError(errno.EEXIST, 'PRIVATE_PATH')
        self.add_mask()
        self.events.append(('create', LEAF))
        # Creating a child legitimately changes this directory's timestamps.
        old = self.nodes[m.PARENT]
        old.st_mtime_ns += 1
        old.st_ctime_ns += 1


class MaintenanceInhibitTests(unittest.TestCase):
    @contextmanager
    def fake(self, fs=None):
        fs = InhibitFS() if fs is None else fs
        try:
            with (patch.object(m, 'os', fs), patch.object(m.cg, 'os', fs),
                  patch.object(m.paths, '_null_anchor_at', return_value=('null',)),
                  patch.object(m.threading, 'get_native_id', return_value=100)):
                yield fs
        finally:
            self.assertEqual(set(fs.fds), {10})

    def run_private(self, checkpoint=None):
        return m._prepare_at(10, checkpoint=Mock(return_value=None) if checkpoint is None else checkpoint)

    def test_public_entry_unconditionally_refuses_before_io(self):
        self.assertEqual(str(inspect.signature(m.prepare_maintenance_inhibition)), '()')
        with self.fake() as fs, patch.object(m, '_prepare_at') as private:
            with self.assertRaisesRegex(core.OperatorError, '^INHIBIT_NOT_RELEASED$'):
                m.prepare_maintenance_inhibition()
            private.assert_not_called()
            fs.open.assert_not_called()
            fs.symlink.assert_not_called()
            fs.fsync.assert_not_called()

    def test_fixed_target_no_cli_no_capsule_integration(self):
        self.assertEqual((m.PARENT, m.UNIT, m.TARGET),
                         (('etc','systemd','system'), 'wazuh-dashboard.service', '/dev/null'))
        self.assertNotIn('if __name__', inspect.getsource(m))
        self.assertNotIn('operator_maintenance_inhibit.py',
                         {row[0] for row in guard.PINNED_MODULES + guard.RUNTIME_MODULES})

    def test_absent_mask_created_once_and_all_directories_synced_in_order(self):
        with self.fake() as fs:
            result = self.run_private()
            self.assertTrue(result.mask_created)
            self.assertEqual(fs.events, [('create', LEAF)] + [('sync', m.PARENT[:n]) for n in (3,2,1,0)])
            fs.symlink.assert_called_once_with('/dev/null', m.UNIT, dir_fd=13)

    def test_exact_existing_mask_is_reverified_and_synced_not_recreated(self):
        with self.fake() as fs:
            fs.add_mask()
            before = vars(fs.nodes[LEAF]).copy()
            result = self.run_private()
            self.assertFalse(result.mask_created)
            fs.symlink.assert_not_called()
            self.assertEqual(fs.fsync.call_count, 4)
            self.assertEqual(vars(fs.nodes[LEAF]), before)

    def test_minimized_immutable_disk_result_is_not_manager_or_start_permission(self):
        with self.fake():
            result = self.run_private()
        for name, value in asdict(result).items():
            self.assertIs(value, name in ('mask_created', 'persistent_mask_entry_present',
                                        'directory_sync_completed', 'review_required'))
        self.assertNotIn('/', repr(result))
        with self.assertRaises(FrozenInstanceError):
            result.startup_authorized = True

    def test_noncallable_and_claim_returning_checkpoints_rejected(self):
        for supplied in (None, True, {}, 'approved'):
            with self.subTest(supplied=supplied), self.fake() as fs:
                with self.assertRaisesRegex(core.OperatorError, '^INHIBIT_CHECKPOINT$'):
                    m._prepare_at(10, checkpoint=supplied)
                fs.open.assert_not_called()
        for answer in (True, False, {}, 'approved'):
            with self.subTest(answer=answer), self.fake() as fs:
                with self.assertRaisesRegex(core.OperatorError, '^INHIBIT_CHECKPOINT$'):
                    self.run_private(checkpoint=Mock(return_value=answer))
                fs.open.assert_not_called()

    def test_checkpoint_exception_sanitized_without_writes(self):
        with self.fake() as fs:
            with self.assertRaisesRegex(core.OperatorError, '^INHIBIT_CHECKPOINT$'):
                self.run_private(checkpoint=Mock(side_effect=RuntimeError('PRIVATE_DETAIL')))
            fs.symlink.assert_not_called()

    def test_missing_parent_never_provisioned(self):
        for n in (1,2,3):
            fs = InhibitFS()
            del fs.nodes[m.PARENT[:n]]
            with self.subTest(n=n), self.fake(fs), self.assertRaisesRegex(core.OperatorError, '^FS_MISSING$'):
                self.run_private()
            fs.symlink.assert_not_called()
            fs.fsync.assert_not_called()

    def test_unsafe_root_or_ancestors_rejected_before_writes(self):
        for n in (0,1,2,3):
            for changes in ({'st_uid':126}, {'st_gid':128}, {'st_mode':stat.S_IFDIR | 0o777},
                            {'st_mode':stat.S_IFLNK | 0o777}):
                fs = InhibitFS()
                fs.change(m.PARENT[:n], **changes)
                if n == 0:
                    fs.fds[10] = (), fs.nodes[()]
                with self.subTest(n=n, changes=changes), self.fake(fs), self.assertRaises(core.OperatorError):
                    self.run_private()
                fs.symlink.assert_not_called()

    def test_existing_unit_files_directories_and_devices_never_overwritten(self):
        for kind in (stat.S_IFREG, stat.S_IFDIR, stat.S_IFCHR, stat.S_IFIFO):
            fs = InhibitFS()
            fs.nodes[LEAF] = metadata(kind | 0o644, st_size=9)
            with self.subTest(kind=kind), self.fake(fs), self.assertRaisesRegex(core.OperatorError, 'INHIBIT_MASK_METADATA'):
                self.run_private()
            fs.symlink.assert_not_called()
            fs.fsync.assert_not_called()

    def test_unsafe_existing_symlink_metadata_refused(self):
        for changes in ({'st_uid':126}, {'st_gid':128}, {'st_nlink':2}, {'st_nlink':0},
                        {'st_size':0}, {'st_size':10}, {'st_dev':2}, {'st_mode':stat.S_IFLNK | 0o700}):
            fs = InhibitFS()
            fs.add_mask()
            fs.change(LEAF, **changes)
            with self.subTest(changes=changes), self.fake(fs), self.assertRaisesRegex(core.OperatorError, 'INHIBIT_MASK_METADATA'):
                self.run_private()
            fs.symlink.assert_not_called()

    def test_other_or_relative_symlink_target_refused(self):
        for target in ('/tmp/null', '../../dev/null', '/dev/zero', '/dev/null/', ''):
            fs = InhibitFS()
            fs.add_mask()
            fs.target = target
            with self.subTest(target=target), self.fake(fs), self.assertRaisesRegex(core.OperatorError, 'INHIBIT_MASK_TARGET'):
                self.run_private()
            fs.symlink.assert_not_called()

    def test_untrusted_null_anchor_aborts_before_creation(self):
        with self.fake() as fs, patch.object(m.paths, '_null_anchor_at', side_effect=core.OperatorError('FS_METADATA')):
            with self.assertRaisesRegex(core.OperatorError, 'FS_METADATA'):
                self.run_private()
            fs.symlink.assert_not_called()

    def test_null_drift_before_creation_refused(self):
        with self.fake() as fs, patch.object(m.paths, '_null_anchor_at', side_effect=[('one',), ('two',)]):
            with self.assertRaisesRegex(core.OperatorError, 'INHIBIT_NULL_CHANGED'):
                self.run_private()
            fs.symlink.assert_not_called()

    def test_checkpoint_failure_immediately_before_create_leaves_absent(self):
        with self.fake() as fs:
            with self.assertRaisesRegex(core.OperatorError, 'INHIBIT_CHECKPOINT'):
                self.run_private(checkpoint=Mock(side_effect=[None, RuntimeError('PRIVATE')]))
            self.assertNotIn(LEAF, fs.nodes)
            fs.symlink.assert_not_called()

    def test_checkpoint_parent_race_is_rechecked_before_create(self):
        with self.fake() as fs:
            count = 0
            def checkpoint():
                nonlocal count
                count += 1
                if count == 2:
                    fs.change(m.PARENT, st_ino=404)
            with self.assertRaises(core.OperatorError):
                self.run_private(checkpoint)
            fs.symlink.assert_not_called()

    def test_no_clobber_collision_is_not_adopted_even_for_expected_mask(self):
        with self.fake() as fs:
            original = fs.symlink.side_effect
            def collide(*a, **kw):
                fs.add_mask()
                return original(*a, **kw)
            fs.symlink.side_effect = collide
            with self.assertRaisesRegex(core.OperatorError, '^INHIBIT_COLLISION$'):
                self.run_private()
            self.assertIn(LEAF, fs.nodes)
            fs.fsync.assert_not_called()

    def test_create_failure_is_sanitized_without_retry(self):
        with self.fake() as fs:
            fs.symlink.side_effect = OSError(errno.ENOSPC, 'PRIVATE')
            with self.assertRaisesRegex(core.OperatorError, '^FS_IO$'):
                self.run_private()
            fs.symlink.assert_called_once()
            self.assertNotIn(LEAF, fs.nodes)

    def test_open_symlink_itself_with_no_target_or_payload_open(self):
        with self.fake() as fs:
            self.run_private()
            for path, flags in fs.calls:
                expected = fs.O_PATH if path == LEAF else fs.O_RDONLY | fs.O_DIRECTORY
                self.assertEqual(flags, expected | fs.O_NOFOLLOW | fs.O_CLOEXEC)
            self.assertEqual([path for path, _ in fs.calls].count(LEAF), 1)

    def test_leaf_replaced_between_stat_and_open_is_refused(self):
        with self.fake() as fs:
            fs.add_mask()
            original = fs.open.side_effect
            def raced(name, flags, **kw):
                if name == m.UNIT:
                    fs.change(LEAF, st_ino=100)
                return original(name, flags, **kw)
            fs.open.side_effect = raced
            with self.assertRaisesRegex(core.OperatorError, 'INHIBIT_MASK_CHANGED'):
                self.run_private()
            fs.fsync.assert_not_called()

    def test_inheritable_mask_handle_fails_and_new_mask_is_retained(self):
        with self.fake() as fs:
            fs.inheritable = True
            with self.assertRaisesRegex(core.OperatorError, 'INHIBIT_INHERITABLE'):
                self.run_private()
            self.assertIn(LEAF, fs.nodes)
            fs.fsync.assert_not_called()

    def test_sync_error_at_every_depth_retains_mask_and_never_returns_success(self):
        for fail in range(4):
            with self.subTest(fail=fail), self.fake() as fs:
                fs.fsync.side_effect = [None]*fail + [OSError(errno.EIO, 'PRIVATE')]
                with self.assertRaisesRegex(core.OperatorError, '^INHIBIT_SYNC$'):
                    self.run_private()
                self.assertIn(LEAF, fs.nodes)
                self.assertEqual(fs.fsync.call_count, fail+1)

    def test_post_sync_leaf_and_parent_drift_refused(self):
        for path in (LEAF, m.PARENT, ('etc',), ()):
            with self.subTest(path=path), self.fake() as fs:
                def sync(_):
                    fs.change(path, st_ino=404)
                    if not path:
                        fs.fds[10] = (), fs.nodes[()]
                fs.fsync.side_effect = sync
                with self.assertRaises(core.OperatorError):
                    self.run_private()

    def test_post_create_and_final_checkpoint_failure_retains_mask(self):
        for fail in range(3,8):
            with self.subTest(fail=fail), self.fake() as fs:
                checkpoint = Mock(side_effect=[None]*(fail-1) + [RuntimeError('PRIVATE')])
                with self.assertRaisesRegex(core.OperatorError, 'INHIBIT_CHECKPOINT'):
                    self.run_private(checkpoint)
                self.assertIn(LEAF, fs.nodes)
                fs.symlink.assert_called_once()

    def test_cross_process_or_thread_checkpoint_fails_before_creation(self):
        for what in ('pid', 'thread'):
            with self.subTest(what=what), self.fake() as fs:
                with patch.object(m.threading, 'get_native_id', return_value=100) as tid:
                    def checkpoint():
                        if what == 'pid':
                            fs.pid += 1
                        else:
                            tid.return_value += 1
                    with self.assertRaisesRegex(core.OperatorError, 'INHIBIT_OWNER'):
                        self.run_private(checkpoint)
                    fs.symlink.assert_not_called()

    def test_keyboard_interrupt_after_creation_closes_handles_retains_mask(self):
        with self.fake() as fs:
            with self.assertRaises(KeyboardInterrupt):
                self.run_private(Mock(side_effect=[None, None, KeyboardInterrupt()]))
            self.assertIn(LEAF, fs.nodes)

    def test_fresh_retry_after_uncertain_sync_checks_existing_mask(self):
        with self.fake() as fs:
            fs.fsync.side_effect = OSError(errno.EIO, 'PRIVATE')
            with self.assertRaisesRegex(core.OperatorError, 'INHIBIT_SYNC'):
                self.run_private()
            stamp = m.fs._stamp(fs.nodes[LEAF])
            fs.fsync.side_effect = None
            fs.fsync.reset_mock()
            result = self.run_private()
            self.assertFalse(result.mask_created)
            fs.symlink.assert_called_once()
            self.assertEqual(fs.fsync.call_count, 4)
            self.assertEqual(stamp, m.fs._stamp(fs.nodes[LEAF]))

    def test_cleanup_error_prevents_success_without_unmask(self):
        with self.fake() as fs:
            original = fs.close.side_effect
            def close(fd):
                original(fd)
                raise OSError(errno.EIO, 'PRIVATE')
            fs.close.side_effect = close
            with self.assertRaisesRegex(core.OperatorError, '^FS_IO$'):
                self.run_private()
            self.assertIn(LEAF, fs.nodes)


@unittest.skipUnless(sys.platform == 'linux', 'Linux disposable-tree symlink and directory fsync')
class NativeMaintenanceInhibitTests(unittest.TestCase):
    @contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.joinpath(*m.PARENT).mkdir(parents=True)
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            old_stat, old_fstat = os.stat, os.fstat
            def normalized(value):
                return SimpleNamespace(**{k: (0 if k in ('st_uid','st_gid') else getattr(value, k)) for k in vars(metadata())})
            try:
                with patch.object(m.os, 'stat', side_effect=lambda *a, **kw: normalized(old_stat(*a, **kw))), patch.object(
                        m.os, 'fstat', side_effect=lambda fd: normalized(old_fstat(fd))), patch.object(
                        m.paths, '_null_anchor_at', return_value=('mocked null anchor',)):
                    yield root_fd, root.joinpath(*LEAF)
            finally:
                os.close(root_fd)

    def test_native_create_then_reentry_preserves_symlink_identity(self):
        with self.fixture() as (root, target):
            self.assertTrue(m._prepare_at(root, checkpoint=lambda: None).mask_created)
            before = m.fs._stamp(target.lstat())
            self.assertEqual(os.readlink(target), '/dev/null')
            self.assertFalse(m._prepare_at(root, checkpoint=lambda: None).mask_created)
            self.assertEqual(before, m.fs._stamp(target.lstat()))

    def test_native_existing_unit_payload_preserved(self):
        with self.fixture() as (root, target):
            target.write_bytes(b'private synthetic unit content\n')
            before = target.read_bytes()
            with self.assertRaisesRegex(core.OperatorError, 'INHIBIT_MASK_METADATA'):
                m._prepare_at(root, checkpoint=lambda: None)
            self.assertEqual(target.read_bytes(), before)

    def test_native_sync_failure_retains_mask_and_fresh_retry_syncs(self):
        with self.fixture() as (root, target):
            with patch.object(m.os, 'fsync', side_effect=OSError(errno.EIO, 'PRIVATE')):
                with self.assertRaisesRegex(core.OperatorError, 'INHIBIT_SYNC'):
                    m._prepare_at(root, checkpoint=lambda: None)
            self.assertTrue(target.is_symlink())
            self.assertFalse(m._prepare_at(root, checkpoint=lambda: None).mask_created)

    def test_native_symlink_collision_preserved_not_adopted(self):
        with self.fixture() as (root, target):
            original = os.symlink
            def race(*a, **kw):
                original(*a, **kw)
                return original(*a, **kw)
            with patch.object(m.os, 'symlink', side_effect=race):
                with self.assertRaisesRegex(core.OperatorError, 'INHIBIT_COLLISION'):
                    m._prepare_at(root, checkpoint=lambda: None)
            self.assertEqual(os.readlink(target), '/dev/null')


if __name__ == '__main__':
    unittest.main()
