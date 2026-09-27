"""Offline fixed cgroup observation tests; never query a real manager or mutate cgroups."""
from contextlib import contextmanager
from dataclasses import FrozenInstanceError, asdict, replace
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
from siem.rbac.broker_tls import operator_maintenance_cgroup as c

BOOT = '12345678-1234-1234-1234-123456789abc'
MOUNT = b'29 1 0:2 / /sys/fs/cgroup rw,nosuid,nodev,noexec - cgroup2 cgroup rw\n'


def manager():
    return dict(Id='wazuh-dashboard.service', LoadState='masked', UnitFileState='masked',
                ActiveState='inactive', SubState='dead', NeedDaemonReload=False,
                Job=[0, '/'], MainPID=0, ControlPID=0, ControlGroup=c.CGROUP_NAME,
                TriggeredBy=[])


def snap(**kw):
    return replace(c._Snapshot(BOOT, True, False, False, ('private-token',)), **kw)


def metadata(mode=stat.S_IFDIR | 0o755, **kw):
    result = dict(st_dev=1, st_ino=1, st_mode=mode, st_uid=0, st_gid=0,
                  st_nlink=1, st_size=0, st_mtime_ns=1, st_ctime_ns=1)
    result.update(kw)
    return SimpleNamespace(**result)


class KernelFS:
    """Fake kernel size-zero files plus held no-follow directories."""
    def __init__(self):
        self.nodes, self.contents, self.fds, self.offsets = {(): metadata()}, {}, {}, {}
        self.next_fd = 10
        self.add(c.BOOT_PARTS, (BOOT + '\n').encode())
        self.add(('proc', '123', 'mountinfo'), MOUNT)
        self.add(c.CGROUP_PARTS + ('cgroup.type',), b'domain\n')
        self.add(c.CGROUP_PARTS + ('cgroup.events',), b'populated 0\nfrozen 0\n')
        self.open = Mock(side_effect=self._open)
        self.close = Mock(side_effect=lambda fd: self.fds.pop(fd))
        self.fstat = Mock(side_effect=lambda fd: self.nodes[self.fds[fd]])
        self.stat = Mock(side_effect=self._stat)
        self.read = Mock(side_effect=self._read)
        self.getpid = lambda: 123
        self.readlink = Mock()
        self.supports_dir_fd = {self.readlink}
        self.major, self.minor = lambda dev: 0, lambda dev: dev
        for name, number in (('O_RDONLY', 0), ('O_DIRECTORY', 1), ('O_NOFOLLOW', 2),
                             ('O_CLOEXEC', 4), ('O_NONBLOCK', 8), ('O_PATH', 16)):
            setattr(self, name, number)

    def add(self, parts, data):
        for size in range(1, len(parts)):
            prefix = parts[:size]
            if prefix not in self.nodes:
                self.nodes[prefix] = metadata(st_ino=len(self.nodes) + 1,
                                             st_dev=2 if prefix[:3] == c.CGROUP_ROOT else 1)
        self.nodes[parts] = metadata(stat.S_IFREG | 0o444, st_ino=len(self.nodes) + 1,
                                    st_dev=2 if parts[:3] == c.CGROUP_ROOT else 1)
        self.contents[parts] = data

    def _path(self, name, dir_fd):
        if name == '/' and dir_fd is None:
            return ()
        return self.fds[dir_fd] + (name,)

    def _stat(self, name, *, dir_fd, follow_symlinks):
        assert follow_symlinks is False
        path = self._path(name, dir_fd)
        if path not in self.nodes:
            raise FileNotFoundError(errno.ENOENT, 'PRIVATE_PATH')
        return self.nodes[path]

    def _open(self, name, flags, *, dir_fd=None):
        assert flags & self.O_NOFOLLOW
        path = self._path(name, dir_fd)
        assert path in self.nodes
        self.next_fd += 1
        self.fds[self.next_fd], self.offsets[self.next_fd] = path, 0
        return self.next_fd

    def _read(self, fd, size):
        data = self.contents[self.fds[fd]]
        start = self.offsets[fd]
        self.offsets[fd] += size
        return data[start:start + size]


class MaintenanceCgroupTests(unittest.TestCase):
    def observe(self, *, first=None, second=None, anchor=None, later=None, masks=None, elapsed=1000000):
        first = snap() if first is None else first
        second = first if second is None else second
        anchor = manager() if anchor is None else anchor
        later = anchor if later is None else later
        fake = KernelFS()
        clock = SimpleNamespace(CLOCK_BOOTTIME=7, clock_gettime_ns=Mock(side_effect=[1000000000, 1000000000 + elapsed]))
        with patch.object(c, 'os', fake), patch.object(c, 'time', clock), patch.object(
                c.state.service, '_check_tool') as check, patch.object(c.state, '_read_mask',
                side_effect=masks or [(True, ('mask',))] * 2), patch.object(c.state, '_read_manager',
                side_effect=[anchor, later]), patch.object(c, '_native_snapshot', side_effect=[first, second]):
            result = c.observe_maintenance_cgroup()
            check.assert_called_once_with()
            self.assertEqual([call.args for call in clock.clock_gettime_ns.call_args_list], [(7,), (7,)])
            return result

    def test_frozen_result_is_boot_bound_narrow_and_not_admission(self):
        result = self.observe()
        self.assertEqual((result.boot_id, result.captured_boottime_ms, result.collection_elapsed_ms), (BOOT, 1000, 1))
        self.assertTrue(result.unit_cgroup_present and result.unit_tree_empty_observed)
        self.assertFalse(result.unit_tree_populated)
        for name in ('host_namespace_proven', 'outside_unit_processes_checked', 'process_quiescence_proven',
                     'exclusive_control_proven', 'atomic_snapshot_proven', 'mutation_authorized', 'startup_authorized'):
            self.assertIs(getattr(result, name), False)
        self.assertTrue(result.review_required and result.persistent_inhibition_observed)
        self.assertNotIn('private-token', repr(result))
        self.assertNotIn('captured_monotonic_ms', asdict(result))
        self.assertNotIn('dashboard_stopped', asdict(result))
        with self.assertRaises(FrozenInstanceError):
            result.startup_authorized = True

    def test_populated_and_frozen_are_independent_and_absent_is_explicit(self):
        for populated in (True, False):
            for frozen in (True, False):
                result = self.observe(first=snap(populated=populated, frozen=frozen))
                self.assertEqual(result.unit_tree_empty_observed, not populated)
                self.assertEqual(result.cgroup_frozen, frozen)
        result = self.observe(first=snap(present=False, populated=False, frozen=None))
        self.assertFalse(result.unit_cgroup_present)
        self.assertTrue(result.unit_tree_empty_observed)
        self.assertIsNone(result.cgroup_frozen)

    def test_manager_requires_mask_stopped_pids_no_job_or_reload(self):
        for key, value in (('Id', 'other.service'), ('LoadState', 'loaded'),
                ('UnitFileState', 'masked-runtime'), ('NeedDaemonReload', True),
                ('ActiveState', 'active'), ('ActiveState', 'activating'), ('SubState', 'running'),
                ('MainPID', 21), ('ControlPID', 21), ('Job', [12, '/job/12'])):
            data = manager(); data[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(core.OperatorError, '^CGROUP_MANAGER_STATE$'):
                self.observe(anchor=data)
        data = manager(); data.update(ActiveState='failed', SubState='failed')
        self.assertTrue(self.observe(anchor=data).unit_tree_empty_observed)

    def test_manager_path_never_controls_filesystem_targets(self):
        for bad in ('/', '/another.slice/wazuh-dashboard.service', c.CGROUP_NAME + '/child',
                    '/../../PRIVATE', '/system.slice/other.service'):
            data = manager(); data['ControlGroup'] = bad
            with patch.object(c, '_native_snapshot') as native:
                with self.assertRaisesRegex(core.OperatorError, '^CGROUP_MANAGER_PATH$'):
                    c._manager_ready(data)
                native.assert_not_called()
        data = manager(); data['ControlGroup'] = ''
        self.assertTrue(self.observe(anchor=data).unit_tree_empty_observed)

    def test_snapshot_boot_inode_contents_and_presence_drift_rejected(self):
        for second in (snap(boot_id='22345678-1234-1234-1234-123456789abc'), snap(populated=True),
                       snap(token=('other-inode',)), snap(present=False), snap(frozen=True)):
            with self.assertRaisesRegex(core.OperatorError, '^CGROUP_CHANGED$'):
                self.observe(second=second)

    def test_full_manager_or_mask_change_rejected(self):
        for key, value in (('TriggeredBy', ['OTHER.socket']), ('ControlGroup', ''), ('MainPID', 22)):
            later = manager(); later[key] = value
            with self.assertRaisesRegex(core.OperatorError, '^CGROUP_CHANGED$'):
                self.observe(later=later)
        for masks, code in (([(False, ('none',))], 'CGROUP_MASK'),
                            ([(True, ('one',)), (True, ('two',))], 'CGROUP_CHANGED')):
            with self.assertRaisesRegex(core.OperatorError, '^' + code + '$'):
                self.observe(masks=masks)

    def test_suspend_inclusive_clock_bound_has_no_rounding_loophole(self):
        self.assertEqual(self.observe(elapsed=c.MAX_COLLECTION_MS * 1000000).collection_elapsed_ms,
                         c.MAX_COLLECTION_MS)
        for elapsed in (-1, c.MAX_COLLECTION_MS * 1000000 + 1, 60000000000):
            with self.assertRaisesRegex(core.OperatorError, '^CGROUP_TIMEOUT$'):
                self.observe(elapsed=elapsed)

    def test_root_platform_and_clock_fail_before_native_observations(self):
        with patch.object(c.state.service, '_check_tool', side_effect=core.OperatorError('FS_ROOT_REQUIRED')), patch.object(
                c, '_native_snapshot') as native:
            with self.assertRaisesRegex(core.OperatorError, '^FS_ROOT_REQUIRED$'):
                c.observe_maintenance_cgroup()
            native.assert_not_called()
        with patch.object(c.state.service, '_check_tool'), patch.object(c, 'os', KernelFS()), patch.object(
                c, 'time', SimpleNamespace()), patch.object(c.state, '_read_mask') as mask:
            with self.assertRaisesRegex(core.OperatorError, '^CGROUP_PLATFORM$'):
                c.observe_maintenance_cgroup()
            mask.assert_not_called()

    def test_os_errors_do_not_echo_paths(self):
        for number, code in ((errno.ENOENT, 'FS_MISSING'), (errno.EACCES, 'FS_ACCESS'), (errno.EIO, 'FS_IO')):
            with patch.object(c.state.service, '_check_tool', side_effect=OSError(number, 'PRIVATE_SECRET')):
                with self.assertRaisesRegex(core.OperatorError, '^' + code + '$') as error:
                    c.observe_maintenance_cgroup()
                self.assertTrue(error.exception.__suppress_context__)

    def test_events_require_exact_unique_typed_binary_fields(self):
        self.assertEqual(c._events(b'frozen 1\npopulated 0\n'), (False, True))
        for bad in (b'', b'populated 0\n', b'populated 0\npopulated 0\n',
                    b'populated 2\nfrozen 0\n', b'populated false\nfrozen 0\n',
                    b'populated 00\nfrozen 0\n', b'populated 0\nfrozen 0',
                    b'populated 0\nfrozen 0\nextra 0\n', b'populated 0\r\nfrozen 0\r\n',
                    b' populated 0\nfrozen 0\n', 'populated 0\nfrozen 0\n', b'x' * 129):
            with self.assertRaisesRegex(core.OperatorError, '^CGROUP_EVENTS$'):
                c._events(bad)

    def test_boot_parser_exact_uuid_and_newline(self):
        self.assertEqual(c._boot((BOOT + '\n').encode()), BOOT)
        for raw in (BOOT.encode(), (BOOT + '\n\n').encode(), (BOOT.upper() + '\n').encode(),
                    b'../PRIVATE\n', b'', 5):
            with self.assertRaisesRegex(core.OperatorError, '^CGROUP_BOOT$'):
                c._boot(raw)

    def test_mount_parser_fixed_full_cgroup2_and_device(self):
        self.assertEqual(c._mount_device(MOUNT), (0, 2))
        other = b'31 1 8:1 / / rw - ext4 /dev/sda1 rw\n'
        self.assertEqual(c._mount_device(other + MOUNT), (0, 2))
        for raw in (MOUNT.replace(b'cgroup2', b'cgroup'), MOUNT.replace(b'0:2 / ', b'0:2 /private '),
                    MOUNT.replace(b'/sys/fs/cgroup', b'/sys/fs/other'),
                    MOUNT + MOUNT.replace(b'29 ', b'30 ', 1)):
            with self.assertRaisesRegex(core.OperatorError, '^CGROUP_MOUNT$'):
                c._mount_device(raw)

    def test_submounts_duplicates_malformed_and_oversize_fail(self):
        for target in (b'/sys/fs/cgroup/system.slice', b'/sys/fs/cgroup/other',
                       b'/sys/fs/cgroup/system.slice/wazuh-dashboard.service/cgroup.events'):
            raw = MOUNT + b'30 29 0:3 / ' + target + b' rw - tmpfs tmpfs rw\n'
            with self.assertRaisesRegex(core.OperatorError, '^CGROUP_SUBMOUNT$'):
                c._mount_device(raw)
        for raw in (b'', b'x' * (c.MAX_MOUNTINFO + 1), MOUNT[:-1], MOUNT + MOUNT,
                    MOUNT.replace(b'0:2', b'not-a-device'), MOUNT.replace(b'29 ', b'xx ', 1),
                    MOUNT.replace(b' - ', b' '), MOUNT.replace(b'cgroup2 cgroup rw', b'cgroup2 cgroup'),
                    b'x\n' * 4097, bytearray(MOUNT)):
            with self.assertRaisesRegex(core.OperatorError, '^CGROUP_MOUNTINFO$'):
                c._mount_device(raw)

    def read_native(self, fake):
        with patch.object(c, 'os', fake):
            try:
                return c._native_snapshot()
            finally:
                self.assertFalse(fake.fds, 'all descriptors must close')

    def test_native_reader_fixed_targets_size_zero_files_and_closes(self):
        fake = KernelFS()
        result = self.read_native(fake)
        self.assertEqual((result.boot_id, result.present, result.populated, result.frozen), (BOOT, True, False, False))
        self.assertEqual(fake.close.call_count, fake.open.call_count)
        names = {call.args[0] for call in fake.open.call_args_list}
        self.assertTrue({'boot_id', 'mountinfo', 'cgroup.type', 'cgroup.events'} <= names)
        self.assertFalse(names & {'cmdline', 'environ', 'cgroup.procs', 'exe'})

    def test_native_populated_descendant_indicator_is_not_inferred_from_main_pid(self):
        fake = KernelFS(); fake.contents[c.CGROUP_PARTS + ('cgroup.events',)] = b'populated 1\nfrozen 0\n'
        result = self.read_native(fake)
        self.assertTrue(result.populated)
        self.assertFalse(self.observe(first=result).unit_tree_empty_observed)

    def test_only_unit_leaf_absence_is_an_empty_tree_observation(self):
        fake = KernelFS(); del fake.nodes[c.CGROUP_PARTS]
        result = self.read_native(fake)
        self.assertEqual((result.present, result.populated, result.frozen), (False, False, None))
        self.assertNotIn('cgroup.events', [call.args[0] for call in fake.open.call_args_list])
        for missing in (c.CGROUP_ROOT, c.CGROUP_PARENT, c.CGROUP_PARTS + ('cgroup.events',)):
            fake = KernelFS(); del fake.nodes[missing]
            with self.assertRaises(FileNotFoundError):
                self.read_native(fake)

    def test_type_mount_and_device_mismatch_refused(self):
        for bad in (b'threaded\n', b'domain threaded\n', b'domain invalid\n', b''):
            fake = KernelFS(); fake.contents[c.CGROUP_PARTS + ('cgroup.type',)] = bad
            with self.assertRaisesRegex(core.OperatorError, '^CGROUP_TYPE$'):
                self.read_native(fake)
        for path in (c.CGROUP_ROOT, c.CGROUP_PARENT, c.CGROUP_PARTS, c.CGROUP_PARTS + ('cgroup.events',)):
            fake = KernelFS(); fake.nodes[path].st_dev = 99
            with self.assertRaisesRegex(core.OperatorError, '^CGROUP_DEVICE$'):
                self.read_native(fake)

    def test_parent_and_leaf_metadata_policy_refuses_unsafe_objects(self):
        for path in ((), ('proc',), c.CGROUP_PARENT, c.CGROUP_PARTS, c.CGROUP_PARTS + ('cgroup.events',)):
            for change in ({'st_uid': 99}, {'st_gid': 99}, {'st_mode': stat.S_IFLNK | 0o777},
                           {'st_mode': stat.S_IFIFO | 0o600}):
                fake = KernelFS()
                fake.nodes[path] = SimpleNamespace(**{**vars(fake.nodes[path]), **change})
                with self.subTest(path=path, change=change), self.assertRaisesRegex(core.OperatorError, '^FS_METADATA$'):
                    self.read_native(fake)
        fake = KernelFS(); fake.nodes[c.CGROUP_PARENT].st_mode |= 0o022
        with self.assertRaisesRegex(core.OperatorError, '^FS_METADATA$'):
            self.read_native(fake)

    def test_read_budget_and_unapproved_target_fail_closed(self):
        fake = KernelFS(); fake.contents[c.CGROUP_PARTS + ('cgroup.events',)] = b'x' * 129
        with self.assertRaisesRegex(core.OperatorError, '^CGROUP_SIZE$'):
            self.read_native(fake)
        fake = KernelFS(); fake.nodes[c.BOOT_PARTS].st_size = 200
        with self.assertRaisesRegex(core.OperatorError, '^CGROUP_SIZE$'):
            self.read_native(fake)
        tree = object.__new__(c._Tree)
        for path, bound in ((('etc', 'passwd'), 100), (c.BOOT_PARTS, True), (c.BOOT_PARTS, 100)):
            with self.assertRaisesRegex(core.OperatorError, '^CGROUP_TARGET$'):
                tree.read(path, bound)

    def test_boot_or_mount_changes_within_snapshot_are_rejected(self):
        for path, raw in ((c.BOOT_PARTS, b'22345678-1234-1234-1234-123456789abc\n'),
                          (('proc', '123', 'mountinfo'), MOUNT.replace(b'rw,nosuid', b'ro,nosuid'))):
            fake = KernelFS(); original = fake._open; seen = 0
            def opening(name, flags, **kw):
                nonlocal seen
                if name == path[-1]:
                    seen += 1
                    if seen == 2:
                        fake.contents[path] = raw
                return original(name, flags, **kw)
            fake.open.side_effect = opening
            with self.assertRaisesRegex(core.OperatorError, '^CGROUP_CHANGED$'):
                self.read_native(fake)

    def test_absent_group_appearance_and_present_inode_change_rejected(self):
        for missing in (True, False):
            fake = KernelFS(); original = fake._stat; seen = 0
            if missing:
                del fake.nodes[c.CGROUP_PARTS]
            def inspecting(name, **kw):
                nonlocal seen
                if name == 'wazuh-dashboard.service':
                    seen += 1
                    if seen == 2:
                        fake.nodes[c.CGROUP_PARTS] = metadata(st_dev=2, st_ino=999)
                return original(name, **kw)
            fake.stat.side_effect = inspecting
            with self.assertRaisesRegex(core.OperatorError, '^CGROUP_CHANGED$'):
                self.read_native(fake)

    def test_file_inode_replacement_and_read_error_close_descriptors(self):
        fake = KernelFS(); original = fake._read
        def reading(fd, size):
            data = original(fd, size)
            if fake.fds[fd][-1:] == ('cgroup.events',):
                fake.nodes[c.CGROUP_PARTS + ('cgroup.events',)].st_ino += 1
            return data
        fake.read.side_effect = reading
        with self.assertRaisesRegex(core.OperatorError, '^CGROUP_CHANGED$'):
            self.read_native(fake)
        fake = KernelFS(); fake.read.side_effect = OSError(errno.EIO, 'PRIVATE_PATH')
        with self.assertRaises(OSError):
            self.read_native(fake)

    def test_public_api_has_no_replay_override_or_executor(self):
        self.assertEqual(len(inspect.signature(c.observe_maintenance_cgroup).parameters), 0)
        self.assertNotIn('operator_maintenance_cgroup.py', {p[0] for p in guard.PINNED_MODULES + guard.RUNTIME_MODULES})
        source = inspect.getsource(c)
        for forbidden in ('__main__', 'os.kill(', 'os.write(', 'os.unlink(', 'os.symlink(',
                          'next_maintenance_step(', 'subprocess', 'cgroup.procs'):
            self.assertNotIn(forbidden, source)


@unittest.skipUnless(sys.platform == 'linux', 'requires native Linux descriptor operations')
class MaintenanceCgroupNativeTests(unittest.TestCase):
    @contextmanager
    def fixture(self):
        # A disposable filesystem fixture, NOT a real procfs/cgroup/kernel proof.
        # Normalize owner metadata so CI need not be root; no /proc or /sys writes.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            dev = os.stat(root).st_dev
            mount = MOUNT.replace(b'0:2', f'{os.major(dev)}:{os.minor(dev)}'.encode())
            for parts, raw in ((c.BOOT_PARTS, (BOOT + '\n').encode()),
                               (('proc', str(os.getpid()), 'mountinfo'), mount),
                               (c.CGROUP_PARTS + ('cgroup.type',), b'domain\n'),
                               (c.CGROUP_PARTS + ('cgroup.events',), b'populated 0\nfrozen 0\n')):
                path = root.joinpath(*parts); path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
            real_open, real_stat, real_fstat = os.open, os.stat, os.fstat
            def owned(value):
                return SimpleNamespace(**{name: getattr(value, name) for name in (
                    'st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')},
                    st_uid=0, st_gid=0)
            def opening(path, flags, **kw):
                return real_open(root if path == '/' else path, flags, **kw)
            with patch.object(c.os, 'open', side_effect=opening), patch.object(c.os, 'stat',
                    side_effect=lambda *a, **kw: owned(real_stat(*a, **kw))), patch.object(
                    c.os, 'fstat', side_effect=lambda fd: owned(real_fstat(fd))):
                yield root

    def test_real_descriptor_fixture_empty_and_populated(self):
        with self.fixture() as root:
            result = c._native_snapshot()
            self.assertTrue(result.present)
            self.assertFalse(result.populated)
            root.joinpath(*c.CGROUP_PARTS, 'cgroup.events').write_bytes(b'populated 1\nfrozen 1\n')
            self.assertTrue(c._native_snapshot().populated)

    def test_real_descriptor_fixture_absence_and_symlink_rejection(self):
        with self.fixture() as root:
            unit = root.joinpath(*c.CGROUP_PARTS)
            (unit / 'cgroup.events').unlink(); (unit / 'cgroup.type').unlink(); unit.rmdir()
            self.assertFalse(c._native_snapshot().present)
            unit.symlink_to('/nonexistent')
            with self.assertRaisesRegex(core.OperatorError, '^FS_METADATA$'):
                c._native_snapshot()


if __name__ == '__main__':
    unittest.main()
