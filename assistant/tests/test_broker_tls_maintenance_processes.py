"""Offline census fixtures: never scan the host's real processes or send signals."""
from contextlib import contextmanager, nullcontext
from dataclasses import asdict, FrozenInstanceError, replace
import errno
import inspect
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_core as core
from siem.rbac.broker_tls import operator_guard_entry as guard
from siem.rbac.broker_tls import operator_maintenance_processes as p
from siem.rbac.broker_tls import operator_maintenance_namespaces as namespaces
from test_broker_tls_maintenance_cgroup import KernelFS, metadata, manager, BOOT

MOUNT = b'20 1 0:1 / /proc rw,nosuid,nodev,noexec - proc proc rw\n'
IDENTITY = (126, 128)
DEADLINE = 30_000_000_000


def stat_raw(pid, start=10, state=b'S', flags=0):
    fields = [state] + [b'0'] * 19
    fields[6], fields[19] = str(flags).encode(), str(start).encode()
    return str(pid).encode() + b' (PRIVATE ) comm) ' + b' '.join(fields) + b'\n'


def status_raw(pid, uids=(0, 0, 0, 0), gids=(0, 0, 0, 0), threads=1):
    return (f'Name:\tPRIVATE_NAME\nPid:\t{pid}\nTgid:\t{pid}\nThreads:\t{threads}\n'
            + 'Uid:\t' + '\t'.join(map(str, uids)) + '\nGid:\t'
            + '\t'.join(map(str, gids)) + '\n').encode()


class CensusFS(KernelFS):
    def __init__(self):
        super().__init__()
        self.contents[('proc', '123', 'mountinfo')] = MOUNT
        self.links = {}
        self.readlink = Mock(side_effect=self._link)
        self.supports_dir_fd = {self.readlink}
        self.scandir = Mock(side_effect=self._scan)
        self.supports_fd = {self.scandir}
        self.add_process(1, exe='/usr/lib/systemd/systemd')
        self.add_process(123, exe='/usr/bin/python3.14')
        self.add_process(400, uids=(126,) * 4, gids=(128,) * 4,
                         exe=core.NODE, group=b'0::/user.slice/manual\n')

    def add_process(self, pid, *, uids=(0,) * 4, gids=(0,) * 4,
                    exe='/usr/bin/other', group=b'0::/system.slice/other.service\n',
                    state=b'S', flags=0, threads=1):
        prefix = ('proc', str(pid))
        self.add(prefix + ('stat',), stat_raw(pid, state=state, flags=flags))
        self.add(prefix + ('status',), status_raw(pid, uids, gids, threads))
        self.add(prefix + ('cgroup',), group)
        old = self.nodes[prefix]
        self.nodes[prefix] = metadata(stat.S_IFDIR | 0o555, st_ino=old.st_ino, st_uid=uids[1], st_gid=gids[1])
        self.nodes[prefix + ('exe',)] = metadata(stat.S_IFLNK | 0o777, st_ino=len(self.nodes) + 1)
        self.links[prefix + ('exe',)] = exe

    def _link(self, name, *, dir_fd):
        assert name == 'exe'
        target = self.links[self._path(name, dir_fd)]
        if target is None:
            raise FileNotFoundError(errno.ENOENT, 'PRIVATE_EXE')
        return target

    @contextmanager
    def _scan(self, fd):
        assert self.fds[fd] == ('proc',)
        names = sorted(path[1] for path in self.nodes if len(path) == 2 and path[0] == 'proc')
        yield iter(SimpleNamespace(name=name) for name in names)


class MaintenanceProcessTests(unittest.TestCase):
    @contextmanager
    def fake(self, fs=None):
        fs = CensusFS() if fs is None else fs
        try:
            with (patch.object(p, 'os', fs), patch.object(p.cg, 'os', fs),
                  patch.object(p.time, 'CLOCK_BOOTTIME', 7, create=True),
                  patch.object(p.time, 'clock_gettime_ns', return_value=1, create=True)):
                yield fs
        finally:
            self.assertEqual(fs.fds, {})

    def native(self, fs=None):
        with self.fake(fs):
            return p._native_scan(IDENTITY, DEADLINE)

    def observation(self, first=None, second=None, *, elapsed=1000, later_identity=IDENTITY,
                    later_manager=None, masks=None):
        first = self.native() if first is None else first
        second = first if second is None else second
        m = manager()
        namespace_handle = SimpleNamespace(checkpoint=lambda: SimpleNamespace(boot_id=BOOT))
        with (patch.object(namespaces, 'hold_maintenance_namespaces',
                           return_value=nullcontext(namespace_handle)),
              patch.object(p.state.service, '_check_tool'),
              patch.object(p.fs, '_identity', side_effect=[IDENTITY, later_identity]),
              patch.object(p.state, '_read_mask', side_effect=masks or [(True, 'mask')] * 2),
              patch.object(p.state, '_read_manager', side_effect=[m, m if later_manager is None else later_manager]),
              patch.object(p, '_native_scan', side_effect=[first, second]),
              patch.object(p.os, 'supports_fd', {p.os.scandir}),
              patch.object(p.os, 'supports_dir_fd', {p.os.readlink}),
              patch.object(p.time, 'CLOCK_BOOTTIME', 7, create=True),
              patch.object(p.time, 'clock_gettime_ns', side_effect=[1_000_000, 1_000_000 + elapsed], create=True)):
            return p.observe_maintenance_processes()

    def test_fixed_api_and_outside_guard_capsule(self):
        self.assertEqual(str(inspect.signature(p.observe_maintenance_processes)), '()')
        self.assertEqual(set(p.LIMITS), {'stat', 'status', 'cgroup'})
        self.assertNotIn('operator_maintenance_processes.py', {v[0] for v in guard.PINNED_MODULES + guard.RUNTIME_MODULES})
        self.assertNotIn('if __name__', inspect.getsource(p))

    def test_positive_outside_match_counts_overlap_once(self):
        value = self.observation()
        self.assertEqual(value.process_leaders_examined, 3)
        self.assertEqual((value.service_identity_matches, value.packaged_node_path_matches), (1, 1))
        self.assertEqual((value.matched_in_unit, value.matched_outside_unit), (0, 1))
        self.assertEqual(value.boot_id, BOOT)

    def test_zero_matches_is_not_global_absence_or_authorization(self):
        fs = CensusFS()
        fs.add_process(400)
        value = self.observation(self.native(fs))
        self.assertEqual(value.matched_outside_unit, 0)
        for name in ('host_namespace_proven', 'all_dashboard_copies_excluded', 'process_quiescence_proven',
                     'exclusive_control_proven', 'atomic_snapshot_proven', 'mutation_authorized', 'startup_authorized'):
            self.assertIs(getattr(value, name), False)
        self.assertTrue(value.process_leader_scope_only and value.review_required)
        self.assertTrue(value.visible_pid1_alignment_observed)
        self.assertEqual(value.coverage_policy, 'leader-credential-or-packaged-node-v1')
        with self.assertRaises(FrozenInstanceError):
            value.mutation_authorized = True
        summary = repr(asdict(value))
        for private in ('PRIVATE_NAME', core.NODE, '/user.slice', '400', 'uid', 'exe_hash'):
            self.assertNotIn(private, summary)

    def test_all_four_uid_and_gid_slots_detected(self):
        for name, expected in (('uids', IDENTITY[0]), ('gids', IDENTITY[1])):
            for slot in range(4):
                values = [999] * 4
                values[slot] = expected
                fs = CensusFS()
                fs.add_process(400, **{name: tuple(values)})
                with self.subTest(name=name, slot=slot):
                    row = self.native(fs).records[-1]
                    self.assertTrue(row.service_identity)
                    self.assertFalse(row.packaged_node_path)

    def test_packaged_node_any_uid_and_deleted_suffix(self):
        for executable in (core.NODE, core.NODE + ' (deleted)'):
            fs = CensusFS()
            fs.add_process(400, exe=executable)
            row = self.native(fs).records[-1]
            self.assertTrue(row.packaged_node_path)
            self.assertFalse(row.service_identity)
        fs = CensusFS()
        fs.add_process(400, exe=core.NODE + '-other')
        self.assertFalse(self.native(fs).records[-1].packaged_node_path)

    def test_unit_membership_exact_descendant_and_prefix_collision(self):
        for group, inside in ((p.cg.CGROUP_NAME, True), (p.cg.CGROUP_NAME + '/child', True),
                               (p.cg.CGROUP_NAME + '-other', False), ('/', False)):
            fs = CensusFS()
            fs.add_process(400, uids=(126,) * 4, group=('0::' + group + '\n').encode())
            value = self.observation(self.native(fs))
            self.assertEqual((value.matched_in_unit, value.matched_outside_unit), (int(inside), int(not inside)))

    def test_stat_parser_pid_comm_start_and_types(self):
        self.assertEqual(p._stat_record(stat_raw(1, start=0, state=b'I', flags=p.PF_KTHREAD), 1), (0, True, False))
        self.assertEqual(p._stat_record(stat_raw(4, state=b'Z'), 4), (10, False, True))
        for value in (b'', b'4 nope\n', stat_raw(5), stat_raw(4, state=b'?'),
                      stat_raw(4, start=-1), stat_raw(4, start=2**64), stat_raw(4, flags=2**32),
                      stat_raw(4)[:-1], b'x' * (p.LIMITS['stat'] + 1)):
            with self.subTest(value=value[:15]), self.assertRaises(core.OperatorError):
                p._stat_record(value, 4)

    def test_status_parser_missing_duplicate_and_mismatched_pid(self):
        raw = status_raw(4)
        for value in (raw + b'Uid:\t0 0 0 0\n', raw.replace(b'Tgid:\t4', b'Tgid:\t5'),
                      raw.replace(b'Pid:\t4', b'Pid:\t0'), raw.replace(b'Uid:\t0\t0\t0\t0', b'Uid:\t0'),
                      raw.replace(b'Threads:\t1', b'Threads:\t0'), raw.replace(b'Gid:', b'NotGid:'),
                      raw.replace(b'Threads:\t1', b'Threads:\t01'), raw[:-1]):
            with self.subTest(value=value[:20]), self.assertRaises(core.OperatorError):
                p._status(value, 4)

    def test_cgroup_parser_rejects_hybrid_and_malformed_paths(self):
        for raw in (b'', b'1:cpu:/\n', b'0::/\n1:cpu:/\n', b'0::/../\n', b'0::/a//b\n', b'0::/a\x00\n', b'0::/a'):
            with self.subTest(raw=raw), self.assertRaises(core.OperatorError):
                p._membership(raw)

    def test_proc_mount_type_root_device_and_visibility(self):
        self.assertEqual(p._proc_device(MOUNT), (0, 1))
        for raw in (MOUNT.replace(b' - proc ', b' - tmpfs '), MOUNT.replace(b' / /proc ', b' /other /proc '),
                    MOUNT.replace(b'proc rw', b'proc rw,hidepid=2'), MOUNT.replace(b'proc rw', b'proc rw,hidepid=invisible'),
                    MOUNT.replace(b'proc rw', b'proc rw,subset=pid'), MOUNT + MOUNT,
                    MOUNT.replace(b'0:1', b'invalid'), MOUNT[:-1]):
            with self.subTest(raw=raw), self.assertRaises(core.OperatorError):
                p._proc_device(raw)

    def test_proc_sensitive_submounts_rejected_unrelated_allowed(self):
        for path in ('/proc/123', '/proc/123/exe', '/proc/sys', '/proc/sys/kernel/random/boot_id'):
            extra = f'21 20 0:2 / {path} rw - tmpfs tmpfs rw\n'.encode()
            with self.subTest(path=path), self.assertRaisesRegex(core.OperatorError, 'CENSUS_PROC_SUBMOUNT'):
                p._proc_device(MOUNT + extra)
        other = b'21 20 0:2 / /proc/sys/fs/binfmt_misc rw - autofs systemd rw\n'
        self.assertEqual(p._proc_device(MOUNT + other), (0, 1))

    def test_missing_exe_kernel_and_single_thread_zombie_only(self):
        for flags, state, threads, allowed in ((p.PF_KTHREAD, b'I', 1, True),
                (0, b'Z', 1, True), (0, b'Z', 2, False), (0, b'S', 1, False)):
            fs = CensusFS()
            fs.add_process(400, exe=None, flags=flags, state=state, threads=threads)
            with self.subTest(flags=flags, state=state, threads=threads):
                if allowed:
                    self.assertFalse(self.native(fs).records[-1].packaged_node_path)
                else:
                    with self.assertRaisesRegex(core.OperatorError, 'CENSUS_EXE_MISSING'):
                        self.native(fs)

    def test_service_zombie_remains_conservative_candidate(self):
        fs = CensusFS()
        fs.add_process(400, uids=(126,) * 4, exe=None, state=b'Z')
        self.assertTrue(self.native(fs).records[-1].service_identity)

    def test_missing_proc_file_or_pid_is_not_skipped(self):
        for path in (('proc', '400', 'stat'), ('proc', '400', 'status'), ('proc', '400', 'cgroup'), ('proc', '400', 'exe')):
            fs = CensusFS()
            del fs.nodes[path]
            with self.subTest(path=path), self.assertRaises(FileNotFoundError):
                self.native(fs)

    def test_file_and_process_metadata_and_device_fail_closed(self):
        for path, changes in ((('proc', '400'), {'st_mode': stat.S_IFDIR | 0o777}),
                (('proc', '400', 'status'), {'st_mode': stat.S_IFLNK | 0o777}),
                (('proc', '400', 'cgroup'), {'st_mode': stat.S_IFREG | 0o644}),
                (('proc', '400', 'stat'), {'st_dev': 99}),
                (('proc', '400', 'exe'), {'st_mode': stat.S_IFREG | 0o444})):
            fs = CensusFS()
            fs.nodes[path] = SimpleNamespace(**(vars(fs.nodes[path]) | changes))
            with self.subTest(path=path, changes=changes), self.assertRaises(core.OperatorError):
                self.native(fs)

    def test_payload_bound_and_unknown_read_target(self):
        fs = CensusFS()
        fs.contents[('proc', '400', 'status')] = b'x' * (p.LIMITS['status'] + 1)
        with self.assertRaisesRegex(core.OperatorError, 'CENSUS_SIZE'):
            self.native(fs)
        with self.assertRaisesRegex(core.OperatorError, 'CENSUS_TARGET'):
            p._small(1234, 'environ', 1, DEADLINE)

    def test_identity_exec_cgroup_start_changes_between_process_samples(self):
        base = CensusFS()
        for name, replacement in (('stat', stat_raw(400, start=99)),
                ('status', status_raw(400)), ('cgroup', b'0::/different\n')):
            fs = CensusFS()
            reads = 0
            original = fs._read
            def changed(fd, size):
                nonlocal reads
                if fs.fds[fd] == ('proc', '400', name) and fs.offsets[fd] == 0:
                    reads += 1
                    if reads == 2:
                        fs.contents[('proc', '400', name)] = replacement
                return original(fd, size)
            fs.read.side_effect = changed
            with self.subTest(name=name), self.assertRaisesRegex(core.OperatorError, 'CENSUS_CHANGED'):
                self.native(fs)
        base.readlink.side_effect = lambda name, dir_fd: ('/changed' if base.readlink.call_count % 2 == 0 else core.NODE)
        with self.assertRaisesRegex(core.OperatorError, 'CENSUS_CHANGED'):
            self.native(base)

    def test_directory_replacement_during_sample_rejected(self):
        fs = CensusFS()
        original = fs._stat
        def changed(name, **kw):
            result = original(name, **kw)
            if name == '400' and fs.readlink.call_count >= 6:
                return SimpleNamespace(**(vars(result) | {'st_ino': 999}))
            return result
        fs.stat.side_effect = changed
        with self.assertRaisesRegex(core.OperatorError, 'CENSUS_CHANGED'):
            self.native(fs)

    def test_complete_pid_list_changes_rejected(self):
        fs = CensusFS()
        original = fs._scan
        @contextmanager
        def changed(fd):
            if fs.scandir.call_count == 2:
                fs.add_process(999)
            with original(fd) as entries:
                yield entries
        fs.scandir.side_effect = changed
        with self.assertRaisesRegex(core.OperatorError, 'CENSUS_CHANGED'):
            self.native(fs)

    def test_missing_pid1_or_self_visibility_rejected(self):
        for pid in (1, 123):
            fs = CensusFS()
            del fs.nodes[('proc', str(pid))]
            with self.subTest(pid=pid), self.assertRaises((core.OperatorError, FileNotFoundError)):
                self.native(fs)

    def test_scan_boot_and_mount_changes_rejected(self):
        for path, replacement in ((p.cg.BOOT_PARTS, b'00000000-0000-0000-0000-000000000000\n'),
                (('proc', '123', 'mountinfo'), MOUNT.replace(b'rw,nosuid', b'ro,nosuid'))):
            fs = CensusFS()
            reads = 0
            original = fs._read
            def changed(fd, size):
                nonlocal reads
                if fs.fds[fd] == path and fs.offsets[fd] == 0:
                    reads += 1
                    if reads == 2:
                        fs.contents[path] = replacement
                return original(fd, size)
            fs.read.side_effect = changed
            with self.subTest(path=path), self.assertRaisesRegex(core.OperatorError, 'CENSUS_CHANGED'):
                self.native(fs)

    def test_proc_exe_permission_failure_is_not_treated_as_missing(self):
        fs = CensusFS()
        fs.readlink.side_effect = PermissionError(errno.EACCES, 'PRIVATE_PATH')
        with self.assertRaises(PermissionError):
            self.native(fs)

    def test_long_exe_path_and_invalid_encoding_fail_closed(self):
        fs = CensusFS()
        fs.links[('proc', '400', 'exe')] = 'x' * 4097
        with self.assertRaisesRegex(core.OperatorError, 'CENSUS_EXE'):
            self.native(fs)
        fs.links[('proc', '400', 'exe')] = '\udcff'
        with self.assertRaises(UnicodeError):
            self.native(fs)

    def test_scan_never_swallows_partial_enumeration_failure(self):
        fs = CensusFS()
        @contextmanager
        def broken(fd):
            def entries():
                yield SimpleNamespace(name='1')
                raise PermissionError(errno.EACCES, 'PRIVATE_ENUMERATION')
            yield entries()
        fs.scandir.side_effect = broken
        with self.assertRaises(PermissionError):
            self.native(fs)

    def test_active_manager_prevents_any_scan(self):
        handle = SimpleNamespace(checkpoint=lambda: SimpleNamespace(boot_id=BOOT))
        with (patch.object(namespaces, 'hold_maintenance_namespaces', return_value=nullcontext(handle)),
              patch.object(p.state.service, '_check_tool'), patch.object(p.fs, '_identity', return_value=IDENTITY),
              patch.object(p.state, '_read_mask', return_value=(True, 'mask')),
              patch.object(p.state, '_read_manager', return_value=dict(manager(), ActiveState='active', SubState='running')),
              patch.object(p, '_native_scan') as scan,
              patch.object(p.os, 'supports_fd', {p.os.scandir}),
              patch.object(p.os, 'supports_dir_fd', {p.os.readlink}),
              patch.object(p.time, 'CLOCK_BOOTTIME', 7, create=True),
              patch.object(p.time, 'clock_gettime_ns', return_value=1, create=True)):
            with self.assertRaisesRegex(core.OperatorError, 'CGROUP_MANAGER_STATE'):
                p.observe_maintenance_processes()
            scan.assert_not_called()

    def test_public_errors_do_not_expose_kernel_data(self):
        for error, code in ((OSError(errno.EACCES, 'PRIVATE_PATH'), 'FS_ACCESS'),
                            (UnicodeError('PRIVATE_BYTES'), 'CENSUS_ENCODING')):
            handle = SimpleNamespace(checkpoint=lambda: SimpleNamespace(boot_id=BOOT))
            with (patch.object(namespaces, 'hold_maintenance_namespaces', return_value=nullcontext(handle)),
                  patch.object(p.state.service, '_check_tool', side_effect=error),
                  self.subTest(code=code), self.assertRaisesRegex(core.OperatorError, '^' + code + '$')):
                p.observe_maintenance_processes()

    def test_enumeration_count_and_noncanonical_pid_refused(self):
        for limit in ('MAX_PIDS', 'MAX_ENTRIES'):
            with self.subTest(limit=limit), patch.object(p, limit, 1), self.assertRaisesRegex(core.OperatorError, 'CENSUS_COUNT'):
                self.native()
        fs = CensusFS()
        fs.nodes[('proc', '004')] = metadata(stat.S_IFDIR | 0o555)
        with self.assertRaisesRegex(core.OperatorError, 'CENSUS_PID'):
            self.native(fs)

    def test_scan_mount_device_mismatch_refused(self):
        fs = CensusFS()
        fs.contents[('proc', '123', 'mountinfo')] = MOUNT.replace(b'0:1', b'0:9')
        with self.assertRaisesRegex(core.OperatorError, 'CENSUS_DEVICE'):
            self.native(fs)

    def test_native_scan_budget_is_checked_during_reads(self):
        with self.fake(), patch.object(p.time, 'clock_gettime_ns', return_value=DEADLINE + 1):
            with self.assertRaisesRegex(core.OperatorError, 'CENSUS_TIMEOUT'):
                p._native_scan(IDENTITY, DEADLINE)

    def test_two_full_scans_compare_private_pid_and_boot_data(self):
        first = self.native()
        for second in (replace(first, boot_id='00000000-0000-0000-0000-000000000000'),
                       replace(first, token=('changed',)),
                       replace(first, records=first.records[:-1]),
                       replace(first, records=(replace(first.records[0], start=99),) + first.records[1:])):
            with self.subTest(second=second), self.assertRaisesRegex(core.OperatorError, 'CENSUS_CHANGED'):
                self.observation(first, second)

    def test_mask_manager_and_service_identity_rechecked(self):
        for kwargs in ({'masks': [(False, 'mask')]}, {'masks': [(True, 'a'), (True, 'b')]},
                       {'later_identity': (999, 128)}, {'later_manager': dict(manager(), MainPID=42)}):
            with self.subTest(kwargs=kwargs), self.assertRaises(core.OperatorError):
                self.observation(**kwargs)

    def test_suspend_budget_backward_clock_and_fractional_overrun(self):
        self.observation(elapsed=p.MAX_COLLECTION_NS)
        for value in (-1, p.MAX_COLLECTION_NS + 1):
            with self.subTest(value=value), self.assertRaisesRegex(core.OperatorError, 'CENSUS_TIMEOUT'):
                self.observation(elapsed=value)

    def test_no_payloads_beyond_allowlist_or_executable_follow(self):
        with self.fake() as fs:
            p._native_scan(IDENTITY, DEADLINE)
            for call in fs.open.call_args_list:
                name = call.args[0]
                self.assertNotIn(name, ('exe', 'cmdline', 'environ', 'mem', 'fd'))
                self.assertTrue(call.args[1] & fs.O_NOFOLLOW)
            self.assertGreater(fs.readlink.call_count, 0)


@unittest.skipUnless(sys.platform == 'linux', 'Linux descriptor fixture only; not a live census')
class NativeMaintenanceProcessTests(unittest.TestCase):
    @contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            boot = root.joinpath(*p.cg.BOOT_PARTS)
            boot.parent.mkdir(parents=True)
            boot.write_text(BOOT + '\n', encoding='ascii')
            pid = os.getpid()
            device = os.stat(root).st_dev
            for n in {1, pid}:
                path = root / 'proc' / str(n)
                path.mkdir()
                for name, data in (('stat', stat_raw(n)), ('status', status_raw(n)), ('cgroup', b'0::/\n')):
                    (path / name).write_bytes(data)
                    (path / name).chmod(0o444)
                (path / 'exe').symlink_to('/not-opened/node')
                path.chmod(0o555)
            mount = root / 'proc' / str(pid) / 'mountinfo'
            mount.parent.chmod(0o755)
            mount.write_bytes(MOUNT.replace(b'0:1', f'{os.major(device)}:{os.minor(device)}'.encode()))
            mount.parent.chmod(0o555)
            old_open, old_stat, old_fstat = os.open, os.stat, os.fstat
            def normalized(value):
                return SimpleNamespace(**{name: (0 if name in ('st_uid', 'st_gid') else getattr(value, name))
                    for name in vars(metadata())})
            def opened(name, flags, **kw):
                return old_open(root if name == '/' and not kw else name, flags, **kw)
            try:
                with (patch.object(p.os, 'open', side_effect=opened),
                      patch.object(p.os, 'stat', side_effect=lambda *a, **kw: normalized(old_stat(*a, **kw))),
                      patch.object(p.os, 'fstat', side_effect=lambda fd: normalized(old_fstat(fd)))):
                    yield root, pid
            finally:
                for n in {1, pid}:
                    (root / 'proc' / str(n)).chmod(0o755)

    def test_native_disposable_proc_tree_and_missing_file(self):
        with self.fixture() as (root, pid):
            deadline = time.clock_gettime_ns(time.CLOCK_BOOTTIME) + p.MAX_COLLECTION_NS
            result = p._native_scan(IDENTITY, deadline)
            self.assertEqual(result.boot_id, BOOT)
            self.assertEqual({r.pid for r in result.records}, {1, pid})
            parent = root / 'proc' / str(pid)
            parent.chmod(0o755)
            (parent / 'status').unlink()
            parent.chmod(0o555)
            with self.assertRaises(FileNotFoundError):
                p._native_scan(IDENTITY, deadline)

    def test_native_proc_file_symlink_is_not_followed(self):
        with self.fixture() as (root, pid):
            parent = root / 'proc' / str(pid)
            parent.chmod(0o755)
            (parent / 'status').unlink()
            (parent / 'status').symlink_to('/must-not-be-opened')
            parent.chmod(0o555)
            with self.assertRaisesRegex(core.OperatorError, 'CENSUS_METADATA'):
                p._native_scan(IDENTITY, time.clock_gettime_ns(time.CLOCK_BOOTTIME) + p.MAX_COLLECTION_NS)


if __name__ == '__main__':
    unittest.main()
