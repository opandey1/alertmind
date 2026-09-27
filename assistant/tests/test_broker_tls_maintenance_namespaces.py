"""Offline namespace fixtures; no host-wide scan, namespace entry or service call."""
from contextlib import contextmanager
from dataclasses import asdict, FrozenInstanceError
import errno
import inspect
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_core as core
from siem.rbac.broker_tls import operator_guard_entry as guard
from siem.rbac.broker_tls import operator_maintenance_namespaces as n
from test_broker_tls_maintenance_cgroup import KernelFS, metadata, BOOT
from test_broker_tls_maintenance_processes import stat_raw, status_raw, MOUNT


class NamespaceFS(KernelFS):
    def __init__(self):
        super().__init__()
        self.contents[('proc', '123', 'mountinfo')] = MOUNT
        self.targets, self.handles = {}, {}
        for pid in (1, 123):
            for name, raw in (('stat', stat_raw(pid)), ('status', status_raw(pid))):
                self.add(('proc', str(pid), name), raw)
            for name, label, kind in n.NAMES:
                path = ('proc', str(pid), 'ns', name)
                self.add(path, b'')
                self.nodes[path] = metadata(stat.S_IFLNK | 0o777, st_ino=len(self.nodes))
                self.targets[path] = (metadata(stat.S_IFREG | 0o444, st_dev=99, st_ino=kind), kind)
        self.readlink = Mock(side_effect=self._readlink)
        self.supports_dir_fd = {self.readlink}
        self.get_inheritable = Mock(return_value=False)
        self.uname = lambda: SimpleNamespace(machine='x86_64')
        self.fstat = Mock(side_effect=self._fstat)
        self.close = Mock(side_effect=self._close)

    def _open(self, name, flags, *, dir_fd=None):
        path = self._path(name, dir_fd)
        if path not in self.targets:
            return super()._open(name, flags, dir_fd=dir_fd)
        assert not flags & self.O_NOFOLLOW
        assert flags & self.O_CLOEXEC and flags & self.O_NONBLOCK
        self.next_fd += 1
        self.handles[self.next_fd] = self.targets[path]
        self.fds[self.next_fd] = path
        return self.next_fd

    def _fstat(self, fd):
        return self.handles[fd][0] if fd in self.handles else self.nodes[self.fds[fd]]

    def _readlink(self, name, *, dir_fd):
        value = self.targets[self._path(name, dir_fd)][0]
        label = next(e[1] for e in n.NAMES if e[0] == name)
        return f'{label}:[{value.st_ino}]'

    def _close(self, fd):
        self.fds.pop(fd)
        self.handles.pop(fd, None)

    def kind(self, fd):
        return self.handles[fd][1]

    def change(self, pid, name, *, inode=None, device=None, kind=None):
        path = ('proc', str(pid), 'ns', name)
        st, old_kind = self.targets[path]
        values = vars(st).copy()
        if inode is not None:
            values['st_ino'] = inode
        if device is not None:
            values['st_dev'] = device
        self.targets[path] = SimpleNamespace(**values), old_kind if kind is None else kind


class MaintenanceNamespaceTests(unittest.TestCase):
    @contextmanager
    def fixture(self, fs=None):
        fs = NamespaceFS() if fs is None else fs
        with (patch.object(n, 'os', fs), patch.object(n.cg, 'os', fs),
              patch.object(n.census, 'os', fs), patch.object(n, '_kind', side_effect=fs.kind),
              patch.object(n.threading, 'get_native_id', return_value=123),
              patch.object(n.time, 'CLOCK_BOOTTIME', 7, create=True),
              patch.object(n.time, 'clock_gettime_ns', return_value=1, create=True)):
            root = fs.open('/', fs.O_NOFOLLOW)
            try:
                yield fs, root
            finally:
                fs.close(root)
                self.assertEqual(fs.fds, {})
                self.assertEqual(fs.handles, {})

    def test_public_fixed_api_outside_capsule_and_no_cli(self):
        self.assertEqual(str(inspect.signature(n.hold_maintenance_namespaces)), '()')
        self.assertEqual(len(n.NAMES), 7)
        self.assertEqual(n.NS_GET_NSTYPE, 0xb703)
        self.assertNotIn('operator_maintenance_namespaces.py',
                         {v[0] for v in guard.PINNED_MODULES + guard.RUNTIME_MODULES})
        self.assertNotIn('if __name__', inspect.getsource(n))

    def test_held_alignment_private_and_non_authorizing(self):
        with self.fixture() as (fs, root), n._hold_at(root, 123, 0) as held:
            self.assertEqual(len(fs.handles), 14)
            result = held.checkpoint()
            self.assertEqual(result.boot_id, BOOT)
            self.assertTrue(result.visible_pid1_alignment_observed and result.review_required)
            self.assertEqual((result.namespace_types_checked, result.child_namespace_targets_checked), (5, 2))
            for name in ('host_namespace_proven', 'process_coverage_complete', 'process_quiescence_proven',
                         'exclusive_control_proven', 'atomic_snapshot_proven', 'mutation_authorized', 'startup_authorized'):
                self.assertIs(getattr(result, name), False)
            self.assertNotIn('private', repr(asdict(result)))
            self.assertEqual(repr(held), '<private maintenance namespace handle>')
            with self.assertRaises(FrozenInstanceError):
                result.host_namespace_proven = True

    def test_each_current_namespace_must_match_visible_pid1(self):
        for name in ('mnt', 'pid', 'user', 'cgroup', 'time'):
            fs = NamespaceFS()
            fs.change(123, name, inode=999)
            with self.subTest(name=name), self.fixture(fs) as (_, root):
                with self.assertRaisesRegex(core.OperatorError, 'NAMESPACE_ALIGNMENT'), n._hold_at(root, 123, 0):
                    self.fail('divergent namespace admitted')

    def test_both_processes_child_targets_must_match_active_namespaces(self):
        for pid in (1, 123):
            for name in ('pid_for_children', 'time_for_children'):
                fs = NamespaceFS()
                fs.change(pid, name, inode=999)
                with self.subTest(pid=pid, name=name), self.fixture(fs) as (_, root):
                    with self.assertRaisesRegex(core.OperatorError, 'NAMESPACE_ALIGNMENT'), n._hold_at(root, 123, 0):
                        self.fail('child namespace admitted')

    def test_equal_inode_text_with_other_device_is_not_alignment(self):
        fs = NamespaceFS()
        fs.change(123, 'mnt', device=77)
        with self.fixture(fs) as (_, root), self.assertRaisesRegex(core.OperatorError, 'NAMESPACE_ALIGNMENT'):
            with n._hold_at(root, 123, 0):
                self.fail('text-only comparison')

    def test_namespace_type_checked_not_just_name(self):
        fs = NamespaceFS()
        fs.change(1, 'mnt', kind=0x20000000)
        with self.fixture(fs) as (_, root), self.assertRaisesRegex(core.OperatorError, 'NAMESPACE_TYPE'):
            with n._hold_at(root, 123, 0):
                self.fail('incorrect ioctl type')

    def test_link_grammar_and_empty_children_rejected(self):
        for text in ('', 'mnt:[0]', 'mnt:[01]', 'pid:[1]', 'mnt:[18446744073709551616]',
                     'mnt:[1]\n', '/some/file', 'mnt:[-1]'):
            fs = NamespaceFS()
            fs.readlink.side_effect = lambda *a, **kw: text
            with self.subTest(text=text), self.fixture(fs) as (_, root):
                with self.assertRaisesRegex(core.OperatorError, 'NAMESPACE_LINK'), n._hold_at(root, 123, 0):
                    self.fail('invalid link')

    def test_link_owner_type_and_device_rejected(self):
        for changes in ({'st_uid': 126}, {'st_gid': 128}, {'st_dev': 3}, {'st_mode': stat.S_IFREG | 0o444}):
            fs = NamespaceFS()
            path = ('proc', '1', 'ns', 'mnt')
            fs.nodes[path] = SimpleNamespace(**dict(vars(fs.nodes[path]), **changes))
            with self.subTest(changes=changes), self.fixture(fs) as (_, root):
                with self.assertRaisesRegex(core.OperatorError, 'NAMESPACE_LINK'), n._hold_at(root, 123, 0):
                    self.fail('bad link metadata')

    def test_namespace_descriptor_metadata_and_inheritable_rejected(self):
        for changes in ({'st_uid': 9}, {'st_mode': stat.S_IFDIR | 0o555}, {'st_mode': stat.S_IFREG | 0o666}):
            fs = NamespaceFS()
            path = ('proc', '1', 'ns', 'mnt')
            st, kind = fs.targets[path]
            fs.targets[path] = SimpleNamespace(**dict(vars(st), **changes)), kind
            with self.subTest(changes=changes), self.fixture(fs) as (_, root):
                with self.assertRaisesRegex(core.OperatorError, 'NAMESPACE_DESCRIPTOR'), n._hold_at(root, 123, 0):
                    self.fail('bad descriptor')
        fs = NamespaceFS()
        fs.get_inheritable.return_value = True
        with self.fixture(fs) as (_, root), self.assertRaisesRegex(core.OperatorError, 'NAMESPACE_INHERITABLE'):
            with n._hold_at(root, 123, 0):
                self.fail('inheritable descriptor')

    def test_namespace_directory_symlink_and_wrong_device_rejected(self):
        for changes in ({'st_mode': stat.S_IFLNK | 0o777}, {'st_dev': 9}, {'st_uid': 126}):
            fs = NamespaceFS()
            path = ('proc', '1', 'ns')
            fs.nodes[path] = SimpleNamespace(**dict(vars(fs.nodes[path]), **changes))
            with self.subTest(changes=changes), self.fixture(fs) as (_, root):
                with self.assertRaises(core.OperatorError), n._hold_at(root, 123, 0):
                    self.fail('bad ancestor')

    def test_filtered_or_shadowed_proc_view_rejected(self):
        for raw in (MOUNT.replace(b'rw,nosuid', b'rw,hidepid=2,nosuid'),
                    MOUNT + b'21 20 0:7 / /proc/1/ns ro - nsfs nsfs ro\n', MOUNT.replace(b'0:1', b'0:7')):
            fs = NamespaceFS()
            fs.contents[('proc', '123', 'mountinfo')] = raw
            with self.subTest(raw=raw), self.fixture(fs) as (_, root):
                with self.assertRaises(core.OperatorError), n._hold_at(root, 123, 0):
                    self.fail('untrusted proc mount')

    def test_credentials_and_multiple_threads_rejected(self):
        for raw in (status_raw(123, uids=(0, 0, 99, 0)), status_raw(123, gids=(0, 1, 0, 0)),
                    status_raw(123, threads=2)):
            fs = NamespaceFS()
            fs.contents[('proc', '123', 'status')] = raw
            with self.subTest(raw=raw), self.fixture(fs) as (_, root):
                with self.assertRaises(core.OperatorError), n._hold_at(root, 123, 0):
                    self.fail('unsupported caller')

    def test_zombie_or_kernel_process_context_rejected(self):
        for raw in (stat_raw(1, state=b'Z'), stat_raw(1, flags=n.census.PF_KTHREAD)):
            fs = NamespaceFS()
            fs.contents[('proc', '1', 'stat')] = raw
            with self.subTest(raw=raw), self.fixture(fs) as (_, root):
                with self.assertRaisesRegex(core.OperatorError, 'NAMESPACE_IDENTITY'), n._hold_at(root, 123, 0):
                    self.fail('unsupported PID1')

    def test_mid_body_namespace_switch_rejected_on_exit(self):
        with self.fixture() as (fs, root), self.assertRaisesRegex(core.OperatorError, 'NAMESPACE_CHANGED'):
            with n._hold_at(root, 123, 0):
                fs.change(123, 'mnt', inode=999)

    def test_opened_descriptor_does_not_hide_rebound_namespace(self):
        with self.fixture() as (fs, root), self.assertRaisesRegex(core.OperatorError, 'NAMESPACE_CHANGED'):
            with n._hold_at(root, 123, 0) as held:
                fs.change(1, 'mnt', inode=999)
                held.checkpoint()

    def test_link_to_open_race_rejected_and_descriptor_closed(self):
        fs = NamespaceFS()
        original = fs.open.side_effect
        def race(name, *a, **kw):
            if name == 'mnt':
                fs.change(1, 'mnt', inode=999)
            return original(name, *a, **kw)
        fs.open.side_effect = race
        with self.fixture(fs) as (_, root), self.assertRaisesRegex(core.OperatorError, 'NAMESPACE_DESCRIPTOR'):
            with n._hold_at(root, 123, 0):
                self.fail('link-to-open race')

    def test_missing_required_child_namespace_fails_without_fallback(self):
        fs = NamespaceFS()
        del fs.nodes[('proc', '123', 'ns', 'pid_for_children')]
        with self.fixture(fs) as (_, root), self.assertRaisesRegex(core.OperatorError, '^FS_MISSING$'):
            with n._hold_at(root, 123, 0):
                self.fail('missing child namespace accepted')

    def test_boot_mount_pid_start_or_thread_drift_rejected(self):
        for path, raw in ((n.cg.BOOT_PARTS, b'00000000-0000-0000-0000-000000000000\n'),
                          (('proc', '123', 'mountinfo'), MOUNT + b'21 1 0:3 / /tmp rw - tmpfs tmpfs rw\n'),
                          (('proc', '1', 'stat'), stat_raw(1, start=99)),
                          (('proc', '123', 'status'), status_raw(123, threads=2))):
            with self.subTest(path=path), self.fixture() as (fs, root):
                with self.assertRaises(core.OperatorError), n._hold_at(root, 123, 0):
                    fs.contents[path] = raw

    def test_ancestor_replacement_rejected_on_exit(self):
        with self.fixture() as (fs, root), self.assertRaisesRegex(core.OperatorError, 'CGROUP_CHANGED'):
            with n._hold_at(root, 123, 0):
                path = ('proc', '123', 'ns')
                fs.nodes[path] = SimpleNamespace(**dict(vars(fs.nodes[path]), st_ino=999))

    def test_closed_handle_or_changed_caller_rejected(self):
        with self.fixture() as (_, root):
            with n._hold_at(root, 123, 0) as held:
                for pid, tid in ((124, 123), (123, 124), (1, 1)):
                    with patch.object(n.os, 'getpid', return_value=pid), patch.object(n.threading, 'get_native_id', return_value=tid):
                        with self.assertRaisesRegex(core.OperatorError, 'NAMESPACE_CALLER'):
                            held.checkpoint()
            with self.assertRaisesRegex(core.OperatorError, 'NAMESPACE_CLOSED'):
                held.checkpoint()

    def test_suspend_backward_clock_and_fractional_overrun_fail(self):
        for value in (-1, n.MAX_WINDOW_NS + 1):
            with self.subTest(value=value), self.fixture() as (_, root):
                with self.assertRaisesRegex(core.OperatorError, 'NAMESPACE_TIMEOUT'):
                    with n._hold_at(root, 123, 0) as held:
                        with patch.object(n.time, 'clock_gettime_ns', return_value=value):
                            held.checkpoint()
        with self.fixture() as (_, root), n._hold_at(root, 123, 0) as held:
            with patch.object(n.time, 'clock_gettime_ns', return_value=n.MAX_WINDOW_NS):
                self.assertEqual(held.checkpoint().window_elapsed_ms, 30000)

    def test_missing_denied_or_nonnamespace_ioctl_errors_are_sanitized(self):
        for error, code in ((errno.ENOENT, 'FS_MISSING'), (errno.EACCES, 'FS_ACCESS'), (errno.ENOTTY, 'FS_IO')):
            with self.subTest(error=error), self.fixture() as (_, root):
                with patch.object(n, '_kind', side_effect=OSError(error, 'PRIVATE_PATH')):
                    with self.assertRaisesRegex(core.OperatorError, '^' + code + '$'), n._hold_at(root, 123, 0):
                        self.fail('unsupported ioctl')

    def test_body_exception_closes_and_invalidates_handle(self):
        with self.fixture() as (_, root):
            with self.assertRaisesRegex(RuntimeError, 'body'):
                with n._hold_at(root, 123, 0) as held:
                    raise RuntimeError('body')
            with self.assertRaisesRegex(core.OperatorError, 'NAMESPACE_CLOSED'):
                held.checkpoint()

    def test_fixed_reads_only_and_magic_links_only_followed_leaves(self):
        with self.fixture() as (fs, root), n._hold_at(root, 123, 0):
            for call in fs.open.call_args_list:
                name, flags = call.args
                if not flags & fs.O_NOFOLLOW:
                    self.assertIn(name, {e[0] for e in n.NAMES})
                self.assertNotIn(name, ('exe', 'cmdline', 'environ', 'mem'))

    def test_public_wrapper_opens_fixed_root_and_checks_platform(self):
        with self.fixture() as (fs, _), patch.object(n.fs, '_platform') as check:
            with n.hold_maintenance_namespaces() as held:
                self.assertTrue(held.checkpoint().visible_pid1_alignment_observed)
            check.assert_called_once_with()
            with patch.object(fs, 'uname', return_value=SimpleNamespace(machine='aarch64')):
                with self.assertRaisesRegex(core.OperatorError, 'NAMESPACE_PLATFORM'), n.hold_maintenance_namespaces():
                    self.fail('unreviewed ioctl ABI')

    def test_public_root_open_failure_is_sanitized(self):
        with self.fixture() as (fs, _), patch.object(n.fs, '_platform'):
            old = fs.open.side_effect
            def fail(name, *a, **kw):
                if name == '/':
                    raise OSError(errno.EACCES, 'PRIVATE_ROOT')
                return old(name, *a, **kw)
            fs.open.side_effect = fail
            with self.assertRaisesRegex(core.OperatorError, '^FS_ACCESS$'), n.hold_maintenance_namespaces():
                self.fail('root denied')

    def test_census_bracket_order_and_result_is_narrow(self):
        calls = []
        @contextmanager
        def hold():
            calls.append('enter')
            yield SimpleNamespace(checkpoint=lambda: (calls.append('check') or SimpleNamespace(boot_id=BOOT)))
            calls.append('exit')
        result = n.census.MaintenanceProcessObservation(BOOT, 0, 1, 2, 0, 0, 0, 0)
        with patch.object(n, 'hold_maintenance_namespaces', side_effect=hold), patch.object(
                n.census, '_observe_processes', side_effect=lambda: (calls.append('scan') or result)):
            value = n.census.observe_maintenance_processes()
        self.assertEqual(calls, ['enter', 'check', 'scan', 'check', 'exit'])
        self.assertTrue(value.visible_pid1_alignment_observed)
        self.assertFalse(value.host_namespace_proven or value.process_quiescence_proven or value.mutation_authorized)

    def test_census_namespace_failure_prevents_scan(self):
        @contextmanager
        def hold():
            raise core.OperatorError('NAMESPACE_ALIGNMENT')
            yield
        with patch.object(n, 'hold_maintenance_namespaces', side_effect=hold), patch.object(n.census, '_observe_processes') as scan:
            with self.assertRaisesRegex(core.OperatorError, 'NAMESPACE_ALIGNMENT'):
                n.census.observe_maintenance_processes()
            scan.assert_not_called()

    def test_census_exit_drift_discards_successful_scan(self):
        @contextmanager
        def hold():
            yield SimpleNamespace(checkpoint=lambda: SimpleNamespace(boot_id=BOOT))
            raise core.OperatorError('NAMESPACE_CHANGED')
        result = n.census.MaintenanceProcessObservation(BOOT, 0, 1, 2, 0, 0, 0, 0)
        with patch.object(n, 'hold_maintenance_namespaces', side_effect=hold), patch.object(n.census, '_observe_processes', return_value=result):
            with self.assertRaisesRegex(core.OperatorError, 'NAMESPACE_CHANGED'):
                n.census.observe_maintenance_processes()

    def test_census_boot_mismatch_never_returns_result(self):
        from contextlib import nullcontext
        result = n.census.MaintenanceProcessObservation(BOOT, 0, 1, 2, 0, 0, 0, 0)
        with patch.object(n, 'hold_maintenance_namespaces', return_value=nullcontext(
                SimpleNamespace(checkpoint=lambda: SimpleNamespace(boot_id='other')))), patch.object(
                n.census, '_observe_processes', return_value=result):
            with self.assertRaisesRegex(core.OperatorError, 'CENSUS_NAMESPACE_BOOT'):
                n.census.observe_maintenance_processes()


@unittest.skipUnless(sys.platform == 'linux' and os.uname().machine == 'x86_64',
                     'Linux x86-64 nsfs syscall test only; not host alignment acceptance')
class NativeMaintenanceNamespaceTests(unittest.TestCase):
    def test_native_own_namespace_types_inode_identity_and_cloexec(self):
        # Only this test process's namespace handles; never PID1, census or setns.
        directory = os.open(f'/proc/{os.getpid()}/ns', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for name, label, kind in n.NAMES:
                with self.subTest(name=name):
                    fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
                    try:
                        self.assertEqual(n._kind(fd), kind)
                        self.assertFalse(os.get_inheritable(fd))
                        self.assertEqual(os.readlink(name, dir_fd=directory), f'{label}:[{os.fstat(fd).st_ino}]')
                        named = os.stat(name, dir_fd=directory)
                        self.assertEqual((named.st_dev, named.st_ino), (os.fstat(fd).st_dev, os.fstat(fd).st_ino))
                    finally:
                        os.close(fd)
        finally:
            os.close(directory)

    def test_native_ordinary_file_is_not_a_namespace_handle(self):
        fd = os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC)
        try:
            with self.assertRaises(OSError) as error:
                n._kind(fd)
            self.assertEqual(error.exception.errno, errno.ENOTTY)
        finally:
            os.close(fd)


if __name__ == '__main__':
    unittest.main()
