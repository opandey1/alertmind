"""Offline maintenance observation contracts; never contact a real service bus."""
from contextlib import contextmanager
from dataclasses import FrozenInstanceError, asdict
import errno
import inspect
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_core as core
from siem.rbac.broker_tls import operator_maintenance_state as m
from siem.rbac.broker_tls import operator_guard_entry as guard


def values():
    return dict(Id=m.UNIT, LoadState='masked', UnitFileState='masked',
                ActiveState='inactive', SubState='dead', NeedDaemonReload=False,
                Job=[0, '/'], TriggeredBy=[], MainPID=0, ControlPID=0,
                ControlGroup='')


def reply(group, data):
    return ('\n'.join(json.dumps({'type': signature, 'data': data[name]})
                      for name, signature in m.GROUPS[group]) + '\n').encode()


def metadata(mode=stat.S_IFDIR | 0o755, **changes):
    data = dict(st_mode=mode, st_uid=0, st_gid=0, st_dev=1, st_ino=1,
                st_nlink=1, st_size=0, st_mtime_ns=1, st_ctime_ns=1)
    data.update(changes)
    return SimpleNamespace(**data)


class MaskFS:
    """Only the fixed root/etc/systemd/system chain; no ambient filesystem."""
    def __init__(self):
        self.nodes = {n: metadata(st_ino=n) for n in (10, 11, 12, 13)}
        self.leaf = metadata(stat.S_IFLNK | 0o777, st_ino=14, st_size=9)
        self.target = '/dev/null'
        self.open = Mock(side_effect=lambda name, *_args, **_kw:
                         {'/': 10, 'etc': 11, 'systemd': 12, 'system': 13}[name])
        self.close = Mock()
        self.fstat = Mock(side_effect=lambda fd: self.nodes[fd])
        self.stat = Mock(side_effect=self.lookup)
        self.readlink = Mock(side_effect=lambda *_args, **_kw: self.target)
        for name, value in (('O_RDONLY', 0), ('O_DIRECTORY', 1), ('O_NOFOLLOW', 2),
                            ('O_CLOEXEC', 4), ('O_PATH', 8)):
            setattr(self, name, value)
        self.major, self.minor = Mock(), Mock()
        self.supports_dir_fd = {self.readlink}

    def lookup(self, name, *, dir_fd, follow_symlinks):
        if follow_symlinks:
            raise AssertionError('must never follow')
        if name == m.UNIT:
            if self.leaf is None:
                raise FileNotFoundError(errno.ENOENT, 'PRIVATE_PATH')
            return self.leaf
        return self.nodes[{(10, 'etc'): 11, (11, 'systemd'): 12, (12, 'system'): 13}[(dir_fd, name)]]


class MaintenanceStateTests(unittest.TestCase):
    def observe(self, data=None, second=None, masks=None, elapsed_ns=1000000):
        data = values() if data is None else data
        second = data if second is None else second
        fake = MaskFS()
        replies = [reply(g, v) for v in (data, second) for g in m.GROUPS]
        with patch.object(m.service, '_check_tool') as check, patch.object(m, 'os', fake), patch.object(
                m, '_read_mask', side_effect=masks or [(True, ('same',))] * 2), patch.object(
                m, '_query', side_effect=replies) as query, patch.object(m.time, 'monotonic_ns',
                side_effect=[1000000000, 1000000000 + elapsed_ns]):
            result = m.observe_maintenance_state()
            check.assert_called_once_with()
            self.assertEqual([c.args for c in query.call_args_list], [('Unit',), ('Service',)] * 2)
            return result

    def test_fixed_properties_match_dbus_interfaces_and_no_secret_inputs(self):
        self.assertEqual(m.GROUPS, {
            'Unit': (('Id', 's'), ('LoadState', 's'), ('UnitFileState', 's'),
                     ('ActiveState', 's'), ('SubState', 's'), ('NeedDaemonReload', 'b'),
                     ('Job', '(uo)'), ('TriggeredBy', 'as')),
            'Service': (('MainPID', 'u'), ('ControlPID', 'u'), ('ControlGroup', 's'))})
        self.assertEqual(m.MASK_PARENT, ('etc', 'systemd', 'system'))
        self.assertEqual(m.UNIT, 'wazuh-dashboard.service')
        self.assertEqual(m.OBJECT, '/org/freedesktop/systemd1/unit/wazuh_2ddashboard_2eservice')

    def test_masked_stopped_observation_never_claims_process_or_execution_proof(self):
        result = self.observe()
        for name in ('persistent_mask_present', 'manager_reports_persistent_mask',
                     'persistent_inhibition_observed', 'manager_reports_stopped', 'review_required'):
            self.assertIs(getattr(result, name), True)
        for name in ('process_quiescence_proven', 'exclusive_control_proven',
                     'atomic_snapshot_proven', 'mutation_authorized', 'startup_authorized'):
            self.assertIs(getattr(result, name), False)
        self.assertEqual((result.passes, result.collection_elapsed_ms), (2, 1))
        with self.assertRaises(FrozenInstanceError):
            result.startup_authorized = True
        self.assertNotIn('dashboard_stopped', asdict(result))

    def test_mask_requires_disk_and_manager_and_no_reload(self):
        for disk in (True, False):
            for load in ('masked', 'loaded', 'not-found'):
                for unit_state in ('masked', 'masked-runtime', 'disabled', ''):
                    for reload in (True, False):
                        data = values()
                        data.update(LoadState=load, UnitFileState=unit_state, NeedDaemonReload=reload)
                        result = self.observe(data, masks=[(disk, ('same',))] * 2)
                        self.assertEqual(result.persistent_inhibition_observed,
                                         disk and load == 'masked' and unit_state == 'masked' and not reload)

    def test_mask_does_not_imply_stopped_and_stopped_does_not_imply_mask(self):
        data = values(); data.update(ActiveState='active', SubState='running', MainPID=101)
        result = self.observe(data)
        self.assertTrue(result.persistent_inhibition_observed)
        self.assertFalse(result.manager_reports_stopped)
        data = values(); data.update(LoadState='loaded', UnitFileState='disabled')
        result = self.observe(data, masks=[(False, ('absent',))] * 2)
        self.assertFalse(result.persistent_inhibition_observed)
        self.assertTrue(result.manager_reports_stopped)

    def test_stopped_requires_exact_state_pair_pids_job_and_reload(self):
        for state in (('inactive', 'dead'), ('failed', 'failed')):
            data = values(); data.update(ActiveState=state[0], SubState=state[1])
            self.assertTrue(self.observe(data).manager_reports_stopped)
        for key, bad in (('ActiveState', 'activating'), ('ActiveState', 'deactivating'),
                         ('ActiveState', 'unknown'), ('SubState', 'running'),
                         ('MainPID', 10), ('ControlPID', 10), ('NeedDaemonReload', True),
                         ('LoadState', 'not-found'), ('Job', [42, '/org/freedesktop/systemd1/job/42'])):
            data = values(); data[key] = bad
            self.assertFalse(self.observe(data).manager_reports_stopped, key)

    def test_control_group_and_triggers_are_not_quiescence_or_leaked(self):
        data = values(); data.update(ControlGroup='/PRIVATE_SECRET', TriggeredBy=['PRIVATE_SECRET.socket'])
        result = self.observe(data)
        self.assertTrue(result.manager_reports_stopped and result.control_group_named)
        self.assertEqual(result.trigger_count, 1)
        self.assertFalse(result.process_quiescence_proven)
        self.assertNotIn('PRIVATE_SECRET', repr(result))

    def test_raw_change_between_passes_rejected_even_if_summary_same(self):
        for key, first_value, second_value in (('MainPID', 1, 2), ('ControlGroup', '/one', '/two'),
                ('TriggeredBy', ['one.socket'], ['two.socket']), ('SubState', 'one', 'two')):
            first = values(); first[key] = first_value
            second = values(); second[key] = second_value
            with self.subTest(key=key), self.assertRaisesRegex(core.OperatorError, '^MAINTENANCE_CHANGED$'):
                self.observe(first, second)
        with self.assertRaisesRegex(core.OperatorError, '^MAINTENANCE_CHANGED$'):
            self.observe(masks=[(True, ('inode1',)), (True, ('inode2',))])

    def test_wrong_identity_unavailable_unit_and_query_failure_never_load(self):
        data = values(); data['Id'] = 'PRIVATE_SECRET.service'
        with self.assertRaisesRegex(core.OperatorError, '^MAINTENANCE_IDENTITY$'):
            self.observe(data)
        with patch.object(m, '_query', side_effect=core.OperatorError('MAINTENANCE_QUERY')) as query:
            with self.assertRaisesRegex(core.OperatorError, '^MAINTENANCE_QUERY$'):
                m._read_manager()
            query.assert_called_once_with('Unit')

    def test_collection_clock_bound_and_clock_reversal(self):
        self.assertEqual(self.observe(elapsed_ns=m.MAX_COLLECTION_MS * 1000000).collection_elapsed_ms,
                         m.MAX_COLLECTION_MS)
        for elapsed in (-1, (m.MAX_COLLECTION_MS + 1) * 1000000):
            with self.assertRaisesRegex(core.OperatorError, '^MAINTENANCE_TIMEOUT$'):
                self.observe(elapsed_ns=elapsed)

    def test_public_api_has_no_overrides_or_guard_integration(self):
        self.assertEqual(len(inspect.signature(m.observe_maintenance_state).parameters), 0)
        self.assertNotIn('operator_maintenance_state.py', {p[0] for p in guard.PINNED_MODULES + guard.RUNTIME_MODULES})
        source = inspect.getsource(m)
        for forbidden in ('__main__', 'next_maintenance_step(', 'systemctl', 'LoadUnit', 'StartUnit',
                          'StopUnit', 'os.write(', 'os.unlink(', 'os.symlink(', 'os.chmod('):
            self.assertNotIn(forbidden, source)

    def test_prerequisite_failure_precedes_mask_and_query(self):
        with patch.object(m.service, '_check_tool', side_effect=core.OperatorError('FS_ROOT_REQUIRED')), patch.object(
                m, '_read_mask') as mask, patch.object(m, '_query') as query:
            with self.assertRaisesRegex(core.OperatorError, '^FS_ROOT_REQUIRED$'):
                m.observe_maintenance_state()
            mask.assert_not_called(); query.assert_not_called()
        fake = MaskFS(); fake.supports_dir_fd = set()
        with patch.object(m.service, '_check_tool'), patch.object(m, 'os', fake), patch.object(m, '_read_mask') as mask:
            with self.assertRaisesRegex(core.OperatorError, '^MAINTENANCE_PLATFORM$'):
                m.observe_maintenance_state()
            mask.assert_not_called()

    def test_public_os_errors_are_fixed_not_paths(self):
        for number, code in ((errno.ENOENT, 'FS_MISSING'), (errno.EACCES, 'FS_ACCESS'), (errno.EIO, 'FS_IO')):
            with patch.object(m.service, '_check_tool', side_effect=OSError(number, 'PRIVATE_SECRET')):
                with self.assertRaisesRegex(core.OperatorError, '^' + code + '$') as caught:
                    m.observe_maintenance_state()
                self.assertTrue(caught.exception.__suppress_context__)

    def test_parser_exact_size_lines_duplicates_and_encoding(self):
        valid = reply('Unit', values())
        self.assertEqual(m.parse_properties(valid, 'Unit'), m.parse_properties(valid[:-1], 'Unit'))
        for raw in (b'', 'text', bytearray(valid), b'x' * (m.MAX_REPLY + 1)):
            with self.assertRaisesRegex(core.OperatorError, '^MAINTENANCE_SIZE$'):
                m.parse_properties(raw, 'Unit')
        for raw in (valid + b'\n', valid + b'{}\n', b'{}\n',
                    valid.replace(b'{', b'{"extra":true,', 1)):
            with self.assertRaisesRegex(core.OperatorError, '^MAINTENANCE_SHAPE$'):
                m.parse_properties(raw, 'Unit')
        for raw in (valid.replace(b'{', b'{"type":"s",', 1),
                    valid.replace(b'"wazuh-dashboard.service"', b'NaN', 1),
                    valid.replace(b'wazuh', b'\xff', 1)):
            with self.assertRaisesRegex(core.OperatorError, '^MAINTENANCE_JSON$'):
                m.parse_properties(raw, 'Unit')

    def test_parser_rejects_type_coercion_and_bad_jobs(self):
        for group, key, bad in (('Unit', 'NeedDaemonReload', 0), ('Service', 'MainPID', True),
                ('Service', 'ControlPID', -1), ('Service', 'MainPID', 2**32),
                ('Unit', 'Id', 'bad\x00name'), ('Unit', 'Id', '\ud800'),
                ('Unit', 'Job', [True, '/']), ('Unit', 'Job', [0, '/bad//path']),
                ('Unit', 'Job', [0, '/bad-path']), ('Unit', 'Job', [0, 'relative']),
                ('Unit', 'Job', [0]), ('Unit', 'Job', '0 /'), ('Unit', 'TriggeredBy', 'socket')):
            data = values(); data[key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaisesRegex(core.OperatorError, '^MAINTENANCE_SHAPE$'):
                m.parse_properties(reply(group, data), group)

    def test_target_allowlist_precedes_child(self):
        for group in ('Manager', '../Unit', None, []):
            with patch.object(m.subprocess, 'Popen') as popen:
                with self.assertRaisesRegex(core.OperatorError, '^MAINTENANCE_TARGET$'):
                    m._query(group)
                popen.assert_not_called()

    def run_query(self, chunks, group='Unit', code=0, ready=True, wait=None, running=False):
        self.proc = Mock()
        self.proc.stdout.fileno.return_value = 19
        self.proc.poll.return_value = None if running else code
        self.proc.wait.side_effect = wait or [code, code]
        selector = Mock(); selector.select.return_value = [(1, 1)] if ready else []
        with patch.object(m.subprocess, 'Popen', return_value=self.proc) as popen, patch.object(
                m.selectors, 'DefaultSelector') as factory, patch.object(m.os, 'read', side_effect=chunks), patch.object(
                m.time, 'monotonic', return_value=10):
            factory.return_value.__enter__.return_value = selector
            try:
                return m._query(group)
            finally:
                self.command = popen.call_args

    def test_transport_is_fixed_read_only_clean_and_closed(self):
        for group in ('Unit', 'Service'):
            self.assertEqual(self.run_query([b'ok', b''], group), b'ok')
            args, kw = self.command
            self.assertEqual(args[0], [m.service.BUSCTL, '--system', '--json=short', '--no-pager',
                '--timeout=5', '--auto-start=no', '--allow-interactive-authorization=no', 'get-property',
                'org.freedesktop.systemd1', m.OBJECT, 'org.freedesktop.systemd1.' + group,
                *(name for name, _ in m.GROUPS[group])])
            self.assertEqual(kw, dict(stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, shell=False, close_fds=True,
                cwd='/', env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}))
            self.proc.stdout.close.assert_called_once_with()

    def test_transport_bounds_timeout_failure_kill_and_close(self):
        for chunks, code, ready, expected in (([b'x' * (m.MAX_REPLY + 1)], 0, True, 'MAINTENANCE_SIZE'),
                ([b''], 1, True, 'MAINTENANCE_QUERY'), ([], 0, False, 'MAINTENANCE_TIMEOUT')):
            with self.subTest(expected=expected), self.assertRaisesRegex(core.OperatorError, '^' + expected + '$'):
                self.run_query(chunks, code=code, ready=ready, running=True)
            self.proc.kill.assert_called_once_with()
            self.proc.stdout.close.assert_called_once_with()
        with self.assertRaisesRegex(core.OperatorError, '^MAINTENANCE_TIMEOUT$'):
            self.run_query([b''], wait=[subprocess.TimeoutExpired('PRIVATE', 5), 0], running=True)
        self.proc.kill.assert_called_once_with()
        self.proc.stdout.close.assert_called_once_with()

    def test_transport_spawn_and_cleanup_errors_are_sanitized(self):
        with patch.object(m.subprocess, 'Popen', side_effect=OSError(errno.EIO, 'PRIVATE_SECRET')):
            with self.assertRaisesRegex(core.OperatorError, '^MAINTENANCE_QUERY$'):
                m._query('Unit')
        with self.assertRaisesRegex(core.OperatorError, '^MAINTENANCE_CLEANUP$'):
            self.run_query([b''], wait=[0, subprocess.TimeoutExpired('PRIVATE_SECRET', 1)])
        self.proc.stdout.close.assert_called_once_with()

    def test_persistent_mask_never_follows_symlink_or_reads_payload(self):
        fake = MaskFS()
        with patch.object(m, 'os', fake), patch.object(m.paths, '_null_anchor_at', return_value=('null',)) as null:
            found, token = m._mask_at(10)
        self.assertTrue(found)
        self.assertIn('/dev/null', token)
        null.assert_called_once_with(10)
        self.assertEqual(fake.open.call_count, 3)
        self.assertEqual(fake.close.call_count, 3)
        for call in fake.open.call_args_list:
            self.assertNotIn(call.args[0], (m.UNIT, 'null'))
            self.assertTrue(call.args[1] & fake.O_NOFOLLOW)

    def test_missing_regular_empty_and_other_symlinks_are_not_accepted_mask(self):
        for leaf, target in ((None, ''), (metadata(stat.S_IFREG | 0o644), ''),
                (metadata(stat.S_IFLNK | 0o777), '../null'),
                (metadata(stat.S_IFLNK | 0o777), '/run/systemd/system/PRIVATE_SECRET')):
            fake = MaskFS(); fake.leaf, fake.target = leaf, target
            with patch.object(m, 'os', fake), patch.object(m.paths, '_null_anchor_at') as null:
                self.assertFalse(m._mask_at(10)[0])
                null.assert_not_called()
            self.assertEqual(fake.close.call_count, fake.open.call_count)

    def test_mask_owners_modes_types_and_null_anchor_fail_closed(self):
        for bad in (metadata(stat.S_IFLNK | 0o777, st_uid=123), metadata(stat.S_IFLNK | 0o777, st_gid=123),
                    metadata(stat.S_IFREG | 0o666), metadata(stat.S_IFIFO | 0o600), metadata()):
            fake = MaskFS(); fake.leaf = bad
            with patch.object(m, 'os', fake), self.assertRaisesRegex(core.OperatorError, '^FS_METADATA$'):
                m._mask_at(10)
            self.assertEqual(fake.close.call_count, fake.open.call_count)
        fake = MaskFS()
        with patch.object(m, 'os', fake), patch.object(m.paths, '_null_anchor_at',
                side_effect=core.OperatorError('PY_NULL_METADATA')), self.assertRaisesRegex(core.OperatorError, '^PY_NULL_METADATA$'):
            m._mask_at(10)
        self.assertEqual(fake.close.call_count, fake.open.call_count)

    def test_unsafe_parent_and_symlinked_parent_fail_before_traversal(self):
        for fd in (10, 11, 12, 13):
            for bad in (metadata(st_uid=123), metadata(stat.S_IFDIR | 0o777), metadata(stat.S_IFLNK | 0o777)):
                fake = MaskFS(); fake.nodes[fd] = bad
                with patch.object(m, 'os', fake), self.assertRaisesRegex(core.OperatorError, '^FS_METADATA$'):
                    m._mask_at(10)
                self.assertEqual(fake.close.call_count, fake.open.call_count)

    def test_mask_replacement_disappearance_appearance_and_target_drift(self):
        for change in ('inode', 'disappear', 'appear', 'target'):
            fake = MaskFS()
            original = fake.lookup
            seen = 0
            def lookup(name, **kw):
                nonlocal seen
                if name == m.UNIT:
                    seen += 1
                    if change == 'appear' and seen == 1:
                        raise FileNotFoundError(errno.ENOENT, 'private')
                    if seen == 2:
                        if change == 'inode':
                            fake.leaf = metadata(stat.S_IFLNK | 0o777, st_ino=99)
                        if change == 'disappear':
                            fake.leaf = None
                return original(name, **kw)
            fake.stat.side_effect = lookup
            if change == 'target':
                fake.readlink.side_effect = ['/dev/null', '/other']
            with patch.object(m, 'os', fake), patch.object(m.paths, '_null_anchor_at', return_value=('null',)):
                with self.assertRaises((core.OperatorError, FileNotFoundError)):
                    m._mask_at(10)
            self.assertEqual(fake.close.call_count, fake.open.call_count)

    def test_parent_name_or_descriptor_drift_is_rejected(self):
        for method in ('stat', 'fstat'):
            fake = MaskFS(); fake.leaf = None
            original = fake.lookup if method == 'stat' else lambda fd: fake.nodes[fd]
            seen = 0
            def read(*args, **kw):
                nonlocal seen
                result = original(*args, **kw)
                if args[0] == ('etc' if method == 'stat' else 11):
                    seen += 1
                    if seen == 2:
                        return metadata(st_ino=999)
                return result
            getattr(fake, method).side_effect = read
            with patch.object(m, 'os', fake), self.assertRaisesRegex(core.OperatorError, '^FS_CHANGED$'):
                m._mask_at(10)
            self.assertEqual(fake.close.call_count, fake.open.call_count)

    def test_root_descriptor_closes_on_leaf_read_failure(self):
        fake = MaskFS()
        with patch.object(m, 'os', fake), patch.object(m, '_mask_at', side_effect=OSError(errno.EIO, 'private')):
            with self.assertRaises(OSError):
                m._read_mask()
        fake.close.assert_called_once_with(10)


@unittest.skipUnless(sys.platform == 'linux', 'requires Linux no-follow descriptor syscalls')
class MaintenanceMaskNativeTests(unittest.TestCase):
    @contextmanager
    def fixture(self):
        # Only a disposable private tree. Never create a mask in /etc or query DBus.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); parent = root / 'etc/systemd/system'; parent.mkdir(parents=True)
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            # Normalize owner metadata for an unprivileged CI fixture; actual
            # descriptor traversal, file types/modes and symlink reads are native.
            def root_owned(value):
                return SimpleNamespace(**{key: getattr(value, key) for key in (
                    'st_mode', 'st_dev', 'st_ino', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')},
                    st_uid=0, st_gid=0)
            real_stat, real_fstat = os.stat, os.fstat
            def fixture_stat(*args, **kwargs):
                return root_owned(real_stat(*args, **kwargs))
            try:
                with patch.object(m.os, 'fstat', side_effect=lambda fd: root_owned(real_fstat(fd))), patch.object(
                        m.os, 'stat', side_effect=fixture_stat), patch.object(
                        m.paths, '_null_anchor_at', return_value=('fixture-only-null',)):
                    yield parent / m.UNIT, fd
            finally:
                os.close(fd)

    def test_native_absent_regular_and_exact_symlink(self):
        with self.fixture() as (leaf, fd):
            self.assertFalse(m._mask_at(fd)[0])
            leaf.write_bytes(b'')
            self.assertFalse(m._mask_at(fd)[0])
            leaf.unlink(); leaf.symlink_to('/dev/null')
            self.assertTrue(m._mask_at(fd)[0])
            leaf.unlink(); leaf.symlink_to('/other')
            self.assertFalse(m._mask_at(fd)[0])

    def test_native_fifo_and_parent_symlink_rejected(self):
        with self.fixture() as (leaf, fd):
            os.mkfifo(leaf, 0o600)
            with self.assertRaisesRegex(core.OperatorError, '^FS_METADATA$'):
                m._mask_at(fd)
            leaf.unlink()
            parent = leaf.parent; moved = parent.with_name('elsewhere')
            parent.rename(moved); parent.symlink_to(moved, target_is_directory=True)
            with self.assertRaisesRegex(core.OperatorError, '^FS_METADATA$'):
                m._mask_at(fd)


if __name__ == '__main__':
    unittest.main()
