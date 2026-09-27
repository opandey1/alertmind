"""Private controller fixtures; no real service or package command is run."""
from contextlib import contextmanager, ExitStack
from dataclasses import asdict, FrozenInstanceError, replace
import json
import os
from pathlib import Path
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
from siem.rbac.broker_tls import operator_maintenance_control as c
import test_broker_tls_maintenance_manager as manager_tests
import test_broker_tls_maintenance_lock as lock_tests
import test_broker_tls_maintenance_packages as package_tests

BOOT = manager_tests.BOOT


class MaintenanceControlTests(unittest.TestCase):
    @contextmanager
    def fixture(self):
        events = []
        observations = {
            'namespace': c.namespaces.MaintenanceNamespaceObservation(BOOT, 1000, 0),
            'cooperative': c.cooperative.MaintenanceLockObservation(),
            'package': c.packages.MaintenancePackageLockObservation(),
        }
        handles = {name: SimpleNamespace(checkpoint=Mock(return_value=value))
                   for name, value in observations.items()}
        f = dict(events=events, handles=handles, acquire_error={}, exit_error={}, exit_hook={},
                 boundary=Mock(return_value=None), clock=Mock(return_value=1_000_000_000),
                 captured=[], active=[])

        @contextmanager
        def held(name):
            events.append('enter:' + name)
            if name in f['acquire_error']:
                raise f['acquire_error'][name]
            f['active'].append(name)
            try:
                yield handles[name]
                events.append('exit-check:' + name)
                if name in f['exit_error']:
                    raise f['exit_error'][name]
            finally:
                events.append('close:' + name)
                f['active'].remove(name)
                if name in f['exit_hook']:
                    f['exit_hook'][name]()

        def disk(root, *, checkpoint):
            self.assertEqual(root, 91)
            self.assertEqual(f['active'], ['namespace', 'cooperative', 'package'])
            f['captured'].append(checkpoint)
            checkpoint()
            events.append('disk')
            return c.disk.MaintenanceMaskResult(True)

        def manager(*, checkpoint):
            self.assertEqual(f['active'], ['namespace', 'cooperative', 'package'])
            self.assertEqual(checkpoint, f['captured'][0])
            checkpoint()
            events.append('manager')
            return c.manager.MaintenanceManagerResult(BOOT, 0, 40)

        with ExitStack() as stack:
            for target, name, mock in (
                (c.namespaces, 'hold_maintenance_namespaces', Mock(side_effect=lambda: held('namespace'))),
                (c.cooperative, 'hold_maintenance_lock', Mock(side_effect=lambda: held('cooperative'))),
                (c.packages, 'hold_maintenance_package_locks', Mock(side_effect=lambda: held('package'))),
                (c, '_clock', f['clock']), (c.fs, '_platform', Mock()),
                (c.disk, '_prepare_at', Mock(side_effect=disk)),
                (c.manager, '_sequence', Mock(side_effect=manager)),
                (c.effects, '_check', Mock(return_value=None)),
                (c.os, 'open', Mock(return_value=91)),
                (c.os, 'close', Mock(side_effect=lambda fd: events.append('close:root'))),
            ):
                f[name] = stack.enter_context(patch.object(target, name, mock))
            for name, value in (('O_DIRECTORY', 1), ('O_NOFOLLOW', 2), ('O_CLOEXEC', 4)):
                stack.enter_context(patch.object(c.os, name, value, create=True))
            stack.enter_context(patch.object(c.time, 'CLOCK_BOOTTIME', 7, create=True))
            stack.enter_context(patch.object(c.time, 'clock_gettime_ns', create=True))
            yield f
        self.assertEqual(f['active'], [])

    def run_private(self, f):
        return c._inhibit(boundary_checkpoint=f['boundary'])

    def assert_error(self, code, callback):
        with self.assertRaises(core.OperatorError) as caught:
            callback()
        self.assertEqual(str(caught.exception), code)

    def test_public_entry_cannot_be_enabled_by_environment_or_receipt(self):
        with (patch.dict(os.environ, {'ALERTMIND_MAINTENANCE_APPROVED': '1'}),
              patch.object(c, '_inhibit') as inhibit, patch.object(c.os, 'open') as opened):
            self.assert_error('CONTROL_NOT_RELEASED', c.run_maintenance_inhibition)
            with self.assertRaises(TypeError):
                c.run_maintenance_inhibition(approved=True)
        inhibit.assert_not_called()
        opened.assert_not_called()

    def test_acquisition_sequence_and_reverse_cleanup_are_fixed(self):
        with self.fixture() as f:
            result = self.run_private(f)
            self.assertEqual(f['events'], ['enter:namespace', 'enter:cooperative', 'enter:package',
                'disk', 'manager', 'close:root', 'exit-check:package', 'close:package',
                'exit-check:cooperative', 'close:cooperative', 'exit-check:namespace', 'close:namespace'])
            for handle in f['handles'].values():
                self.assertGreaterEqual(handle.checkpoint.call_count, 6)
            self.assertEqual(result.boot_id, BOOT)
            self.assertEqual(result.process_leaders_examined, 40)

    def test_result_describes_released_window_and_never_authorizes_more_work(self):
        with self.fixture() as f:
            result = self.run_private(f)
        data = asdict(result)
        self.assertTrue(data['controls_released'])
        self.assertTrue(data['review_required'])
        self.assertTrue(data['cooperative_lock_held_during_sequence'])
        for key, value in data.items():
            if key.endswith(('_proven', '_authorized', '_excluded')):
                self.assertIs(value, False, key)
        self.assertNotIn('checkpoint', repr(result))
        with self.assertRaises(FrozenInstanceError):
            result.startup_authorized = True

    def test_checkpoint_needs_callable_and_none_not_approval_boolean(self):
        with self.fixture() as f:
            for invalid in (True, None, 'approved'):
                self.assert_error('CONTROL_BOUNDARY', lambda: c._inhibit(boundary_checkpoint=invalid))
            f['boundary'].return_value = True
            self.assert_error('CONTROL_BOUNDARY', lambda: self.run_private(f))
            f['hold_maintenance_namespaces'].assert_not_called()
            f['_prepare_at'].assert_not_called()

    def test_boundary_exception_is_sanitized_before_acquisition(self):
        with self.fixture() as f:
            f['boundary'].side_effect = ValueError('PRIVATE downtime detail')
            self.assert_error('CONTROL_BOUNDARY', lambda: self.run_private(f))
            self.assertEqual(f['events'], [])

    def test_each_acquisition_failure_unwinds_only_acquired_resources(self):
        names = ['namespace', 'cooperative', 'package']
        for index, name in enumerate(names):
            with self.subTest(name=name), self.fixture() as f:
                f['acquire_error'][name] = core.OperatorError('SYNTHETIC_BUSY')
                self.assert_error('SYNTHETIC_BUSY', lambda: self.run_private(f))
                closes = [e for e in f['events'] if e.startswith('close:')]
                self.assertEqual(closes, ['close:' + n for n in reversed(names[:index])])
                f['_prepare_at'].assert_not_called()
                f['_sequence'].assert_not_called()

    def test_each_checkpoint_failure_stops_before_disk(self):
        for name in ('namespace', 'cooperative', 'package'):
            with self.subTest(name=name), self.fixture() as f:
                f['handles'][name].checkpoint.side_effect = core.OperatorError('LOST_CONTROL')
                self.assert_error('LOST_CONTROL', lambda: self.run_private(f))
                f['_prepare_at'].assert_not_called()

    def test_observation_types_must_match_the_acquired_resource(self):
        for name in ('namespace', 'cooperative', 'package'):
            with self.subTest(name=name), self.fixture() as f:
                f['handles'][name].checkpoint.return_value = True
                self.assert_error('CONTROL_OBSERVATION', lambda: self.run_private(f))
                f['_prepare_at'].assert_not_called()

    def test_disk_failure_prevents_manager_and_unwinds_without_retry(self):
        with self.fixture() as f:
            f['_prepare_at'].side_effect = core.OperatorError('INHIBIT_SYNC')
            self.assert_error('INHIBIT_SYNC', lambda: self.run_private(f))
            f['_sequence'].assert_not_called()
            self.assertEqual(f['_prepare_at'].call_count, 1)
            self.assertEqual([e for e in f['events'] if e.startswith('close:')],
                             ['close:root', 'close:package', 'close:cooperative', 'close:namespace'])

    def test_disk_result_wrong_type_prevents_manager(self):
        with self.fixture() as f:
            f['_prepare_at'].side_effect = None
            f['_prepare_at'].return_value = {'directory_sync_completed': True}
            self.assert_error('CONTROL_DISK_RESULT', lambda: self.run_private(f))
            f['_sequence'].assert_not_called()

    def test_revocation_after_disk_prevents_manager(self):
        with self.fixture() as f:
            original = f['_prepare_at'].side_effect
            def disk(*a, **kw):
                result = original(*a, **kw)
                f['boundary'].side_effect = RuntimeError('PRIVATE revoked')
                return result
            f['_prepare_at'].side_effect = disk
            self.assert_error('CONTROL_BOUNDARY', lambda: self.run_private(f))
            f['_sequence'].assert_not_called()

    def test_manager_failure_preserves_disk_and_discards_result(self):
        with self.fixture() as f:
            f['_sequence'].side_effect = core.OperatorError('MANAGER_ACTION_TIMEOUT')
            self.assert_error('MANAGER_ACTION_TIMEOUT', lambda: self.run_private(f))
            self.assertEqual(f['_prepare_at'].call_count, 1)
            self.assertEqual(f['_sequence'].call_count, 1)
            self.assertEqual(f['events'].count('disk'), 1)

    def test_manager_result_type_and_boot_must_match_fresh_namespace(self):
        for item, code in ((True, 'CONTROL_MANAGER_RESULT'),
                           (c.manager.MaintenanceManagerResult('other-boot', 0, 1), 'CONTROL_BOOT')):
            with self.subTest(code=code), self.fixture() as f:
                f['_sequence'].side_effect = None
                f['_sequence'].return_value = item
                self.assert_error(code, lambda: self.run_private(f))

    def test_all_resource_exit_failures_discard_otherwise_successful_result(self):
        for name in ('package', 'cooperative', 'namespace'):
            with self.subTest(name=name), self.fixture() as f:
                f['exit_error'][name] = core.OperatorError('EXIT_FAILED')
                self.assert_error('EXIT_FAILED', lambda: self.run_private(f))
                self.assertEqual([e for e in f['events'] if e.startswith('close:')],
                                 ['close:root', 'close:package', 'close:cooperative', 'close:namespace'])

    def test_root_close_failure_discards_success_and_closes_controls(self):
        with self.fixture() as f:
            f['close'].side_effect = PermissionError('PRIVATE root descriptor')
            with self.assertRaises(core.OperatorError) as caught:
                self.run_private(f)
            self.assertNotIn('PRIVATE', str(caught.exception))
            self.assertIn('close:namespace', f['events'])

    def test_root_open_is_fixed_and_after_all_acquisitions(self):
        with self.fixture() as f:
            def opened(*args, **kwargs):
                self.assertEqual(f['active'], ['namespace', 'cooperative', 'package'])
                self.assertEqual(args, ('/', c.os.O_RDONLY | 1 | 2 | 4))
                self.assertEqual(kwargs, {})
                return 91
            f['open'].side_effect = opened
            self.run_private(f)
            f['open'].assert_called_once()

    def test_checkpoint_cannot_escape_body_lifetime(self):
        with self.fixture() as f:
            self.run_private(f)
            count = f['boundary'].call_count
            self.assert_error('CONTROL_CLOSED', f['captured'][0])
            self.assertEqual(count, f['boundary'].call_count)

    def test_pid_or_thread_drift_is_rejected(self):
        for target, name in ((c.os, 'getpid'), (c.threading, 'get_native_id')):
            with self.subTest(name=name), self.fixture() as f:
                with patch.object(target, name, side_effect=[50, 50, 51]):
                    self.assert_error('CONTROL_OWNER', lambda: self.run_private(f))
                f['_prepare_at'].assert_not_called()

    def test_clock_backwards_or_suspend_exhaustion_stops_before_acquisition(self):
        for value in (0, 31_000_000_000):
            with self.subTest(value=value), self.fixture() as f:
                f['clock'].side_effect = [1_000_000_000, value]
                self.assert_error('CONTROL_TIMEOUT', lambda: self.run_private(f))
                self.assertEqual(f['events'], [])

    def test_namespace_capture_elapsed_and_shape_are_checked(self):
        bad = [dict(captured_boottime_ms=999), dict(captured_boottime_ms=1001),
               dict(captured_boottime_ms=True), dict(window_elapsed_ms=-1),
               dict(window_elapsed_ms=1), dict(window_elapsed_ms=30001)]
        for change in bad:
            with self.subTest(change=change), self.fixture() as f:
                h = f['handles']['namespace'].checkpoint
                h.return_value = replace(h.return_value, **change)
                self.assert_error('CONTROL_NAMESPACE_TIME', lambda: self.run_private(f))
                f['_prepare_at'].assert_not_called()

    def test_namespace_boot_or_capture_change_aborts_acquisition(self):
        for changes in (dict(boot_id='new-boot'), dict(captured_boottime_ms=1001)):
            with self.subTest(changes=changes), self.fixture() as f:
                f['clock'].return_value = 1_001_000_000
                original = c.namespaces.MaintenanceNamespaceObservation(BOOT, 1001, 0)
                changed = replace(original, **(changes if 'boot_id' in changes else {'captured_boottime_ms': 1002}))
                f['clock'].side_effect = [1_000_000_000] + [1_003_000_000] * 100
                f['handles']['namespace'].checkpoint.side_effect = [original, changed]
                self.assert_error('CONTROL_NAMESPACE_CHANGED', lambda: self.run_private(f))
                f['_prepare_at'].assert_not_called()

    def test_namespace_elapsed_cannot_go_backwards(self):
        with self.fixture() as f:
            f['clock'].side_effect = [1_000_000_000] + [1_002_000_000] * 100
            h = f['handles']['namespace'].checkpoint
            h.side_effect = [replace(h.return_value, window_elapsed_ms=1), h.return_value]
            self.assert_error('CONTROL_NAMESPACE_TIME', lambda: self.run_private(f))

    def test_outer_deadline_is_not_silently_extended_to_manager_budget(self):
        with self.fixture() as f:
            original = f['_sequence'].side_effect
            def manager(**kwargs):
                result = original(**kwargs)
                f['clock'].return_value = 31_000_000_000
                return result
            f['_sequence'].side_effect = manager
            self.assert_error('CONTROL_TIMEOUT', lambda: self.run_private(f))
            self.assertEqual(c.MAX_WINDOW_NS, c.namespaces.MAX_WINDOW_NS)
            self.assertLess(c.MAX_WINDOW_NS, c.manager.MAX_SEQUENCE_NS)

    def test_cleanup_time_is_included_in_whole_window(self):
        with self.fixture() as f:
            original = f['close'].side_effect
            def close(fd):
                original(fd)
                f['clock'].return_value = 31_000_000_000
            f['close'].side_effect = close
            self.assert_error('CONTROL_TIMEOUT', lambda: self.run_private(f))

    def test_deadline_after_last_context_release_discards_result(self):
        with self.fixture() as f:
            f['exit_hook']['namespace'] = lambda: setattr(f['clock'], 'return_value', 31_000_000_000)
            self.assert_error('CONTROL_TIMEOUT', lambda: self.run_private(f))
            self.assertEqual(f['active'], [])

    def test_reentrant_checkpoint_refused_and_window_invalidated(self):
        with self.fixture() as f:
            def boundary():
                if f['captured']:
                    f['captured'][0]()
            f['boundary'].side_effect = boundary
            self.assert_error('CONTROL_BOUNDARY', lambda: self.run_private(f))
            self.assert_error('CONTROL_CLOSED', f['captured'][0])

    def test_keyboard_interrupt_is_preserved_and_resources_close(self):
        with self.fixture() as f:
            f['_sequence'].side_effect = KeyboardInterrupt()
            with self.assertRaises(KeyboardInterrupt):
                self.run_private(f)
            self.assertIn('close:namespace', f['events'])
            self.assert_error('CONTROL_CLOSED', f['captured'][0])

    def test_no_unmask_package_or_arbitrary_command_interface(self):
        with self.fixture() as f:
            with self.assertRaises(TypeError):
                c._inhibit(boundary_checkpoint=f['boundary'], command=['start'])
            f['_prepare_at'].assert_not_called()
            f['_sequence'].assert_not_called()

    def test_platform_failure_prevents_control_acquisition(self):
        with self.fixture() as f:
            f['_platform'].side_effect = core.OperatorError('FS_PLATFORM')
            self.assert_error('FS_PLATFORM', lambda: self.run_private(f))
            self.assertEqual(f['events'], [])

    def test_private_real_manager_sequence_uses_composed_checkpoint(self):
        real_sequence = c.manager._sequence
        # Manager fixture patches its native reads/actions, not the sequence.
        with manager_tests.MaintenanceManagerTests().fixture() as mf, self.fixture() as f:
            f['_sequence'].side_effect = real_sequence
            result = self.run_private(f)
            self.assertEqual(result.process_leaders_examined, 40)
            self.assertEqual(mf['events'], ['reload', 'stop', 'tree', 'census', 'tree'])
            self.assertGreater(f['handles']['package'].checkpoint.call_count, 20)


@unittest.skipUnless(sys.platform == 'linux' and os.uname().machine == 'x86_64',
                     'Linux disposable flock/OFD/child fixture; no real manager')
class NativeMaintenanceControlTests(unittest.TestCase):
    @contextmanager
    def held_fixtures(self):
        with (lock_tests.NativeMaintenanceLockTests().fixture() as (lr, lp),
              package_tests.NativeMaintenancePackageTests().fixture() as (pr, paths)):
            with c.cooperative._hold_at(lr) as lock, c.packages._hold_at(pr) as package:
                yield lock, package, lp, paths

    def run_child(self, lock, package, lockpath, paths, *, timeout=False):
        # Substitute ONLY in the test, after asserting the production request.
        # Child checks inherited FD identity and independent lock contention on
        # disposable files, never calls systemctl or actual package tools.
        code = '''import errno,fcntl,json,os,sys,time
for fd,device,inode in json.loads(sys.argv[1]):
    try: st=os.fstat(fd)
    except OSError as e:
        if e.errno != errno.EBADF: raise
    else:
        assert (st.st_dev,st.st_ino) != (device,inode), 'inherited held fd'
for index,path in enumerate(sys.argv[2:7]):
    fd=os.open(path,os.O_RDWR)
    try:
        if index == 0: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        else: fcntl.lockf(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except OSError as e:
        assert e.errno in (errno.EAGAIN,errno.EACCES)
    else: raise AssertionError('parent lock lost')
    finally: os.close(fd)
if sys.argv[7] == 'sleep': time.sleep(120)
'''
        real_spawn = subprocess.Popen
        children = []
        with tempfile.TemporaryFile() as extra:
            os.set_inheritable(extra.fileno(), True)  # Tests close_fds, not just CLOEXEC.
            fds = [lock._fd] + [r[2] for r in package._records] + [extra.fileno()]
            records = [(fd, os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in fds]
            def spawn(argv, **kwargs):
                self.assertEqual(argv, ['/usr/bin/systemctl', '--system', '--no-ask-password',
                                        '--no-pager', 'daemon-reload'])
                self.assertEqual(kwargs, dict(stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, shell=False, close_fds=True, cwd='/',
                    env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}))
                child = real_spawn([sys.executable, '-I', '-S', '-B', '-c', code, json.dumps(records),
                                    str(lockpath), *(str(p) for p in paths),
                                    'sleep' if timeout else 'exit'], **kwargs)
                children.append(child)
                return child
            def check():
                lock.checkpoint()
                package.checkpoint()
            try:
                with (patch.object(c.manager.subprocess, 'Popen', side_effect=spawn),
                      patch.object(c.manager.fs, '_platform'), patch.object(c.manager.fs, '_read_root_owned'),
                      patch.dict(c.manager.ACTION_SECONDS, {'reload': 2 if timeout else 10})):
                    if timeout:
                        with self.assertRaisesRegex(core.OperatorError, '^MANAGER_ACTION_TIMEOUT$'):
                            c.manager._run_action('reload', checkpoint=check)
                    else:
                        c.manager._run_action('reload', checkpoint=check)
                self.assertEqual(len(children), 1)
                self.assertIsNotNone(children[0].poll())
                check()
            finally:
                for child in children:
                    if child.poll() is None:
                        child.kill()
                    child.wait(timeout=5)

    def test_native_fixed_child_closes_fds_and_preserves_parent_locks(self):
        with self.held_fixtures() as args:
            self.run_child(*args)

    def test_native_timed_out_child_is_reaped_without_unlocking_parent(self):
        with self.held_fixtures() as args:
            self.run_child(*args, timeout=True)


if __name__ == '__main__':
    unittest.main()
