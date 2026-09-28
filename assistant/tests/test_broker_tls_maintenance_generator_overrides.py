"""Sensitive PID 1 environment is never logged, serialized or sent to systemd."""
from contextlib import contextmanager, ExitStack
from dataclasses import FrozenInstanceError
import errno
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
from siem.rbac.broker_tls import operator_maintenance_generator_overrides as m


BOOT = '00000000-0000-0000-0000-000000000001'


def metadata(**changes):
    values = dict(st_mode=stat.S_IFREG | 0o400, st_dev=7, st_ino=9,
                  st_uid=0, st_gid=0, st_size=0)
    values.update(changes)
    return SimpleNamespace(**values)


class GeneratorOverrideTests(unittest.TestCase):
    def error(self, code, call):
        with self.assertRaisesRegex(core.OperatorError, '^' + code + '$'):
            call()

    @contextmanager
    def linux_symbols(self):
        with ExitStack() as stack:
            for name, value in (('O_NOFOLLOW', 131072), ('O_CLOEXEC', 524288),
                                ('O_DIRECTORY', 65536), ('O_NONBLOCK', 2048)):
                stack.enter_context(patch.object(m.os, name, getattr(os, name, value),
                                                 create=True))
            stack.enter_context(patch.object(m.os, 'major', return_value=0, create=True))
            stack.enter_context(patch.object(m.os, 'minor', return_value=7, create=True))
            yield

    def test_fixed_target_names_and_no_public_arguments(self):
        self.assertEqual(m.OVERRIDES, (b'SYSTEMD_GENERATOR_PATH',
                                       b'SYSTEMD_ENVIRONMENT_GENERATOR_PATH'))
        self.assertEqual(str(inspect.signature(m.observe_initial_generator_path_overrides)), '()')

    def test_initial_environment_without_override_names(self):
        self.assertIsNone(m._parse_initial(b'PATH=/usr/bin\0HOME=/\0LANG=C\0'))
        self.assertIsNone(m._parse_initial(b'container=demo\0PATH=x=y\0'))
        self.assertIsNone(m._parse_initial(b'PATH=/usr/bin\0HOME=/'))

    def test_both_override_names_fail_without_echoing_values(self):
        for name in m.OVERRIDES:
            secret = b'SENSITIVE-NEVER-EMIT'
            with self.assertRaises(core.OperatorError) as raised:
                m._parse_initial(b'PATH=x\0' + name + b'=' + secret + b'\0')
            self.assertEqual(str(raised.exception), 'GENERATOR_PATH_OVERRIDE_PRESENT')
            self.assertNotIn(secret.decode(), str(raised.exception))

    def test_prefixes_case_and_values_are_not_false_overrides(self):
        m._parse_initial(b'SYSTEMD_GENERATOR_PATH_EXTRA=1\0'
                         b'systemd_generator_path=2\0'
                         b'OTHER=SYSTEMD_GENERATOR_PATH=/bad\0')

    def test_duplicate_override_is_rejected(self):
        self.error('GENERATOR_INITIAL_ENV_DUPLICATE', lambda: m._parse_initial(
            b'SYSTEMD_GENERATOR_PATH=a\0SYSTEMD_GENERATOR_PATH=b\0'))

    def test_initial_environment_malformed_fails(self):
        for raw in (b'', b'\0', b'A=1\0\0', b'=x\0', b'bad name=x\0',
                    b'9VAR=x\0', b'X=1\0NO_EQUAL\0', bytearray(b'A=1\0')):
            self.error('GENERATOR_INITIAL_ENV_FORMAT', lambda raw=raw:
                       m._parse_initial(raw))

    def test_initial_environment_bounds(self):
        self.error('GENERATOR_INITIAL_ENV_FORMAT', lambda: m._parse_initial(
            b'A=' + b'x' * m.MAX_ENV_BYTES + b'\0'))
        with patch.object(m, 'MAX_ENV_ENTRIES', 2):
            self.error('GENERATOR_INITIAL_ENV_COUNT', lambda: m._parse_initial(
                b'A=1\0B=2\0C=3\0'))

    @contextmanager
    def environ(self, value=b'PATH=/usr/bin\0', before=None, chunks=None):
        before = metadata() if before is None else before
        with self.linux_symbols(), ExitStack() as stack:
            f = {}
            mocks = dict(stat=Mock(return_value=before),
                         fstat=Mock(return_value=before),
                         open=Mock(return_value=17), close=Mock(),
                         read=Mock(side_effect=[value, b''] if chunks is None else chunks))
            for name, obj in mocks.items():
                f[name] = stack.enter_context(patch.object(m.os, name, obj))
            stack.enter_context(patch.object(m.census, '_metadata'))
            yield f

    def test_fixed_proc_leaf_read_and_cleanup(self):
        with self.environ() as f:
            self.assertEqual(m._environ_at(11, 7, lambda: None), b'PATH=/usr/bin\0')
            self.assertEqual(f['open'].call_args.args[0], 'environ')
            self.assertEqual(f['open'].call_args.kwargs, {'dir_fd': 11})
            flags = f['open'].call_args.args[1]
            for value in (m.os.O_RDONLY, m.os.O_NOFOLLOW, m.os.O_NONBLOCK,
                          m.os.O_CLOEXEC):
                self.assertEqual(flags & value, value)
            f['close'].assert_called_once_with(17)

    def test_proc_leaf_wrong_owner_or_size_fails_before_open(self):
        for before, code in ((metadata(st_uid=1), 'GENERATOR_INITIAL_ENV_METADATA'),
                             (metadata(st_gid=1), 'GENERATOR_INITIAL_ENV_METADATA'),
                             (metadata(st_size=m.MAX_ENV_BYTES + 1),
                              'GENERATOR_INITIAL_ENV_METADATA')):
            with self.environ(before=before) as f:
                self.error(code, lambda: m._environ_at(11, 7, lambda: None))
                f['open'].assert_not_called()

    def test_proc_leaf_symlink_is_rejected_before_open(self):
        metadata_check = m.census._metadata
        with self.environ(before=metadata(st_mode=stat.S_IFLNK | 0o777)) as f, \
             patch.object(m.census, '_metadata', side_effect=metadata_check):
            self.error('CENSUS_METADATA', lambda: m._environ_at(11, 7, lambda: None))
            f['open'].assert_not_called()

    def test_proc_leaf_changed_metadata_or_oversize_fails_closed(self):
        with self.environ() as f:
            f['fstat'].side_effect = [metadata(), metadata(st_ino=10)]
            self.error('GENERATOR_INITIAL_ENV_CHANGED',
                       lambda: m._environ_at(11, 7, lambda: None))
            f['close'].assert_called_once_with(17)
        with patch.object(m, 'MAX_ENV_BYTES', 5), self.environ(chunks=[b'ABCDEF']) as f:
            self.error('GENERATOR_INITIAL_ENV_SIZE',
                       lambda: m._environ_at(11, 7, lambda: None))
            f['close'].assert_called_once_with(17)

    def test_proc_leaf_read_error_closes_descriptor(self):
        with self.environ(chunks=[OSError(errno.EIO, 'secret')]) as f:
            with self.assertRaises(OSError):
                m._environ_at(11, 7, lambda: None)
            f['close'].assert_called_once_with(17)

    def test_proc_leaf_checkpoint_failure_closes_descriptor(self):
        calls = [0]
        def check():
            calls[0] += 1
            if calls[0] == 2:
                raise core.OperatorError('GENERATOR_INITIAL_ENV_TIMEOUT')
        with self.environ() as f:
            self.error('GENERATOR_INITIAL_ENV_TIMEOUT',
                       lambda: m._environ_at(11, 7, check))
            f['close'].assert_called_once_with(17)

    def test_snapshot_uses_fixed_pid1_and_returns_only_private_hashes(self):
        tree = Mock()
        tree.read.side_effect = [(BOOT.encode() + b'\n', ('boot',)),
                                 (b'private mount', ('mount',))]
        tree.directory.side_effect = [10, 11]
        tree.verify.return_value = ('verified',)
        with self.linux_symbols(), patch.object(m.census, '_proc_device', return_value=(0, 7)), \
             patch.object(m.os, 'fstat', return_value=metadata()), \
             patch.object(m.census, '_small', side_effect=[b'stat', b'status']), \
             patch.object(m.census, '_stat_record', return_value=(123, False, False)), \
             patch.object(m.census, '_status', return_value=((0,) * 4, (0,) * 4, 1)), \
             patch.object(m.census, '_exe', return_value='/usr/lib/systemd/systemd'), \
             patch.object(m, '_environ_at', return_value=b'PATH=secret\0') as environ, \
             patch.object(m.cg, '_boot', return_value=BOOT):
            result = m._snapshot(tree, 44, 100, lambda: None)
        environ.assert_called_once_with(11, 7, unittest.mock.ANY)
        self.assertEqual(result[:2], (BOOT, 123))
        self.assertNotIn(b'secret', repr(result).encode())
        self.assertNotIn('/usr/lib/systemd/systemd', repr(result))
        self.assertEqual(tree.read.call_args_list[1].args[0], ('proc', '44', 'mountinfo'))

    def test_snapshot_rejects_nonroot_or_missing_exe(self):
        tree = Mock()
        tree.read.side_effect = [(BOOT.encode() + b'\n', ()), (b'mount', ())]
        tree.directory.side_effect = [10, 11]
        with self.linux_symbols(), patch.object(m.census, '_proc_device', return_value=(0, 7)), \
             patch.object(m.os, 'fstat', return_value=metadata()), \
             patch.object(m.census, '_small', side_effect=[b'stat', b'status']), \
             patch.object(m.census, '_stat_record', return_value=(123, False, False)), \
             patch.object(m.census, '_status', return_value=((0, 1, 0, 0), (0,) * 4, 1)), \
             patch.object(m.cg, '_boot', return_value=BOOT), \
             patch.object(m, '_environ_at') as environ:
            self.error('GENERATOR_PID1_IDENTITY',
                       lambda: m._snapshot(tree, 44, 100, lambda: None))
            environ.assert_not_called()

    def test_snapshot_rejects_wrong_proc_mount_before_sensitive_read(self):
        tree = Mock()
        tree.read.side_effect = [(BOOT.encode() + b'\n', ()), (b'mount', ())]
        tree.directory.return_value = 10
        with self.linux_symbols(), patch.object(m.census, '_proc_device',
                                                 return_value=(0, 99)), \
             patch.object(m.os, 'fstat', return_value=metadata()), \
             patch.object(m.cg, '_boot', return_value=BOOT), \
             patch.object(m, '_environ_at') as environ:
            self.error('GENERATOR_PROC_DEVICE',
                       lambda: m._snapshot(tree, 44, 100, lambda: None))
            environ.assert_not_called()

    def test_snapshot_rejects_missing_pid1_executable_before_sensitive_read(self):
        tree = Mock()
        tree.read.side_effect = [(BOOT.encode() + b'\n', ()), (b'mount', ())]
        tree.directory.side_effect = [10, 11]
        with self.linux_symbols(), patch.object(m.census, '_proc_device',
                                                 return_value=(0, 7)), \
             patch.object(m.os, 'fstat', return_value=metadata()), \
             patch.object(m.census, '_small', side_effect=[b'stat', b'status']), \
             patch.object(m.census, '_stat_record', return_value=(123, False, False)), \
             patch.object(m.census, '_status', return_value=((0,) * 4, (0,) * 4, 1)), \
             patch.object(m.census, '_exe', return_value=None), \
             patch.object(m.cg, '_boot', return_value=BOOT), \
             patch.object(m, '_environ_at') as environ:
            self.error('GENERATOR_PID1_EXE',
                       lambda: m._snapshot(tree, 44, 100, lambda: None))
            environ.assert_not_called()

    @contextmanager
    def observer(self):
        with self.linux_symbols(), ExitStack() as stack:
            stack.enter_context(patch.object(m.fs, '_platform'))
            stack.enter_context(patch.object(m.time, 'CLOCK_BOOTTIME', 7, create=True))
            stack.enter_context(patch.object(m.time, 'clock_gettime_ns', create=True))
            stack.enter_context(patch.object(m.os, 'supports_dir_fd', {os.readlink}))
            f = dict(clock=Mock(return_value=1000), snapshot=Mock(
                return_value=(BOOT, 123, (b'SENSITIVE-NEVER-EMIT',))), open=Mock(return_value=17),
                close=Mock(), tree=Mock())
            stack.enter_context(patch.object(m.time, 'clock_gettime_ns', f['clock']))
            stack.enter_context(patch.object(m, '_snapshot', f['snapshot']))
            stack.enter_context(patch.object(m.os, 'open', f['open']))
            stack.enter_context(patch.object(m.os, 'close', f['close']))
            stack.enter_context(patch.object(m.cg, '_Tree', return_value=f['tree']))
            yield f

    def test_public_result_is_immutable_and_never_an_authorization(self):
        with self.observer() as f:
            result = m.observe_initial_generator_path_overrides()
            self.assertEqual(f['snapshot'].call_count, 2)
            f['tree'].verify.assert_called_once()
            f['close'].assert_called_once_with(17)
        self.assertTrue(result.procfs_initial_environment_no_path_override_observed)
        self.assertNotIn('SENSITIVE-NEVER-EMIT', repr(result))
        for name in ('pid1_is_installed_systemd_proven', 'current_process_environment_proven',
                     'effective_search_paths_proven', 'compiled_vendor_paths_proven',
                     'generator_selection_proven', 'atomic_snapshot_proven',
                     'continuous_control_proven', 'mutation_authorized', 'startup_authorized'):
            self.assertIs(getattr(result, name), False)
        self.assertTrue(result.review_required)
        with self.assertRaises(FrozenInstanceError):
            result.startup_authorized = True

    def test_public_observer_rejects_drift_and_closes_root(self):
        with self.observer() as f:
            f['snapshot'].side_effect = [(BOOT, 123, (b'a',)), (BOOT, 123, (b'b',))]
            self.error('GENERATOR_INITIAL_ENV_CHANGED',
                       m.observe_initial_generator_path_overrides)
            f['close'].assert_called_once_with(17)

    def test_public_observer_rejects_platform_and_caller_change(self):
        with self.observer() as f, patch.object(m.os, 'supports_dir_fd', set()):
            self.error('GENERATOR_INITIAL_ENV_PLATFORM',
                       m.observe_initial_generator_path_overrides)
            f['open'].assert_not_called()
        with self.observer(), patch.object(m.threading, 'get_native_id',
                                           side_effect=chain([1], repeat(2))):
            self.error('GENERATOR_INITIAL_ENV_CALLER',
                       m.observe_initial_generator_path_overrides)

    def test_public_observer_rejects_timeout_and_cleanup_failure(self):
        with self.observer() as f:
            f['clock'].side_effect = chain([1000, 1000, 1000 + m.MAX_WINDOW_NS],
                                           repeat(1000 + m.MAX_WINDOW_NS))
            self.error('GENERATOR_INITIAL_ENV_TIMEOUT',
                       m.observe_initial_generator_path_overrides)
        with self.observer() as f:
            f['close'].side_effect = OSError(errno.EIO, 'secret')
            self.error('FS_IO', m.observe_initial_generator_path_overrides)

    def test_public_observer_sanitizes_native_error(self):
        with self.observer() as f:
            f['snapshot'].side_effect = PermissionError(errno.EACCES, 'secret')
            self.error('FS_ACCESS', m.observe_initial_generator_path_overrides)
            f['close'].assert_called_once_with(17)

    def test_public_observer_never_runs_systemd_or_uses_caller_environment(self):
        from siem.rbac.broker_tls import operator_maintenance_control as control
        source = inspect.getsource(m)
        for forbidden in ('subprocess', 'os.system', 'os.environ', 'eval(', 'exec('):
            self.assertNotIn(forbidden, source)
        self.assertNotIn('generator_overrides', inspect.getsource(control))


@unittest.skipUnless(sys.platform == 'linux', 'Linux descriptor-relative fixture')
class GeneratorOverrideNativeTests(unittest.TestCase):
    def test_disposable_proc_leaf_read_has_no_side_effect_or_fd_leak(self):
        with tempfile.TemporaryDirectory() as directory:
            leaf = Path(directory, 'environ')
            leaf.write_bytes(b'PATH=/usr/bin\0')
            leaf.chmod(0o400)  # Match the observer's non-writable procfs-leaf policy.
            before = len(os.listdir('/proc/self/fd'))
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                original_stat, original_fstat = os.stat, os.fstat
                def root_owner(value):
                    names = ('st_mode', 'st_dev', 'st_ino', 'st_size', 'st_uid', 'st_gid')
                    data = {name: getattr(value, name) for name in names}
                    data['st_uid'] = data['st_gid'] = 0
                    return SimpleNamespace(**data)
                with patch.object(m.os, 'stat', side_effect=lambda *args, **kw:
                                  root_owner(original_stat(*args, **kw))), \
                     patch.object(m.os, 'fstat', side_effect=lambda *args, **kw:
                                  root_owner(original_fstat(*args, **kw))):
                    for _ in range(3):
                        self.assertEqual(m._environ_at(fd, os.fstat(fd).st_dev,
                                                        lambda: None), b'PATH=/usr/bin\0')
            finally:
                os.close(fd)
            self.assertEqual(len(os.listdir('/proc/self/fd')), before)


if __name__ == '__main__':
    unittest.main()
