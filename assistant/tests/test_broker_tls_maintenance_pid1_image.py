"""Offline PID 1 image/dpkg-claim contract; no VM or package execution."""
from contextlib import contextmanager, ExitStack
from dataclasses import FrozenInstanceError
import errno
import inspect
from itertools import chain, repeat
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
from siem.rbac.broker_tls import operator_maintenance_pid1_image as m

BOOT = '00000000-0000-0000-0000-000000000001'
STATUS = (b'Package: other\nStatus: install ok installed\n\n'
          b'Package: systemd\nStatus: install ok installed\n'
          b'Version: 259.5-0ubuntu3.4\nArchitecture: amd64\n'
          b'Description: demo\n continued text\n')
LIST = b'/usr/lib/systemd\n/usr/lib/systemd/systemd\n'


def metadata(**changes):
    values = dict(st_mode=stat.S_IFREG | 0o400, st_dev=7, st_ino=9,
                  st_uid=0, st_gid=0, st_nlink=1, st_size=3,
                  st_mtime_ns=10, st_ctime_ns=11)
    values.update(changes)
    return SimpleNamespace(**values)


class Pid1ImageTests(unittest.TestCase):
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

    def test_fixed_paths_public_signature_and_no_live_wiring(self):
        self.assertEqual(m.IMAGE_PARTS, ('usr', 'lib', 'systemd', 'systemd'))
        self.assertEqual(m.STATUS_PARTS, ('var', 'lib', 'dpkg', 'status'))
        self.assertEqual(m.LIST_PARTS, ('var', 'lib', 'dpkg', 'info', 'systemd.list'))
        self.assertEqual(str(inspect.signature(m.observe_pid1_image_inventory)), '()')
        from siem.rbac.broker_tls import operator_maintenance_control as control
        self.assertNotIn('pid1_image', inspect.getsource(control))
        source = inspect.getsource(m)
        for forbidden in ('subprocess', 'os.system', 'os.environ', 'eval(', 'exec('):
            self.assertNotIn(forbidden, source)

    def test_dpkg_status_selects_one_installed_amd64_record(self):
        self.assertEqual(m._status_version(STATUS), '259.5-0ubuntu3.4')
        self.assertEqual(m._status_version(STATUS.replace(b'Package: systemd',
                                                   b'pAcKaGe: systemd')), '259.5-0ubuntu3.4')

    def test_dpkg_status_absent_duplicate_or_uninstalled_is_rejected(self):
        for raw in (STATUS.replace(b'Package: systemd', b'Package: not-systemd'),
                    STATUS + b'\nPackage: systemd\nStatus: install ok installed\n'
                    b'Version: 1\nArchitecture: amd64\n',
                    STATUS.replace(b'install ok installed', b'deinstall ok config-files')):
            self.error('PID1_DPKG_STATUS', lambda raw=raw: m._status_version(raw))

    def test_dpkg_status_rejects_selected_field_duplicates_and_folding(self):
        for replacement in (b'Version: 1\nVersion: 2',
                            b'Version: 1\n version continuation',
                            b'Version: 1\nARCHITECTURE: amd64'):
            raw = STATUS.replace(b'Version: 259.5-0ubuntu3.4', replacement)
            self.error('PID1_DPKG_STATUS', lambda raw=raw: m._status_version(raw))

    def test_dpkg_status_rejects_architecture_version_and_format(self):
        for raw in (STATUS.replace(b'Architecture: amd64', b'Architecture: arm64'),
                    STATUS.replace(b'259.5-0ubuntu3.4', b'bad version'),
                    STATUS.replace(b'Package: systemd', b'Package: systemd\r'),
                    STATUS[:-1], STATUS + b'\0'):
            self.error('PID1_DPKG_STATUS', lambda raw=raw: m._status_version(raw))

    def test_dpkg_status_bounds(self):
        with patch.object(m, 'MAX_STATUS_PARAGRAPHS', 1):
            self.error('PID1_DPKG_STATUS', lambda: m._status_version(STATUS))
        with patch.dict(m.LIMITS, {m.STATUS_PARTS: 4}):
            self.error('PID1_DPKG_STATUS', lambda: m._status_version(STATUS))

    def test_dpkg_list_requires_exact_once_and_bounded_lines(self):
        self.assertIsNone(m._listed_image(LIST))
        for raw in (LIST.replace(b'/usr/lib/systemd/systemd\n', b''),
                    LIST + b'/usr/lib/systemd/systemd\n',
                    LIST.replace(b'/usr/lib/systemd\n', b'bad\n'),
                    LIST[:-1], LIST + b'\0'):
            self.error('PID1_DPKG_LIST', lambda raw=raw: m._listed_image(raw))
        with patch.object(m, 'MAX_LIST_LINES', 1):
            self.error('PID1_DPKG_LIST', lambda: m._listed_image(LIST))

    @contextmanager
    def file_io(self, content=b'abc', before=None):
        before = metadata(st_size=len(content)) if before is None else before
        with self.linux_symbols(), ExitStack() as stack:
            f = dict(stat=Mock(return_value=before), fstat=Mock(return_value=before),
                     open=Mock(return_value=17), close=Mock(),
                     read=Mock(side_effect=[content, b'']))
            for name, obj in f.items():
                stack.enter_context(patch.object(m.os, name, obj))
            yield f

    def test_fixed_disk_read_is_nofollow_bounded_and_closed(self):
        tree = Mock()
        tree.directory.return_value = 11
        with self.file_io() as f:
            raw, stamp = m._disk_at(tree, m.IMAGE_PARTS, lambda: None)
            self.assertEqual(raw, b'abc')
            self.assertEqual(stamp, m.fs._stamp(metadata()))
            self.assertEqual(tree.directory.call_args.args[0], m.IMAGE_PARTS[:-1])
            self.assertEqual(f['open'].call_args.args[0], 'systemd')
            self.assertEqual(f['open'].call_args.kwargs, {'dir_fd': 11})
            self.assertTrue(f['open'].call_args.args[1] & m.os.O_NOFOLLOW)
            f['close'].assert_called_once_with(17)

    def test_disk_read_rejects_caller_path_wrong_owner_and_group_write(self):
        tree = Mock()
        tree.directory.return_value = 11
        with self.file_io() as f:
            self.error('PID1_IMAGE_TARGET', lambda: m._disk_at(tree, ('tmp',), lambda: None))
            f['open'].assert_not_called()
        for bad in (metadata(st_uid=1), metadata(st_mode=stat.S_IFREG | 0o420),
                    metadata(st_nlink=2), metadata(st_size=0)):
            with self.file_io(before=bad) as f:
                with self.assertRaises(core.OperatorError):
                    m._disk_at(tree, m.IMAGE_PARTS, lambda: None)
                f['open'].assert_not_called()

    def test_disk_read_rejects_drift_size_and_closes_fd(self):
        tree = Mock()
        tree.directory.return_value = 11
        with self.file_io() as f:
            f['fstat'].side_effect = [metadata(), metadata(st_ino=12)]
            self.error('PID1_IMAGE_CHANGED', lambda: m._disk_at(tree, m.IMAGE_PARTS,
                                                                lambda: None))
            f['close'].assert_called_once_with(17)
        with self.file_io(content=b'abcd', before=metadata(st_size=3)) as f:
            self.error('PID1_IMAGE_SIZE', lambda: m._disk_at(tree, m.IMAGE_PARTS,
                                                             lambda: None))
            f['close'].assert_called_once_with(17)

    def test_disk_read_error_or_checkpoint_failure_closes_fd(self):
        tree = Mock()
        tree.directory.return_value = 11
        with self.file_io() as f:
            f['read'].side_effect = OSError(errno.EIO, 'private')
            with self.assertRaises(OSError):
                m._disk_at(tree, m.IMAGE_PARTS, lambda: None)
            f['close'].assert_called_once_with(17)
        calls = [0]
        def check():
            calls[0] += 1
            if calls[0] == 2:
                raise core.OperatorError('PID1_IMAGE_TIMEOUT')
        with self.file_io() as f:
            self.error('PID1_IMAGE_TIMEOUT', lambda: m._disk_at(tree, m.IMAGE_PARTS, check))
            f['close'].assert_called_once_with(17)

    def test_proc_magic_link_requires_exact_text_before_following(self):
        with self.file_io() as f, patch.object(m.census, '_exe', return_value='/bad'):
            self.error('PID1_IMAGE_PATH', lambda: m._running_image(11, 7, lambda: None))
            f['stat'].assert_not_called()
            f['open'].assert_not_called()

    def test_proc_magic_link_backing_is_checked_and_closed(self):
        with self.file_io() as f, patch.object(m.census, '_exe', return_value=m.IMAGE_PATH):
            self.assertEqual(m._running_image(11, 7, lambda: None)[0], b'abc')
            self.assertEqual(f['open'].call_args.args[0], 'exe')
            self.assertFalse(f['open'].call_args.args[1] & m.os.O_NOFOLLOW)
            f['close'].assert_called_once_with(17)

    def test_proc_magic_link_changed_backing_rejected(self):
        with self.file_io() as f, patch.object(m.census, '_exe', return_value=m.IMAGE_PATH):
            f['fstat'].side_effect = [metadata(), metadata(st_ino=12)]
            self.error('PID1_IMAGE_CHANGED', lambda: m._running_image(11, 7,
                                                                       lambda: None))
            f['close'].assert_called_once_with(17)

    def test_snapshot_binds_proc_image_disk_and_local_claim(self):
        tree = Mock()
        tree.read.side_effect = [(BOOT.encode() + b'\n', ('boot',)),
                                 (b'mount', ('mount',)),
                                 (BOOT.encode() + b'\n', ('boot',)),
                                 (b'mount', ('mount',))]
        tree.directory.side_effect = [10, 11]
        tree.verify.return_value = ('verified',)
        with self.linux_symbols(), patch.object(m.cg, '_boot', return_value=BOOT), \
             patch.object(m.census, '_proc_device', return_value=(0, 7)), \
             patch.object(m.os, 'fstat', return_value=metadata()), \
             patch.object(m.census, '_small', side_effect=[b'stat', b'status'] * 2), \
             patch.object(m.census, '_stat_record', return_value=(123, False, False)), \
             patch.object(m.census, '_status', return_value=((0,) * 4, (0,) * 4, 1)), \
             patch.object(m, '_running_image', return_value=(b'abc', m.fs._stamp(metadata()))), \
             patch.object(m, '_disk_at', side_effect=[(b'abc', m.fs._stamp(metadata())),
                                                      (STATUS, ('status',)),
                                                      (LIST, ('list',))]) as disk:
            result = m._snapshot(tree, 44, 100, lambda: None)
        self.assertEqual(result[:2], (BOOT, 123))
        self.assertEqual(result[2], m.hashlib.sha256(b'abc').hexdigest())
        self.assertEqual(result[3], '259.5-0ubuntu3.4')
        self.assertEqual([call.args[1] for call in disk.call_args_list],
                         [m.IMAGE_PARTS, m.STATUS_PARTS, m.LIST_PARTS])
        self.assertNotIn(b'Description: demo', repr(result).encode())

    def test_snapshot_mismatched_running_image_blocks_dpkg_read(self):
        tree = Mock()
        tree.read.side_effect = [(BOOT.encode() + b'\n', ()), (b'mount', ())]
        tree.directory.side_effect = [10, 11]
        with self.linux_symbols(), patch.object(m.cg, '_boot', return_value=BOOT), \
             patch.object(m.census, '_proc_device', return_value=(0, 7)), \
             patch.object(m.os, 'fstat', return_value=metadata()), \
             patch.object(m.census, '_small', side_effect=[b'stat', b'status']), \
             patch.object(m.census, '_stat_record', return_value=(123, False, False)), \
             patch.object(m.census, '_status', return_value=((0,) * 4, (0,) * 4, 1)), \
             patch.object(m, '_running_image', return_value=(b'abc', m.fs._stamp(metadata()))), \
             patch.object(m, '_disk_at', return_value=(b'xyz', m.fs._stamp(metadata()))) as disk:
            self.error('PID1_IMAGE_MISMATCH', lambda: m._snapshot(tree, 44, 100,
                                                                  lambda: None))
            disk.assert_called_once()

    @contextmanager
    def observer(self):
        with self.linux_symbols(), ExitStack() as stack:
            stack.enter_context(patch.object(m.fs, '_platform'))
            stack.enter_context(patch.object(m.time, 'CLOCK_BOOTTIME', 7, create=True))
            stack.enter_context(patch.object(m.os, 'supports_dir_fd', {os.readlink}))
            f = dict(clock=Mock(return_value=1000), snapshot=Mock(
                return_value=(BOOT, 123, 'a' * 64, '259.5-0ubuntu3.4', (b'private',))),
                open=Mock(return_value=17), close=Mock(), tree=Mock())
            stack.enter_context(patch.object(m.time, 'clock_gettime_ns', f['clock'],
                                             create=True))
            stack.enter_context(patch.object(m, '_snapshot', f['snapshot']))
            stack.enter_context(patch.object(m.os, 'open', f['open']))
            stack.enter_context(patch.object(m.os, 'close', f['close']))
            stack.enter_context(patch.object(m.cg, '_Tree', return_value=f['tree']))
            yield f

    def test_public_observation_is_immutable_and_non_authorizing(self):
        with self.observer() as f:
            result = m.observe_pid1_image_inventory()
            self.assertEqual(f['snapshot'].call_count, 2)
            f['tree'].verify.assert_called_once()
            f['close'].assert_called_once_with(17)
        self.assertEqual(result.executable_sha256, 'a' * 64)
        self.assertEqual(result.dpkg_claimed_version, '259.5-0ubuntu3.4')
        self.assertNotIn('private', repr(result))
        for name in ('independently_pinned_image_verified', 'package_authenticity_proven',
                     'intended_host_proven', 'loaded_code_proven',
                     'current_generator_paths_proven', 'atomic_snapshot_proven',
                     'continuous_control_proven', 'mutation_authorized', 'startup_authorized'):
            self.assertIs(getattr(result, name), False)
        with self.assertRaises(FrozenInstanceError):
            result.startup_authorized = True

    def test_public_observation_rejects_two_pass_drift(self):
        with self.observer() as f:
            f['snapshot'].side_effect = [(BOOT, 123, 'a' * 64, '1', (b'a',)),
                                         (BOOT, 123, 'a' * 64, '2', (b'a',))]
            self.error('PID1_IMAGE_CHANGED', m.observe_pid1_image_inventory)
            f['close'].assert_called_once_with(17)

    def test_public_observation_rejects_wrong_platform_or_caller(self):
        with self.observer() as f, patch.object(m.os, 'supports_dir_fd', set()):
            self.error('PID1_IMAGE_PLATFORM', m.observe_pid1_image_inventory)
            f['open'].assert_not_called()
        with self.observer(), patch.object(m.threading, 'get_native_id',
                                           side_effect=chain([1], repeat(2))):
            self.error('PID1_IMAGE_CALLER', m.observe_pid1_image_inventory)

    def test_public_observation_rejects_timeout_and_sanitizes_os_error(self):
        with self.observer() as f:
            f['clock'].side_effect = chain([1000, 1000 + m.MAX_WINDOW_NS],
                                           repeat(1000 + m.MAX_WINDOW_NS))
            self.error('PID1_IMAGE_TIMEOUT', m.observe_pid1_image_inventory)
        with self.observer() as f:
            f['snapshot'].side_effect = PermissionError(errno.EACCES, 'private')
            self.error('FS_ACCESS', m.observe_pid1_image_inventory)
            f['close'].assert_called_once_with(17)


if __name__ == '__main__':
    unittest.main()
