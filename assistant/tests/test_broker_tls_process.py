"""Offline process policies plus Linux-only self-process descriptor checks."""
from dataclasses import asdict
import hashlib
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_process as p
from siem.rbac.broker_tls import operator_core as core
if __package__:
    from .test_broker_tls_service import values
    from .test_broker_tls_operator_fs import metadata
else:
    from test_broker_tls_service import values
    from test_broker_tls_operator_fs import metadata


def stat_bytes(pid=123, start=999, name=b'node', state=b'S'):
    return str(pid).encode() + b' (' + name + b') ' + b' '.join([state] + [b'0'] * 18 + [str(start).encode()])


def status_bytes(uid=126, gid=128):
    return b'Name:\tnode\nUid:\t' + b'\t'.join([str(uid).encode()] * 4) + b'\nGid:\t' + b'\t'.join([str(gid).encode()] * 4) + b'\n'


def snapshot(**kwargs):
    return p._Snapshot(**dict(dict(start_time=999, executable_inode=(1, 2),
        cmdline=core.NODE.encode() + b'\0--secret=PRIVATE\0', environment=b'PRIVATE=VALUE\0'), **kwargs))


class ProcessTests(unittest.TestCase):
    def native_double(self, *, changed=False, read_error=False):
        nodes={10: metadata(True), 11: metadata(True, st_ino=11),
               12: metadata(True, st_ino=12, st_uid=126, st_gid=128)}
        names={(10, 'proc'): 11, (11, '123'): 12}
        stat_reads=iter([stat_bytes(), stat_bytes(start=1000 if changed else 999)])
        def small(fd, name, owners):
            if read_error:
                raise OSError('PRIVATE')
            self.assertEqual((fd, owners), (12, ((0, 0), (126, 128))))
            if name == 'stat':
                return next(stat_reads)
            return {'status': status_bytes(), 'cmdline': snapshot().cmdline,
                    'environ': snapshot().environment}[name]
        with patch.object(p.os, 'open', side_effect=lambda name, flags, dir_fd=None:
                10 if name == '/' else names[dir_fd, name]), patch.object(p.os, 'stat',
                side_effect=lambda name, dir_fd, follow_symlinks: nodes[names[dir_fd, name]]), patch.object(
                p.os, 'fstat', side_effect=lambda fd: nodes[fd]), patch.object(p.os, 'close') as close, patch.object(
                p, '_read_small', side_effect=small) as reader, patch.object(p, '_executable', return_value=(1, 2)):
            try:
                result=p._native_snapshot(123, (126, 128))
                self.assertEqual([c.args[1] for c in reader.call_args_list],
                                 ['stat', 'status', 'cmdline', 'environ', 'status', 'stat'])
                return result
            finally:
                self.assertEqual([c.args[0] for c in close.call_args_list], [12, 11, 10])

    def test_native_composition_holds_directory_descriptors_and_closes(self):
        self.assertEqual(self.native_double(), snapshot())

    def test_native_composition_detects_start_change_and_cleans_errors(self):
        with self.assertRaisesRegex(core.OperatorError, '^PROCESS_CHANGED$'):
            self.native_double(changed=True)
        with self.assertRaises(OSError):
            self.native_double(read_error=True)

    def test_invalid_pid_never_opens_proc(self):
        for value in (0, 1, True, '123', -1, 2**32):
            with self.subTest(value=value), patch.object(p.os, 'open') as opened, self.assertRaisesRegex(core.OperatorError, '^PROCESS_PID$'):
                p._native_snapshot(value, (126, 128))
            opened.assert_not_called()

    def test_executable_size_and_inode_drift_stop_and_close(self):
        for size, code in ((0, 'PROCESS_SIZE'), (p.EXE_LIMIT + 1, 'PROCESS_SIZE'), (4, 'PROCESS_CHANGED')):
            st=metadata(st_size=size)
            changed=metadata(st_size=size, st_ino=2)
            with patch.object(p.os, 'readlink', return_value=core.NODE), patch.object(p.os, 'open', return_value=20), patch.object(
                    p.os, 'fstat', side_effect=[st, changed]), patch.object(p.os, 'read', side_effect=[b'fake', b'']), patch.object(
                    p.os, 'close') as close, self.subTest(size=size), self.assertRaisesRegex(core.OperatorError, '^'+code+'$'):
                p._executable(12, ((0, 0),))
            close.assert_called_once_with(20)

    def observe(self, snapshots=None, anchors=None):
        with patch.object(p.service, '_check_tool'), patch.object(p.fs, '_identity', return_value=(126, 128)), patch.object(
                p, '_anchor', side_effect=anchors or [values()] * 3) as anchor, patch.object(
                p, '_native_snapshot', side_effect=snapshots or [snapshot()] * 2) as native:
            result = p.observe_running_process()
            self.assertEqual(anchor.call_count, 3)
            self.assertEqual([c.args for c in native.call_args_list], [(123, (126, 128))] * 2)
            return result

    def test_stat_parser_handles_comm_spaces_parens_and_newlines(self):
        for name in (b'node', b'a ) b ( c', b'a\nb'):
            self.assertEqual(p._start_time(stat_bytes(name=name), 123), 999)
        for raw in (b'', b'123 bad', stat_bytes(pid=124), stat_bytes(start=0),
                    stat_bytes(start=2**64), stat_bytes(state=b'Z')):
            with self.subTest(raw=raw[:25]), self.assertRaisesRegex(core.OperatorError, '^PROCESS_STAT$'):
                p._start_time(raw, 123)

    def test_credentials_require_four_exact_ids_and_unique_fields(self):
        p._credentials(status_bytes(), (126, 128))
        for raw in (status_bytes(uid=0), status_bytes(gid=0), b'', status_bytes() + b'Uid: 126 126 126 126\n',
                    status_bytes().replace(b'126\t126', b'126\t0', 1)):
            with self.assertRaisesRegex(core.OperatorError, '^PROCESS_IDENTITY$'):
                p._credentials(raw, (126, 128))

    def test_nul_boundaries_and_environment_names(self):
        self.assertEqual(p._nul_fields(b'node\0\0value\0'), [b'node', b'', b'value'])
        self.assertEqual(p._nul_fields(b'', environment=True), [])
        for raw in (b'', b'node', b'\0', b'x' * (p.LIMITS['cmdline'] + 1)):
            with self.assertRaisesRegex(core.OperatorError, '^PROCESS_CMDLINE$'):
                p._nul_fields(raw)
        for raw in (b'bad', b'X\0', b'X=1\0X=2\0', b'BAD-NAME=x\0', b'\0'):
            with self.assertRaisesRegex(core.OperatorError, '^PROCESS_ENVIRONMENT$'):
                p._nul_fields(raw, environment=True)

    def test_anchor_requires_running_named_service_and_valid_pid(self):
        with patch.object(p.service, '_read_configuration', return_value=values()):
            self.assertEqual(p._anchor()['MainPID'], 123)
        for field, val, code in (('ActiveState', 'inactive', 'PROCESS_NOT_RUNNING'),
                ('MainPID', 0, 'PROCESS_PID'), ('MainPID', True, 'PROCESS_PID'),
                ('MainPID', 2**32, 'PROCESS_PID'),
                ('ExecMainStartTimestampMonotonic', 0, 'PROCESS_NOT_RUNNING'),
                ('User', 'root', 'PROCESS_IDENTITY'), ('Group', 'root', 'PROCESS_IDENTITY')):
            data=values(); data[field]=val
            with patch.object(p.service, '_read_configuration', return_value=data), self.subTest(field=field), self.assertRaisesRegex(core.OperatorError, '^'+code+'$'):
                p._anchor()

    def test_sanitized_observation_and_private_repr(self):
        result=self.observe()
        self.assertEqual((result.argument_count, result.environment_entries, result.passes, result.service_reads), (2, 1, 2, 3))
        self.assertTrue(result.process_executable_matches_pin and result.argv0_matches_packaged_path)
        for flag in ('startup_authorized', 'loaded_code_proven', 'effective_environment_proven'):
            self.assertIs(getattr(result, flag), False)
            with self.assertRaises(AttributeError):
                setattr(result, flag, True)
        self.assertNotIn('PRIVATE', repr(result) + repr(snapshot()) + str(asdict(result)))
        self.assertNotIn('VALUE', repr(snapshot()))
        changed=snapshot(cmdline=b'node\0', environment=b'NODE_OPTIONS=PRIVATE\0')
        result=self.observe([changed] * 2)
        self.assertTrue(result.runtime_override_named)
        self.assertFalse(result.argv0_matches_packaged_path)

    def test_snapshot_or_manager_changes_stop(self):
        for changed in (snapshot(start_time=1000), snapshot(executable_inode=(1, 3)),
                        snapshot(environment=b'PRIVATE=CHANGED\0'), snapshot(cmdline=b'node\0')):
            with self.subTest(changed=repr(changed)), self.assertRaisesRegex(core.OperatorError, '^PROCESS_CHANGED$'):
                self.observe([snapshot(), changed])
        second=values(); second['MainPID']=124
        with self.assertRaisesRegex(core.OperatorError, '^PROCESS_CHANGED$'):
            self.observe(anchors=[values(), second, second])

    def test_tool_gate_and_proc_error_suppress_raw_details(self):
        with patch.object(p.service, '_check_tool', side_effect=core.OperatorError('FS_METADATA')), patch.object(
                p, '_native_snapshot') as native, self.assertRaisesRegex(core.OperatorError, '^FS_METADATA$'):
            p.observe_running_process()
        native.assert_not_called()
        with self.assertRaises(core.OperatorError) as caught:
            self.observe([OSError('PRIVATE')])
        self.assertEqual(str(caught.exception), 'PROCESS_IO')
        self.assertTrue(caught.exception.__suppress_context__)

    def test_small_file_bound_and_close(self):
        st=metadata(False, st_size=0)
        for chunks, code in (([b'hello', b''], None), ([b'x' * 8193], 'PROCESS_SIZE')):
            with patch.object(p.os, 'stat', return_value=st), patch.object(p.os, 'fstat', return_value=st), patch.object(
                    p.os, 'open', return_value=20) as opened, patch.object(p.os, 'read', side_effect=chunks), patch.object(p.os, 'close') as close:
                if code:
                    with self.assertRaisesRegex(core.OperatorError, '^'+code+'$'):
                        p._read_small(10, 'stat', ((0, 0),))
                else:
                    self.assertEqual(p._read_small(10, 'stat', ((0, 0),)), b'hello')
                close.assert_called_once_with(20)
                self.assertTrue(opened.call_args.args[1] & os.O_NOFOLLOW if hasattr(os, 'O_NOFOLLOW') else True)

    def test_executable_path_and_digest_checks_close_fd(self):
        # POSIX flag values are injected on Windows; no OS calls occur.
        st=metadata(False, st_size=4)
        with patch.object(p.os, 'readlink', return_value='/unapproved'), patch.object(p.os, 'open') as opened, self.assertRaisesRegex(core.OperatorError, '^PROCESS_EXECUTABLE$'):
            p._executable(10, ((0, 0),))
        opened.assert_not_called()
        with patch.object(p.os, 'readlink', return_value=core.NODE), patch.object(p.os, 'open', return_value=20), patch.object(
                p.os, 'fstat', return_value=st), patch.object(p.os, 'stat', return_value=st), patch.object(
                p.os, 'read', side_effect=[b'fake', b'']), patch.object(p.os, 'close') as close, self.assertRaisesRegex(core.OperatorError, '^PROCESS_DIGEST$'):
            p._executable(10, ((0, 0),))
        close.assert_called_once_with(20)

    def setUp(self):
        # Match the existing native-reader policy tests' portable syscall doubles.
        for name, value in (('O_NOFOLLOW', 0x20000), ('O_DIRECTORY', 0x10000), ('O_NONBLOCK', 0x800), ('O_CLOEXEC', 0x80000)):
            if not hasattr(os, name):
                patcher=patch.object(os, name, value, create=True)
                patcher.start(); self.addCleanup(patcher.stop)


@unittest.skipUnless(sys.platform == 'linux', 'real procfs requires Linux')
class NativeProcessTests(unittest.TestCase):
    def test_self_stat_and_credentials_through_real_proc_fd(self):
        fd=os.open('/proc/' + str(os.getpid()), os.O_RDONLY | os.O_DIRECTORY)
        try:
            owners=((0, 0), (os.getuid(), os.getgid()))
            self.assertGreater(p._start_time(p._read_small(fd, 'stat', owners), os.getpid()), 0)
            p._credentials(p._read_small(fd, 'status', owners), (os.getuid(), os.getgid()))
        finally:
            os.close(fd)

    def test_real_self_executable_magic_link_and_streamed_digest(self):
        path=os.readlink('/proc/self/exe')
        digest=hashlib.sha256(Path('/proc/self/exe').read_bytes()).hexdigest()
        fd=os.open('/proc/' + str(os.getpid()), os.O_RDONLY | os.O_DIRECTORY)
        try:
            with patch.object(core, 'NODE', path), patch.dict(core.CONTRACT, packaged_linux_node_sha256=digest):
                self.assertEqual(p._executable(fd, ((0, 0), (os.getuid(), os.getgid()))),
                                 (os.stat('/proc/self/exe').st_dev, os.stat('/proc/self/exe').st_ino))
        finally:
            os.close(fd)

    def test_unknown_proc_target_does_not_open_or_leak(self):
        before=len(os.listdir('/proc/self/fd'))
        with self.assertRaisesRegex(core.OperatorError, '^PROCESS_TARGET$'):
            p._read_small(0, 'mem', ((0, 0),))
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)


if __name__ == '__main__':
    unittest.main()
