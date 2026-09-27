"""Offline package-lock fixtures; never open real package locks or run APT/dpkg."""
from contextlib import contextmanager
from dataclasses import asdict, FrozenInstanceError
import errno
import inspect
import os
from pathlib import Path
import stat
import struct
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
from siem.rbac.broker_tls import operator_guard_entry as guard
from siem.rbac.broker_tls import operator_maintenance_packages as p
from test_broker_tls_maintenance_lock import LockFS, metadata


def api(reply=None):
    return SimpleNamespace(F_OFD_SETLK=37, F_GETLK=5, F_WRLCK=1,
        fcntl=Mock(return_value=struct.pack(p.FLOCK_FORMAT, 1, 0, 0, 0, -1) if reply is None else reply))


class PackageFS(LockFS):
    def __init__(self):
        super().__init__()
        self.nodes = {(): metadata()}
        self.fds = {10: ((), self.nodes[()])}
        for path in p.LOCK_PATHS:
            for length in range(1, len(path)):
                self.nodes.setdefault(path[:length], metadata(st_ino=len(self.nodes) + 1))
            self.nodes[path] = metadata(stat.S_IFREG | 0o640, st_ino=len(self.nodes) + 1)
        self.O_RDWR, self.SEEK_SET = 16, 0
        self.uname = lambda: SimpleNamespace(machine='x86_64')
        self.locked = set()
        self.acquire = Mock(side_effect=lambda fd: self.locked.add(fd))
        self.check = Mock(side_effect=self._check)
        self.close = Mock(side_effect=self._close)

    def _check(self, fd):
        if fd not in self.locked:
            raise core.OperatorError('PACKAGE_LOCK_STATE')

    def _close(self, fd):
        self.fds.pop(fd)
        self.locked.discard(fd)


class MaintenancePackageTests(unittest.TestCase):
    @contextmanager
    def fake(self, fs=None):
        fs = PackageFS() if fs is None else fs
        try:
            with (patch.object(p, 'os', fs), patch.object(p.cg, 'os', fs),
                  patch.object(p, '_acquire', fs.acquire), patch.object(p, '_check_locked', fs.check),
                  patch.object(p.threading, 'get_native_id', return_value=100)):
                yield fs
        finally:
            self.assertEqual(set(fs.fds), {10})
            self.assertEqual(fs.locked, set())

    def test_fixed_paths_api_and_outside_capsule(self):
        self.assertEqual(str(inspect.signature(p.hold_maintenance_package_locks)), '()')
        self.assertEqual(tuple('/' + '/'.join(x) for x in p.LOCK_PATHS),
            ('/var/lib/dpkg/lock-frontend', '/var/lib/dpkg/lock',
             '/var/lib/apt/lists/lock', '/var/cache/apt/archives/lock'))
        self.assertNotIn('operator_maintenance_packages.py', {v[0] for v in guard.PINNED_MODULES + guard.RUNTIME_MODULES})
        self.assertNotIn('if __name__', inspect.getsource(p))

    def test_all_four_locks_held_until_successful_exit(self):
        with self.fake() as fs:
            with p._hold_at(10) as held:
                self.assertEqual(len(fs.locked), 4)
                self.assertEqual([fs.fds[c.args[0]][0] for c in fs.acquire.call_args_list], list(p.LOCK_PATHS))
                held.checkpoint()
                self.assertEqual(len(fs.locked), 4)
            self.assertEqual(fs.acquire.call_count, 4)
            self.assertEqual(fs.check.call_count, 12)  # entry, explicit, exit

    def test_minimized_immutable_observation_is_not_authority(self):
        with self.fake(), p._hold_at(10) as held:
            value = held.checkpoint()
            self.assertEqual(value.fixed_record_locks_held, 4)
            self.assertEqual(repr(held), '<private package-lock handle>')
            for name, item in asdict(value).items():
                if name == 'fixed_record_locks_held':
                    continue
                self.assertIs(item, name in ('fixed_paths_rechecked', 'default_lock_paths_only', 'review_required'))
            with self.assertRaises(FrozenInstanceError):
                value.exclusive_control_proven = True

    def test_missing_leaf_or_ancestor_not_created(self):
        for path in (('var',), ('var', 'lib', 'apt', 'lists'), *p.LOCK_PATHS):
            fs = PackageFS()
            del fs.nodes[path]
            with self.subTest(path=path), self.fake(fs), self.assertRaisesRegex(core.OperatorError, '^FS_MISSING$'):
                with p._hold_at(10):
                    self.fail('missing lock admitted')
            self.assertNotIn(path, fs.nodes)

    def test_unsafe_root_or_directory_rejected(self):
        for path in ((), ('var',), p.LOCK_PATHS[0][:-1]):
            for changes in ({'st_uid': 126}, {'st_gid': 128}, {'st_mode': stat.S_IFLNK | 0o777},
                            {'st_mode': stat.S_IFDIR | 0o777}):
                fs = PackageFS()
                fs.change(path, **changes)
                if not path:
                    fs.fds[10] = (), fs.nodes[()]
                with self.subTest(path=path, changes=changes), self.fake(fs), self.assertRaises(core.OperatorError):
                    with p._hold_at(10):
                        self.fail('bad directory admitted')

    def test_lock_leaf_owner_type_linkcount_size_and_mode_rejected(self):
        for changes in ({'st_uid': 126}, {'st_gid': 128}, {'st_nlink': 2}, {'st_nlink': 0},
                        {'st_size': 1}, {'st_size': -1}, {'st_mode': stat.S_IFIFO | 0o600},
                        {'st_mode': stat.S_IFLNK | 0o777}, {'st_mode': stat.S_IFREG | 0o660},
                        {'st_mode': stat.S_IFREG | 0o1600}, {'st_mode': stat.S_IFREG | 0o400}):
            fs = PackageFS()
            fs.change(p.LOCK_PATHS[0], **changes)
            with self.subTest(changes=changes), self.fake(fs), self.assertRaises(core.OperatorError):
                with p._hold_at(10):
                    self.fail('unsafe leaf admitted')
            fs.acquire.assert_not_called()

    def test_supported_empty_lock_modes(self):
        for mode in (0o600, 0o640, 0o644):
            fs = PackageFS()
            for path in p.LOCK_PATHS:
                fs.change(path, st_mode=stat.S_IFREG | mode)
            with self.subTest(mode=mode), self.fake(fs), p._hold_at(10):
                self.assertEqual(len(fs.locked), 4)

    def test_distinct_device_leaf_and_inode_alias_rejected(self):
        for changes, code in (({'st_dev': 99}, 'PACKAGE_LOCK_DEVICE'),
                              ({'st_ino': PackageFS().nodes[p.LOCK_PATHS[0]].st_ino}, 'PACKAGE_LOCK_ALIAS')):
            fs = PackageFS()
            fs.change(p.LOCK_PATHS[1], **changes)
            with self.subTest(changes=changes), self.fake(fs), self.assertRaisesRegex(core.OperatorError, code):
                with p._hold_at(10):
                    self.fail('alias/device admitted')

    def test_preopen_to_held_inode_race_rejected(self):
        fs = PackageFS()
        original = fs.open.side_effect
        def race(name, flags, **kw):
            path = fs._path(name, kw.get('dir_fd'))
            if path == p.LOCK_PATHS[0]:
                fs.change(path, st_ino=999)
            return original(name, flags, **kw)
        fs.open.side_effect = race
        with self.fake(fs), self.assertRaisesRegex(core.OperatorError, 'PACKAGE_LOCK_CHANGED'):
            with p._hold_at(10):
                self.fail('open race admitted')

    def test_replacement_during_acquire_rechecked_before_yield(self):
        fs = PackageFS()
        def acquire(fd):
            fs.locked.add(fd)
            if len(fs.locked) == 4:
                fs.change(p.LOCK_PATHS[0], st_ino=999)
        fs.acquire.side_effect = acquire
        with self.fake(fs), self.assertRaisesRegex(core.OperatorError, 'PACKAGE_LOCK_CHANGED'):
            with p._hold_at(10):
                self.fail('acquisition race admitted')

    def test_busy_at_each_position_unwinds_without_partial_success(self):
        for index in range(4):
            fs = PackageFS()
            def acquire(fd):
                if fs.fds[fd][0] == p.LOCK_PATHS[index]:
                    raise core.OperatorError('PACKAGE_LOCK_BUSY')
                fs.locked.add(fd)
            fs.acquire.side_effect = acquire
            with self.subTest(index=index), self.fake(fs), self.assertRaisesRegex(core.OperatorError, '^PACKAGE_LOCK_BUSY$'):
                with p._hold_at(10):
                    self.fail('partial acquisition yielded')
            self.assertEqual(fs.acquire.call_count, index + 1)

    def test_checkpoint_and_exit_reject_name_or_metadata_drift(self):
        for path in (('var', 'lib'), *p.LOCK_PATHS):
            fs = PackageFS()
            with self.subTest(path=path), self.fake(fs), self.assertRaises(core.OperatorError):
                with p._hold_at(10):
                    fs.change(path, st_ino=999)
        fs = PackageFS()
        with self.fake(fs), self.assertRaisesRegex(core.OperatorError, 'PACKAGE_LOCK_CHANGED'):
            with p._hold_at(10):
                fs.change(p.LOCK_PATHS[0], st_mtime_ns=99)

    def test_unrelated_parent_timestamps_do_not_abort(self):
        with self.fake() as fs, p._hold_at(10) as held:
            path = p.LOCK_PATHS[0][:-1]
            fs.change(path, st_mtime_ns=99, st_ctime_ns=99)
            held.checkpoint()

    def test_missing_lock_state_never_reacquired(self):
        fs = PackageFS()
        with self.fake(fs), self.assertRaisesRegex(core.OperatorError, 'PACKAGE_LOCK_STATE'):
            with p._hold_at(10) as held:
                fs.locked.clear()
                held.checkpoint()
        self.assertEqual(fs.acquire.call_count, 4)

    def test_inheritable_descriptor_rejected_before_locking(self):
        fs = PackageFS()
        fs.inheritable = True
        with self.fake(fs), self.assertRaisesRegex(core.OperatorError, 'PACKAGE_LOCK_INHERITABLE'):
            with p._hold_at(10):
                self.fail('inheritable fd admitted')
        fs.acquire.assert_not_called()

    def test_inheritable_after_yield_rejected(self):
        with self.fake() as fs, self.assertRaisesRegex(core.OperatorError, 'PACKAGE_LOCK_INHERITABLE'):
            with p._hold_at(10):
                fs.inheritable = True

    def test_closed_pid_and_thread_reuse_rejected(self):
        with self.fake() as fs:
            with p._hold_at(10) as held:
                fs.pid = 101
                with self.assertRaisesRegex(core.OperatorError, 'PACKAGE_LOCK_OWNER'):
                    held.checkpoint()
                fs.pid = 100
                with patch.object(p.threading, 'get_native_id', return_value=101):
                    with self.assertRaisesRegex(core.OperatorError, 'PACKAGE_LOCK_OWNER'):
                        held.checkpoint()
            with self.assertRaisesRegex(core.OperatorError, 'PACKAGE_LOCK_CLOSED'):
                held.checkpoint()

    def test_body_failure_preserved_and_all_handles_closed(self):
        sentinel = RuntimeError('body')
        with self.fake(), self.assertRaises(RuntimeError) as caught:
            with p._hold_at(10):
                raise sentinel
        self.assertIs(caught.exception, sentinel)

    def test_exact_ofd_nonblocking_whole_file_request(self):
        stub = api()
        with patch.dict(sys.modules, {'fcntl': stub}):
            p._acquire(41)
        args = stub.fcntl.call_args.args
        self.assertEqual(args[:2], (41, 37))
        self.assertEqual(len(args[2]), 32)
        self.assertEqual(struct.unpack(p.FLOCK_FORMAT, args[2]), (1, 0, 0, 0, 0))
        stub.fcntl.assert_called_once()

    def test_record_lock_busy_and_unsupported_fail_without_fallback(self):
        for error, code in ((errno.EACCES, 'BUSY'), (errno.EAGAIN, 'BUSY'), (errno.EINVAL, 'ACQUIRE'),
                            (errno.ENOLCK, 'ACQUIRE'), (errno.EINTR, 'ACQUIRE'), (errno.EOPNOTSUPP, 'ACQUIRE')):
            stub = api()
            stub.fcntl.side_effect = OSError(error, 'PRIVATE_DETAIL')
            with self.subTest(error=error), patch.dict(sys.modules, {'fcntl': stub}):
                with self.assertRaisesRegex(core.OperatorError, '^PACKAGE_LOCK_' + code + '$'):
                    p._acquire(41)
                stub.fcntl.assert_called_once()

    def test_checkpoint_uses_traditional_query_not_relock(self):
        stub = api()
        with patch.dict(sys.modules, {'fcntl': stub}):
            p._check_locked(41)
        stub.fcntl.assert_called_once_with(41, 5, struct.pack(p.FLOCK_FORMAT, 1, 0, 0, 0, 0))

    def test_lost_partial_foreign_and_malformed_record_replies_rejected(self):
        replies = [b'', b'x'*31, b'x'*33, bytearray(32)]
        replies += [struct.pack(p.FLOCK_FORMAT, *v) for v in
                    ((2,0,0,0,0), (0,0,0,0,-1), (1,1,0,0,-1), (1,0,1,0,-1),
                     (1,0,0,1,-1), (1,0,0,0,100), (1,0,0,0,0))]
        for raw in replies:
            with self.subTest(raw=raw), patch.dict(sys.modules, {'fcntl': api(raw)}):
                with self.assertRaisesRegex(core.OperatorError, '^PACKAGE_LOCK_STATE$'):
                    p._check_locked(41)

    def test_check_os_errors_sanitized(self):
        stub = api()
        stub.fcntl.side_effect = OSError(errno.EIO, 'PRIVATE_PATH')
        with patch.dict(sys.modules, {'fcntl': stub}), self.assertRaisesRegex(core.OperatorError, '^PACKAGE_LOCK_CHECK$'):
            p._check_locked(41)

    def test_missing_ofd_support_fails_closed(self):
        stub = api()
        del stub.F_OFD_SETLK
        with patch.dict(sys.modules, {'fcntl': stub}), self.assertRaisesRegex(core.OperatorError, 'PACKAGE_LOCK_PLATFORM'):
            p._acquire(41)
        stub.fcntl.assert_not_called()

    def test_no_payload_io_create_truncate_or_unlink(self):
        with self.fake() as fs:
            before = {path: vars(st).copy() for path, st in fs.nodes.items()}
            with p._hold_at(10):
                pass
            self.assertEqual(before, {path: vars(st) for path, st in fs.nodes.items()})
            for path, flags in fs.calls:
                expected = (fs.O_RDWR | fs.O_NONBLOCK | fs.O_NOFOLLOW | fs.O_CLOEXEC
                            if path in p.LOCK_PATHS else fs.O_RDONLY | fs.O_DIRECTORY | fs.O_NOFOLLOW | fs.O_CLOEXEC)
                self.assertEqual(flags, expected)

    def test_public_platform_guard_precedes_any_open(self):
        with patch.object(p.fs, '_platform', side_effect=core.OperatorError('FS_PLATFORM')), patch.object(p.os, 'open') as opened:
            with self.assertRaisesRegex(core.OperatorError, 'FS_PLATFORM'), p.hold_maintenance_package_locks():
                self.fail('platform guard bypassed')
            opened.assert_not_called()

    def test_public_abi_guard_before_open(self):
        fs = PackageFS()
        fs.uname = lambda: SimpleNamespace(machine='aarch64')
        with self.fake(fs), patch.object(p.fs, '_platform'):
            with self.assertRaisesRegex(core.OperatorError, 'PACKAGE_LOCK_PLATFORM'), p.hold_maintenance_package_locks():
                self.fail('unreviewed ABI')
            fs.open.assert_not_called()

    def test_public_wrapper_fixed_root_and_cleanup(self):
        with self.fake() as fs, patch.object(p.fs, '_platform'), patch.object(p, '_api', return_value=api()):
            with self.assertRaisesRegex(RuntimeError, 'abort'), p.hold_maintenance_package_locks():
                raise RuntimeError('abort')
            self.assertEqual(fs.calls[0][0], ())

    def test_open_errors_and_close_errors_are_sanitized(self):
        fs = PackageFS()
        fs.open.side_effect = OSError(errno.EACCES, 'PRIVATE_PATH')
        with self.fake(fs), self.assertRaisesRegex(core.OperatorError, '^FS_ACCESS$'), p._hold_at(10):
            self.fail('open error swallowed')
        with patch.object(p.os, 'close', side_effect=OSError(errno.EIO, 'PRIVATE_DETAIL')) as close:
            with self.assertRaisesRegex(core.OperatorError, '^PACKAGE_LOCK_CLEANUP$'):
                p._close(41)
            close.assert_called_once_with(41)


@unittest.skipUnless(sys.platform == 'linux' and os.uname().machine == 'x86_64',
                     'Linux x86-64 record-lock fixture; never real package locks')
class NativeMaintenancePackageTests(unittest.TestCase):
    @contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            targets = [root.joinpath(*path) for path in p.LOCK_PATHS]
            for target in targets:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.touch(mode=0o640)
                target.chmod(0o640)
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            old_stat, old_fstat = os.stat, os.fstat
            def normalized(st):
                return SimpleNamespace(**{k: (0 if k in ('st_uid', 'st_gid') else getattr(st, k)) for k in vars(metadata())})
            try:
                with patch.object(p.os, 'stat', side_effect=lambda *a, **kw: normalized(old_stat(*a, **kw))), patch.object(
                        p.os, 'fstat', side_effect=lambda fd: normalized(old_fstat(fd))):
                    yield root_fd, targets
            finally:
                os.close(root_fd)

    def probe(self, target):
        # Independent process uses a traditional POSIX lock, like the upstream
        # package tools, on a disposable file. Never invokes either package tool.
        code = ('import errno,fcntl,os,sys\nfd=os.open(sys.argv[1],os.O_RDWR)\n'
                'try: fcntl.lockf(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)\n'
                'except OSError as e:\n'
                ' if e.errno in (errno.EAGAIN,errno.EACCES): sys.exit(23)\n'
                ' raise\nfinally: os.close(fd)\n')
        result = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', code, str(target)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            close_fds=True, timeout=10, check=False)
        self.assertIn(result.returncode, (0, 23), result.stderr.decode(errors='replace'))
        return result.returncode

    def test_native_all_four_conflict_with_posix_then_release(self):
        with self.fixture() as (root, targets):
            before = [p.fs._stamp(x.stat()) for x in targets]
            with p._hold_at(root) as held:
                held.checkpoint()
                self.assertEqual([self.probe(x) for x in targets], [23]*4)
            self.assertEqual([self.probe(x) for x in targets], [0]*4)
            self.assertEqual(before, [p.fs._stamp(x.stat()) for x in targets])

    def test_native_closing_unrelated_fd_does_not_drop_ofd_lock(self):
        with self.fixture() as (root, targets):
            with self.assertRaisesRegex(RuntimeError, 'abort'):
                with p._hold_at(root) as held:
                    extra = os.open(targets[0], os.O_RDONLY)
                    os.close(extra)
                    held.checkpoint()
                    self.assertEqual(self.probe(targets[0]), 23)
                    raise RuntimeError('abort')
            self.assertEqual(self.probe(targets[0]), 0)

    def test_native_existing_traditional_lock_conflicts_without_conversion(self):
        import fcntl
        with self.fixture() as (_, targets):
            fd = os.open(targets[0], os.O_RDWR)
            try:
                fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaisesRegex(core.OperatorError, 'PACKAGE_LOCK_BUSY'):
                    p._acquire(fd)
                self.assertEqual(self.probe(targets[0]), 23)
            finally:
                os.close(fd)
            self.assertEqual(self.probe(targets[0]), 0)

    def test_native_partial_acquire_unwinds_without_releasing_blocker(self):
        with self.fixture() as (root, targets):
            blocker = os.open(targets[-1], os.O_RDWR)
            try:
                p._acquire(blocker)
                with self.assertRaisesRegex(core.OperatorError, 'PACKAGE_LOCK_BUSY'), p._hold_at(root):
                    self.fail('partial acquired')
                self.assertEqual([self.probe(x) for x in targets], [0,0,0,23])
                p._check_locked(blocker)
            finally:
                os.close(blocker)
            self.assertEqual(self.probe(targets[-1]), 0)


if __name__ == '__main__':
    unittest.main()
