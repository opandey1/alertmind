"""Offline cooperative-lock tests; never touch real /run or query services."""
from contextlib import contextmanager
from dataclasses import asdict, FrozenInstanceError
import errno
import inspect
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
from siem.rbac.broker_tls import operator_guard_entry as guard
from siem.rbac.broker_tls import operator_maintenance_lock as lock


def metadata(mode=stat.S_IFDIR | 0o755, **kw):
    value = dict(st_dev=1, st_ino=1, st_mode=mode, st_uid=0, st_gid=0,
                 st_nlink=1, st_size=0, st_mtime_ns=1, st_ctime_ns=1)
    value.update(kw)
    return SimpleNamespace(**value)


class LockFS:
    """Held inode metadata differs from a subsequently replaced directory entry."""
    def __init__(self):
        self.nodes = {(): metadata(), ('run',): metadata(st_ino=2),
            lock.PARENT: metadata(stat.S_IFDIR | 0o700, st_ino=3),
            lock.PARENT + (lock.NAME,): metadata(stat.S_IFREG | 0o600, st_ino=4)}
        self.fds = {10: ((), self.nodes[()])}
        self.next_fd = 10
        self.calls = []
        self.pid = 100
        self.inheritable = False
        self.open = Mock(side_effect=self._open)
        self.close = Mock(side_effect=lambda fd: self.fds.pop(fd))
        self.stat = Mock(side_effect=self._stat)
        self.fstat = Mock(side_effect=lambda fd: self.fds[fd][1])
        self.getpid = lambda: self.pid
        self.get_inheritable = lambda fd: self.inheritable
        for name, value in (('O_RDONLY', 0), ('O_DIRECTORY', 1), ('O_NOFOLLOW', 2),
                             ('O_CLOEXEC', 4), ('O_NONBLOCK', 8)):
            setattr(self, name, value)

    def _path(self, name, dir_fd):
        if name == '/' and dir_fd is None:
            return ()
        return self.fds[dir_fd][0] + (name,)

    def _stat(self, name, *, dir_fd, follow_symlinks):
        assert follow_symlinks is False
        value = self.nodes.get(self._path(name, dir_fd))
        if value is None:
            raise FileNotFoundError(errno.ENOENT, 'PRIVATE_PATH')
        return value

    def _open(self, name, flags, *, dir_fd=None):
        assert flags & self.O_NOFOLLOW and flags & self.O_CLOEXEC
        path = self._path(name, dir_fd)
        self.next_fd += 1
        self.fds[self.next_fd] = path, self.nodes[path]
        self.calls.append((path, flags))
        return self.next_fd

    def change(self, path, **kw):
        self.nodes[path] = SimpleNamespace(**(vars(self.nodes[path]) | kw))


class MaintenanceLockTests(unittest.TestCase):
    @contextmanager
    def fake(self, fs=None, acquire=None):
        fs = LockFS() if fs is None else fs
        with patch.object(lock, 'os', fs), patch.object(lock, '_try_lock',
                Mock() if acquire is None else acquire):
            yield fs
        self.assertEqual(set(fs.fds), {10})

    def test_fixed_public_api_and_not_guard_wired(self):
        self.assertEqual(str(inspect.signature(lock.hold_maintenance_lock)), '()')
        self.assertEqual(lock.PARENT, ('run', 'alertmind-broker-maintenance'))
        self.assertEqual(lock.NAME, 'owner.lock')
        self.assertNotIn('operator_maintenance_lock.py',
                         {p[0] for p in guard.PINNED_MODULES + guard.RUNTIME_MODULES})
        self.assertNotIn('if __name__', inspect.getsource(lock))

    def test_observation_is_minimized_immutable_and_not_permission(self):
        with self.fake():
            with lock._hold_at(10) as held:
                value = held.checkpoint()
                self.assertTrue(value.cooperative_lock_held)
                self.assertTrue(value.fixed_path_rechecked)
                self.assertTrue(value.review_required)
                for name, item in asdict(value).items():
                    self.assertIs(type(item), bool)
                    if name not in ('cooperative_lock_held', 'fixed_path_rechecked', 'review_required'):
                        self.assertFalse(item, name)
                with self.assertRaises(FrozenInstanceError):
                    value.mutation_authorized = True
                self.assertEqual(repr(held), '<private maintenance lock handle>')

    def test_handle_rejected_after_context_exit(self):
        with self.fake():
            with lock._hold_at(10) as held:
                held.checkpoint()
            with self.assertRaisesRegex(core.OperatorError, 'MAINTENANCE_LOCK_CLOSED'):
                held.checkpoint()

    def test_missing_anchor_or_leaf_never_created(self):
        for path in (('run',), lock.PARENT, lock.PARENT + (lock.NAME,)):
            with self.subTest(path=path):
                fs = LockFS()
                del fs.nodes[path]
                with self.fake(fs), self.assertRaisesRegex(core.OperatorError, 'FS_MISSING'):
                    with lock._hold_at(10):
                        self.fail('missing anchor accepted')
                self.assertNotIn(path, fs.nodes)

    def test_unsafe_directory_metadata_refused(self):
        for path in ((), ('run',), lock.PARENT):
            for kw in ({'st_uid': 126}, {'st_gid': 128}, {'st_mode': stat.S_IFDIR | 0o777},
                       {'st_mode': stat.S_IFLNK | 0o777}, {'st_mode': stat.S_IFREG | 0o600}):
                with self.subTest(path=path, kw=kw):
                    fs = LockFS()
                    fs.change(path, **kw)
                    if path == ():
                        fs.fds[10] = (), fs.nodes[()]
                    acquire = Mock()
                    with self.fake(fs, acquire), self.assertRaises(core.OperatorError):
                        with lock._hold_at(10):
                            self.fail('unsafe directory accepted')
                    acquire.assert_not_called()

    def test_private_directory_requires_exact_mode(self):
        for mode in (0o750, 0o755, 0o1700, 0o2700, 0o4700):
            fs = LockFS()
            fs.change(lock.PARENT, st_mode=stat.S_IFDIR | mode)
            with self.subTest(mode=mode), self.fake(fs), self.assertRaises(core.OperatorError):
                with lock._hold_at(10):
                    self.fail('private directory mode accepted')

    def test_leaf_metadata_type_and_hardlinks_refused(self):
        for kw in ({'st_uid': 126}, {'st_gid': 128}, {'st_nlink': 0}, {'st_nlink': 2},
                   {'st_size': 1}, {'st_size': -1}, {'st_mode': stat.S_IFREG | 0o640},
                   {'st_mode': stat.S_IFREG | 0o1600}, {'st_mode': stat.S_IFLNK | 0o777},
                   {'st_mode': stat.S_IFIFO | 0o600}, {'st_mode': stat.S_IFCHR | 0o600}):
            fs = LockFS()
            fs.change(lock.PARENT + (lock.NAME,), **kw)
            acquire = Mock()
            with self.subTest(kw=kw), self.fake(fs, acquire), self.assertRaises(core.OperatorError):
                with lock._hold_at(10):
                    self.fail('unsafe leaf accepted')
            acquire.assert_not_called()

    def test_submount_device_refused(self):
        for path in (lock.PARENT, lock.PARENT + (lock.NAME,)):
            fs = LockFS()
            fs.change(path, st_dev=99)
            with self.subTest(path=path), self.fake(fs), self.assertRaisesRegex(
                    core.OperatorError, 'MAINTENANCE_LOCK_DEVICE'):
                with lock._hold_at(10):
                    self.fail('device mismatch accepted')

    def test_opened_inode_must_match_preopen_metadata(self):
        for target in (('run',), lock.PARENT, lock.PARENT + (lock.NAME,)):
            fs = LockFS()
            original = fs._open
            def replace_before_open(name, flags, *, dir_fd=None):
                path = fs._path(name, dir_fd)
                if path == target:
                    fs.change(path, st_ino=99)
                return original(name, flags, dir_fd=dir_fd)
            fs.open.side_effect = replace_before_open
            with self.subTest(target=target), self.fake(fs), self.assertRaisesRegex(
                    core.OperatorError, 'MAINTENANCE_LOCK_CHANGED'):
                with lock._hold_at(10):
                    self.fail('replacement accepted')

    def test_acquisition_race_rechecked_before_yield(self):
        fs = LockFS()
        acquire = Mock(side_effect=lambda fd: fs.change(lock.PARENT + (lock.NAME,), st_ino=99))
        with self.fake(fs, acquire), self.assertRaisesRegex(core.OperatorError, 'MAINTENANCE_LOCK_CHANGED'):
            with lock._hold_at(10):
                self.fail('changed locked path yielded')

    def test_checkpoint_and_exit_detect_named_replacement(self):
        for path in (('run',), lock.PARENT, lock.PARENT + (lock.NAME,)):
            fs = LockFS()
            with self.subTest(path=path), self.fake(fs), self.assertRaisesRegex(
                    core.OperatorError, 'MAINTENANCE_LOCK_CHANGED'):
                with lock._hold_at(10) as held:
                    fs.change(path, st_ino=99)
                    with self.assertRaisesRegex(core.OperatorError, 'MAINTENANCE_LOCK_CHANGED'):
                        held.checkpoint()
                    # Catching the error does not make a successful context exit possible.

    def test_checkpoint_missing_leaf_not_recreated(self):
        fs = LockFS()
        with self.fake(fs), self.assertRaisesRegex(core.OperatorError, 'FS_MISSING'):
            with lock._hold_at(10) as held:
                del fs.nodes[lock.PARENT + (lock.NAME,)]
                held.checkpoint()

    def test_checkpoint_metadata_change_refused(self):
        for path, kw in ((lock.PARENT, {'st_mode': stat.S_IFDIR | 0o755}),
                         (lock.PARENT, {'st_mtime_ns': 2}),
                         (lock.PARENT + (lock.NAME,), {'st_nlink': 2}),
                         (lock.PARENT + (lock.NAME,), {'st_size': 5}),
                         (lock.PARENT + (lock.NAME,), {'st_ctime_ns': 2})):
            fs = LockFS()
            with self.subTest(path=path, kw=kw), self.fake(fs), self.assertRaises(core.OperatorError):
                with lock._hold_at(10) as held:
                    fs.change(path, **kw)
                    held.checkpoint()

    def test_root_identity_drift_refused(self):
        fs = LockFS()
        with self.fake(fs), self.assertRaisesRegex(core.OperatorError, 'MAINTENANCE_LOCK_CHANGED'):
            with lock._hold_at(10) as held:
                fs.fds[10] = (), metadata(st_ino=99)
                held.checkpoint()

    def test_unrelated_run_timestamp_change_allowed(self):
        fs = LockFS()
        with self.fake(fs):
            with lock._hold_at(10) as held:
                fs.change(('run',), st_mtime_ns=99, st_ctime_ns=99)
                held.checkpoint()

    def test_inheritable_descriptor_refused_before_lock(self):
        fs = LockFS()
        fs.inheritable = True
        acquire = Mock()
        with self.fake(fs, acquire), self.assertRaisesRegex(core.OperatorError, 'MAINTENANCE_LOCK_INHERITABLE'):
            with lock._hold_at(10):
                self.fail('inheritable fd accepted')
        acquire.assert_not_called()

    def test_inheritable_change_refused_at_checkpoint(self):
        fs = LockFS()
        with self.fake(fs), self.assertRaisesRegex(core.OperatorError, 'MAINTENANCE_LOCK_INHERITABLE'):
            with lock._hold_at(10) as held:
                fs.inheritable = True
                held.checkpoint()

    def test_changed_process_cannot_use_or_exit_handle_successfully(self):
        fs = LockFS()
        acquire = Mock()
        with self.fake(fs, acquire), self.assertRaisesRegex(core.OperatorError, 'MAINTENANCE_LOCK_OWNER'):
            with lock._hold_at(10) as held:
                fs.pid += 1
                with self.assertRaisesRegex(core.OperatorError, 'MAINTENANCE_LOCK_OWNER'):
                    held.checkpoint()
        acquire.assert_called_once()  # No explicit unlock, including the child exit path.

    def test_body_exception_closes_and_invalidates_without_swallowing(self):
        sentinel = RuntimeError('synthetic caller failure')
        with self.fake():
            with self.assertRaises(RuntimeError) as caught:
                with lock._hold_at(10) as held:
                    raise sentinel
            self.assertIs(caught.exception, sentinel)
            with self.assertRaisesRegex(core.OperatorError, 'MAINTENANCE_LOCK_CLOSED'):
                held.checkpoint()

    def test_busy_lock_never_yields_and_closes_descriptors(self):
        with self.fake(acquire=Mock(side_effect=core.OperatorError('MAINTENANCE_LOCK_BUSY'))):
            with self.assertRaisesRegex(core.OperatorError, 'MAINTENANCE_LOCK_BUSY'):
                with lock._hold_at(10):
                    self.fail('busy lock yielded')

    def test_fixed_nonblocking_exclusive_flock(self):
        api = SimpleNamespace(LOCK_EX=2, LOCK_NB=4, flock=Mock())
        with patch.dict(sys.modules, {'fcntl': api}):
            lock._try_lock(41)
        api.flock.assert_called_once_with(41, 6)

    def test_flock_failures_sanitized_without_retry(self):
        for error, expected in ((errno.EAGAIN, 'BUSY'), (errno.EACCES, 'BUSY'),
                                (errno.EINTR, 'ACQUIRE'), (errno.ENOLCK, 'ACQUIRE')):
            api = SimpleNamespace(LOCK_EX=2, LOCK_NB=4,
                flock=Mock(side_effect=OSError(error, 'PRIVATE_DETAIL')))
            with self.subTest(error=error), patch.dict(sys.modules, {'fcntl': api}):
                with self.assertRaisesRegex(core.OperatorError, 'MAINTENANCE_LOCK_' + expected) as caught:
                    lock._try_lock(41)
                self.assertNotIn('PRIVATE_DETAIL', str(caught.exception))
                api.flock.assert_called_once()

    def test_close_error_not_retried_or_exposed(self):
        with patch.object(lock.os, 'close', side_effect=OSError('PRIVATE_DETAIL')) as close:
            with self.assertRaisesRegex(core.OperatorError, '^MAINTENANCE_LOCK_CLEANUP$'):
                lock._close(42)
            close.assert_called_once_with(42)

    def test_no_payload_io_or_create_or_unlink(self):
        with self.fake() as fs:
            original = {p: vars(s).copy() for p, s in fs.nodes.items()}
            with lock._hold_at(10) as held:
                held.checkpoint()
            self.assertEqual(original, {p: vars(s) for p, s in fs.nodes.items()})
            self.assertEqual(fs.calls, [(('run',), 7), (lock.PARENT, 7),
                                       (lock.PARENT + (lock.NAME,), 14)])

    def test_public_platform_guard_precedes_open(self):
        with (patch.object(lock.fs, '_platform', side_effect=core.OperatorError('FS_PLATFORM')),
              patch.object(lock.os, 'open') as opened):
            with self.assertRaisesRegex(core.OperatorError, 'FS_PLATFORM'):
                with lock.hold_maintenance_lock():
                    self.fail('platform bypass')
            opened.assert_not_called()

    def test_public_root_closes_on_body_error(self):
        fs = LockFS()
        with self.fake(fs), patch.object(lock.fs, '_platform'):
            with self.assertRaisesRegex(RuntimeError, 'caller'):
                with lock.hold_maintenance_lock():
                    raise RuntimeError('caller')
            self.assertEqual(fs.calls[0], ((), 7))


@unittest.skipUnless(sys.platform == 'linux', 'Linux flock/descriptor fixture only')
class NativeMaintenanceLockTests(unittest.TestCase):
    @contextmanager
    def fixture(self):
        # Normalize ownership for unprivileged CI only. Paths, modes, inode
        # replacement, descriptors and kernel flock are real disposable objects.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = root.joinpath(*lock.PARENT)
            parent.mkdir(parents=True, mode=0o700)
            parent.chmod(0o700)
            target = parent / lock.NAME
            target.touch(mode=0o600)
            target.chmod(0o600)
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            original_stat, original_fstat = os.stat, os.fstat
            def norm(value):
                return SimpleNamespace(**{name: (0 if name in ('st_uid', 'st_gid') else getattr(value, name))
                    for name in vars(metadata())})
            try:
                with (patch.object(lock.os, 'stat', side_effect=lambda *a, **k: norm(original_stat(*a, **k))),
                      patch.object(lock.os, 'fstat', side_effect=lambda fd: norm(original_fstat(fd)))):
                    yield root_fd, target
            finally:
                os.close(root_fd)

    def test_native_contention_release_and_no_file_mutation(self):
        with self.fixture() as (root, target):
            before = target.stat()
            with lock._hold_at(root) as held:
                held.checkpoint()
                with self.assertRaisesRegex(core.OperatorError, 'MAINTENANCE_LOCK_BUSY'):
                    with lock._hold_at(root):
                        self.fail('simultaneous acquisition')
            with lock._hold_at(root) as replacement:
                replacement.checkpoint()
            self.assertEqual(lock.fs._stamp(before), lock.fs._stamp(target.stat()))

    def test_native_symlink_hardlink_and_replacement_denied(self):
        with self.fixture() as (root, target):
            original = target.with_name('original')
            target.rename(original)
            target.symlink_to(original)
            with self.assertRaises(core.OperatorError):
                with lock._hold_at(root):
                    self.fail('symlink accepted')
            target.unlink()
            os.link(original, target)
            with self.assertRaises(core.OperatorError):
                with lock._hold_at(root):
                    self.fail('hardlink accepted')
            original.unlink()
            with self.assertRaisesRegex(core.OperatorError, 'MAINTENANCE_LOCK_CHANGED'):
                with lock._hold_at(root):
                    target.rename(original)
                    target.touch(mode=0o600)

    def test_native_independent_process_contention_and_exception_release(self):
        # Child accesses ONLY the disposable lock fixture, not /run or a service.
        code = ('import fcntl,os,sys\nfd=os.open(sys.argv[1],os.O_RDONLY)\n'
                'try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)\n'
                'except BlockingIOError: sys.exit(23)\n'
                'finally: os.close(fd)\n')
        with self.fixture() as (root, target):
            def probe():
                return subprocess.run([sys.executable, '-I', '-S', '-B', '-c', code, str(target)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    close_fds=True, timeout=10, check=False).returncode
            with self.assertRaisesRegex(RuntimeError, 'abort'):
                with lock._hold_at(root):
                    self.assertEqual(probe(), 23)
                    raise RuntimeError('abort')
            self.assertEqual(probe(), 0)


if __name__ == '__main__':
    unittest.main()
