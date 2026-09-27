"""Native mapping policy and descriptor tests; no lab access or subject execution."""
import ast
from dataclasses import FrozenInstanceError, replace
import errno
import hashlib
import inspect
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_core as core
from siem.rbac.broker_tls import operator_fs as fs
from siem.rbac.broker_tls import operator_python_policy as policy
from siem.rbac.broker_tls import operator_python_native as native
from siem.rbac.broker_tls import operator_guard_entry as entry
if __package__:
    from .test_broker_tls_operator_fs import metadata
else:
    from test_broker_tls_operator_fs import metadata


def maps_text(pins=policy.MAPPED_FILES):
    lines = []
    for i, pin in enumerate(pins):
        start = (i + 1) * 0x10000
        for offset, perms in ((0, 'r--p'), (4096, 'r-xp')):
            lines.append(f'{start + offset:08x}-{start + offset + 4096:08x} '
                         f'{perms} {offset:08x} 08:01 {100 + i}   {pin.path}\n')
    # The kernel emits a trailing space even when there is no pathname.
    lines.extend(('00100000-00102000 rw-p 00000000 00:00 0 \n',
                  '00200000-00202000 rw-p 00000000 00:00 0   [heap]\n',
                  '00300000-00302000 r-xp 00000000 00:00 0   [vdso]\n'))
    return ''.join(lines).encode()


class NativeMapsPolicyTests(unittest.TestCase):
    def test_all_nine_pins_all_segments_and_kernel_executable_retained(self):
        rows = native._parse_maps(maps_text())
        self.assertEqual(len(rows), 19)
        self.assertEqual({r.path for r in rows if r.inode}, {p.path for p in policy.MAPPED_FILES})
        self.assertEqual(rows[0].link, '10000-11000')
        self.assertEqual(rows[-1].path, '[vdso]')
        self.assertEqual(native._parse_maps(maps_text().replace(b'0 \n', b'0\n')), rows)
        self.assertEqual(native._parse_maps(maps_text().replace(b'0 \n', b'0    \n')), rows)

    def test_size_type_ascii_rows_and_line_bounds(self):
        for raw in (b'', None, bytearray(maps_text()), maps_text().decode(),
                    b'x' * (native.MAX_MAPS + 1)):
            with self.assertRaisesRegex(core.OperatorError, '^PY_MAPS_SIZE$'):
                native._parse_maps(raw)
        for raw in (maps_text()[:-1], maps_text().replace(b'08:01', b'08:\xff', 1),
                    maps_text() + b'\n', maps_text().replace(b'   /usr', b'   \t/usr', 1),
                    maps_text().replace(b'08:01', b'8:01', 1), b'x' * 513 + b'\n',
                    maps_text().replace(b'\n', b'\r\n')):
            with self.assertRaises(core.OperatorError):
                native._parse_maps(raw)
        with patch.object(native, 'MAX_ROWS', 1), self.assertRaisesRegex(core.OperatorError, '^PY_MAPS_FORMAT$'):
            native._parse_maps(maps_text())

    def test_unknown_deleted_memfd_and_escaped_paths_fail(self):
        for name in (b'/tmp/other.so', b'/memfd:payload (deleted)', b'/usr/bin/python3.14 (deleted)',
                     b'/usr/bin/python3.14\\012', b'[anon:custom]', b'/usr/bin/../bin/python3.14'):
            with self.subTest(name=name), self.assertRaises(core.OperatorError):
                native._parse_maps(maps_text().replace(b'/usr/bin/python3.14', name))

    def test_shared_writable_executable_and_anonymous_exec_fail(self):
        for before, after in ((b'r--p', b'r--s'), (b'r-xp', b'rwxp'),
                              (b'00102000 rw-p', b'00102000 r-xp')):
            with self.assertRaises(core.OperatorError):
                native._parse_maps(maps_text().replace(before, after, 1))

    def test_file_set_missing_readonly_only_and_no_offset_zero_fail(self):
        lines = maps_text().splitlines(keepends=True)
        for pin in policy.MAPPED_FILES:
            with self.subTest(pin=pin.path), self.assertRaisesRegex(core.OperatorError, '^PY_MAPS_MISSING$'):
                native._parse_maps(b''.join(x for x in lines if pin.path.encode() not in x))
        for raw in (maps_text().replace(b'r-xp 00001000', b'r--p 00001000'), b''.join(lines[1:])):
            with self.assertRaisesRegex(core.OperatorError, '^PY_MAPS_MISSING$'):
                native._parse_maps(raw)

    def test_mixed_file_inode_zero_device_and_huge_inode_fail(self):
        for a, b in ((b'08:01 100', b'00:00 100'), (b'08:01 100', b'08:01 0'),
                     (b'08:01 100', b'08:01 101'), (b'08:01 100', b'08:01 18446744073709551616')):
            with self.assertRaisesRegex(core.OperatorError, '^PY_MAPS_IDENTITY$'):
                native._parse_maps(maps_text().replace(a, b, 1))

    def test_ranges_order_alignment_overlap_offset_and_eof(self):
        for a, b in ((b'00010000-00011000', b'00010000-00010000'),
                     (b'00010000-00011000', b'00010001-00011000'),
                     (b'00011000-00012000', b'00010000-00012000'),
                     (b'00001000 08:01', b'00001001 08:01'),
                     (b'00001000 08:01', b'fffff000 08:01'),
                     (b'00010000-00011000', b'00010000-10011000')):
            with self.assertRaises(core.OperatorError):
                native._parse_maps(maps_text().replace(a, b, 1))

    def test_kernel_names_not_generic_executable_exception(self):
        for a, b in ((b'[vdso]', b'[other]'), (b'[vdso]', b'[stack]'),
                     (b'r-xp 00000000 00:00', b'rwxp 00000000 00:00'),
                     (b'0   [vdso]', b'1   [vdso]')):
            with self.assertRaises(core.OperatorError):
                native._parse_maps(maps_text().replace(a, b))
        with self.assertRaisesRegex(core.OperatorError, '^PY_MAPS_VDSO$'):
            native._parse_maps(maps_text().split(b'00300000')[0])
        with self.assertRaises(core.OperatorError):
            native._parse_maps(maps_text() + b'00400000-00401000 r-xp 00000000 00:00 0   [vdso]\n')

    def test_nonexecutable_anonymous_growth_is_intentionally_not_snapshot_equality(self):
        before = native._parse_maps(maps_text())
        after = native._parse_maps(maps_text().replace(b'00102000', b'00103000'))
        self.assertEqual(before, after)
        changed = native._parse_maps(maps_text().replace(b'00302000', b'00303000'))
        self.assertNotEqual(before, changed)

    def test_segment_work_bound_and_named_kernel_variants(self):
        extra = (b'00400000-00401000 r--p 00000000 00:00 0   [vvar]\n'
                 b'00500000-00501000 r--p 00000000 00:00 0   [vvar_vclock]\n'
                 b'00600000-00601000 rw-p 00000000 00:00 0   [stack]\n'
                 b'ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0   [vsyscall]\n')
        self.assertEqual(len(native._parse_maps(maps_text() + extra)), 20)
        pin = policy.MAPPED_FILES[0].path
        rows = b''.join(f'{i * 4096:08x}-{(i + 1) * 4096:08x} r--p 00000000 08:01 100 {pin}\n'.encode()
                        for i in range(1, 18))
        with self.assertRaisesRegex(core.OperatorError, '^PY_MAPS_SEGMENTS$'):
            native._parse_maps(rows)


class NativeOS:
    """Held-descriptor model: proc magic links only, no real OS side effects."""
    O_RDONLY, O_NOFOLLOW, O_NONBLOCK, O_CLOEXEC, O_DIRECTORY = 0, 1, 2, 4, 8
    SEEK_SET = 0

    def __init__(self):
        self.nodes, self.contents, self.links, self.fds = {}, {}, {}, {}
        self.next_fd = 10
        self.pins = []
        self.add('/', directory=True)
        for directory in ('/proc', '/proc/1234', '/proc/1234/map_files'):
            self.add(directory, directory=True)
        for i, pin in enumerate(policy.MAPPED_FILES):
            blob = bytes([65 + i]) * 8192
            self.pins.append(replace(pin, size=len(blob), sha256=hashlib.sha256(blob).hexdigest()))
            self.add(pin.path, blob, inode=100 + i, device=0x801)
            start = (i + 1) * 0x10000
            for offset in (0, 4096):
                self.links[f'/proc/1234/map_files/{start + offset:x}-{start + offset + 4096:x}'] = pin.path
        self.links['/proc/1234/exe'] = policy.MAPPED_FILES[0].path
        self.add('/proc/1234/maps', maps_text(), inode=99)
        self.nodes['/proc/1234/maps'].st_size = 0
        self.open = Mock(side_effect=self._open)
        self.close = Mock(side_effect=lambda fd: self.fds.pop(fd))
        self.stat = Mock(side_effect=self._stat)
        self.fstat = Mock(side_effect=lambda fd: self.nodes[self.fds[fd][0]])
        self.read = Mock(side_effect=self._read)
        self.readlink = Mock(side_effect=lambda name, dir_fd: self.links[self.resolve(name, dir_fd)])
        self.lseek = Mock(side_effect=self._seek)
        self.getpid = Mock(return_value=1234)
        self.major = lambda dev: dev >> 8
        self.minor = lambda dev: dev & 255
        self.supports_dir_fd = {self.readlink}

    def add(self, path, blob=b'', *, directory=False, inode=None, device=1):
        if path != '/':
            parent = path.rsplit('/', 1)[0] or '/'
            if parent not in self.nodes:
                self.add(parent, directory=True)
        self.nodes[path] = metadata(directory, st_ino=inode or 1000 + len(self.nodes),
                                    st_dev=device, st_size=len(blob))
        self.contents[path] = blob

    def resolve(self, name, parent):
        return name if parent is None else self.fds[parent][0].rstrip('/') + '/' + name

    def _open(self, name, flags, dir_fd=None):
        path = self.resolve(name, dir_fd)
        if path in self.links:
            if flags & self.O_NOFOLLOW:
                raise OSError(errno.ELOOP, 'PRIVATE')
            path = self.links[path]
        if path not in self.nodes:
            raise FileNotFoundError(errno.ENOENT, 'PRIVATE')
        fd, self.next_fd = self.next_fd, self.next_fd + 1
        self.fds[fd] = [path, 0]
        return fd

    def _stat(self, name, dir_fd=None, follow_symlinks=False):
        path = self.resolve(name, dir_fd)
        if path in self.links:
            if not follow_symlinks:
                return metadata(st_mode=stat.S_IFLNK | 0o777)
            path = self.links[path]
        return self.nodes[path]

    def _read(self, fd, count):
        path, pos = self.fds[fd]
        chunk = self.contents[path][pos:pos + count]
        self.fds[fd][1] += len(chunk)
        return chunk

    def _seek(self, fd, offset, whence):
        assert offset == whence == 0
        self.fds[fd][1] = 0


class NativeObservationTests(unittest.TestCase):
    def setUp(self):
        self.fake = NativeOS()
        for context in (patch.object(native, 'os', self.fake), patch.object(fs, '_platform'),
                        patch.object(policy, 'MAPPED_FILES', tuple(self.fake.pins))):
            context.start()
            self.addCleanup(context.stop)

    def observe(self):
        try:
            return native.observe_python_native()
        finally:
            self.assertEqual(self.fake.fds, {}, 'all descriptors close, even on denial')

    def test_two_byte_passes_four_maps_reads_no_authorization(self):
        result = self.observe()
        self.assertEqual(result.file_count, 9)
        self.assertEqual(result.maps_reads, 4)
        self.assertEqual(self.fake.lseek.call_count, 18)
        self.assertEqual(sum(c.args[0] == 'maps' for c in self.fake.open.call_args_list), 4)
        self.assertTrue(result.mapped_backing_pins_match)
        for name in ('native_resolution_proven', 'loaded_memory_proven', 'symbol_bindings_proven',
                     'package_authenticity_proven', 'atomic_snapshot_proven', 'runtime_trusted', 'startup_authorized'):
            self.assertIs(getattr(result, name), False)
        with self.assertRaises(FrozenInstanceError):
            result.startup_authorized = True

    def test_only_fixed_root_self_paths_and_explicit_map_magic_links_opened(self):
        self.observe()
        calls = self.fake.open.call_args_list
        self.assertEqual(calls[0].args, ('/', 13))
        magic = [c for c in calls if not c.args[1] & self.fake.O_NOFOLLOW]
        self.assertEqual(len(magic), 9)
        self.assertTrue(all('-' in c.args[0] and c.kwargs.get('dir_fd') for c in magic))
        self.assertTrue(all(c.args[1] & self.fake.O_CLOEXEC for c in calls))
        self.assertNotIn('self', [c.args[0] for c in calls])
        self.assertEqual(inspect.signature(native.observe_python_native).parameters, {})

    def test_wrong_platform_pid_or_capability_before_open(self):
        with patch.object(fs, '_platform', side_effect=core.OperatorError('FS_PLATFORM')):
            with self.assertRaisesRegex(core.OperatorError, '^FS_PLATFORM$'):
                self.observe()
        for pid in (True, 0, 1, -1, 2**32):
            self.fake.getpid.return_value = pid
            with self.assertRaisesRegex(core.OperatorError, '^PY_NATIVE_PID$'):
                self.observe()
        self.fake.getpid.return_value = 1234
        self.fake.supports_dir_fd = set()
        with self.assertRaisesRegex(core.OperatorError, '^PY_NATIVE_PLATFORM$'):
            self.observe()
        self.fake.open.assert_not_called()

    def test_unexpected_mapping_rejected_before_any_file_payload_read(self):
        self.fake.contents['/proc/1234/maps'] = maps_text().replace(b'/usr/bin/python3.14', b'/tmp/PRIVATE')
        with self.assertRaisesRegex(core.OperatorError, '^PY_MAPS_UNEXPECTED$'):
            self.observe()
        self.fake.lseek.assert_not_called()

    def test_changed_or_deleted_link_target_never_opened(self):
        self.fake.links['/proc/1234/map_files/10000-11000'] += ' (deleted)'
        with self.assertRaisesRegex(core.OperatorError, '^PY_NATIVE_LINK$'):
            self.observe()
        self.assertFalse(any(not c.args[1] & 1 for c in self.fake.open.call_args_list))

    def test_each_file_digest_is_enforced(self):
        for pin in self.fake.pins:
            original = self.fake.contents[pin.path]
            self.fake.contents[pin.path] = b'x' * len(original)
            with self.subTest(path=pin.path), self.assertRaisesRegex(core.OperatorError, '^PY_NATIVE_DIGEST$'):
                self.observe()
            self.fake.contents[pin.path] = original

    def test_size_and_mapped_inode_mismatch(self):
        pin = self.fake.pins[0]
        self.fake.nodes[pin.path].st_size += 1
        with self.assertRaisesRegex(core.OperatorError, '^PY_NATIVE_SIZE$'):
            self.observe()
        self.fake.nodes[pin.path].st_size -= 1
        self.fake.nodes[pin.path].st_ino += 1
        with self.assertRaisesRegex(core.OperatorError, '^PY_NATIVE_IDENTITY$'):
            self.observe()

    def test_wrong_executable_not_interchangeable_with_loaded_library(self):
        self.fake.links['/proc/1234/exe'] = self.fake.pins[1].path
        with self.assertRaisesRegex(core.OperatorError, '^PY_NATIVE_EXECUTABLE$'):
            self.observe()

    def test_file_and_ancestor_ownership_mode_and_symlink_rejected(self):
        for path in ('/', '/proc', '/proc/1234', '/proc/1234/map_files', '/usr', self.fake.pins[0].path):
            before = vars(self.fake.nodes[path]).copy()
            for key, value in (('st_uid', 1000), ('st_gid', 1000),
                               ('st_mode', before['st_mode'] | 0o020), ('st_mode', stat.S_IFLNK | 0o777)):
                setattr(self.fake.nodes[path], key, value)
                with self.subTest(path=path, key=key), self.assertRaisesRegex(core.OperatorError, '^FS_METADATA$'):
                    self.observe()
                self.fake.nodes[path] = NS(**before)

    def test_maps_drift_at_every_later_read_fails(self):
        real = native._read_maps
        for fail_at in (2, 3, 4):
            count = 0
            def changed(fd):
                nonlocal count
                count += 1
                result = real(fd)
                return result[:-1] if count == fail_at else result
            with patch.object(native, '_read_maps', new=changed), self.assertRaisesRegex(
                    core.OperatorError, '^PY_NATIVE_MAPS_CHANGED$'):
                self.observe()

    def test_file_metadata_drift_after_read_and_ancestor_drift(self):
        real = native._hash_fd
        for target in (self.fake.pins[0].path, '/usr', '/'):
            original = self.fake.nodes[target]
            def changed(*args):
                real(*args)
                values = vars(original).copy()
                values['st_ino'] += 1
                self.fake.nodes[target] = NS(**values)
            with patch.object(native, '_hash_fd', new=changed), self.assertRaisesRegex(
                    core.OperatorError, '^PY_NATIVE_(IDENTITY|CHANGED|EXECUTABLE)$'):
                self.observe()
            self.fake.nodes[target] = original

    def test_magic_link_permission_failure_has_no_path_hash_fallback(self):
        real = self.fake._open
        def denied(name, flags, dir_fd=None):
            if not flags & 1:
                raise PermissionError(errno.EPERM, 'PRIVATE')
            return real(name, flags, dir_fd)
        self.fake.open.side_effect = denied
        with self.assertRaisesRegex(core.OperatorError, '^FS_ACCESS$') as caught:
            self.observe()
        self.assertTrue(caught.exception.__suppress_context__)
        self.fake.lseek.assert_not_called()

    def test_all_segments_checked_not_just_first_and_links_rechecked_after_hash(self):
        key = '/proc/1234/map_files/11000-12000'
        self.fake.links[key] = self.fake.pins[1].path
        with self.assertRaisesRegex(core.OperatorError, '^PY_NATIVE_LINK$'):
            self.observe()
        self.fake.links[key] = self.fake.pins[0].path
        real = native._hash_fd
        def change_after_hash(*args):
            real(*args)
            self.fake.links[key] = self.fake.pins[1].path
        with patch.object(native, '_hash_fd', new=change_after_hash), self.assertRaisesRegex(
                core.OperatorError, '^PY_NATIVE_LINK$'):
            self.observe()

    def test_backing_descriptor_swap_and_named_open_race(self):
        real = self.fake._open
        for magic in (False, True):
            def swapped(name, flags, dir_fd=None):
                fd = real(name, flags, dir_fd)
                if (magic and not flags & 1) or (not magic and name == 'python3.14' and not flags & 8):
                    self.fake.fds[fd][0] = self.fake.pins[1].path
                return fd
            self.fake.open.side_effect = swapped
            with self.assertRaisesRegex(core.OperatorError, '^PY_NATIVE_(CHANGED|IDENTITY)$'):
                self.observe()

    def test_payload_length_and_second_pass_hash_not_optional(self):
        pin = self.fake.pins[0]
        original = self.fake.contents[pin.path]
        for content in (original[:-1], original + b'x'):
            self.fake.contents[pin.path] = content
            with self.assertRaisesRegex(core.OperatorError, '^PY_NATIVE_SIZE$'):
                self.observe()
        self.fake.contents[pin.path] = original
        real = native._hash_fd
        count = 0
        def changed(*args):
            nonlocal count
            real(*args)
            count += 1
            if count == 9:
                self.fake.contents[pin.path] = b'z' * len(original)
        with patch.object(native, '_hash_fd', new=changed), self.assertRaisesRegex(
                core.OperatorError, '^PY_NATIVE_DIGEST$'):
            self.observe()

    def test_metadata_change_during_hash_is_rejected(self):
        real = self.fake._read
        pin = self.fake.pins[0]
        def changed(fd, count):
            result = real(fd, count)
            if self.fake.fds[fd][0] == pin.path:
                values = vars(self.fake.nodes[pin.path]).copy()
                values['st_mtime_ns'] += 1
                self.fake.nodes[pin.path] = NS(**values)
            return result
        self.fake.read.side_effect = changed
        with self.assertRaisesRegex(core.OperatorError, '^PY_NATIVE_CHANGED$'):
            self.observe()

    def test_failures_close_fds_and_errors_do_not_echo_paths(self):
        for call in ('open', 'stat', 'fstat', 'read', 'readlink', 'lseek'):
            mock = getattr(self.fake, call)
            real = mock.side_effect
            mock.side_effect = OSError(errno.EIO, 'PRIVATE_VALUE')
            with self.subTest(call=call), self.assertRaisesRegex(core.OperatorError, '^FS_IO$') as caught:
                self.observe()
            self.assertIsNone(caught.exception.__cause__)
            mock.side_effect = real

    def test_maps_byte_limit_reads_one_extra_byte_and_closes(self):
        with patch.object(native, 'MAX_MAPS', 10), self.assertRaisesRegex(core.OperatorError, '^PY_MAPS_SIZE$'):
            self.observe()
        self.assertEqual(self.fake.read.call_args.args[1], 11)

    def test_no_activation_import_or_capsule_expansion(self):
        source = inspect.getsource(native)
        tree = ast.parse(source, feature_version=(3, 10))
        calls = {ast.unparse(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
        for forbidden in ('eval', 'exec', 'compile', 'open', 'os.write', 'os.system', 'os.listdir',
                          'os.scandir', 'os.execve', 'subprocess.run', 'ctypes.CDLL'):
            self.assertNotIn(forbidden, calls)
        self.assertNotIn('operator_python_native.py', {pin[0] for pin in entry.PINNED_MODULES})
        self.assertIn('operator_python_native.py', {pin[0] for pin in entry.RUNTIME_MODULES})
        self.assertEqual(len(entry.PINNED_MODULES), 13)


@unittest.skipUnless(sys.platform == 'linux', 'real no-follow descriptors require Linux')
class NativeDescriptorTests(unittest.TestCase):
    def test_actual_temporary_tree_file_and_symlink_cleanup(self):
        # Test the syscall path as the test user, not root-policy acceptance.
        from contextlib import ExitStack
        trusted = fs._trusted
        def local_owner(st, directory, owners):
            trusted(st, directory, ((os.getuid(), os.getgid()),))
        with tempfile.TemporaryDirectory() as tmp, patch.object(fs, '_trusted', new=local_owner):
            path = Path(tmp) / 'file'
            path.write_bytes(b'fixture')
            (Path(tmp) / 'link').symlink_to(path)
            with ExitStack() as stack:
                root = os.open(tmp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                stack.callback(os.close, root)
                records = []
                fd = native._open_checked(stack, root, 'file', records, directory=False)
                self.assertEqual(os.read(fd, 20), b'fixture')
                native._recheck(records)
                with self.assertRaisesRegex(core.OperatorError, '^FS_METADATA$'):
                    native._open_checked(stack, root, 'link', records, directory=False)
            with self.assertRaises(OSError):
                os.fstat(fd)


if __name__ == '__main__':
    unittest.main()
