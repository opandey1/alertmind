"""Offline guard-entry candidate checks; no systemd, VM or installer action."""
import ast
from contextlib import nullcontext, redirect_stderr
import hashlib
from io import StringIO
from pathlib import Path
import stat
import sys
from types import CodeType, SimpleNamespace as NS
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_guard_entry as entry


def metadata(directory=True, **changes):
    values = dict(st_dev=1, st_ino=10, st_mode=(stat.S_IFDIR if directory else stat.S_IFREG) |
                  (0o755 if directory else 0o644), st_uid=0, st_gid=0,
                  st_nlink=2 if directory else 1,
                  st_size=4096 if directory else 120, st_mtime_ns=1, st_ctime_ns=1)
    values.update(changes)
    return NS(**values)


class FakeOS:
    O_RDONLY, O_NOFOLLOW, O_CLOEXEC, O_DIRECTORY, O_NONBLOCK = 0, 1, 2, 4, 8

    def __init__(self):
        self.nodes = {10: metadata()}
        self.names = {}
        parent = 10
        for index, name in enumerate(entry.ENTRY_PARTS):
            child = 11 + index
            self.names[parent, name] = child
            self.nodes[child] = metadata(index < len(entry.ENTRY_PARTS) - 1,
                                         st_ino=child)
            parent = child
        self.contents = {}
        self.offsets = {}
        self.scan_aliases = {}
        self.next_scan_fd = 40
        for index, (name, _, _) in enumerate(entry.PINNED_MODULES):
            child = 20 + index
            raw = (Path(entry.__file__).parent / name).read_bytes()
            self.names[14, name] = child
            self.nodes[child] = metadata(False, st_ino=child, st_size=len(raw))
            self.contents[child] = raw
        self.open = Mock(side_effect=self._open)
        self.stat = Mock(side_effect=self._stat)
        self.fstat = Mock(side_effect=lambda fd: self.nodes[fd])
        self.close = Mock()
        self.listdir = Mock(side_effect=self._listdir)
        self.scandir = Mock(side_effect=lambda fd: nullcontext(
            (NS(name=name) for name in self.listdir(fd))))
        self.read = Mock(side_effect=self._read)
        self.geteuid = lambda: 0
        self.supports_dir_fd = {self.open, self.stat}
        self.supports_follow_symlinks = {self.stat}
        self.supports_fd = {self.scandir}

    def _open(self, name, flags, dir_fd=None):
        if name == '/':
            return 10
        if name == '.':
            scan_fd = self.next_scan_fd
            self.next_scan_fd += 1
            self.nodes[scan_fd] = self.nodes[dir_fd]
            self.scan_aliases[scan_fd] = dir_fd
            return scan_fd
        return self.names[dir_fd, name]

    def _stat(self, name, dir_fd, follow_symlinks):
        return self.nodes[self.names[dir_fd, name]]

    def _listdir(self, fd):
        parent_fd = self.scan_aliases.get(fd, fd)
        return [name for parent, name in self.names if parent == parent_fd]

    def _read(self, fd, length):
        offset = self.offsets.get(fd, 0)
        result = self.contents[fd][offset:offset + length]
        self.offsets[fd] = offset + len(result)
        return result


def isolated_sys(**changes):
    values = dict(platform='linux', argv=[entry.ENTRY_PATH], path=['/usr/lib/python3.14'],
                  flags=NS(isolated=1, ignore_environment=1, no_site=1,
                           dont_write_bytecode=1), stderr=StringIO(),
                  modules=sys.modules, meta_path=sys.meta_path)
    values.update(changes)
    return NS(**values)


class GuardEntryTests(unittest.TestCase):
    def test_fixed_candidate_path_and_no_project_import_before_checks(self):
        self.assertEqual(entry.ENTRY_PATH, '/usr/local/libexec/alertmind-broker-tls/guard_entry.py')
        self.assertEqual('/' + '/'.join(entry.ENTRY_PARTS), entry.ENTRY_PATH)
        source = Path(entry.__file__).read_text(encoding='utf-8')
        tree = ast.parse(source)
        imports = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]
        self.assertEqual([node.module if isinstance(node, ast.ImportFrom) else node.names[0].name
                          for node in imports], ['contextlib', 'hashlib', 'os', 'stat', 'sys'])

    def test_no_success_path_even_when_entry_checks_pass(self):
        output = StringIO()
        with patch.object(entry, '_check_entry') as checked, redirect_stderr(output):
            self.assertEqual(entry.main(), 1)
        checked.assert_called_once_with()
        self.assertEqual(output.getvalue(), 'GUARD_NOT_READY\n')

    def test_failures_emit_only_static_codes_and_nonzero(self):
        for error, expected in ((entry.GuardLaunchError('GUARD_PATH'), 'GUARD_PATH'),
                                (OSError('PRIVATE'), 'GUARD_UNEXPECTED')):
            output = StringIO()
            with self.subTest(code=expected), patch.object(entry, '_check_entry',
                    side_effect=error), redirect_stderr(output):
                self.assertEqual(entry.main(), 1)
            self.assertEqual(output.getvalue(), expected + '\n')
            self.assertNotIn('PRIVATE', output.getvalue())

    def test_isolated_root_python_and_exact_entry_argument_required(self):
        fs = FakeOS()
        with patch.object(entry, 'os', fs), patch.object(entry, 'sys', isolated_sys()):
            entry._check_isolation()
        for kwargs, code in ((dict(platform='win32'), 'GUARD_PLATFORM'),
                             (dict(argv=['-c']), 'GUARD_ARGUMENTS'),
                             (dict(argv=[entry.ENTRY_PATH, '--unsafe']), 'GUARD_ARGUMENTS'),
                             (dict(path=['', '/usr/lib']), 'GUARD_IMPORT_PATH'),
                             (dict(path=[entry.CANDIDATE_ROOT]), 'GUARD_IMPORT_PATH'),
                             (dict(flags=NS(isolated=0, ignore_environment=1,
                                            no_site=1, dont_write_bytecode=1)), 'GUARD_ISOLATION'),
                             (dict(flags=NS(isolated=1, ignore_environment=1,
                                            no_site=1, dont_write_bytecode=0)), 'GUARD_ISOLATION')):
            with self.subTest(kwargs=kwargs), patch.object(entry, 'os', FakeOS()), patch.object(
                    entry, 'sys', isolated_sys(**kwargs)), self.assertRaisesRegex(
                    entry.GuardLaunchError, '^' + code + '$'):
                entry._check_isolation()
        fs = FakeOS(); fs.geteuid = lambda: 1000
        with patch.object(entry, 'os', fs), patch.object(entry, 'sys', isolated_sys()), self.assertRaisesRegex(
                entry.GuardLaunchError, '^GUARD_PLATFORM$'):
            entry._check_isolation()

    def test_descriptor_walk_is_fixed_no_follow_and_closes_all_children(self):
        fs = FakeOS()
        with patch.object(entry, 'os', fs):
            entry._check_entry_at(10)
        self.assertEqual([call.args[0] for call in fs.open.call_args_list], list(entry.ENTRY_PARTS))
        self.assertTrue(all(call.args[1] & fs.O_NOFOLLOW for call in fs.open.call_args_list))
        self.assertTrue(fs.open.call_args_list[-1].args[1] & fs.O_NONBLOCK)
        self.assertTrue(all(call.args[1] & fs.O_DIRECTORY for call in fs.open.call_args_list[:-1]))
        self.assertFalse(fs.open.call_args_list[-1].args[1] & fs.O_DIRECTORY)
        self.assertEqual([call.args[0] for call in fs.close.call_args_list], [15, 14, 13, 12, 11])
        self.assertEqual(fs.stat.call_count, 10)
        self.assertTrue(all(call.kwargs['follow_symlinks'] is False for call in fs.stat.call_args_list))

    def test_each_ancestor_and_entry_reject_unsafe_metadata(self):
        for fd in range(10, 16):
            for change in (dict(st_uid=126), dict(st_gid=128),
                           dict(st_mode=metadata(fd != 15).st_mode | 0o020),
                           dict(st_mode=stat.S_IFLNK | 0o777)):
                fs = FakeOS()
                fs.nodes[fd] = metadata(fd != 15, st_ino=fd, **change)
                with self.subTest(fd=fd, change=change), patch.object(entry, 'os', fs), self.assertRaisesRegex(
                        entry.GuardLaunchError, '^GUARD_PATH$'):
                    entry._check_entry_at(10)
        for change in (dict(st_nlink=2), dict(st_size=0),
                       dict(st_size=entry.MAX_ENTRY_BYTES + 1)):
            fs = FakeOS(); fs.nodes[15] = metadata(False, st_ino=15, **change)
            with self.subTest(change=change), patch.object(entry, 'os', fs), self.assertRaisesRegex(
                    entry.GuardLaunchError, '^GUARD_PATH$'):
                entry._check_entry_at(10)

    def test_changed_name_or_fd_stops_and_closes(self):
        fs = FakeOS()
        original = fs.stat.side_effect
        seen = 0
        def drifting(name, dir_fd, follow_symlinks):
            nonlocal seen
            seen += 1
            value = original(name, dir_fd, follow_symlinks)
            return metadata(False, st_ino=99) if seen == 6 else value
        fs.stat.side_effect = drifting
        with patch.object(entry, 'os', fs), self.assertRaisesRegex(
                entry.GuardLaunchError, '^GUARD_CHANGED$'):
            entry._check_entry_at(10)
        self.assertEqual([call.args[0] for call in fs.close.call_args_list], [15, 14, 13, 12, 11])

    def test_public_entry_maps_os_failure_without_leaking_it(self):
        fs = FakeOS(); fs.stat.side_effect = OSError('PRIVATE')
        with patch.object(entry, 'os', fs), patch.object(entry, 'sys', isolated_sys()), self.assertRaises(
                entry.GuardLaunchError) as caught:
            entry._check_entry()
        self.assertEqual(str(caught.exception), 'GUARD_IO')
        self.assertTrue(caught.exception.__suppress_context__)
        fs.close.assert_called_once_with(10)

    def test_pinned_modules_match_lf_source_and_relative_import_closure(self):
        pinned = {name for name, _, _ in entry.PINNED_MODULES}
        self.assertEqual(len(pinned), len(entry.PINNED_MODULES))
        self.assertEqual(len(pinned), 13)
        self.assertNotIn('operator_process.py', pinned)
        self.assertNotIn('operator_effective_launch.py', pinned)
        for name, size, digest in entry.PINNED_MODULES:
            raw = (Path(entry.__file__).parent / name).read_bytes()
            with self.subTest(name=name):
                self.assertEqual(len(raw), size)
                self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)
                self.assertNotIn(b'\r\n', raw)
                for node in ast.walk(ast.parse(raw)):
                    if not isinstance(node, ast.ImportFrom) or node.level != 1:
                        continue
                    relatives = ([node.module] if node.module else
                                 [alias.name for alias in node.names])
                    self.assertTrue(all(item + '.py' in pinned for item in relatives))

    def test_bundle_uses_only_pinned_names_and_closes_every_descriptor(self):
        fs = FakeOS()
        with patch.object(entry, 'os', fs):
            entry._verify_bundle_at(10)
        self.assertEqual([call.args[0] for call in fs.open.call_args_list],
                         list(entry.ENTRY_PARTS[:-1]) + ['.'] +
                         [name for name, _, _ in entry.PINNED_MODULES] + ['.'])
        self.assertTrue(all(call.args[1] & fs.O_NOFOLLOW for call in fs.open.call_args_list))
        self.assertTrue(all(call.args[1] & fs.O_NONBLOCK for call in fs.open.call_args_list[5:-1]))
        self.assertEqual(fs.close.call_count, 19)
        self.assertEqual(fs.listdir.call_count, 2)
        self.assertEqual(fs.scandir.call_count, 2)
        self.assertEqual([call.args[0] for call in fs.scandir.call_args_list], [40, 41])
        self.assertGreater(fs.read.call_count, 13)

    def test_bundle_rejects_missing_or_unlisted_file_before_read(self):
        for missing in (False, True):
            fs = FakeOS()
            if missing:
                del fs.names[14, entry.PINNED_MODULES[0][0]]
            else:
                fs.names[14, 'extra.py'] = 100
            with self.subTest(missing=missing), patch.object(entry, 'os', fs), self.assertRaisesRegex(
                    entry.GuardLaunchError, '^GUARD_BUNDLE_SET$'):
                entry._verify_bundle_at(10)
            fs.read.assert_not_called()
            self.assertEqual(fs.close.call_count, 5)

    def test_bundle_rejects_owner_symlink_size_and_digest(self):
        cases = (
            (dict(st_uid=126), None, 'GUARD_PATH'),
            (dict(st_mode=stat.S_IFLNK | 0o777), None, 'GUARD_PATH'),
            (dict(st_size=1), None, 'GUARD_BUNDLE_SIZE'),
            ({}, b'X', 'GUARD_BUNDLE_DIGEST'),
        )
        for changes, first_byte, code in cases:
            fs = FakeOS()
            values = dict(st_ino=20, st_size=entry.PINNED_MODULES[0][1])
            values.update(changes)
            fs.nodes[20] = metadata(False, **values)
            if first_byte is not None:
                fs.contents[20] = first_byte + fs.contents[20][1:]
            with self.subTest(code=code), patch.object(entry, 'os', fs), self.assertRaisesRegex(
                    entry.GuardLaunchError, '^' + code + '$'):
                entry._verify_bundle_at(10)
            self.assertEqual(fs.close.call_count, 5 if code in ('GUARD_PATH',
                             'GUARD_BUNDLE_SIZE') else 6)

    def test_bundle_handles_short_reads_and_rejects_growth(self):
        fs = FakeOS()
        original = fs.read.side_effect
        fs.read.side_effect = lambda fd, length: original(fd, min(length, 257))
        with patch.object(entry, 'os', fs):
            entry._verify_bundle_at(10)
        self.assertGreater(fs.read.call_count, 300)
        fs = FakeOS()
        fs.contents[20] += b'X'
        with patch.object(entry, 'os', fs), self.assertRaisesRegex(
                entry.GuardLaunchError, '^GUARD_BUNDLE_SIZE$'):
            entry._verify_bundle_at(10)

    def test_bundle_returns_only_held_verified_bytes_in_fixed_order(self):
        fs = FakeOS()
        with patch.object(entry, 'os', fs):
            sources = entry._verify_bundle_at(10)
        self.assertIs(type(sources), tuple)
        self.assertEqual([name for name, _ in sources],
                         [name for name, _, _ in entry.PINNED_MODULES])
        for name, raw in sources:
            self.assertIs(type(raw), bytes)
            self.assertEqual(raw, (Path(entry.__file__).parent / name).read_bytes())
        fs.contents[20] = b'changed after the descriptor read'
        self.assertEqual(sources[0][1],
                         (Path(entry.__file__).parent / sources[0][0]).read_bytes())

    def test_compile_uses_held_bytes_without_import_or_execution(self):
        fs = FakeOS()
        with patch.object(entry, 'os', fs):
            sources = entry._verify_bundle_at(10)
        before = {name for name in sys.modules if name.startswith('siem.rbac.broker_tls.operator_')}
        compiled = entry._compile_verified_bundle(sources)
        self.assertEqual([name for name, _ in compiled], [name for name, _ in sources])
        self.assertTrue(all(type(code) is CodeType and
                            code.co_filename == '<alertmind-guard>/' + name
                            for name, code in compiled))
        self.assertEqual(before, {name for name in sys.modules
                                  if name.startswith('siem.rbac.broker_tls.operator_')})
        marker = b"raise RuntimeError('SENTINEL_NOT_EXECUTED')\n"
        with patch.object(entry, 'PINNED_MODULES',
                          (('operator_sentinel.py', len(marker), hashlib.sha256(marker).hexdigest()),)):
            code = entry._compile_verified_bundle((('operator_sentinel.py', marker),))
        self.assertIs(type(code[0][1]), CodeType)

    def test_compile_rejects_wrong_set_bytes_and_syntax_with_static_codes(self):
        fs = FakeOS()
        with patch.object(entry, 'os', fs):
            sources = entry._verify_bundle_at(10)
        cases = ((sources[:-1], 'GUARD_COMPILE_SET'),
                 ((('wrong.py', sources[0][1]),) + sources[1:], 'GUARD_COMPILE_SET'),
                 (((sources[0][0], b'SECRET_CHANGED'),) + sources[1:], 'GUARD_COMPILE_BYTES'))
        for changed, code in cases:
            with self.subTest(code=code), self.assertRaisesRegex(
                    entry.GuardLaunchError, '^' + code + '$') as caught:
                entry._compile_verified_bundle(changed)
            self.assertNotIn('SECRET', str(caught.exception))
        invalid = b'def broken(:\n'
        with patch.object(entry, 'PINNED_MODULES',
                          (('operator_syntax.py', len(invalid), hashlib.sha256(invalid).hexdigest()),)):
            with self.assertRaisesRegex(entry.GuardLaunchError, '^GUARD_COMPILE$') as caught:
                entry._compile_verified_bundle((('operator_syntax.py', invalid),))
        self.assertTrue(caught.exception.__suppress_context__)

    def test_loader_executes_pinned_held_bytes_and_cleans_private_namespace(self):
        fs = FakeOS()
        with patch.object(entry, 'os', fs):
            sources = entry._verify_bundle_at(10)
        before_finders = tuple(sys.meta_path)
        prefix = entry.HELD_PACKAGE
        self.assertFalse(any(name == prefix or name.startswith(prefix + '.')
                             for name in sys.modules))
        with entry._loaded_verified_bundle(sources) as loaded:
            self.assertEqual(len(loaded), len(entry.PINNED_MODULES) + 1)
            self.assertEqual(loaded[prefix].__path__, ())
            core = loaded[prefix + '.operator_core']
            fs_module = loaded[prefix + '.operator_fs']
            self.assertIs(fs_module.installed_checks, core.installed_checks)
            self.assertIs(loaded[prefix].operator_fs, fs_module)
            self.assertEqual(fs_module.__file__, '<alertmind-guard>/operator_fs.py')
            self.assertIs(sys.modules[prefix + '.operator_fs'], fs_module)
        self.assertFalse(any(name == prefix or name.startswith(prefix + '.')
                             for name in sys.modules))
        self.assertEqual(tuple(sys.meta_path), before_finders)

    def test_loader_rejects_unlisted_private_import_before_ambient_finder(self):
        raw = b'from . import operator_unlisted\n'
        pin = ('operator_probe.py', len(raw), hashlib.sha256(raw).hexdigest())
        ambient = Mock()
        ambient.find_spec = Mock(side_effect=AssertionError('FALLBACK_USED'))
        sys.meta_path.insert(0, ambient)
        try:
            with patch.object(entry, 'PINNED_MODULES', (pin,)), self.assertRaisesRegex(
                    entry.GuardLaunchError, '^GUARD_LOAD$') as caught:
                with entry._loaded_verified_bundle(((pin[0], raw),)):
                    self.fail('unlisted private import reached the guard body')
        finally:
            sys.meta_path.remove(ambient)
        ambient.find_spec.assert_not_called()
        self.assertTrue(caught.exception.__suppress_context__)
        self.assertFalse(any(name == entry.HELD_PACKAGE or
                             name.startswith(entry.HELD_PACKAGE + '.') for name in sys.modules))

    def test_loader_rejects_preexisting_private_module_without_deleting_it(self):
        raw = b'VALUE = 17\n'
        pin = ('operator_probe.py', len(raw), hashlib.sha256(raw).hexdigest())
        sentinel = object()
        name = entry.HELD_PACKAGE + '.preexisting'
        sys.modules[name] = sentinel
        try:
            with patch.object(entry, 'PINNED_MODULES', (pin,)), self.assertRaisesRegex(
                    entry.GuardLaunchError, '^GUARD_LOAD_COLLISION$'):
                with entry._loaded_verified_bundle(((pin[0], raw),)):
                    self.fail('collision reached the guard body')
            self.assertIs(sys.modules[name], sentinel)
        finally:
            del sys.modules[name]

    def test_loader_fails_closed_on_execution_and_namespace_drift(self):
        cases = (b"raise SystemExit(0)\n",
                 b"import sys; sys.modules['_alertmind_guard_held.extra'] = object()\n")
        for raw in cases:
            with self.subTest(raw=raw):
                pin = ('operator_probe.py', len(raw), hashlib.sha256(raw).hexdigest())
                before_finders = tuple(sys.meta_path)
                with patch.object(entry, 'PINNED_MODULES', (pin,)), self.assertRaisesRegex(
                        entry.GuardLaunchError, '^GUARD_LOAD$'):
                    with entry._loaded_verified_bundle(((pin[0], raw),)):
                        self.fail('failed module reached the guard body')
                self.assertFalse(any(name == entry.HELD_PACKAGE or
                                     name.startswith(entry.HELD_PACKAGE + '.')
                                     for name in sys.modules))
                self.assertEqual(tuple(sys.meta_path), before_finders)

    def test_public_entry_does_not_execute_loader_and_remains_nonzero(self):
        fs = FakeOS()
        fake_sys = isolated_sys()
        with patch.object(entry, 'os', fs), patch.object(entry, 'sys', fake_sys), patch.object(
                entry, '_loaded_verified_bundle', side_effect=AssertionError('LOAD_CALLED')) as loader:
            self.assertEqual(entry.main(), 1)
        loader.assert_not_called()
        self.assertEqual(fake_sys.stderr.getvalue(), 'GUARD_NOT_READY\n')
        self.assertEqual(fs.close.call_count, 25)
        self.assertFalse(any(name == entry.HELD_PACKAGE or
                             name.startswith(entry.HELD_PACKAGE + '.') for name in sys.modules))

    def test_bundle_rejects_later_name_or_metadata_drift(self):
        fs = FakeOS()
        original = fs.listdir.side_effect
        seen = 0
        def changed(fd):
            nonlocal seen
            seen += 1
            names = original(fd)
            return names + ['late.py'] if seen == 2 else names
        fs.listdir.side_effect = changed
        with patch.object(entry, 'os', fs), self.assertRaisesRegex(
                entry.GuardLaunchError, '^GUARD_CHANGED$'):
            entry._verify_bundle_at(10)
        self.assertEqual(fs.close.call_count, 19)
        fs = FakeOS()
        original = fs.stat.side_effect
        seen = 0
        def drift(name, dir_fd, follow_symlinks):
            nonlocal seen
            seen += 1
            value = original(name, dir_fd, follow_symlinks)
            return metadata(False, st_ino=999) if seen == 6 else value
        fs.stat.side_effect = drift
        with patch.object(entry, 'os', fs), self.assertRaisesRegex(
                entry.GuardLaunchError, '^GUARD_CHANGED$'):
            entry._verify_bundle_at(10)
        self.assertEqual(fs.close.call_count, 6)

    def test_public_entry_checks_bundle_after_entry_and_maps_read_error(self):
        fs = FakeOS()
        fs.read.side_effect = OSError('PRIVATE')
        with patch.object(entry, 'os', fs), patch.object(entry, 'sys', isolated_sys()), self.assertRaises(
                entry.GuardLaunchError) as caught:
            entry._check_entry()
        self.assertEqual(str(caught.exception), 'GUARD_IO')
        self.assertTrue(caught.exception.__suppress_context__)
        self.assertEqual(fs.close.call_count, 12)


if __name__ == '__main__':
    unittest.main()
