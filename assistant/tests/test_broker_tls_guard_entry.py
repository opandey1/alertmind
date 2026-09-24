"""Offline guard-entry candidate checks; no systemd, VM or installer action."""
import ast
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
import stat
import sys
from types import SimpleNamespace as NS
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
    O_RDONLY, O_NOFOLLOW, O_CLOEXEC, O_DIRECTORY = 0, 1, 2, 4

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
        self.open = Mock(side_effect=self._open)
        self.stat = Mock(side_effect=self._stat)
        self.fstat = Mock(side_effect=lambda fd: self.nodes[fd])
        self.close = Mock()
        self.geteuid = lambda: 0
        self.supports_dir_fd = {self.open, self.stat}
        self.supports_follow_symlinks = {self.stat}

    def _open(self, name, flags, dir_fd=None):
        return 10 if name == '/' else self.names[dir_fd, name]

    def _stat(self, name, dir_fd, follow_symlinks):
        return self.nodes[self.names[dir_fd, name]]


def isolated_sys(**changes):
    values = dict(platform='linux', argv=[entry.ENTRY_PATH], path=['/usr/lib/python3.14'],
                  flags=NS(isolated=1, ignore_environment=1, no_site=1,
                           dont_write_bytecode=1), stderr=StringIO())
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
                          for node in imports], ['contextlib', 'os', 'stat', 'sys'])

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


if __name__ == '__main__':
    unittest.main()
