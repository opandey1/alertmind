"""Offline selected-import path tests; native cases use disposable trees only."""
from contextlib import contextmanager
from dataclasses import FrozenInstanceError
import errno
import hashlib
import inspect
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_core as core
from siem.rbac.broker_tls import operator_fs as fs
from siem.rbac.broker_tls import operator_guard_entry as guard
from siem.rbac.broker_tls import operator_python_candidates as candidates
from siem.rbac.broker_tls import operator_python_policy as policy
if __package__:
    from .test_broker_tls_operator_fs import FakeFS, metadata
else:
    from test_broker_tls_operator_fs import FakeFS, metadata


class CandidateFS(FakeFS):
    def __init__(self):
        super().__init__()
        self.nodes, self.names, self.parts = {}, {}, {}
        for path in candidates.DIRECTORY_PARTS + candidates.EXPECTED_PARTS:
            self.add(path, metadata(path in candidates.DIRECTORY_PARTS,
                                   st_size=policy.MAPPED_FILES[1].size if path == candidates.EXTENSION_PARTS else 10))
        self.open = Mock(side_effect=self.open_name)
        self.stat = Mock(side_effect=self.lookup)
        self.write = Mock()
        self.listdir = Mock()

    def add(self, parts, value):
        fd = len(self.nodes) + 10
        value.st_ino = fd
        self.nodes[fd], self.parts[parts] = value, fd
        if parts:
            self.names[self.parts[parts[:-1]], parts[-1]] = fd
        return fd

    def open_name(self, name, flags, dir_fd=None):
        return self.parts[()] if name == '/' and dir_fd is None else self.names[dir_fd, name]

    def lookup(self, name, dir_fd, follow_symlinks):
        if (dir_fd, name) not in self.names:
            raise FileNotFoundError(errno.ENOENT, 'not present')
        return self.nodes[self.names[dir_fd, name]]


@contextmanager
def fake_host(fake):
    with patch.object(fs, '_platform'), patch.object(fs, 'os', fake), patch.object(candidates, 'os', fake):
        yield


class PythonCandidateTests(unittest.TestCase):
    def test_fixed_policy_count_digest_and_disjoint_paths(self):
        self.assertEqual((len(candidates.EXPECTED_PARTS), len(candidates.ALTERNATE_PARTS), len(candidates.DIRECTORY_PARTS)), (50, 514, 11))
        self.assertEqual(set(candidates.EXPECTED_PARTS), {
            tuple(pin.path.split('/')[1:]) for pin in policy.SOURCE_FILES + (policy.MAPPED_FILES[1],)})
        for paths in (candidates.EXPECTED_PARTS, candidates.ALTERNATE_PARTS, candidates.DIRECTORY_PARTS):
            self.assertEqual(len(set(paths)), len(paths))
        self.assertFalse(set(candidates.EXPECTED_PARTS) & set(candidates.ALTERNATE_PARTS))
        text = '\n'.join('/' + '/'.join(p) for p in candidates.ALTERNATE_PARTS) + '\n'
        self.assertEqual(hashlib.sha256(text.encode()).hexdigest(), '2ce1946a7348e64a136fbcfbb577ead89df34bab6479865fb412ce38994ad956')

    def test_all_selected_names_have_package_native_source_and_bytecode_peers(self):
        absent = set(candidates.ALTERNATE_PARTS)
        expected = set(candidates.EXPECTED_PARTS)
        roots = (('usr', 'lib', 'python3.14'), ('usr', 'lib', 'python3.14', 'lib-dynload'))
        suffixes = ('.cpython-314-x86_64-linux-gnu.so', '.abi3.so', '.so', '.py', '.pyc')
        package_dirs = {p[:-1] for p in expected if p[-1] == '__init__.py'}
        for origin in expected:
            package = origin[-1] == '__init__.py'
            root = origin[:-2] if package else origin[:-1]
            name = origin[-2] if package else origin[-1].split('.')[0]
            search = roots if root in roots else (root,)
            for directory in search:
                self.assertIn(directory + (name,), absent | package_dirs)
                for suffix in suffixes:
                    self.assertIn(directory + (name + suffix,), absent | expected)
            if package:
                for suffix in suffixes:
                    self.assertIn(origin[:-1] + ('__init__' + suffix,), absent | expected)
        self.assertTrue(all('__pycache__' not in p for p in absent))

    def test_required_directories_are_root_first_and_parents_precede_children(self):
        seen = set()
        for parts in candidates.DIRECTORY_PARTS:
            if parts:
                self.assertIn(parts[:-1], seen)
            seen.add(parts)
        self.assertEqual(candidates.DIRECTORY_PARTS[0], ())
        for parts in candidates.EXPECTED_PARTS + candidates.ALTERNATE_PARTS:
            self.assertIn(parts[:-1], seen)

    def test_two_passes_use_all_fixed_names_without_payload_io_or_nss(self):
        fake = CandidateFS()
        with fake_host(fake), patch.object(candidates, '_snapshot', wraps=candidates._snapshot) as snapshot, patch.object(fs, '_identity') as nss:
            result = candidates.observe_python_import_candidates()
        self.assertEqual(snapshot.call_count, 2)
        self.assertEqual((result.selected_module_count, result.alternate_name_count, result.passes), (50, 514, 2))
        for parts in candidates.EXPECTED_PARTS + candidates.ALTERNATE_PARTS:
            calls = [c for c in fake.stat.call_args_list if c.args[0] == parts[-1] and c.kwargs['dir_fd'] == fake.parts[parts[:-1]]]
            self.assertEqual(len(calls), 2)
            self.assertTrue(all(c.kwargs['follow_symlinks'] is False for c in calls))
        self.assertEqual(fake.open.call_count, 11)
        self.assertEqual(fake.close.call_count, fake.open.call_count)
        for c in fake.open.call_args_list:
            self.assertEqual(c.args[1], fake.O_DIRECTORY | fake.O_NOFOLLOW | fake.O_CLOEXEC)
        fake.read.assert_not_called()
        fake.write.assert_not_called()
        fake.listdir.assert_not_called()
        nss.assert_not_called()

    def test_public_entry_rejects_platform_and_overrides_before_io(self):
        self.assertEqual(len(inspect.signature(candidates.observe_python_import_candidates).parameters), 0)
        with patch.object(fs, '_platform', side_effect=core.OperatorError('FS_ROOT_REQUIRED')), patch.object(candidates.os, 'open') as opening:
            with self.assertRaisesRegex(core.OperatorError, '^FS_ROOT_REQUIRED$'):
                candidates.observe_python_import_candidates()
            with self.assertRaises(TypeError):
                candidates.observe_python_import_candidates('/tmp')
        opening.assert_not_called()
        for parts in ((), fs.VENDOR, candidates.EXPECTED_PARTS[0]):
            self.assertEqual(candidates._root_owners(parts), ((0, 0),))

    def test_every_alternate_is_rejected_not_only_first_or_higher_precedence(self):
        # Exercise all 514 leaves directly through the same production snapshot.
        for parts in candidates.ALTERNATE_PARTS:
            fake = CandidateFS()
            fake.add(parts, metadata(st_size=0))
            with self.subTest(parts=parts), fake_host(fake), self.assertRaisesRegex(core.OperatorError, '^PY_CANDIDATE_PRESENT$'):
                candidates._snapshot(fake.parts, candidates._root_owners)
            fake.open.assert_not_called()

    def test_alternate_objects_fail_in_either_pass_without_opening_them(self):
        target = candidates.ALTERNATE_PARTS[-1]
        for kind in (stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK, stat.S_IFIFO, stat.S_IFCHR, stat.S_IFSOCK):
            for bad_pass in (1, 2):
                fake = CandidateFS()
                seen = 0
                def lookup(name, dir_fd, follow_symlinks):
                    nonlocal seen
                    if (dir_fd, name) == (fake.parts[target[:-1]], target[-1]):
                        seen += 1
                        if seen == bad_pass:
                            return metadata(st_mode=kind | 0o777)
                    return fake.lookup(name, dir_fd, follow_symlinks)
                fake.stat.side_effect = lookup
                with fake_host(fake), self.assertRaisesRegex(core.OperatorError, '^PY_CANDIDATE_PRESENT$'):
                    candidates.observe_python_import_candidates()
                self.assertEqual(fake.close.call_count, fake.open.call_count)
                self.assertFalse(any(c.args[0] == target[-1] for c in fake.open.call_args_list))

    def test_missing_origins_and_required_parents_are_not_absence_success(self):
        for parts in candidates.EXPECTED_PARTS + candidates.DIRECTORY_PARTS[1:]:
            fake = CandidateFS()
            del fake.names[fake.parts[parts[:-1]], parts[-1]]
            with self.subTest(parts=parts), fake_host(fake), self.assertRaisesRegex(core.OperatorError, '^FS_MISSING$'):
                candidates.observe_python_import_candidates()
            self.assertEqual(fake.close.call_count, fake.open.call_count)

    def test_all_required_directory_ownership_and_symlinks_are_checked(self):
        for parts in candidates.DIRECTORY_PARTS:
            for changes in ({'st_uid': 126}, {'st_gid': 128}, {'st_mode': stat.S_IFDIR | 0o777}, {'st_mode': stat.S_IFLNK | 0o777}):
                fake = CandidateFS()
                vars(fake.nodes[fake.parts[parts]]).update(changes)
                with self.subTest(parts=parts), fake_host(fake), self.assertRaisesRegex(core.OperatorError, '^FS_METADATA$'):
                    candidates.observe_python_import_candidates()
                self.assertEqual(fake.close.call_count, fake.open.call_count)

    def test_origin_type_ownership_mode_and_size_are_checked(self):
        for changes, code in (({'st_uid': 126}, 'FS_METADATA'), ({'st_gid': 128}, 'FS_METADATA'),
                              ({'st_mode': stat.S_IFREG | 0o666}, 'FS_METADATA'),
                              ({'st_mode': stat.S_IFLNK | 0o777}, 'FS_METADATA'),
                              ({'st_mode': stat.S_IFIFO | 0o600}, 'FS_METADATA'),
                              ({'st_size': 0}, 'PY_CANDIDATE_SIZE'),
                              ({'st_size': policy.SOURCE_LIMIT + 1}, 'PY_CANDIDATE_SIZE')):
            fake = CandidateFS()
            vars(fake.nodes[fake.parts[candidates.EXPECTED_PARTS[0]]]).update(changes)
            with fake_host(fake), self.assertRaisesRegex(core.OperatorError, '^' + code + '$'):
                candidates.observe_python_import_candidates()
            self.assertEqual(fake.close.call_count, fake.open.call_count)
        fake = CandidateFS()
        fake.nodes[fake.parts[candidates.EXTENSION_PARTS]].st_size += 1
        with fake_host(fake), self.assertRaisesRegex(core.OperatorError, '^PY_CANDIDATE_SIZE$'):
            candidates.observe_python_import_candidates()

    def test_each_origin_is_compared_between_passes(self):
        for target in candidates.EXPECTED_PARTS:
            fake = CandidateFS()
            seen = 0
            def lookup(name, dir_fd, follow_symlinks):
                nonlocal seen
                value = fake.lookup(name, dir_fd, follow_symlinks)
                if (dir_fd, name) == (fake.parts[target[:-1]], target[-1]):
                    seen += 1
                    if seen == 2:
                        value = metadata(**vars(value))
                        value.st_ino += 1000
                return value
            fake.stat.side_effect = lookup
            with self.subTest(target=target), fake_host(fake), self.assertRaisesRegex(core.OperatorError, '^PY_CANDIDATE_CHANGED$'):
                candidates.observe_python_import_candidates()
            self.assertEqual(fake.close.call_count, fake.open.call_count)

    def test_expected_file_change_on_second_pass_fails(self):
        for key in ('st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_dev', 'st_nlink'):
            fake = CandidateFS()
            target = next(p for p in candidates.EXPECTED_PARTS if p != candidates.EXTENSION_PARTS)
            original = candidates._snapshot
            calls = 0
            def snapshot(handles, owners):
                nonlocal calls
                calls += 1
                if calls == 2:
                    node = fake.nodes[fake.parts[target]]
                    setattr(node, key, getattr(node, key) + 1)
                return original(handles, owners)
            with fake_host(fake), patch.object(candidates, '_snapshot', side_effect=snapshot), self.assertRaisesRegex(core.OperatorError, '^PY_CANDIDATE_CHANGED$'):
                candidates.observe_python_import_candidates()

    def test_directory_open_race_fails_and_closes_descriptors(self):
        for parts in candidates.DIRECTORY_PARTS[1:]:
            fake = CandidateFS()
            target = fake.parts[parts]
            def fstat(fd):
                value = fake.nodes[fd]
                if fd == target:
                    value = metadata(True, **vars(value))
                    value.st_ino += 1000
                return value
            fake.fstat.side_effect = fstat
            with fake_host(fake), self.assertRaisesRegex(core.OperatorError, '^FS_CHANGED$'):
                candidates.observe_python_import_candidates()
            self.assertEqual(fake.close.call_count, fake.open.call_count)

    def test_directory_name_and_descriptor_rechecks_in_both_passes(self):
        for target in candidates.DIRECTORY_PARTS:
            for check_pass in (1, 2):
                for method in ('stat', 'fstat'):
                    if not target and method == 'stat':
                        continue
                    fake = CandidateFS()
                    phase = 0
                    original = candidates._directory_recheck
                    def recheck(handles, stamps):
                        nonlocal phase
                        phase += 1
                        return original(handles, stamps)
                    def lookup(*args, **kwargs):
                        value = fake.nodes[args[0]] if method == 'fstat' else fake.lookup(*args, **kwargs)
                        match = args[0] == fake.parts[target] if method == 'fstat' else (kwargs['dir_fd'], args[0]) == (fake.parts[target[:-1]], target[-1])
                        if phase == check_pass and match:
                            value = metadata(**vars(value))
                            value.st_ctime_ns += 1
                        return value
                    getattr(fake, method).side_effect = lookup
                    with self.subTest(target=target, check_pass=check_pass, method=method), fake_host(fake), patch.object(
                            candidates, '_directory_recheck', side_effect=recheck), self.assertRaisesRegex(core.OperatorError, '^FS_CHANGED$'):
                        candidates.observe_python_import_candidates()
                    self.assertEqual(fake.close.call_count, fake.open.call_count)

    def test_permission_and_other_errors_never_count_as_absence(self):
        target = candidates.ALTERNATE_PARTS[0]
        for number, code in ((errno.EACCES, 'FS_ACCESS'), (errno.ENOTDIR, 'FS_NOT_DIRECTORY'),
                             (errno.ELOOP, 'FS_SYMLINK'), (errno.EIO, 'FS_IO')):
            fake = CandidateFS()
            def lookup(name, dir_fd, follow_symlinks):
                if (dir_fd, name) == (fake.parts[target[:-1]], target[-1]):
                    raise OSError(number, 'PRIVATE')
                return fake.lookup(name, dir_fd, follow_symlinks)
            fake.stat.side_effect = lookup
            with fake_host(fake), self.assertRaisesRegex(core.OperatorError, '^' + code + '$') as caught:
                candidates.observe_python_import_candidates()
            self.assertTrue(caught.exception.__suppress_context__)
            self.assertEqual(fake.close.call_count, fake.open.call_count)

    def test_failed_directory_open_closes_prior_handles(self):
        fake = CandidateFS()
        def opening(name, flags, dir_fd=None):
            if name == 'json':
                raise PermissionError(errno.EACCES, 'PRIVATE')
            return fake.open_name(name, flags, dir_fd)
        fake.open.side_effect = opening
        with fake_host(fake), self.assertRaisesRegex(core.OperatorError, '^FS_ACCESS$'):
            candidates.observe_python_import_candidates()
        self.assertEqual(fake.close.call_count, fake.open.call_count - 1)

    def test_unrelated_files_and_legacy_cache_inventory_are_not_enumerated(self):
        fake = CandidateFS()
        root = ('usr', 'lib', 'python3.14')
        fake.add(root + ('unselected.py',), metadata())
        fake.add(root + ('__pycache__',), metadata(True))
        with fake_host(fake):
            result = candidates.observe_python_import_candidates()
        fake.listdir.assert_not_called()
        self.assertFalse(result.complete_import_coverage_proven)
        self.assertFalse(result.effective_cache_redirection_proven)

    def test_result_is_immutable_non_authorizing_and_not_a_byte_or_resolution_proof(self):
        fake = CandidateFS()
        with fake_host(fake):
            result = candidates.observe_python_import_candidates()
        for name in ('on_disk_bytes_proven', 'complete_import_coverage_proven', 'effective_cache_redirection_proven',
                     'actual_resolution_proven', 'loaded_code_proven', 'atomic_snapshot_proven', 'runtime_trusted', 'startup_authorized'):
            self.assertIs(getattr(result, name), False)
        with self.assertRaises(FrozenInstanceError):
            result.startup_authorized = True
        self.assertNotIn('operator_python_candidates.py', {pin[0] for pin in guard.PINNED_MODULES})
        self.assertIn('operator_python_candidates.py', {pin[0] for pin in guard.RUNTIME_MODULES})


@unittest.skipUnless(sys.platform == 'linux', 'descriptor-relative Linux fixture')
class NativePythonCandidateTests(unittest.TestCase):
    @contextmanager
    def tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for parts in candidates.DIRECTORY_PARTS:
                root.joinpath(*parts).mkdir(mode=0o700, exist_ok=True)
            for parts in candidates.EXPECTED_PARTS:
                leaf = root.joinpath(*parts)
                leaf.write_bytes(b'x' * (policy.MAPPED_FILES[1].size if parts == candidates.EXTENSION_PARTS else 10))
                leaf.chmod(0o600)
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                yield root, fd, lambda _: ((os.geteuid(), os.getegid()),)
            finally:
                os.close(fd)

    def test_native_fixed_tree_and_real_shadow_objects(self):
        with self.tree() as (root, fd, owners):
            candidates._observe_at(fd, owners)
            target = root.joinpath(*candidates.ALTERNATE_PARTS[0])
            for kind in ('file', 'directory', 'symlink', 'fifo'):
                if kind == 'file':
                    target.write_bytes(b'')
                elif kind == 'directory':
                    target.mkdir()
                elif kind == 'symlink':
                    target.symlink_to('absent-target')
                else:
                    os.mkfifo(target)
                with self.assertRaisesRegex(core.OperatorError, '^PY_CANDIDATE_PRESENT$'):
                    candidates._observe_at(fd, owners)
                target.rmdir() if kind == 'directory' else target.unlink()
                candidates._observe_at(fd, owners)

    def test_native_symlinked_parent_and_between_pass_origin_change(self):
        with self.tree() as (root, fd, owners):
            package = root / 'usr/lib/python3.14/json'
            original = package.with_name('json-original')
            package.rename(original)
            package.symlink_to(original, target_is_directory=True)
            with self.assertRaisesRegex(core.OperatorError, '^FS_METADATA$'):
                candidates._observe_at(fd, owners)
            package.unlink()
            original.rename(package)
            snapshot = candidates._snapshot
            calls = 0
            def changed(handles, owner):
                nonlocal calls
                calls += 1
                if calls == 2:
                    source = next(p for p in candidates.EXPECTED_PARTS if p != candidates.EXTENSION_PARTS)
                    root.joinpath(*source).write_bytes(b'changed-content')
                return snapshot(handles, owner)
            with patch.object(candidates, '_snapshot', side_effect=changed), self.assertRaisesRegex(core.OperatorError, '^PY_CANDIDATE_CHANGED$'):
                candidates._observe_at(fd, owners)


if __name__ == '__main__':
    unittest.main()
