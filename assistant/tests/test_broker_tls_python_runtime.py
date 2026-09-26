"""Fixed-file adapter tests with synthetic bytes; never inspect the lab VM."""
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
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_core as core
from siem.rbac.broker_tls import operator_fs as fs
from siem.rbac.broker_tls import operator_guard_entry as guard
from siem.rbac.broker_tls import operator_python_policy as policy
from siem.rbac.broker_tls import operator_python_runtime as runtime
if __package__:
    from .test_broker_tls_operator_fs import FakeFS, metadata
else:
    from test_broker_tls_operator_fs import FakeFS, metadata


def stanza(name, arch, version, state='install ok installed'):
    return (f'Package: {name}\nStatus: {state}\nArchitecture: {arch}\n'
            f'Version: {version}\nDescription: public fixture\n continuation\n\n').encode()


def database(state='install ok installed'):
    return b''.join(stanza(name, arch, version, state) for name, arch, version in runtime.PACKAGE_PINS)


class PythonPackageRecordTests(unittest.TestCase):
    def test_seven_pinned_amd64_identities_and_multiarch_name_handling(self):
        records = runtime.parse_package_records(database())
        self.assertEqual(len(records), 7)
        self.assertEqual(tuple((x.name, x.architecture, x.version) for x in records), runtime.PACKAGE_PINS)
        self.assertTrue(all(x.selection == 'install' for x in records))
        self.assertEqual(runtime.parse_package_records(database().replace(b'\n', b'\r\n')), records)
        self.assertEqual(runtime.parse_package_records(database().replace(b'Package:', b'pAcKaGe:')), records)
        expected = {(p.package.split(':')[0], 'amd64', p.version) for p in policy.MAPPED_FILES}
        self.assertEqual(set(runtime.PACKAGE_PINS), expected)

    def test_hold_is_installed_but_other_selections_or_states_fail(self):
        self.assertTrue(all(x.selection == 'hold' for x in runtime.parse_package_records(database('hold ok installed'))))
        for state in ('deinstall ok installed', 'purge ok config-files', 'install reinstreq installed',
                      'install ok unpacked', 'install ok half-configured', 'install ok triggers-pending', ''):
            with self.subTest(state=state), self.assertRaisesRegex(
                    core.OperatorError, '^PY_PACKAGE_NOT_INSTALLED$'):
                runtime.parse_package_records(database(state))

    def test_missing_wrong_version_and_foreign_architecture_not_a_substitute(self):
        name, arch, version = runtime.PACKAGE_PINS[0]
        for raw, code in ((database().replace(stanza(name, arch, version), b''), 'PY_PACKAGE_MISSING'),
                          (database().replace(stanza(name, arch, version), stanza(name, arch, 'OTHER')), 'PY_PACKAGE_VERSION'),
                          (database().replace(stanza(name, arch, version), stanza(name, 'i386', version)), 'PY_PACKAGE_MISSING')):
            with self.assertRaisesRegex(core.OperatorError, '^' + code + '$'):
                runtime.parse_package_records(raw)
        self.assertEqual(runtime.parse_package_records(stanza(name, 'i386', 'foreign') + database()),
                         runtime.parse_package_records(database()))

    def test_duplicate_selected_stanzas_and_case_insensitive_fields_fail(self):
        for name, arch, version in runtime.PACKAGE_PINS:
            with self.assertRaisesRegex(core.OperatorError, '^PY_PACKAGE_AMBIGUOUS$'):
                runtime.parse_package_records(database() + stanza(name, arch, version))
        for field in (b'PACKAGE: other\n', b'Status: install ok installed\n', b'Version: other\n'):
            with self.assertRaisesRegex(core.OperatorError, '^PY_PACKAGE_DUPLICATE$'):
                runtime.parse_package_records(field + database())

    def test_identity_continuations_empty_arch_and_malformed_fields_fail(self):
        for key in (b'Package', b'Status', b'Architecture', b'Version'):
            lines = database().splitlines(keepends=True)
            index = next(i for i, line in enumerate(lines) if line.startswith(key + b':'))
            with self.assertRaisesRegex(core.OperatorError, '^PY_PACKAGE_FORMAT$'):
                runtime.parse_package_records(b''.join(lines[:index + 1] + [b' continuation\n'] + lines[index + 1:]))
        for raw in (database().replace(b'Architecture: amd64', b'Architecture:', 1),
                    b' continuation\n' + database(), b'bad-line\n' + database(),
                    b'#Bad: value\n' + database()):
            with self.assertRaisesRegex(core.OperatorError, '^PY_PACKAGE_FORMAT$'):
                runtime.parse_package_records(raw)

    def test_bounded_input_utf8_controls_and_field_work(self):
        for raw in (b'', None, bytearray(database()), database().decode()):
            with self.assertRaisesRegex(core.OperatorError, '^PY_PACKAGE_SIZE$'):
                runtime.parse_package_records(raw)
        with patch.object(runtime, 'MAX_STATUS', 1), self.assertRaisesRegex(core.OperatorError, '^PY_PACKAGE_SIZE$'):
            runtime.parse_package_records(database())
        with patch.object(runtime, 'MAX_STATUS_LINES', 1), self.assertRaisesRegex(core.OperatorError, '^PY_PACKAGE_FORMAT$'):
            runtime.parse_package_records(database())
        for extra in (b'Description: \xff\n', b'Description: \x00\n', b'Description: \x7f\n',
                      b'Description: ' + b'x' * 65537 + b'\n',
                      b''.join(f'X-{i}: value\n'.encode() for i in range(257))):
            with self.assertRaisesRegex(core.OperatorError, '^PY_PACKAGE_FORMAT$'):
                runtime.parse_package_records(database() + extra)

    def test_unrelated_fields_never_enter_result_or_errors(self):
        extra = b'Package: other\nDescription: PRIVATE_VALUE\n Package: libc6\n\n'
        records = runtime.parse_package_records(extra + database())
        self.assertNotIn('PRIVATE', repr(records))
        self.assertEqual(records, runtime.parse_package_records(database()))
        with self.assertRaises(core.OperatorError) as caught:
            runtime.parse_package_records(database().replace(b'install ok installed', b'PRIVATE_VALUE', 1))
        self.assertEqual(str(caught.exception), 'PY_PACKAGE_NOT_INSTALLED')


class PythonRuntimeAdapterTests(unittest.TestCase):
    def setUp(self):
        # Original paths/versions retained, byte pins replaced ONLY for these
        # synthetic fixtures. No real Python/shared-library bytes are executed.
        self.blobs = {}
        files = []
        for i, pin in enumerate(policy.MAPPED_FILES + (policy.LOADER_CACHE,)):
            raw = f'public-fixture-{i}'.encode()
            self.blobs[tuple(pin.path.split('/')[1:])] = raw
            files.append(replace(pin, size=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
        self.files, self.cache = tuple(files[:-1]), files[-1]
        self.sources = []
        for index, pin in enumerate(policy.SOURCE_FILES):
            raw = f'source-fixture-{index}'.encode()
            self.blobs[tuple(pin.path.split('/')[1:])] = raw
            self.sources.append(replace(pin, sha256=hashlib.sha256(raw).hexdigest()))
        self.blobs[runtime.STATUS_PARTS] = database()
        self.start_patch(patch.object(policy, 'MAPPED_FILES', self.files))
        self.start_patch(patch.object(policy, 'LOADER_CACHE', self.cache))
        self.start_patch(patch.object(policy, 'SOURCE_FILES', tuple(self.sources)))
        self.start_patch(patch.object(policy, 'SOURCE_LIMIT', 64))

    def start_patch(self, context):
        value = context.start()
        self.addCleanup(context.stop)
        return value

    def test_exact_fixed_reads_two_passes_and_three_package_snapshots(self):
        with patch.object(fs, '_platform') as platform, patch.object(fs, '_identity') as nss, patch.object(
                fs, '_read_root_owned', side_effect=lambda parts, limit: self.blobs[parts]) as read:
            result = runtime.observe_python_runtime()
        file_reads = [(tuple(pin.path.split('/')[1:]), pin.size) for pin in self.files + (self.cache,)]
        file_reads += [(tuple(pin.path.split('/')[1:]), policy.SOURCE_LIMIT) for pin in self.sources]
        status_read = (runtime.STATUS_PARTS, runtime.MAX_STATUS)
        self.assertEqual([call.args for call in read.call_args_list],
                         [status_read] + file_reads + [status_read] + file_reads + [status_read])
        self.assertEqual(platform.call_count, 121)
        nss.assert_not_called()
        self.assertEqual((result.file_passes, result.package_reads), (2, 3))
        self.assertIs(result.on_disk_byte_pins_match, True)
        self.assertIs(result.on_disk_source_pins_match, True)
        self.assertEqual(result.source_file_count, 49)

    def test_no_public_overrides_and_platform_failure_prevents_io(self):
        self.assertEqual(len(inspect.signature(runtime.observe_python_runtime).parameters), 0)
        with patch.object(fs, '_read_root_owned') as read, patch.object(fs, '_platform',
                side_effect=core.OperatorError('FS_ROOT_REQUIRED')):
            with self.assertRaisesRegex(core.OperatorError, '^FS_ROOT_REQUIRED$'):
                runtime.observe_python_runtime()
            with self.assertRaises(TypeError):
                runtime.observe_python_runtime('/tmp')
        read.assert_not_called()

    def test_bad_initial_package_prevents_all_pinned_file_reads(self):
        with patch.object(fs, '_platform'), patch.object(fs, '_read_root_owned',
                return_value=b'Package: unrelated\n\n') as read, self.assertRaisesRegex(
                core.OperatorError, '^PY_PACKAGE_MISSING$'):
            runtime.observe_python_runtime()
        read.assert_called_once_with(runtime.STATUS_PARTS, runtime.MAX_STATUS)

    def test_each_file_first_and_second_pass_digest_drift_fails(self):
        for pin in self.files + (self.cache,):
            target = tuple(pin.path.split('/')[1:])
            for bad_pass in (1, 2):
                seen = 0
                def changed(parts, limit):
                    nonlocal seen
                    if parts == target:
                        seen += 1
                        if seen == bad_pass:
                            return b'x' * len(self.blobs[parts])
                    return self.blobs[parts]
                with self.subTest(path=target, bad_pass=bad_pass), patch.object(fs, '_platform'), patch.object(
                        fs, '_read_root_owned', side_effect=changed), self.assertRaisesRegex(
                        core.OperatorError, '^PY_RUNTIME_DIGEST$'):
                    runtime.observe_python_runtime()
                self.assertEqual(seen, bad_pass)

    def test_file_return_type_short_and_oversize_fail(self):
        for bad in (None, 'text', b'', b'x', b'x' * 100, bytearray(b'public-fixture-0')):
            def read(parts, limit):
                return database() if parts == runtime.STATUS_PARTS else bad
            with self.subTest(bad=bad), patch.object(fs, '_platform'), patch.object(
                    fs, '_read_root_owned', side_effect=read), self.assertRaisesRegex(
                    core.OperatorError, '^PY_RUNTIME_SIZE$'):
                runtime.observe_python_runtime()

    def test_every_source_first_and_second_pass_digest_drift_fails(self):
        for pin in self.sources:
            target = tuple(pin.path.split('/')[1:])
            for bad_pass in (1, 2):
                seen = 0
                def changed(parts, limit):
                    nonlocal seen
                    if parts == target:
                        seen += 1
                        if seen == bad_pass:
                            return b'altered source, never executed'
                    return self.blobs[parts]
                with self.subTest(path=target, bad_pass=bad_pass), patch.object(fs, '_platform'), patch.object(
                        fs, '_read_root_owned', side_effect=changed), self.assertRaisesRegex(
                        policy.PythonPolicyError, '^PY_SOURCE_DIGEST$'):
                    runtime.observe_python_runtime()
                self.assertEqual(seen, bad_pass)

    def test_source_type_and_bound_failure_stops_before_following_source(self):
        target = tuple(self.sources[0].path.split('/')[1:])
        for raw in (None, b'', 'source', bytearray(b'source'), b'x' * 65):
            reads = []
            def read(parts, limit):
                reads.append(parts)
                return raw if parts == target else self.blobs[parts]
            with patch.object(fs, '_platform'), patch.object(fs, '_read_root_owned', side_effect=read), self.assertRaisesRegex(
                    policy.PythonPolicyError, '^PY_SOURCE_SIZE$'):
                runtime.observe_python_runtime()
            self.assertEqual(reads[-1], target)
            self.assertEqual(len(reads), 12)

    def test_middle_and_final_package_selection_drift_fails(self):
        for bad_read in (2, 3):
            seen = 0
            def read(parts, limit):
                nonlocal seen
                if parts == runtime.STATUS_PARTS:
                    seen += 1
                    return database('hold ok installed') if seen == bad_read else database()
                return self.blobs[parts]
            with patch.object(fs, '_platform'), patch.object(fs, '_read_root_owned', side_effect=read), self.assertRaisesRegex(
                    core.OperatorError, '^PY_PACKAGE_CHANGED$'):
                runtime.observe_python_runtime()
            self.assertEqual(seen, bad_read)

    def test_sanitized_os_errors_and_metadata_failures_propagate(self):
        for number, code in ((errno.ENOENT, 'FS_MISSING'), (errno.EACCES, 'FS_ACCESS'),
                             (errno.ELOOP, 'FS_SYMLINK'), (errno.ENOTDIR, 'FS_NOT_DIRECTORY'),
                             (errno.EIO, 'FS_IO')):
            with patch.object(fs, '_platform'), patch.object(fs, '_read_root_owned',
                    side_effect=OSError(number, 'PRIVATE_VALUE')), self.assertRaises(core.OperatorError) as caught:
                runtime.observe_python_runtime()
            self.assertEqual(str(caught.exception), code)
            self.assertTrue(caught.exception.__suppress_context__)
        with patch.object(fs, '_platform'), patch.object(fs, '_read_root_owned',
                side_effect=core.OperatorError('FS_CHANGED')), self.assertRaisesRegex(core.OperatorError, '^FS_CHANGED$'):
            runtime.observe_python_runtime()

    def test_real_root_wrapper_dispatch_has_no_service_owner_exception(self):
        fake = FakeFS()
        fake.open = Mock(return_value=10)
        with patch.object(fs, '_platform'), patch.object(fs, 'os', fake), patch.object(
                fs, '_read_at', return_value=b'public') as at:
            self.assertEqual(runtime._read_fixed(('usr', 'bin', 'python3.14'), 10), b'public')
        fake.open.assert_called_once_with('/', fake.O_RDONLY | fake.O_DIRECTORY | fake.O_NOFOLLOW | fake.O_CLOEXEC)
        self.assertEqual(at.call_args.args[:3], (10, ('usr', 'bin', 'python3.14'), 10))
        owners = at.call_args.args[3]
        self.assertEqual(owners(()), ((0, 0),))
        self.assertEqual(owners(fs.VENDOR), ((0, 0),))
        fake.close.assert_called_once_with(10)

    def test_shared_reader_rejects_untrusted_metadata_and_closes_on_drift(self):
        # Compose through the same private _read_at primitive used in production.
        for changes in ({'st_uid': 126}, {'st_gid': 128}, {'st_mode': stat.S_IFREG | 0o666},
                        {'st_mode': stat.S_IFLNK | 0o777}, {'st_mode': stat.S_IFIFO | 0o600}):
            fake = FakeFS()
            fake.nodes[12] = metadata(**changes)
            with patch.object(fs, '_platform'), patch.object(fs, 'os', fake), patch.object(
                    fs, '_read_root_owned', side_effect=lambda parts, limit: fs._read_at(10, ('dir', 'file'), 3, lambda _: ((0, 0),))), self.assertRaisesRegex(
                    core.OperatorError, '^FS_METADATA$'):
                runtime._read_fixed(('usr', 'bin', 'python3.14'), 3)
            fake.read.assert_not_called()
            self.assertEqual(fake.close.call_count, 1)
        fake = FakeFS()
        def read(fd, amount):
            fake.nodes[11] = metadata(True, st_ino=999)
            fake.read.side_effect = [b'']
            return b'abc'
        fake.read.side_effect = read
        with patch.object(fs, '_platform'), patch.object(fs, 'os', fake), patch.object(
                fs, '_read_root_owned', side_effect=lambda parts, limit: fs._read_at(10, ('dir', 'file'), 3, lambda _: ((0, 0),))), self.assertRaisesRegex(
                core.OperatorError, '^FS_CHANGED$'):
            runtime._read_fixed(('usr', 'bin', 'python3.14'), 3)
        self.assertEqual(fake.close.call_count, 2)

    def test_non_authorizing_result_and_no_guard_or_execution_wiring(self):
        with patch.object(fs, '_platform'), patch.object(fs, '_read_root_owned',
                side_effect=lambda parts, limit: self.blobs[parts]):
            result = runtime.observe_python_runtime()
        for name in ('source_origins_verified', 'package_file_ownership_verified',
                     'package_authenticity_proven', 'native_resolution_proven', 'atomic_snapshot_proven', 'loaded_code_proven',
                     'effective_environment_proven', 'runtime_trusted', 'startup_authorized'):
            self.assertIs(getattr(result, name), False)
        with self.assertRaises(FrozenInstanceError):
            result.startup_authorized = True
        self.assertNotIn('operator_python_runtime.py', {pin[0] for pin in guard.PINNED_MODULES})
        self.assertNotIn('operator_python_runtime', Path(guard.__file__).read_text(encoding='utf-8'))
        source = Path(runtime.__file__).read_text(encoding='utf-8')
        tree = ast.parse(source)
        self.assertFalse(any(isinstance(n, ast.Import) and any(a.name in ('subprocess', 'socket', 'pwd', 'grp')
                                                             for a in n.names) for n in ast.walk(tree)))
        self.assertNotIn('check_c3_report(', source)


@unittest.skipUnless(sys.platform == 'linux', 'requires Linux no-follow descriptor reads')
class PythonRuntimeNativeCompositionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'dir').mkdir(mode=0o700)
        self.file = self.root / 'dir/file'
        self.file.write_bytes(b'abc')
        self.file.chmod(0o600)
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)

    def read(self):
        # Native syscall composition on fresh fixtures, not production root trust.
        def native(parts, limit):
            return fs._read_at(self.fd, ('dir', 'file'), 3, lambda _: ((os.geteuid(), os.getegid()),))
        with patch.object(fs, '_platform'), patch.object(fs, '_read_root_owned', side_effect=native):
            return runtime._read_fixed(('usr', 'bin', 'python3.14'), 3)

    def test_native_fixture_bytes_and_leaf_symlink_denial(self):
        self.assertEqual(self.read(), b'abc')
        self.file.rename(self.root / 'dir/target')
        self.file.symlink_to('target')
        with self.assertRaisesRegex(core.OperatorError, '^FS_METADATA$'):
            self.read()

    def test_native_fixture_permissions_and_fifo_denial(self):
        self.file.chmod(0o666)
        with self.assertRaisesRegex(core.OperatorError, '^FS_METADATA$'):
            self.read()
        self.file.unlink()
        os.mkfifo(self.file, 0o600)
        with self.assertRaisesRegex(core.OperatorError, '^FS_METADATA$'):
            self.read()


if __name__ == '__main__':
    unittest.main()
