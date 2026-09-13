"""Offline package database and runtime observation checks. Never executes Node."""
import errno
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac.broker_tls import operator_core as core
from siem.rbac.broker_tls import operator_fs as fs
from siem.rbac.broker_tls import operator_runtime as r


def status(version=core.PACKAGE_VERSION, architecture='amd64', state='install ok installed'):
    return ('Package: wazuh-dashboard\nStatus: ' + state + '\nVersion: ' + version
            + '\nArchitecture: ' + architecture + '\n').encode()


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.identity = r.parse_package_status(status())
        files = {'original.cjs': b'original', 'candidate.cjs': b'candidate'}
        self.entries = {name: {'bytes': len(raw), 'sha256': core.sha(raw)} for name, raw in files.items()}
        self.contract = dict(core.CONTRACT, original_sha256=core.sha(b'original'),
                             candidate_sha256=core.sha(b'candidate'),
                             packaged_linux_node_sha256=core.sha(b'node'),
                             packaged_node_header_sha256=core.sha(b'header'))
        self.repin()
        self.patcher = patch.object(core, 'CONTRACT', self.contract)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.blobs = {core.NODE: b'node', core.HEADER: b'header'}
        self.reader = Mock(side_effect=lambda path, limit: self.blobs[path])

    def repin(self):
        self.contract['files_digest'] = core.sha(json.dumps(self.entries, sort_keys=True, separators=(',', ':')).encode())
        self.manifest = json.dumps(dict(self.contract, files=self.entries)).encode()

    def observe(self, identities=None):
        with patch.object(r, 'read_package_identity', side_effect=identities or [self.identity] * 3), patch.object(
                fs.InstalledReader, '__call__', side_effect=self.reader):
            return r.observe_package_runtime(self.manifest)

    def test_exact_installed_or_held_package(self):
        for selection in ('install', 'hold'):
            result = r.parse_package_status(status(state=selection + ' ok installed'))
            self.assertEqual(result, r.PackageIdentity(core.PACKAGE_VERSION, 'amd64', selection))

    def test_case_whitespace_stanzas_and_description_continuations(self):
        other = b'Package: other\nDescription: text\n Package: wazuh-dashboard\n .\n more text\n\n'
        for raw in (other + status(), status().upper().replace(b'WAZUH-DASHBOARD', b'wazuh-dashboard').replace(
                b'INSTALL OK INSTALLED', b'install ok installed').replace(b'AMD64', b'amd64'),
                status().replace(b': ', b':\t').replace(b'\n', b'\r\n'), status().rstrip(b'\n')):
            self.assertEqual(r.parse_package_status(raw), self.identity)

    def test_size_and_format_failures_are_static(self):
        for raw in (None, '', bytearray(status()), b'', b'x' * (r.MAX_STATUS + 1)):
            with self.assertRaisesRegex(core.OperatorError, '^PACKAGE_STATUS_SIZE$'):
                r.parse_package_status(raw)
        for raw in (b'\xff', b'\x00', b'Package wazuh-dashboard', b' bad continuation',
                    status() + b' extra', status() + b'#comment', status() + b'Bad Key: a',
                    status() + b'Bad\rKey: a'):
            with self.subTest(raw=raw[:30]), self.assertRaisesRegex(core.OperatorError, '^PACKAGE_STATUS_FORMAT$'):
                r.parse_package_status(raw)

    def test_duplicate_fields_and_target_stanzas(self):
        for raw in (status() + b'Version: 0\n', status() + b'pAcKaGe: other\n'):
            with self.assertRaisesRegex(core.OperatorError, '^PACKAGE_STATUS_DUPLICATE$'):
                r.parse_package_status(raw)
        with self.assertRaisesRegex(core.OperatorError, '^PACKAGE_STATUS_AMBIGUOUS$'):
            r.parse_package_status(status() + b'\n' + status(architecture='arm64'))

    def test_whitespace_only_separator_policy_is_explicit(self):
        self.assertEqual(r.parse_package_status(b'Package: unrelated\n \t\n' + status()), self.identity)
        with self.assertRaisesRegex(core.OperatorError, '^PACKAGE_STATUS_FORMAT$'):
            r.parse_package_status(b'Package: unrelated\nDescription: text\n \n continuation\n\n' + status())

    def test_controls_and_invalid_utf8_in_unrelated_values_are_rejected(self):
        for value in (b'bad\x00text', b'bad\x1ftext', b'bad\x7ftext', b'bad\xfftext'):
            with self.subTest(value=value), self.assertRaisesRegex(core.OperatorError, '^PACKAGE_STATUS_FORMAT$'):
                r.parse_package_status(status() + b'Description: ' + value + b'\n')

    def test_unrelated_fields_never_enter_returned_identity(self):
        result = r.parse_package_status(status() + b'Description: PRIVATE_VALUE\n X-Secret: PRIVATE_VALUE\n')
        self.assertEqual(vars(result), dict(version=core.PACKAGE_VERSION, architecture='amd64', selection='install'))
        self.assertNotIn('PRIVATE_VALUE', repr(result))

    def test_partial_removed_error_and_pending_states_rejected(self):
        for state in ('install ok half-configured', 'install reinstreq installed', 'deinstall ok installed',
                      'purge ok config-files', 'install ok triggers-pending', 'install ok unpacked', ''):
            with self.subTest(state=state), self.assertRaisesRegex(core.OperatorError, '^PACKAGE_NOT_INSTALLED$'):
                r.parse_package_status(status(state=state))

    def test_missing_package_version_and_architecture_mismatch(self):
        for raw, code in ((status().replace(b'wazuh-dashboard', b'wazuh-dashboard-other'), 'PACKAGE_STATUS_MISSING'),
                          (status(version='4.14.8-1'), 'PACKAGE_VERSION'),
                          (status(architecture='arm64'), 'PACKAGE_ARCHITECTURE'),
                          (status().replace(b'Architecture: amd64\n', b''), 'PACKAGE_ARCHITECTURE')):
            with self.assertRaisesRegex(core.OperatorError, '^' + code + '$'):
                r.parse_package_status(raw)

    def test_fresh_fixed_root_database_read_without_subprocess_or_nss(self):
        with patch.object(fs, '_platform') as platform, patch.object(fs, '_identity') as nss, patch.object(
                fs, '_read_root_owned', return_value=status()) as read:
            self.assertEqual(r.read_package_identity(), self.identity)
            read.assert_called_once_with(('var', 'lib', 'dpkg', 'status'), 32 * 1024 * 1024)
            platform.assert_called_once_with()
            nss.assert_not_called()
        with patch.object(fs, '_platform', side_effect=core.OperatorError('FS_ROOT_REQUIRED')), patch.object(
                fs, '_read_root_owned') as read, self.assertRaisesRegex(core.OperatorError, '^FS_ROOT_REQUIRED$'):
            r.read_package_identity()
        read.assert_not_called()

    def test_database_os_errors_suppress_details(self):
        for number, code in ((errno.EACCES, 'FS_ACCESS'), (errno.ENOENT, 'FS_MISSING'), (errno.EIO, 'FS_IO')):
            with patch.object(fs, '_platform'), patch.object(fs, '_read_root_owned',
                    side_effect=OSError(number, 'SECRET')), self.assertRaises(core.OperatorError) as caught:
                r.read_package_identity()
            self.assertEqual(str(caught.exception), code)
            self.assertTrue(caught.exception.__suppress_context__)

    def test_observation_two_runtime_passes_bracketed_by_package_reads(self):
        order = []
        def package():
            order.append('package')
            return self.identity
        def read(path, limit):
            order.append(path)
            return self.blobs[path]
        with patch.object(r, 'read_package_identity', side_effect=package), patch.object(
                fs.InstalledReader, '__call__', side_effect=read):
            result = r.observe_package_runtime(self.manifest)
        self.assertEqual(order, ['package', core.NODE, core.HEADER, 'package', core.NODE, core.HEADER, 'package'])
        self.assertEqual(result.package, self.identity)
        self.assertEqual(result.packaged_node_version, core.CONTRACT['packaged_node_version'])
        self.assertEqual((result.runtime_passes, result.package_reads), (2, 3))
        self.assertIs(result.startup_authorized, False)
        self.assertIs(result.selected_runtime_proven, False)
        with self.assertRaises(AttributeError):
            result.startup_authorized = True

    def test_bad_manifest_or_package_prevents_runtime_reads(self):
        with patch.object(r, 'read_package_identity') as package, self.assertRaisesRegex(
                core.OperatorError, '^MANIFEST_CONTRACT$'):
            r.observe_package_runtime(b'{}')
        package.assert_not_called()
        with self.assertRaisesRegex(core.OperatorError, '^PACKAGE_NOT_INSTALLED$'):
            self.observe([core.OperatorError('PACKAGE_NOT_INSTALLED')])
        self.reader.assert_not_called()

    def test_runtime_type_bound_and_digest_failures(self):
        for raw, code in ((b'tamp', 'RUNTIME_DIGEST'), ('node', 'RUNTIME_SIZE'),
                          (b'x' * 65537, 'RUNTIME_SIZE')):
            self.blobs[core.HEADER] = raw
            with self.assertRaisesRegex(core.OperatorError, '^' + code + '$'):
                self.observe()

    def test_second_pass_runtime_or_package_change_rejected(self):
        self.reader.side_effect = [b'node', b'header', b'tamp', b'header']
        with self.assertRaisesRegex(core.OperatorError, '^RUNTIME_DIGEST$'):
            self.observe()
        self.reader.side_effect = lambda path, limit: self.blobs[path]
        held = r.parse_package_status(status(state='hold ok installed'))
        for identities in ([self.identity, held, held], [self.identity, self.identity, held],
                           [self.identity, core.OperatorError('PACKAGE_VERSION')]):
            with self.subTest(identities=identities), self.assertRaisesRegex(
                    core.OperatorError, '^(PACKAGE_CHANGED|PACKAGE_VERSION)$'):
                self.observe(identities)

    def test_native_inventory_rejects_non_ascii_before_any_live_read(self):
        name = 'node_modules/caf\u00e9/index.js'
        self.entries[name] = {'bytes': 1, 'sha256': core.sha(b'x')}
        self.repin()
        # The generic pinned format permits Unicode; native policy rejects it
        # at construction rather than surprising the operator halfway through IO.
        self.assertTrue(any(name in c.path for c in core.installed_checks(self.manifest)))
        with patch.object(fs, '_platform') as platform, self.assertRaisesRegex(
                core.OperatorError, '^FS_COMPONENTS$'):
            fs.InstalledReader(self.manifest)
        platform.assert_not_called()


if __name__ == '__main__':
    unittest.main()
