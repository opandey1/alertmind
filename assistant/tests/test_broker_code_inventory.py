"""Offline-only checks. No installed Dashboard, credentials or HTTP required."""
import ast
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / 'siem/rbac/collect_broker_code_inventory.py'
spec = importlib.util.spec_from_file_location('broker_code_inventory', PATH)
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


class BrokerCodeInventoryTests(unittest.TestCase):
    def blobs(self):
        data = {name: b'// SECRET-SENTINEL: never echo installed code\n' for name in inventory.FILES}
        for label, plugin in (('core_manifest', 'wazuhCore'), ('main_manifest', 'wazuh'),
                              ('security_manifest', 'securityDashboards')):
            data[label] = json.dumps({'id': plugin, 'version': '4.14.7-01' if plugin != 'securityDashboards' else '2.19.5',
                                     'server': True, 'optionalPlugins': ['securityDashboards'],
                                     'requiredPlugins': ['wazuhCore']}).encode()
        data['broker_client'] += b'rejectUnauthorized: false; authContext; getCurrentUser; /run_as; isEnabledAuthWithRunAs'
        data['context_factory'] += b'/_opendistro/_security/api/account; asCurrentUser; user_name'
        data['factory_selector'] += b'securityDashboards'
        data['core_plugin'] += b'asScoped'
        data['login_route'] += b'/api/login; /api/request'
        data['login_controller'] += b'asCurrentUser.authenticate'
        return data

    def test_summary_is_sanitized_and_never_authorizes_broker(self):
        data = self.blobs()
        result = inventory.summarize(data)
        self.assertTrue(all(result['literal_indicators_only'].values()))
        self.assertEqual(result['tls_source_observation']['classification'], 'explicit_false_text_present')
        self.assertFalse(result['broker_execution_authorized'])
        self.assertFalse(result['mutation_authorized'])
        self.assertFalse(result['tls_source_observation']['effective_verification_proven'])
        self.assertTrue(result['review_required'])
        self.assertNotIn('SECRET-SENTINEL', json.dumps(result))
        for item in result['files']:
            self.assertEqual(item['sha256'], hashlib.sha256(data[item['label']]).hexdigest())
        self.assertEqual(result['upstream_reference_commit'], '7659dead50782307faa1c0a313b1fd29d0b2c014')

    def test_absence_true_literal_and_comments_never_prove_tls(self):
        for source in (b'other code', b'rejectUnauthorized: true', b'// rejectUnauthorized: false',
                       b'rejectUnauthorized: true; rejectUnauthorized: false', b'rejectUnauthorized: option'):
            with self.subTest(source=source):
                data = self.blobs(); data['broker_client'] = source
                result = inventory.summarize(data)
                self.assertFalse(result['broker_execution_authorized'])
                self.assertFalse(result['tls_source_observation']['effective_verification_proven'])
                expected = 'explicit_false_text_present' if b': false' in source else 'unresolved'
                self.assertEqual(result['tls_source_observation']['classification'], expected)

    def test_manifest_identity_version_and_dependencies_fail_closed(self):
        mutations = [('id', 'wrong'), ('version', '4.14.8-01'), ('version', 'SECRET-SENTINEL'),
                     ('server', 1), ('server', False), ('optionalPlugins', []),
                     ('optionalPlugins', 'securityDashboards')]
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                data = self.blobs(); manifest = json.loads(data['core_manifest']); manifest[field] = value
                data['core_manifest'] = json.dumps(manifest).encode()
                with self.assertRaises(inventory.InventoryError): inventory.summarize(data)
        data = self.blobs(); value = json.loads(data['main_manifest']); value['requiredPlugins'] = []
        data['main_manifest'] = json.dumps(value).encode()
        with self.assertRaisesRegex(inventory.InventoryError, 'PLUGIN_DEPENDENCIES'): inventory.summarize(data)

    def test_manifest_duplicate_json_invalid_numbers_and_shapes_rejected(self):
        for raw in (b'{"id":"wazuhCore","id":"wazuhCore"}', b'[]', b'{"version":NaN}', b'\xff'):
            with self.subTest(raw=raw), self.assertRaises(Exception):
                inventory.parse_manifest(raw, 'wazuhCore', '4.14.7-01')

    def test_exact_files_size_and_encoding(self):
        for label in inventory.FILES:
            data = self.blobs(); del data[label]
            with self.subTest(missing=label), self.assertRaisesRegex(inventory.InventoryError, 'FILE_SET'):
                inventory.summarize(data)
        data = self.blobs(); data['other'] = b'x'
        with self.assertRaisesRegex(inventory.InventoryError, 'FILE_SET'): inventory.summarize(data)
        for raw in (b'', b'x' * (inventory.MAX_BYTES + 1), b'\x00', b'\xff'):
            data = self.blobs(); data['broker_client'] = raw
            with self.subTest(raw=raw[:5]), self.assertRaises(Exception): inventory.summarize(data)
        with mock.patch.object(inventory, 'MAX_TOTAL_BYTES', 1):
            with self.assertRaisesRegex(inventory.InventoryError, 'TOTAL_SIZE'): inventory.summarize(self.blobs())

    def test_two_pass_observation_and_fixed_path_allowlist(self):
        data = self.blobs()
        paths = [inventory.ROOT / relative for relative in inventory.FILES.values()]
        reader = mock.Mock(side_effect=list(data.values()) * 2)
        result = inventory.collect(reader)
        self.assertTrue(result['two_pass_bytes_equal'])
        self.assertEqual([x.args[0] for x in reader.call_args_list], paths * 2)
        changed = list(data.values()); changed[-1] += b' changed'
        with self.assertRaisesRegex(inventory.InventoryError, 'SOURCE_DRIFT'):
            inventory.collect(mock.Mock(side_effect=list(data.values()) + changed))
        with mock.patch.object(inventory, 'MAX_TOTAL_BYTES', 1):
            reader = mock.Mock(return_value=b'xx')
            with self.assertRaisesRegex(inventory.InventoryError, 'TOTAL_SIZE'): inventory.collect(reader)
            self.assertEqual(reader.call_count, 1)

    def metadata(self, mode=stat.S_IFREG | 0o644, uid=0, size=4):
        return SimpleNamespace(st_mode=mode, st_uid=uid, st_gid=0, st_dev=1, st_ino=2,
                               st_size=size, st_mtime_ns=3, st_ctime_ns=4)

    def test_reject_symlink_permissions_owner_and_wrong_types(self):
        for mode, uid in ((stat.S_IFLNK | 0o777, 0), (stat.S_IFREG | 0o666, 0),
                          (stat.S_IFREG | 0o644, 1000), (stat.S_IFIFO | 0o600, 0)):
            with self.subTest(mode=mode, uid=uid), self.assertRaises(inventory.InventoryError):
                inventory.trusted(self.metadata(mode, uid))
        inventory.trusted(self.metadata())
        inventory.trusted(self.metadata(stat.S_IFDIR | 0o755), directory=True)
        with self.assertRaises(inventory.InventoryError): inventory.trusted(self.metadata(), directory=True)

    def read_fixture(self, raw=b'text', states=None, parent_bad=False, initial_size=4):
        # Mock only the filesystem boundary: exercise open flags, bounded reads,
        # descriptor/path drift, close handling and metadata guards on all OSes.
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        initial = self.metadata(size=initial_size)
        directory = self.metadata(stat.S_IFDIR | (0o777 if parent_bad else 0o755))
        path = mock.Mock(); path.is_absolute.return_value = True
        parent = mock.Mock(); parent.lstat.return_value = directory
        path.parents = [parent]; path.lstat.side_effect = [initial, initial]
        source = mock.MagicMock(); source.__enter__.return_value = source
        source.fileno.return_value = 10; source.read.return_value = raw
        stack.enter_context(mock.patch.object(inventory.os, 'O_NOFOLLOW', 0x20000, create=True))
        stack.enter_context(mock.patch.object(inventory.os, 'O_NONBLOCK', 0x800, create=True))
        opener = stack.enter_context(mock.patch.object(inventory.os, 'open', return_value=10))
        stack.enter_context(mock.patch.object(inventory.os, 'fdopen', return_value=source))
        stack.enter_context(mock.patch.object(inventory.os, 'fstat', side_effect=states or [initial] * 3))
        closer = stack.enter_context(mock.patch.object(inventory.os, 'close'))
        return path, source, opener, closer

    def test_descriptor_read_is_bounded_nonfollowing_and_closed(self):
        path, source, opener, _ = self.read_fixture()
        self.assertEqual(inventory.read_public(path), b'text')
        self.assertEqual(opener.call_args.args[1], inventory.os.O_RDONLY | 0x20000 | 0x800)
        source.read.assert_called_once_with(inventory.MAX_BYTES + 1)
        source.__exit__.assert_called_once()

    def test_file_read_drift_and_failures(self):
        for raw in (b'', b'textx', b'\xffxxx', b'\x00xxx'):
            with self.subTest(raw=raw):
                path, source, _, _ = self.read_fixture(raw=raw)
                with self.assertRaises(Exception): inventory.read_public(path)
                source.__exit__.assert_called_once()
        before = self.metadata(); changed = copy.copy(before); changed.st_ino += 1
        path, _, _, _ = self.read_fixture(states=[before, changed])
        with self.assertRaisesRegex(inventory.InventoryError, 'FILE_CHANGED'): inventory.read_public(path)
        path, _, opener, _ = self.read_fixture(parent_bad=True)
        with self.assertRaisesRegex(inventory.InventoryError, 'UNTRUSTED_FILE_METADATA'): inventory.read_public(path)
        opener.assert_not_called()
        path, _, opener, _ = self.read_fixture(initial_size=inventory.MAX_BYTES + 1)
        with self.assertRaisesRegex(inventory.InventoryError, 'FILE_SIZE'): inventory.read_public(path)
        opener.assert_not_called()

    def test_main_static_errors_and_no_partial_results(self):
        with mock.patch.object(inventory.sys, 'argv', ['collector']), \
             mock.patch.object(inventory.sys, 'platform', 'linux'), \
             mock.patch.object(inventory.os, 'geteuid', return_value=0, create=True):
            for error in (FileNotFoundError('SECRET-SENTINEL'), ValueError('SECRET-SENTINEL'),
                          KeyboardInterrupt(), inventory.InventoryError('SOURCE_DRIFT')):
                output = io.StringIO()
                with mock.patch.object(inventory, 'collect', side_effect=error), contextlib.redirect_stdout(output):
                    self.assertEqual(inventory.main(), 1)
                self.assertNotIn('SECRET-SENTINEL', output.getvalue())
                self.assertNotIn('inventory_version', output.getvalue())
                self.assertNotIn('STOP POINT:', output.getvalue())
            result = inventory.summarize(self.blobs())
            output = io.StringIO()
            with mock.patch.object(inventory, 'collect', return_value=result), contextlib.redirect_stdout(output):
                self.assertEqual(inventory.main(), 0)
            self.assertIn('broker execution and live changes remain on hold', output.getvalue())

    def test_main_rejects_args_and_nonroot_before_read(self):
        for args, uid, platform in ((['collector', 'path'], 0, 'linux'), (['collector'], 1000, 'linux'),
                                    (['collector'], 0, 'win32')):
            with mock.patch.object(inventory.sys, 'argv', args), mock.patch.object(inventory.sys, 'platform', platform), \
                 mock.patch.object(inventory.os, 'geteuid', return_value=uid, create=True), \
                 mock.patch.object(inventory, 'collect') as collector, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(inventory.main(), 1)
                collector.assert_not_called()

    def test_public_manifest_and_no_network_or_execution_imports(self):
        manifest = PATH.with_name('BROKER-CODE-SHA256SUMS').read_text(encoding='ascii').splitlines()
        self.assertEqual(len(manifest), 1)
        digest, name = manifest[0].split()
        self.assertEqual((digest, name), (hashlib.sha256(PATH.read_bytes()).hexdigest(), PATH.name))
        source = PATH.read_text(encoding='utf-8')
        tree = ast.parse(source, feature_version=(3, 10))
        imports = {n.names[0].name for n in ast.walk(tree) if isinstance(n, ast.Import)}
        self.assertEqual(imports, {'hashlib', 'json', 'os', 're', 'stat', 'sys'})
        for forbidden in ('subprocess', 'socket', 'urllib', 'getpass', 'eval(', 'exec(', '.write_text(', '.write_bytes('):
            self.assertNotIn(forbidden, source)
        for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call)):
            if isinstance(call.func, ast.Name) and call.func.id == 'require':
                self.assertIsInstance(call.args[1], ast.Constant)
        attrs = (ROOT / '.gitattributes').read_text()
        self.assertIn('siem/rbac/collect_broker_code_inventory.py text eol=lf', attrs)
        self.assertIn('siem/rbac/BROKER-CODE-SHA256SUMS text eol=lf', attrs)


if __name__ == '__main__':
    unittest.main()
