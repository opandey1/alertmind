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
REAL_SERVICE_IDENTITY = inventory.service_identity


class BrokerCodeInventoryTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(inventory, 'service_identity', return_value=(991, 992))
        self.identity = patcher.start()
        self.addCleanup(patcher.stop)
        self.resolve_identity = REAL_SERVICE_IDENTITY

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
        self.assertEqual(result['inventory_version'], 2)
        self.assertTrue(result['ownership_policy']['service_owned_code_is_service_mutable'])
        self.assertFalse(result['ownership_policy']['package_authenticity_proven'])
        self.assertFalse(result['ownership_policy']['atomic_snapshot_proven'])
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

    def metadata(self, mode=stat.S_IFREG | 0o644, uid=0, size=4, gid=0):
        return SimpleNamespace(st_mode=mode, st_uid=uid, st_gid=gid, st_dev=1, st_ino=2,
                               st_size=size, st_mtime_ns=3, st_ctime_ns=4)

    def test_reject_symlink_permissions_owner_and_wrong_types(self):
        for mode, uid in ((stat.S_IFLNK | 0o777, 0), (stat.S_IFREG | 0o666, 0),
                          (stat.S_IFREG | 0o644, 1000), (stat.S_IFIFO | 0o600, 0)):
            with self.subTest(mode=mode, uid=uid), self.assertRaises(inventory.InventoryError):
                inventory.trusted(self.metadata(mode, uid))
        inventory.trusted(self.metadata())
        inventory.trusted(self.metadata(stat.S_IFDIR | 0o755), directory=True)
        with self.assertRaises(inventory.InventoryError): inventory.trusted(self.metadata(), directory=True)

    def read_fixture(self, raw=b'text', states=None, parent_bad=False, initial_size=4,
                     service_owned=False, overrides=None, path=None):
        # Mock only the filesystem boundary: exercise open flags, bounded reads,
        # descriptor/path drift, close handling and metadata guards on all OSes.
        if hasattr(self, 'fixture_stack'):
            self.fixture_stack.close()
        stack = contextlib.ExitStack()
        self.fixture_stack = stack
        self.addCleanup(stack.close)
        path = path or inventory.ROOT / inventory.FILES['core_manifest']
        initial = self.metadata(size=initial_size, uid=991 if service_owned else 0,
                                gid=992 if service_owned else 0)
        directories = list(reversed(path.parents))
        records = {}
        for parent in directories:
            service = service_owned and inventory.DASHBOARD_ROOT in (parent, *parent.parents)
            records[parent] = self.metadata(stat.S_IFDIR | (0o750 if service else 0o755),
                                            uid=991 if service else 0, gid=992 if service else 0)
        records[path] = initial
        if parent_bad:
            records[directories[0]].st_mode = stat.S_IFDIR | 0o777
        records.update(overrides or {})
        stack.enter_context(mock.patch.object(inventory.Path, 'lstat', autospec=True,
                                              side_effect=lambda p: records[p]))
        source = mock.MagicMock(); source.__enter__.return_value = source
        source.fileno.return_value = 10; source.read.return_value = raw
        stack.enter_context(mock.patch.object(inventory.os, 'O_NOFOLLOW', 0x20000, create=True))
        stack.enter_context(mock.patch.object(inventory.os, 'O_NONBLOCK', 0x800, create=True))
        stack.enter_context(mock.patch.object(inventory.os, 'O_DIRECTORY', 0x10000, create=True))
        def open_fd(name, flags, *, dir_fd):
            if flags & inventory.os.O_DIRECTORY:
                index = 0 if dir_fd is None else dir_fd - 20 + 1
                self.assertEqual(name, str(directories[0]) if index == 0 else directories[index].name)
                return 20 + index
            self.assertEqual(name, path.name)
            self.assertEqual(dir_fd, 20 + len(directories) - 1)
            return 10
        opener = stack.enter_context(mock.patch.object(inventory.os, 'open', side_effect=open_fd))
        stack.enter_context(mock.patch.object(inventory.os, 'fdopen', return_value=source))
        file_states = iter(states or [initial] * 2)
        stack.enter_context(mock.patch.object(inventory.os, 'fstat',
            side_effect=lambda fd: next(file_states) if fd == 10 else records[directories[fd - 20]]))
        closer = stack.enter_context(mock.patch.object(inventory.os, 'close'))
        return path, source, opener, closer

    def test_descriptor_read_is_bounded_nonfollowing_and_closed(self):
        path, source, opener, closer = self.read_fixture()
        self.assertEqual(inventory.read_public(path), b'text')
        self.assertEqual(opener.call_args.args[1], inventory.os.O_RDONLY | 0x20000 | 0x800)
        source.read.assert_called_once_with(inventory.MAX_BYTES + 1)
        source.__exit__.assert_called_once()
        self.assertEqual([c.args[0] for c in closer.call_args_list],
                         list(reversed(range(20, 20 + len(path.parents)))))
        for call in opener.call_args_list[:-1]:
            self.assertEqual(call.args[1], inventory.os.O_RDONLY | 0x20000 | 0x800 | 0x10000)

    def test_file_read_drift_and_failures(self):
        for raw in (b'', b'textx', b'\xffxxx', b'\x00xxx'):
            with self.subTest(raw=raw):
                path, source, _, _ = self.read_fixture(raw=raw)
                code = 'SOURCE_ENCODING' if raw in (b'\xffxxx', b'\x00xxx') else 'FILE_SIZE'
                with self.assertRaisesRegex(inventory.InventoryError, '^' + code + '$'):
                    inventory.read_public(path)
                source.__exit__.assert_called_once()
        before = self.metadata(); changed = copy.copy(before); changed.st_ino += 1
        path, _, _, _ = self.read_fixture(states=[before, changed])
        with self.assertRaisesRegex(inventory.InventoryError, 'FILE_CHANGED'): inventory.read_public(path)
        path, _, opener, _ = self.read_fixture(parent_bad=True)
        with self.assertRaisesRegex(inventory.InventoryError, 'UNTRUSTED_FILE_METADATA'): inventory.read_public(path)
        opener.assert_not_called()

        for raw in (b'\xff', b'\x00'):
            data = self.blobs(); data['broker_client'] = raw
            with self.assertRaisesRegex(inventory.InventoryError, '^SOURCE_ENCODING$'):
                inventory.summarize(data)
            with self.assertRaisesRegex(inventory.InventoryError, '^SOURCE_ENCODING$'):
                inventory.parse_manifest(raw, 'wazuhCore')

        for error, code in ((FileNotFoundError, 'PUBLIC_FILE_MISSING'),
                            (PermissionError, 'PUBLIC_FILE_ACCESS_DENIED'),
                            (IsADirectoryError, 'PUBLIC_FILE_IS_DIRECTORY')):
            for boundary in ('lstat', 'open', 'read'):
                with self.subTest(error=error, boundary=boundary):
                    path, source, opener, _ = self.read_fixture()
                    target = {'lstat': inventory.Path.lstat, 'open': opener, 'read': source.read}[boundary]
                    target.side_effect = error('SECRET-SENTINEL')
                    with self.assertRaisesRegex(inventory.InventoryError, '^' + code + '$') as caught:
                        inventory.read_public(path)
                    self.assertTrue(caught.exception.__suppress_context__)
                    if boundary == 'read':
                        source.__exit__.assert_called_once()
        path, _, opener, _ = self.read_fixture(initial_size=inventory.MAX_BYTES + 1)
        with self.assertRaisesRegex(inventory.InventoryError, 'FILE_SIZE'): inventory.read_public(path)
        inventory.os.fdopen.assert_not_called()

        path, _, _, closer = self.read_fixture()
        inventory.os.fdopen.side_effect = OSError('SECRET-SENTINEL')
        with self.assertRaises(OSError):
            inventory.read_public(path)
        self.assertEqual([c.args[0] for c in closer.call_args_list],
                         [10] + list(reversed(range(20, 20 + len(path.parents)))))

    def test_service_identity_is_named_and_nonroot(self):
        user = SimpleNamespace(pw_name='wazuh-dashboard', pw_uid=991, pw_gid=992)
        group = SimpleNamespace(gr_name='wazuh-dashboard', gr_gid=992)
        pwd = SimpleNamespace(getpwnam=mock.Mock(return_value=user))
        grp = SimpleNamespace(getgrnam=mock.Mock(return_value=group))
        with mock.patch.dict('sys.modules', {'pwd': pwd, 'grp': grp}):
            self.assertEqual(self.resolve_identity(), (991, 992))
            pwd.getpwnam.assert_called_once_with('wazuh-dashboard')
            grp.getgrnam.assert_called_once_with('wazuh-dashboard')
            for record, field, bad in ((user, 'pw_name', 'other'), (group, 'gr_name', 'other'),
                                        (user, 'pw_uid', 0), (group, 'gr_gid', 0),
                                        (user, 'pw_gid', 123)):
                old = getattr(record, field)
                setattr(record, field, bad)
                with self.assertRaisesRegex(inventory.InventoryError, '^SERVICE_IDENTITY_INVALID$'):
                    self.resolve_identity()
                setattr(record, field, old)
            for lookup in (pwd.getpwnam, grp.getgrnam):
                lookup.side_effect = KeyError('SECRET-SENTINEL')
                with self.assertRaisesRegex(inventory.InventoryError, '^SERVICE_IDENTITY_UNAVAILABLE$') as caught:
                    self.resolve_identity()
                self.assertTrue(caught.exception.__suppress_context__)
                lookup.side_effect = None

    def test_service_identity_changes_stop_collection(self):
        self.identity.side_effect = [(991, 992), (991, 993)]
        reader = mock.Mock(side_effect=list(self.blobs().values()) * 2)
        with self.assertRaisesRegex(inventory.InventoryError, '^SERVICE_IDENTITY_CHANGED$'):
            inventory.collect(reader)
        self.identity.side_effect = inventory.InventoryError('SERVICE_IDENTITY_UNAVAILABLE')
        reader.reset_mock()
        with self.assertRaises(inventory.InventoryError):
            inventory.collect(reader)
        reader.assert_not_called()

    def test_ownership_boundary_rejects_service_ancestors_and_prefixes(self):
        for name in ('/', '/usr', '/usr/share', '/usr/share/wazuh-dashboard-other',
                     '/usr/share/wazuh-dashboard-other/plugins'):
            owners = inventory.allowed_owners(Path(name), (991, 992))
            self.assertEqual(owners, ((0, 0),))
            with self.assertRaises(inventory.InventoryError):
                inventory.trusted(self.metadata(uid=991, gid=992), owners=owners)
        for path in (inventory.DASHBOARD_ROOT, inventory.ROOT, inventory.ROOT / 'wazuh'):
            owners = inventory.allowed_owners(path, (991, 992))
            self.assertEqual(owners, ((0, 0), (991, 992)))
            for uid, gid in ((991, 0), (0, 992), (1000, 992), (991, 1000)):
                with self.assertRaises(inventory.InventoryError):
                    inventory.trusted(self.metadata(uid=uid, gid=gid), owners=owners)

    def test_service_owned_fixed_tree_reads_and_rejects_bad_metadata(self):
        for relative in inventory.FILES.values():
            path, _, _, _ = self.read_fixture(service_owned=True, path=inventory.ROOT / relative)
            self.assertEqual(inventory.read_public(path), b'text')
        target = inventory.ROOT / inventory.FILES['core_manifest']
        for component in (*target.parents, target):
            directory = component != target
            for mode, uid, gid in ((0o770, 991, 992), (0o757, 991, 992),
                                   (0o750, 1000, 992), (0o750, 991, 1000)):
                bad = self.metadata((stat.S_IFDIR if directory else stat.S_IFREG) | mode, uid, gid=gid)
                path, source, _, _ = self.read_fixture(service_owned=True, overrides={component: bad})
                with self.assertRaisesRegex(inventory.InventoryError, '^UNTRUSTED_FILE_METADATA$'):
                    inventory.read_public(path)
                source.read.assert_not_called()
            for kind in (stat.S_IFLNK, stat.S_IFIFO, stat.S_IFREG if directory else stat.S_IFDIR):
                bad = self.metadata(kind | 0o750)
                path, source, _, _ = self.read_fixture(service_owned=True, overrides={component: bad})
                with self.assertRaisesRegex(inventory.InventoryError, '^UNTRUSTED_FILE_METADATA$'):
                    inventory.read_public(path)
                source.read.assert_not_called()

    def test_directory_descriptor_and_path_replacement_fail_closed(self):
        for boundary in ('open', 'after_read_fd', 'after_read_path'):
            path, source, _, closer = self.read_fixture(service_owned=True)
            original = inventory.os.fstat.side_effect
            calls = 0
            def fstat(fd):
                nonlocal calls
                value = original(fd)
                if fd == 20:
                    calls += 1
                    if boundary == 'open' or (boundary == 'after_read_fd' and calls == 2):
                        value = copy.copy(value); value.st_ino += 1
                return value
            inventory.os.fstat.side_effect = fstat
            if boundary == 'after_read_path':
                original_lstat = inventory.Path.lstat.side_effect
                def changed_lstat(p):
                    value = original_lstat(p)
                    if p == path.parents[-1] and source.read.called:
                        value = copy.copy(value); value.st_ino += 1
                    return value
                inventory.Path.lstat.side_effect = changed_lstat
            with self.assertRaisesRegex(inventory.InventoryError, '^DIRECTORY_CHANGED$'):
                inventory.read_public(path)
            self.assertIn(mock.call(20), closer.call_args_list)
            if boundary == 'open':
                source.read.assert_not_called()

    def test_only_fixed_paths_can_be_read(self):
        for path in (Path('relative'), inventory.DASHBOARD_ROOT / 'wazuh.yml',
                     inventory.ROOT / 'other.js', inventory.ROOT / '../plugins/wazuhCore/opensearch_dashboards.json',
                     Path('/usr/share/wazuh-dashboard-other/plugins/wazuhCore/opensearch_dashboards.json')):
            with mock.patch.object(inventory.os, 'open') as opener:
                with self.assertRaisesRegex(inventory.InventoryError, '^FIXED_PATH_REQUIRED$'):
                    inventory.read_public(path)
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

            for error, code in ((FileNotFoundError('SECRET-SENTINEL'), 'PUBLIC_FILE_MISSING'),
                                (PermissionError('SECRET-SENTINEL'), 'PUBLIC_FILE_ACCESS_DENIED'),
                                (IsADirectoryError('SECRET-SENTINEL'), 'PUBLIC_FILE_IS_DIRECTORY')):
                output = io.StringIO()
                # Exercise translation -> collect -> CLI, not a pretranslated mock.
                with mock.patch.object(inventory, '_read_public', side_effect=error), contextlib.redirect_stdout(output):
                    self.assertEqual(inventory.main(), 1)
                self.assertEqual(output.getvalue(), 'STOP: broker code inventory failed; code=' + code + '; no result accepted.\n')

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
        def check_capabilities(tree):
            imports = {alias.name for n in ast.walk(tree) if isinstance(n, ast.Import) for alias in n.names}
            imports |= {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
            self.assertEqual(imports, {'contextlib', 'hashlib', 'json', 'os', 'pathlib', 'pwd', 'grp', 're', 'stat', 'sys'})
            os_calls = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call)
                        and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name)
                        and n.func.value.id == 'os'}
            self.assertLessEqual(os_calls, {'open', 'fdopen', 'fstat', 'close', 'geteuid'})
        check_capabilities(tree)
        # Parse only: these regression mutations must never be imported/executed.
        for addition in ('from http.client import HTTPSConnection', 'os.system("never execute")',
                         'os.popen("never execute")', 'os.execv("never execute", [])'):
            with self.subTest(addition=addition), self.assertRaises(AssertionError):
                check_capabilities(ast.parse(source + '\n' + addition, feature_version=(3, 10)))
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
