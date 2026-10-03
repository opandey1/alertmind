"""Synthetic permission/transport/packet checks; no VM or credentials used."""
import base64
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    path = ROOT / 'siem/rbac' / (name + '.py')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m = load('collect_human_baseline')
b = load('build_human_baseline_packet')
s = m.load_server()
EXPECTED, PRESERVED = m.public_inputs(s)


def search(value=1, **kwargs):
    result = {'timed_out': False, '_shards': {'failed': 0},
              'hits': {'total': {'value': value, 'relation': 'eq'}, 'hits': []}}
    result.update(kwargs)
    return result


class FakeIndexer:
    def __init__(self, username='socanalyst'):
        self.username, self.calls = username, []
        self.records = {m.GROUPS: {
            'cluster_composite_ops_ro': {'allowed_actions': ['indices:data/read/msearch']},
            'read': {'allowed_actions': ['indices:data/read*', 'indices:admin/mappings/fields/get*']}}}
        self.records['/_plugins/_security/api/rolesmapping/own_index'] = {'own_index': {
            'users': list(PRESERVED), 'backend_roles': [], 'hosts': [], 'and_backend_roles': [], 'reserved': False}}
        for user, role in m.ROLES.items():
            self.records['/_plugins/_security/api/roles/' + role] = {role: {
                **copy.deepcopy(EXPECTED[user]['role']), 'reserved': False, 'hidden': False, 'static': False}}
            self.records['/_plugins/_security/api/rolesmapping/' + role] = {role: {
                **copy.deepcopy(EXPECTED[user]['role-mapping']), 'and_backend_roles': []}}
            self.records['/_plugins/_security/api/internalusers/' + user] = {user: {
                'backend_roles': [], 'attributes': {}, 'opendistro_security_roles': [],
                'hash': 'SYNTHETIC-DO-NOT-PRINT', 'reserved': False, 'hidden': False}}
        self.account = {'user_name': username, 'backend_roles': [], 'roles': [m.ROLES.get(username)],
                        'private_unexpected_field': 'SYNTHETIC-CONTEXT-DO-NOT-PRINT'}
        self.change = None

    def request(self, method, path):
        self.calls.append((method, path))
        if self.change:
            self.change(self, path)
        if path in (m.AUTHINFO, m.ACCOUNT):
            result = copy.deepcopy(self.account)
            if path == m.AUTHINFO:
                # Every live request uses a new TCP connection/source port.
                result['remote_address'] = '127.0.0.1:' + str(40000 + len(self.calls))
            return result
        if path in m.SEARCH.values():
            return search(0 if path == m.SEARCH['000'] else 3)
        return copy.deepcopy(self.records[path])


class PermissionBaselineTests(unittest.TestCase):
    def test_enrollment_hash_comparison_is_local_and_never_returns_key(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'synthetic.keys'
            path.write_bytes(b'001 win-victim any SYNTHETIC-KEY-ONE\n002 linux-victim any SYNTHETIC-KEY-TWO\n')
            bindings = {'001': ('win-victim', hashlib.sha256(b'SYNTHETIC-KEY-ONE').hexdigest()),
                        '002': ('linux-victim', hashlib.sha256(b'SYNTHETIC-KEY-TWO').hexdigest())}
            with mock.patch.object(m, 'CLIENT_KEYS', path), mock.patch.object(m, 'BINDINGS', bindings):
                result = m.enrollment_bindings()
                self.assertEqual(result, {'agent_001_002_existing_enrollment_bindings_match': True})
                self.assertNotIn('SYNTHETIC-KEY', json.dumps(result))
                for content in (b'001 win-victim any changed\n002 linux-victim any SYNTHETIC-KEY-TWO\n',
                                b'001 win-victim any SYNTHETIC-KEY-ONE\n',
                                path.read_bytes() + b'001 win-victim any SYNTHETIC-KEY-ONE\n'):
                    path.write_bytes(content)
                    with self.assertRaises(m.BaselineError):
                        m.enrollment_bindings()

    def test_exact_grants_and_live_action_expansion_without_private_output(self):
        api = FakeIndexer('admin')
        result = m.administrative_baseline(api, EXPECTED, PRESERVED)
        self.assertEqual(result['own_index_preserved_users'], 7)
        self.assertTrue(result['two_pass_observation_equal'])
        self.assertNotIn('SYNTHETIC-DO-NOT-PRINT', json.dumps(result))
        self.assertEqual(api.calls, [('GET', path) for path in m.ADMIN_READS] * 2)

    def test_role_mapping_user_and_own_index_drift_fail_closed(self):
        def mutate(api, kind):
            role = m.ROLES['socanalyst']
            if kind == 'role':
                api.records['/_plugins/_security/api/roles/' + role][role]['cluster_permissions'] = ['all_access']
            elif kind == 'mapping':
                api.records['/_plugins/_security/api/rolesmapping/' + role][role]['and_backend_roles'] = ['admin']
            elif kind == 'user':
                api.records['/_plugins/_security/api/internalusers/socanalyst']['socanalyst']['backend_roles'] = ['admin']
            elif kind == 'unknown_grant':
                api.records['/_plugins/_security/api/roles/' + role][role]['new_permission'] = ['*']
            else:
                api.records['/_plugins/_security/api/rolesmapping/own_index']['own_index']['users'] = ['*']
        for kind in ('role', 'mapping', 'user', 'unknown_grant', 'own_index'):
            api = FakeIndexer('admin')
            mutate(api, kind)
            with self.subTest(kind=kind), self.assertRaises(m.BaselineError):
                m.administrative_baseline(api, EXPECTED, PRESERVED)

    def test_catalog_change_between_passes_is_rejected(self):
        api = FakeIndexer('admin')
        def change(api, path):
            if len(api.calls) == len(m.ADMIN_READS) + 1:
                api.records[m.GROUPS]['read']['description'] = 'changed'
        api.change = change
        with self.assertRaisesRegex(m.BaselineError, '^INDEXER_BASELINE_DRIFT$'):
            m.administrative_baseline(api, EXPECTED, PRESERVED)

    def test_nested_cycle_missing_group_and_write_action_refused(self):
        api = FakeIndexer('admin')
        api.records[m.GROUPS]['nested'] = {'allowed_actions': ['indices:data/read/search']}
        api.records[m.GROUPS]['read']['allowed_actions'] = ['nested']
        self.assertIn('indices:data/read/search', m.administrative_baseline(api, EXPECTED, PRESERVED)['inherited_read_actions'])
        for actions in (['read'], ['missing'], ['indices:data/write/bulk'], ['indices:*']):
            api = FakeIndexer('admin')
            api.records[m.GROUPS]['read']['allowed_actions'] = actions
            with self.subTest(actions=actions), self.assertRaises(m.BaselineError):
                m.administrative_baseline(api, EXPECTED, PRESERVED)

    def test_effective_identity_and_dls_positive_and_negative_controls(self):
        for user in m.PRINCIPALS:
            result = m.principal_baseline(FakeIndexer(user), 5)
            self.assertEqual(result['identity'], user)
            self.assertFalse(result['actual_dashboard_context_observed'])
            self.assertNotIn('SYNTHETIC-CONTEXT-DO-NOT-PRINT', json.dumps(result))
        with self.assertRaisesRegex(m.BaselineError, '^DLS_CONTROL$'):
            m.principal_baseline(FakeIndexer(), 0)

    def test_authinfo_snapshot_removes_only_port_and_leaves_input_unchanged(self):
        info = {'user_name': 'socanalyst', 'roles': [m.ROLES['socanalyst']],
                'backend_roles': [], 'tenants': {'global_tenant': False},
                'user_requested_tenant': None, 'custom_attribute_names': [],
                'unknown_field': {'preserve': True}, 'remote_address': '127.0.0.1:41001'}
        original = copy.deepcopy(info)
        stable = m.authinfo_snapshot(info)
        self.assertEqual(info, original)
        expected = copy.deepcopy(info)
        expected['remote_address'] = '127.0.0.1'
        self.assertEqual(stable, expected)
        self.assertIsNot(stable, info)
        self.assertEqual(m.authinfo_snapshot({'roles': []}), {'roles': []})

    def test_two_pass_identity_accepts_ipv4_and_bracketed_ipv6_port_changes(self):
        for host in ('127.0.0.1', '[::1]', '[::ffff:127.0.0.1]'):
            with self.subTest(host=host):
                api = FakeIndexer()
                ordinary = api.request
                addresses = []
                def request(method, path):
                    value = ordinary(method, path)
                    if path == m.AUTHINFO:
                        value['remote_address'] = host + ':' + str(41000 + len(addresses))
                        addresses.append(value['remote_address'])
                    return value
                api.request = request
                self.assertTrue(m.principal_baseline(api, 5)['identity_two_pass_equal'])
                self.assertEqual(len(addresses), 2)
                self.assertNotEqual(addresses[0], addresses[1])

    def test_connection_host_or_presence_change_still_fails(self):
        for change in ('host', 'missing'):
            with self.subTest(change=change):
                api = FakeIndexer()
                ordinary = api.request
                calls = []
                def request(method, path):
                    value = ordinary(method, path)
                    if path == m.AUTHINFO:
                        calls.append(path)
                        if len(calls) == 2:
                            if change == 'host':
                                value['remote_address'] = '127.0.0.2:42000'
                            else:
                                value.pop('remote_address')
                    return value
                api.request = request
                with self.assertRaisesRegex(m.BaselineError, '^IDENTITY_DRIFT$'):
                    m.principal_baseline(api, 5)

    def test_authinfo_and_account_nonconnection_drift_still_fails(self):
        changes = (
            ('user_name', 'other', 'GRANT'),
            ('backend_roles', ['admin'], 'GRANT'),
            ('roles', [m.ROLES['socanalyst'], 'own_index'], 'GRANT'),
            ('tenants', {'global_tenant': True}, 'IDENTITY_DRIFT'),
            ('user_requested_tenant', 'global_tenant', 'IDENTITY_DRIFT'),
            ('custom_attribute_names', ['new'], 'IDENTITY_DRIFT'),
            ('principal', 'new', 'IDENTITY_DRIFT'),
            ('peer_certificates', '1', 'IDENTITY_DRIFT'),
            ('unknown_field', {'new': True}, 'IDENTITY_DRIFT'),
        )
        for endpoint in (m.AUTHINFO, m.ACCOUNT):
            for key, changed, code in changes:
                with self.subTest(endpoint=endpoint, key=key):
                    api = FakeIndexer()
                    ordinary = api.request
                    calls = []
                    def request(method, path):
                        value = ordinary(method, path)
                        if path == endpoint:
                            calls.append(path)
                            if len(calls) == 2:
                                value[key] = changed
                        return value
                    api.request = request
                    if code == 'GRANT':
                        code = 'EFFECTIVE_ROLE_DRIFT' if endpoint == m.AUTHINFO else 'ACCOUNT_DRIFT'
                    with self.assertRaisesRegex(m.BaselineError, '^' + code + '$'):
                        m.principal_baseline(api, 5)

    def test_malformed_connection_metadata_is_refused(self):
        for address in (None, True, [], {}, '', 'hostname:41000', '999.0.0.1:41000',
                        '127.0.0.1:0', '127.0.0.1:65536', '127.0.0.1:1e2',
                        '[::1]:65536', '[127.0.0.1]:41000', '::1:41000',
                        '127.0.0.1:41000\nSYNTHETIC-PRIVATE-DETAIL'):
            with self.subTest(address=address), self.assertRaisesRegex(
                    m.BaselineError, '^REMOTE_ADDRESS_SHAPE$'):
                m.authinfo_snapshot({'remote_address': address})

    def test_extra_effective_roles_or_backend_roles_refused(self):
        for key, value in (('roles', ['own_index', m.ROLES['socanalyst']]),
                           ('backend_roles', ['admin']), ('user_name', 'admin')):
            api = FakeIndexer()
            api.account[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(m.BaselineError, '^EFFECTIVE_ROLE_DRIFT$'):
                m.identity(api)

    def test_partial_approximate_or_source_returning_search_refused(self):
        for data in (search(timed_out=True), search(_shards={'failed': 1}),
                     search(True), search(-1), search(hits=None),
                     search(hits={'total': {'value': 4, 'relation': 'gte'}, 'hits': []}),
                     search(hits={'total': {'value': 4, 'relation': 'eq'}, 'hits': [{'_source': 'not metadata'}]})):
            with self.subTest(data=data), self.assertRaises(m.BaselineError):
                m.count(data)

    def test_combined_summary_does_not_authorize_context_or_mutation(self):
        result = m.assemble({}, [], {})
        for key in ('mutation_authorized', 'actual_dashboard_context_observed', 'matching_server_rules_reviewed'):
            self.assertIs(result[key], False)
        self.assertIsNone(result['server_mapping_payload'])
        self.assertFalse(result['owner_scope_consent_attested_by_collector'])
        self.assertNotIn('owner_broader_server_read_scope', result['outstanding'])


class ClientBaselineTests(unittest.TestCase):
    def client(self, user='socanalyst'):
        return m.IndexerClient(s, mock.Mock(), user, 'SYNTHETIC-PASSWORD')

    def test_route_allowlist_denies_every_write_and_arbitrary_or_admin_read(self):
        client = self.client()
        for method, path in (('POST', m.SEARCH['001']), ('PUT', m.ACCOUNT), ('DELETE', m.ACCOUNT),
                             ('GET', '/_cluster/health'), ('GET', m.GROUPS),
                             ('GET', m.SEARCH['001'] + '&extra=1')):
            with self.subTest(method=method, path=path), mock.patch.object(client, 'connect') as connect:
                with self.assertRaisesRegex(m.BaselineError, '^ROUTE_DENIED$'):
                    client.request(method, path)
                connect.assert_not_called()

    def test_pin_failure_occurs_before_any_http_authorization_and_closes_peer(self):
        client = self.client()
        client.context.verify_mode = m.ssl.CERT_REQUIRED
        client.context.check_hostname = True
        raw, peer = mock.Mock(), mock.Mock()
        peer.getpeercert.return_value = b'wrong certificate'
        client.context.wrap_socket.return_value = peer
        with mock.patch.object(m.socket, 'socket', return_value=raw), mock.patch.object(m.http.client, 'HTTPConnection') as connection:
            with self.assertRaisesRegex(m.BaselineError, '^INDEXER_PEER_CHANGED$'):
                client.request('GET', m.AUTHINFO)
            connection.assert_not_called()
        raw.connect.assert_called_once_with(('127.0.0.1', 9200))
        peer.close.assert_called_once()

    def test_failed_handshake_closes_raw_socket_and_secret_can_be_released(self):
        client = self.client()
        client.context.verify_mode, client.context.check_hostname = m.ssl.CERT_REQUIRED, True
        client.context.wrap_socket.side_effect = OSError('SYNTHETIC-TLS-DETAIL')
        raw = mock.Mock()
        with mock.patch.object(m.socket, 'socket', return_value=raw), self.assertRaises(OSError):
            client.connect()
        raw.close.assert_called_once()
        client.clear()
        self.assertIsNone(client.basic)

    def test_wrong_hostname_requires_specific_mismatch_not_generic_tls_failure(self):
        client = self.client()
        for code in (62, 20):
            error = m.ssl.SSLCertVerificationError('SYNTHETIC-TLS-DETAIL')
            error.verify_code = code
            with mock.patch.object(client, 'connect', side_effect=error):
                if code == 62:
                    client.wrong_hostname_probe()
                else:
                    with self.assertRaisesRegex(m.BaselineError, '^NEGATIVE_TLS_CAUSE$'):
                        client.wrong_hostname_probe()
        peer = mock.Mock()
        with mock.patch.object(client, 'connect', return_value=peer), self.assertRaisesRegex(
                m.BaselineError, '^NEGATIVE_TLS_ACCEPTED$'):
            client.wrong_hostname_probe()
        peer.close.assert_called_once()

    def test_successful_response_uses_bounded_reader_and_closes_http_resources(self):
        client = self.client()
        peer, connection, response = mock.Mock(), mock.Mock(), mock.Mock()
        connection.getresponse.return_value = response
        response.status = 200
        response.getheader.side_effect = lambda key, default=None: {
            'Content-Type': 'application/json; charset=UTF-8',
            'Content-Encoding': 'identity'}.get(key, default)
        with mock.patch.object(client, 'connect', return_value=peer), \
             mock.patch.object(m.http.client, 'HTTPConnection', return_value=connection), \
             mock.patch.object(client.reader, 'read_body', return_value=b'{"user_name":"socanalyst"}') as read:
            self.assertEqual(client.request('GET', m.ACCOUNT), {'user_name': 'socanalyst'})
        read.assert_called_once_with(response, peer)
        response.close.assert_called_once()
        connection.close.assert_called_once()
        self.assertEqual(connection.request.call_args.args[:2], ('GET', m.ACCOUNT))
        headers = connection.request.call_args.kwargs['headers']
        self.assertEqual(headers['Accept-Encoding'], 'identity')
        self.assertEqual(headers['Connection'], 'close')

    def test_http_failure_does_not_decode_error_body_and_closes_resources(self):
        client = self.client()
        connection, response = mock.Mock(), mock.Mock()
        connection.getresponse.return_value = response
        response.status = 401
        with mock.patch.object(client, 'connect'), \
             mock.patch.object(m.http.client, 'HTTPConnection', return_value=connection), \
             mock.patch.object(client.reader, 'read_body') as read, self.assertRaisesRegex(
                 m.BaselineError, '^INDEXER_HTTP_STATUS$'):
            client.request('GET', m.AUTHINFO)
        read.assert_not_called()
        response.close.assert_called_once()
        connection.close.assert_called_once()
        peer = mock.Mock()
        with mock.patch.object(client, 'connect', return_value=peer), \
             mock.patch.object(m.http.client, 'HTTPConnection', side_effect=OSError('SYNTHETIC-DETAIL')), \
             self.assertRaises(OSError):
            client.request('GET', m.AUTHINFO)
        peer.close.assert_called_once()

    def test_cli_suppresses_exception_details_and_does_not_emit_partial_result(self):
        with mock.patch.object(m.sys, 'argv', ['baseline']), mock.patch.object(m.os, 'geteuid', create=True, return_value=0), \
             mock.patch.object(m.sys.stdin, 'isatty', return_value=True), mock.patch.object(m.sys.stdout, 'isatty', return_value=True), \
             mock.patch('builtins.input', return_value='REVIEWED-BASELINE'), \
             mock.patch.object(m, 'load_server', side_effect=ValueError('SYNTHETIC-PASSWORD')), \
             mock.patch('builtins.print') as output:
            self.assertEqual(m.main(), 1)
        text = ' '.join(str(call) for call in output.call_args_list)
        self.assertIn('STOP: human baseline failed at preflight', text)
        self.assertNotIn('SYNTHETIC-PASSWORD', text)

    def test_cli_connects_read_only_phases_and_emits_only_complete_sanitized_result(self):
        made, server_client = [], mock.Mock()
        def make_client(server, context, username, password):
            api = FakeIndexer(username)
            ordinary = api.request
            def request(method, path):
                if username == 'admin' and path == m.SEARCH['000']:
                    api.calls.append((method, path))
                    return search(5)
                return ordinary(method, path)
            api.request = request
            api.reader = mock.Mock()
            api.connect = mock.Mock(return_value=mock.Mock())
            api.wrong_hostname_probe = mock.Mock()
            api.clear = mock.Mock()
            made.append(api)
            return api
        with mock.patch.object(m.sys, 'argv', ['baseline']), mock.patch.object(m.os, 'geteuid', create=True, return_value=0), \
             mock.patch.object(m.sys.stdin, 'isatty', return_value=True), mock.patch.object(m.sys.stdout, 'isatty', return_value=True), \
             mock.patch('builtins.input', return_value='REVIEWED-BASELINE'), \
             mock.patch.object(m, 'secret', side_effect=['SYNTHETIC-admin', 'SYNTHETIC-human', 'SYNTHETIC-service',
                                                       'SYNTHETIC-Server-user', 'SYNTHETIC-Server-password']), \
             mock.patch.object(m, 'tls_context'), mock.patch.object(m, 'IndexerClient', side_effect=make_client), \
             mock.patch.object(m, 'enrollment_bindings', return_value={'agent_001_002_existing_enrollment_bindings_match': True}), \
             mock.patch.object(s, 'make_context'), mock.patch.object(s, 'Client', return_value=server_client), \
             mock.patch.object(s, 'collect', return_value={'inventory_version': 1}) as collect, \
             mock.patch.object(m, 'load_server', return_value=s), mock.patch('builtins.print') as output:
            self.assertEqual(m.main(), 0)
        texts = [call.args[0] for call in output.call_args_list]
        summary = json.loads(next(text for text in texts if text.startswith('{')))
        self.assertFalse(summary['actual_dashboard_context_observed'])
        self.assertTrue(summary['indexer']['agent_001_002_existing_enrollment_bindings_match'])
        self.assertNotIn('SYNTHETIC', ' '.join(texts))
        self.assertEqual([p['identity'] for p in summary['principals']], list(m.PRINCIPALS))
        collect.assert_called_once_with(server_client, 'SYNTHETIC-Server-user')
        server_client.authenticate.assert_called_once_with('SYNTHETIC-Server-user', 'SYNTHETIC-Server-password')
        self.assertIsNone(server_client.token)
        for client in made:
            client.clear.assert_called_once()
        self.assertEqual(len(made[1].calls), 4 * len(m.ADMIN_READS) + 1)

    def test_ca_size_and_pin_failure_do_not_create_trust_context(self):
        for raw, code in ((b'A' * 65537, 'CA_SIZE'),
                          (b'-----BEGIN CERTIFICATE-----\nYQ==\n-----END CERTIFICATE-----\n', 'CA_CHANGED')):
            path = mock.Mock()
            handle = mock.Mock()
            handle.read.return_value = raw
            path.open.return_value.__enter__ = mock.Mock(return_value=handle)
            path.open.return_value.__exit__ = mock.Mock(return_value=False)
            with mock.patch.object(m, 'CA', path), mock.patch.object(m.ssl, 'SSLContext') as context, \
                 self.assertRaisesRegex(m.BaselineError, '^' + code + '$'):
                m.tls_context()
            handle.read.assert_called_once_with(65537)
            context.assert_not_called()


class BaselinePacketTests(unittest.TestCase):
    def test_public_runbook_stage_syntax_and_python310_compatibility(self):
        doc = (ROOT / 'docs/runbooks/rbac-human-permission-baseline.md').read_text(encoding='utf-8')
        stage = doc.split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
        ast.parse(stage, feature_version=(3, 10))
        self.assertIn("Path('/root/alertmind-human-baseline-identityfix')", stage)
        self.assertIn('need(not os.path.lexists(root))', stage)
        self.assertIn('cd /root/alertmind-human-baseline-identityfix\n', doc)
        self.assertNotIn('cd /root/alertmind-human-baseline\n', doc)
        for name in ('collect_human_baseline.py', 'build_human_baseline_packet.py'):
            ast.parse((m.HERE / name).read_bytes(), feature_version=(3, 10))
        self.assertIn('No VM execution, authentication or permission change is released', doc)
        self.assertIn('not actual Dashboard-generated context', doc)
        for line in (m.HERE / 'HUMAN-BASELINE-SHA256SUMS').read_text(encoding='ascii').splitlines():
            digest, name = line.split('  ')
            self.assertEqual(hashlib.sha256((m.HERE / name).read_bytes().replace(b'\r\n', b'\n')).hexdigest(), digest)
    def test_public_packet_exact_files_hashes_lf_and_no_helper_execution(self):
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(m, 'main', side_effect=AssertionError('executed')):
            path = Path(temp) / 'packet.json'
            digest = b.build(path)
            self.assertEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest())
            data = json.loads(path.read_bytes())
            self.assertEqual(data['review_status'], 'awaiting-focused-review')
            self.assertEqual({f['name'] for f in data['files']}, set(b.FILES) | {'SHA256SUMS'})
            for item in data['files']:
                raw = base64.b64decode(item['base64'], validate=True)
                self.assertEqual(hashlib.sha256(raw).hexdigest(), item['sha256'])
                self.assertNotIn(b'\r', raw)
            with self.assertRaises(FileExistsError):
                b.build(path)

    def test_reused_server_reader_drift_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            for name in b.FILES:
                raw = (b.HERE / name).read_bytes().replace(b'\r\n', b'\n')
                (folder / name).write_bytes(raw + (b'\n' if name == 'collect_server_inventory.py' else b''))
            with mock.patch.object(b, 'HERE', folder), self.assertRaisesRegex(ValueError, '^SERVER_READER_CHANGED$'):
                b.build(folder / 'packet.json')
            self.assertFalse((folder / 'packet.json').exists())

    def test_oversize_raw_crlf_file_refused_before_normalization(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            (folder / b.FILES[0]).write_bytes(b'#\r\n' * 45000)
            with mock.patch.object(b, 'HERE', folder), self.assertRaisesRegex(ValueError, '^PUBLIC_FILE_SIZE$'):
                b.build(folder / 'packet.json')
            self.assertFalse((folder / 'packet.json').exists())


if __name__ == '__main__':
    unittest.main()
