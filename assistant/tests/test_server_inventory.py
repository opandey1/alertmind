"""Offline tests only. No credentials, VM, model, DNS or live Server requests."""
import ast
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / 'siem/rbac/collect_server_inventory.py'
spec = importlib.util.spec_from_file_location('server_inventory', PATH)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def page(items, total=None):
    return {'affected_items': items, 'total_affected_items': len(items) if total is None else total,
            'total_failed_items': 0, 'failed_items': []}


def fixture():
    policies = [{'id': n, 'name': name, 'roles': [8],
                 'policy': {'actions': list(actions), 'resources': list(resources), 'effect': 'allow'}}
                for n, (name, (actions, resources)) in enumerate(m.READONLY.items(), 1)]
    catalog = {
        'users': [{'id': 3, 'username': 'SERVER-OPERATOR-SECRET', 'roles': [7], 'allow_run_as': False},
                  {'id': 4, 'username': 'wazuh-wui', 'roles': [7], 'allow_run_as': True}],
        'roles': [{'id': 7, 'name': 'administrator', 'users': [3, 4], 'policies': [], 'rules': [11]},
                  {'id': 8, 'name': 'readonly', 'users': [], 'policies': [p['id'] for p in policies], 'rules': []}],
        'policies': policies,
        'rules': [{'id': 11, 'name': 'non-public-name', 'roles': [7], 'rule': {'FIND': {'user_name': 'admin'}}}],
    }
    processed = {'rbac_mode': 'white', 'security:read': {
        key: 'allow' for key in ('user:id:*', 'role:id:*', 'policy:id:*', 'rule:id:*')},
        'security:read_config': {'*:*:*': 'allow'}}
    return catalog, page([{'id': 3, 'username': 'SERVER-OPERATOR-SECRET'}]), processed, {'rbac_mode': 'white'}


class FakeAPI:
    def __init__(self):
        self.catalog, self.me, self.processed, self.config = fixture()
        self.calls = []

    def request(self, method, path):
        self.calls.append((method, path))
        if path == '/':
            return {'api_version': '4.14.7'}
        if path == '/security/users/me':
            return copy.deepcopy(self.me)
        if path == '/security/users/me/policies':
            return copy.deepcopy(self.processed)
        if path == '/security/config':
            return copy.deepcopy(self.config)
        kind = path.split('/')[2].split('?')[0]
        return page(copy.deepcopy(self.catalog[kind]))


class FragmentedReader(io.BufferedReader):
    def __init__(self, data, fragment):
        super().__init__(io.BytesIO(data))
        self.fragment = fragment
        self.body_reads = 0

    def read1(self, size=-1):
        self.body_reads += 1
        return super().read1(min(size, self.fragment))


class WirePeer:
    """Synthetic socket.makefile lifetime; real HTTPConnection/HTTPResponse.

    No network socket: close() drops the connection's reference while the
    response file keeps it alive. Its final close makes settimeout fail just
    as a released socket descriptor would. sendall discards request bytes.
    """
    def __init__(self, wire, fragment=65536):
        self.file = FragmentedReader(wire, fragment)
        self.closed = False
        self.timeouts_after_release = 0

    def makefile(self, *args, **kwargs):
        return self.file

    def sendall(self, data):
        pass

    def close(self):
        self.closed = True

    def settimeout(self, value):
        if self.closed and self.file.closed:
            self.timeouts_after_release += 1
            raise OSError(9, 'synthetic released socket')


def wire(body, framing='length', extra=b'', connection=b'close'):
    header = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: ' + connection + b'\r\n'
    if framing == 'length':
        header += b'Content-Length: ' + str(len(body)).encode() + b'\r\n'
    elif framing == 'chunked':
        header += b'Transfer-Encoding: chunked\r\n'
        # Multiple chunks, including valid JSON prefixes, must all be consumed.
        pieces = (body[:7], body[7:])
        body = b''.join(format(len(p), 'x').encode() + b'\r\n' + p + b'\r\n'
                        for p in pieces if p) + b'0\r\n\r\n'
    return header + extra + b'\r\n' + body


class ServerInventoryTests(unittest.TestCase):
    def read_wire(self, message, fragment=65536):
        peer = WirePeer(message, fragment)
        client = m.Client(mock.Mock())
        client.token = 'SYNTHETIC-TOKEN'
        try:
            with mock.patch.object(client, 'connect', return_value=peer):
                return client.request('GET', '/')
        finally:
            self.assertTrue(peer.closed)
            self.assertTrue(peer.file.closed)
            self.assertEqual(peer.timeouts_after_release, 0)

    def test_real_http_fixed_length_socket_lifetime(self):
        body = b'{"error":0,"data":{"value":1}}'
        for fragment in (1, 7, 65536):
            for connection in (b'close', b'keep-alive'):
                with self.subTest(fragment=fragment, connection=connection):
                    self.assertEqual(self.read_wire(wire(body, connection=connection), fragment), {'value': 1})
        # An empty declared body is invalid JSON, not a socket-lifetime failure.
        with self.assertRaises(json.JSONDecodeError):
            self.read_wire(wire(b''))

    def test_real_http_chunked_and_close_delimited_bodies(self):
        body = b'{"error":0,"data":{"value":1}}'
        for framing in ('chunked', 'eof'):
            for fragment in (1, 7, 65536):
                with self.subTest(framing=framing, fragment=fragment):
                    self.assertEqual(self.read_wire(wire(body, framing), fragment), {'value': 1})
        trailer = wire(body, 'chunked').replace(b'0\r\n\r\n', b'0\r\nX-Note: synthetic\r\n\r\n')
        self.assertEqual(self.read_wire(trailer), {'value': 1})

    def test_real_http_truncation_rejected_even_for_valid_json_prefix(self):
        body = b'{"error":0,"data":{}}'
        length = str(len(body)).encode()
        short = wire(body).replace(b'Content-Length: ' + length,
                                   b'Content-Length: ' + str(len(body) + 4).encode())
        cases = [(short, 'TRUNCATED_RESPONSE'),
                 (wire(body)[:-3], 'TRUNCATED_RESPONSE'),
                 (wire(body, 'chunked')[:-5], 'RESPONSE_IO'),
                 (wire(body, 'chunked').replace(b'0\r\n\r\n', b'Z\r\n'), 'RESPONSE_IO')]
        for message, code in cases:
            with self.subTest(code=code), mock.patch.object(m, 'envelope') as parse:
                with self.assertRaisesRegex(m.InventoryError, '^' + code + '$'):
                    self.read_wire(message, 3)
                parse.assert_not_called()

    def test_real_http_ambiguous_and_unsupported_framing_rejected(self):
        body = b'{"error":0,"data":{}}'
        for extra in (b'Content-Length: -1\r\n', b'Content-Length: +20\r\n',
                      b'Content-Length: nope\r\n', b'Content-Length: 20, 20\r\n',
                      b'Transfer-Encoding: gzip\r\n', b'Transfer-Encoding: gzip, chunked\r\n'):
            with self.subTest(extra=extra), self.assertRaisesRegex(m.InventoryError, '^HTTP_FRAMING$'):
                self.read_wire(wire(body, 'eof', extra))
        for message in (wire(body, extra=b'Content-Length: 20\r\n'),
                        wire(body, 'chunked', extra=b'Content-Length: 20\r\n')):
            with self.assertRaisesRegex(m.InventoryError, '^HTTP_FRAMING$'):
                self.read_wire(message)

    def test_real_http_body_bounds_and_safe_io_errors(self):
        body = b'{"error":0,"data":{}}'
        # The pre-credential 401 must close the file without reading its body.
        peer = WirePeer(wire(b'SECRET-ERROR').replace(b'200 OK', b'401 Unauthorized'))
        client = m.Client(mock.Mock())
        with mock.patch.object(client, 'connect', return_value=peer):
            self.assertIsNone(client.request('GET', '/'))
        self.assertTrue(peer.file.closed)
        self.assertTrue(peer.closed)
        self.assertEqual(peer.file.body_reads, 0)
        with mock.patch.object(m, 'MAX_BYTES', 64):
            for framing in ('length', 'chunked', 'eof'):
                with self.subTest(framing=framing):
                    self.assertEqual(self.read_wire(wire(body.ljust(64), framing)), {})
                    with self.assertRaisesRegex(m.InventoryError, '^RESPONSE_SIZE$'):
                        self.read_wire(wire(body.ljust(65), framing))
        for error, code in ((TimeoutError('SECRET'), 'RESPONSE_TIMEOUT'),
                            (OSError('SECRET'), 'RESPONSE_IO'),
                            (m.http.client.IncompleteRead(b'SECRET'), 'RESPONSE_IO')):
            peer = WirePeer(wire(body))
            client = m.Client(mock.Mock())
            client.token = 'SYNTHETIC-TOKEN'
            with mock.patch.object(client, 'connect', return_value=peer), \
                 mock.patch.object(peer.file, 'read1', side_effect=error):
                with self.assertRaisesRegex(m.InventoryError, '^' + code + '$') as failure:
                    client.request('GET', '/')
                self.assertNotIn('SECRET', str(failure.exception))
            self.assertTrue(peer.file.closed)
            self.assertTrue(peer.closed)
        peer = WirePeer(wire(body))
        client = m.Client(mock.Mock())
        client.token = 'SYNTHETIC-TOKEN'
        with mock.patch.object(client, 'connect', return_value=peer), \
             mock.patch.object(client, 'timeout', side_effect=[10, m.InventoryError('DEADLINE')]):
            with self.assertRaisesRegex(m.InventoryError, '^DEADLINE$'):
                client.request('GET', '/')
        self.assertTrue(peer.file.closed)
        self.assertTrue(peer.closed)

    def test_real_http_authentication_and_full_inventory_sequence(self):
        api = FakeAPI()
        expected = m.collect(api, 'SERVER-OPERATOR-SECRET')
        paths = list(api.calls)
        frames = [wire(b'{"error":0,"data":{"token":"a.b.c"}}', 'chunked')]
        frames += [wire(json.dumps({'error': 0, 'data': api.request(method, path)}).encode(),
                        'length' if i % 2 == 0 else 'chunked')
                   for i, (method, path) in enumerate(paths)]
        peers = [WirePeer(frame, 11) for frame in frames]
        client = m.Client(mock.Mock())
        with mock.patch.object(client, 'connect', side_effect=peers) as connect:
            client.authenticate('SERVER-OPERATOR-SECRET', 'SYNTHETIC-PASSWORD')
            self.assertEqual(m.collect(client, 'SERVER-OPERATOR-SECRET'), expected)
            self.assertEqual(connect.call_count, len(frames))
        self.assertTrue(all(p.closed and p.file.closed and p.timeouts_after_release == 0 for p in peers))

    def test_complete_sanitized_graph_and_no_authorization_claim(self):
        client = FakeAPI()
        out = m.collect(client, 'SERVER-OPERATOR-SECRET')
        self.assertEqual(out['readonly_role_id'], 8)  # not a guessed built-in ID
        self.assertTrue(out['two_pass_observation_equal'])
        self.assertFalse(out['mutation_authorized'])
        self.assertIn('actual_dashboard_context_and_broker_execution', out['outstanding'])
        text = json.dumps(out)
        self.assertNotIn('SERVER-OPERATOR-SECRET', text)
        self.assertNotIn('non-public-name', text)
        self.assertNotIn('wazuh-wui', text)
        self.assertEqual(len([p for _, p in client.calls if '?limit=' in p]), 8)
        self.assertTrue(all(method == 'GET' for method, _ in client.calls))

    def test_unknown_predicate_is_not_silently_excluded(self):
        c, me, p, cfg = fixture()
        c['rules'][0]['rule'] = {'MATCH': {'SECRET-FIELD': 'SECRET-VALUE'}}
        out = m.summarize(c, me, p, cfg, 'SERVER-OPERATOR-SECRET')
        self.assertEqual(out['rules'][0]['predicate_class'], 'unreviewed_predicate')
        self.assertNotIn('SECRET-', json.dumps(out))

    def test_admin_mode_broker_and_collisions_fail_closed(self):
        for mutation in (
            lambda c, me, p, cfg: cfg.update(rbac_mode='black'),
            lambda c, me, p, cfg: p.update(rbac_mode='black'),
            lambda c, me, p, cfg: p['security:read'].update({'user:id:3': 'deny'}),
            lambda c, me, p, cfg: p.pop('security:read_config'),
            lambda c, me, p, cfg: me['affected_items'][0].update(id=999),
            lambda c, me, p, cfg: c['users'][1].update(allow_run_as=False),
            lambda c, me, p, cfg: c['users'][1].update(username='assistant-svc'),
            lambda c, me, p, cfg: c['rules'][0].update(name='alertmind_socanalyst_server_ro'),
            lambda c, me, p, cfg: c['users'][0].update(roles=[]),
            lambda c, me, p, cfg: c['roles'][1].update(name='administrator'),
        ):
            args = fixture()
            mutation(*args)
            with self.subTest(mutation=mutation), self.assertRaises(m.InventoryError):
                m.summarize(*args, 'SERVER-OPERATOR-SECRET')

    def test_readonly_drift_and_relationships_fail_closed(self):
        for mutation in (
            lambda c: c['policies'][0]['policy']['actions'].append('agent:restart'),
            lambda c: c['policies'][0]['policy'].update(resources=['*:*:*']),
            lambda c: c['policies'][0]['policy'].update(effect='deny'),
            lambda c: c['policies'][0].update(name='unexpected'),
            lambda c: c['roles'][1]['policies'].append(999),
            lambda c: c['policies'][0].update(roles=[]),
            lambda c: c['roles'][0]['users'].append(999),
            lambda c: c['users'][0].update(roles=[7, 7]),
        ):
            args = fixture()
            mutation(args[0])
            with self.subTest(mutation=mutation), self.assertRaises(m.InventoryError):
                m.summarize(*args, 'SERVER-OPERATOR-SECRET')

    def test_two_pass_drift_and_version_stop(self):
        client = FakeAPI()
        original = client.request
        n = 0
        def drift(method, path):
            nonlocal n
            if path.startswith('/security/rules?'):
                n += 1
                if n == 2:
                    client.catalog['rules'][0]['rule'] = {'SECRET': 'CHANGED'}
            return original(method, path)
        client.request = drift
        with self.assertRaisesRegex(m.InventoryError, 'CATALOG_DRIFT'):
            m.collect(client, 'SERVER-OPERATOR-SECRET')
        client = mock.Mock()
        client.request.return_value = {'api_version': '4.15.0'}
        with self.assertRaisesRegex(m.InventoryError, 'SERVER_VERSION'):
            m.collect(client, 'unused')
        self.assertEqual(client.request.call_count, 1)

    def test_pagination_complete_and_bounded(self):
        client = mock.Mock()
        client.request.side_effect = [page([{'id': n} for n in range(1, 101)], 102),
                                      page([{'id': 101}, {'id': 102}], 102)]
        self.assertEqual(len(m.fetch_collection(client, 'roles')), 102)
        self.assertEqual(client.request.call_args.args[1], '/security/roles?limit=100&offset=100&sort=id')
        self.assertEqual(m.fetch_collection(mock.Mock(request=mock.Mock(return_value=page([]))), 'rules'), [])
        for pages in ([page([], 1)], [page([{'id': 1}, {'id': 1}], 2)],
                      [page([{'id': True}])], [page([{'id': 2}, {'id': 1}])],
                      [page([{'id': 1}], 2), page([{'id': 2}], 3)],
                      [page([{'id': 1}], 0)], [page([], m.MAX_ITEMS + 1)],
                      [dict(page([]), total_failed_items=1)],
                      [dict(page([]), failed_items=[{'SECRET': 'BODY'}])]):
            client = mock.Mock()
            client.request.side_effect = pages
            with self.subTest(pages=pages), self.assertRaises(m.InventoryError):
                m.fetch_collection(client, 'users')

    def test_route_allowlist_rejects_before_socket(self):
        client = m.Client(mock.Mock())
        client.token = 'TOKEN'
        with mock.patch.object(client, 'connect') as connect:
            for method, path in [('DELETE', '/security/users'), ('POST', '/security/user/authenticate/run_as'),
                                 ('GET', 'https://evil.invalid/'), ('GET', '//evil.invalid'),
                                 ('GET', '/manager/configuration'), ('PUT', '/active-response'),
                                 ('GET', '/security/users?limit=100&offset=1000&sort=id')]:
                with self.subTest(path=path), self.assertRaises(m.InventoryError):
                    client.request(method, path)
            connect.assert_not_called()

    def test_hostname_and_pin_precede_any_http(self):
        context = mock.Mock(verify_mode=ssl.CERT_REQUIRED, check_hostname=True)
        peer = mock.Mock()
        peer.getpeercert.return_value = b'PEER'
        context.wrap_socket.return_value = peer
        client = m.Client(context)
        with mock.patch.object(m.socket, 'socket') as raw, mock.patch.object(m.http.client, 'HTTPConnection') as http:
            with self.assertRaisesRegex(m.InventoryError, 'PEER_CERT_CHANGED'):
                client.request('GET', '/')
            raw.return_value.connect.assert_called_once_with(('127.0.0.1', 55000))
            context.wrap_socket.assert_called_once_with(raw.return_value, server_hostname='localhost')
            peer.close.assert_called_once()
            http.assert_not_called()
        context.check_hostname = False
        with mock.patch.object(m.socket, 'socket') as raw, self.assertRaises(m.InventoryError):
            client.connect()
        raw.assert_not_called()

    def test_negative_tls_requires_hostname_specific_cause(self):
        client = m.Client(mock.Mock())
        for code in (62, 18, 20):
            error = ssl.SSLCertVerificationError('SECRET TLS ERROR')
            error.verify_code = code
            with mock.patch.object(client, 'connect', side_effect=error):
                if code == 62:
                    client.wrong_hostname_probe()
                else:
                    with self.assertRaises(m.InventoryError):
                        client.wrong_hostname_probe()
        with mock.patch.object(client, 'connect') as connect, self.assertRaises(m.InventoryError):
            client.wrong_hostname_probe()
        connect.return_value.close.assert_called_once()

    def test_http_failures_and_bodies_do_not_escape(self):
        client = m.Client(mock.Mock())
        client.token = 'TOKEN'
        for status in (301, 302, 401, 403, 429, 500):
            response = mock.Mock(status=status)
            with mock.patch.object(client, 'connect'), mock.patch.object(m.http.client, 'HTTPConnection') as http:
                http.return_value.getresponse.return_value = response
                with self.assertRaises(m.InventoryError):
                    client.request('GET', '/security/config')
                response.read1.assert_not_called()
                http.return_value.close.assert_called_once()

    def test_http_success_and_size_bound(self):
        client = m.Client(mock.Mock())
        client.token = 'TOKEN'
        for chunks, succeeds in (([b'{"error":0,"data":{"rbac_mode":"white"}}', b''], True),
                                 ([b'x' * (m.MAX_BYTES + 1)], False)):
            response = mock.Mock(status=200)
            response.getheader.side_effect = lambda name, default: 'application/json' if name == 'Content-Type' else default
            response.read1.side_effect = chunks
            with mock.patch.object(client, 'connect'), mock.patch.object(m.http.client, 'HTTPConnection') as http:
                http.return_value.getresponse.return_value = response
                if succeeds:
                    self.assertEqual(client.request('GET', '/security/config'), {'rbac_mode': 'white'})
                    self.assertEqual(http.return_value.request.call_args.kwargs['headers']['Host'], 'localhost:55000')
                else:
                    with self.assertRaises(m.InventoryError):
                        client.request('GET', '/security/config')

    def test_one_auth_attempt_no_retry_and_token_validation(self):
        client = m.Client(mock.Mock())
        with mock.patch.object(client, 'connect', side_effect=OSError('private')):
            with self.assertRaises(OSError):
                client.authenticate('server', 'secret')
            with self.assertRaisesRegex(m.InventoryError, 'ROUTE_DENIED'):
                client.authenticate('server', 'secret')
        for token in ('a.b.c', 'invalid\r\nHEADER', '', 'x' * 9000):
            client = m.Client(mock.Mock())
            with mock.patch.object(client, 'request', return_value={'token': token}):
                if token == 'a.b.c':
                    client.authenticate('server', 'secret')
                    self.assertEqual(client.token, token)
                else:
                    with self.assertRaises(m.InventoryError):
                        client.authenticate('server', 'secret')

    def test_json_duplicate_nan_and_envelope_failures(self):
        for raw in (b'{"error":0,"error":1,"data":{}}', b'{"error":true,"data":{}}',
                    b'{"error":0,"data":{"x":NaN}}', b'{"error":1,"message":"SECRET"}', b'not json'):
            with self.subTest(raw=raw), self.assertRaises(Exception):
                m.envelope(raw)

    def test_deadline_and_request_budget(self):
        client = m.Client(mock.Mock())
        with mock.patch.object(m.time, 'monotonic', return_value=client.deadline + 1):
            with self.assertRaises(m.InventoryError):
                client.timeout()
        client.requests = 100
        with mock.patch.object(client, 'connect') as connect, self.assertRaises(m.InventoryError):
            client.request('GET', '/')
        connect.assert_not_called()

    def test_main_failure_suppresses_secrets_and_clears_token(self):
        # Enforce the reason these codes are safe to print: every production
        # call site uses a literal, with only require() forwarding its argument.
        tree = ast.parse(PATH.read_text(encoding='utf-8'))
        guard = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'require')
        forwarded = [n for n in ast.walk(guard) if isinstance(n, ast.Call)
                     and isinstance(n.func, ast.Name) and n.func.id == 'InventoryError']
        self.assertEqual(len(forwarded), 1)
        self.assertEqual(ast.dump(forwarded[0]), ast.dump(ast.parse('InventoryError(code)', mode='eval').body))
        codes = set()
        nodes = list(guard.args.defaults)
        for call in ast.walk(tree):
            if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name):
                continue
            if call.func.id == 'require':
                self.assertFalse(call.keywords)
                self.assertIn(len(call.args), (1, 2))
                nodes.extend(call.args[1:])
            elif call.func.id == 'InventoryError' and call is not forwarded[0]:
                self.assertFalse(call.keywords)
                self.assertEqual(len(call.args), 1)
                nodes.extend(call.args)
        for node in nodes:
            self.assertIsInstance(node, ast.Constant)
            self.assertIsInstance(node.value, str)
            self.assertRegex(node.value, r'^[A-Z][A-Z0-9_]*$')
            codes.add(node.value)
        self.assertTrue({'SERVICE_SERVER_IDENTITY', 'MAPPING_COLLISION', 'BROKER_RUN_AS_DISABLED',
                         'RBAC_MODE', 'READONLY_POLICY_DRIFT', 'PEER_CERT_CHANGED'} <= codes)
        failures = [(m.InventoryError(code), code) for code in sorted(codes)]
        failures += [(error('SECRET-PAYLOAD PEER_CERT_CHANGED'), None)
                     for error in (ValueError, OSError, ssl.SSLError, KeyboardInterrupt)]
        for failure, code in failures:
            with self.subTest(code=code, error_type=type(failure).__name__):
                client = mock.Mock(token='SECRET-TOKEN')
                with mock.patch.object(m.sys, 'argv', ['inventory']), mock.patch.object(m.os, 'geteuid', return_value=0, create=True), \
                     mock.patch.object(m.sys.stdin, 'isatty', return_value=True), \
                     mock.patch('builtins.input', return_value='REVIEWED'), mock.patch.object(m, 'make_context'), \
                     mock.patch.object(m, 'Client', return_value=client), mock.patch.object(m.getpass, 'getpass', side_effect=['OPERATOR', 'SECRET']), \
                     mock.patch.object(m, 'collect', side_effect=failure):
                    output = io.StringIO()
                    output.isatty = lambda: True
                    with contextlib.redirect_stdout(output):
                        self.assertEqual(m.main(), 1)
                    expected = 'STOP: Server inventory failed at inventory'
                    if code is not None:
                        expected += '; code=' + code
                    expected += '; no result accepted. Do not paste credentials or raw responses.'
                    self.assertEqual(output.getvalue().splitlines()[-1], expected)
                    self.assertNotIn('SECRET', output.getvalue())
                    self.assertNotIn('OPERATOR', output.getvalue())
                    self.assertNotIn('inventory_version', output.getvalue())
                    self.assertIsNone(client.token)

    def test_context_uses_only_checked_public_certificate(self):
        # A synthetic PEM is enough here because the parser and context are mocked.
        pem = b'-----BEGIN CERTIFICATE-----\nUEVFUg==\n-----END CERTIFICATE-----\n'
        with mock.patch.object(m, 'CERT', mock.Mock(open=mock.mock_open(read_data=pem))), \
             mock.patch.object(m.ssl, 'PEM_cert_to_DER_cert', return_value=b'PEER'), \
             mock.patch.object(m, 'FINGERPRINT', hashlib.sha256(b'PEER').hexdigest()), \
             mock.patch.object(m.ssl, 'SSLContext') as factory:
            context = factory.return_value
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True
            self.assertIs(m.make_context(), context)
            context.load_verify_locations.assert_called_once_with(cadata=pem.decode().strip())
            context.load_default_certs.assert_not_called()
            factory.assert_called_once_with(ssl.PROTOCOL_TLS_CLIENT)

    def test_real_tls_memory_handshakes_no_network(self):
        openssl = shutil.which('openssl')
        if openssl is None and os.name == 'nt':
            candidate = Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'Git/usr/bin/openssl.exe'
            if candidate.is_file():
                openssl = str(candidate)
        self.assertIsNotNone(openssl, 'OpenSSL CLI required for the offline synthetic TLS fixture')
        with tempfile.TemporaryDirectory() as directory:
            public = Path(directory) / 'public.pem'
            private = Path(directory) / 'synthetic-key.pem'
            # Disposable synthetic material only; no production key/certificate is read.
            result = subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                '-keyout', str(private), '-out', str(public), '-days', '2',
                '-subj', '/CN=synthetic-test', '-addext', 'subjectAltName=DNS:localhost',
                '-addext', 'basicConstraints=CA:FALSE'], stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE, timeout=30)
            self.assertEqual(result.returncode, 0, 'synthetic certificate generation failed')
            expected = hashlib.sha256(ssl.PEM_cert_to_DER_cert(public.read_text())).hexdigest()
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(public, private)
            with mock.patch.object(m, 'CERT', public), mock.patch.object(m, 'FINGERPRINT', expected):
                context = m.make_context()
            def handshake(hostname, trust):
                ci, co, si, so = (ssl.MemoryBIO() for _ in range(4))
                client = trust.wrap_bio(ci, co, server_hostname=hostname)
                server = server_context.wrap_bio(si, so, server_side=True)
                done = [False, False]
                for _ in range(20):
                    for i, session in enumerate((client, server)):
                        if not done[i]:
                            try:
                                session.do_handshake()
                                done[i] = True
                            except ssl.SSLWantReadError:
                                pass
                    if co.pending:
                        si.write(co.read())
                    if so.pending:
                        ci.write(so.read())
                    if all(done):
                        return client
                self.fail('synthetic TLS handshake did not terminate')
            peer = handshake('localhost', context)
            self.assertEqual(hashlib.sha256(peer.getpeercert(binary_form=True)).hexdigest(), expected)
            for wrong_name in ('127.0.0.1', 'alertmind-server-hostname-check.invalid'):
                with self.assertRaises(ssl.SSLCertVerificationError) as failure:
                    handshake(wrong_name, context)
                self.assertIn(failure.exception.verify_code, (62, 64))
            with self.assertRaises(ssl.SSLCertVerificationError):
                handshake('localhost', ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))

    def test_main_success_and_noninteractive_refusal(self):
        client = mock.Mock(token='SECRET-TOKEN')
        with mock.patch.object(m.sys, 'argv', ['inventory']), mock.patch.object(m.os, 'geteuid', return_value=0, create=True), \
             mock.patch.object(m.sys.stdin, 'isatty', return_value=True), \
             mock.patch('builtins.input', return_value='REVIEWED'), mock.patch.object(m, 'make_context'), \
             mock.patch.object(m, 'Client', return_value=client), mock.patch.object(m.getpass, 'getpass', side_effect=['OPERATOR', 'SECRET']), \
             mock.patch.object(m, 'collect', return_value={'inventory_version': 1}) as collect:
            output = io.StringIO()
            output.isatty = lambda: True
            with contextlib.redirect_stdout(output):
                self.assertEqual(m.main(), 0)
            client.authenticate.assert_called_once_with('OPERATOR', 'SECRET')
            collect.assert_called_once_with(client, 'OPERATOR')
            self.assertNotIn('SECRET', output.getvalue())
            self.assertIsNone(client.token)
        with mock.patch.object(m.sys, 'argv', ['inventory']), mock.patch.object(m.os, 'geteuid', return_value=0, create=True), \
             mock.patch.object(m.sys.stdin, 'isatty', return_value=False), mock.patch.object(m, 'Client') as factory:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(m.main(), 1)
            factory.assert_not_called()

    def test_additional_shape_encoding_and_context_changes(self):
        client = m.Client(mock.Mock())
        client.token = 'TOKEN'
        for headers in ({'Content-Type': 'text/html'}, {'Content-Encoding': 'gzip'}):
            response = mock.Mock(status=200)
            response.getheader.side_effect = lambda name, default: headers.get(name, 'application/json' if name == 'Content-Type' else default)
            with mock.patch.object(client, 'connect'), mock.patch.object(m.http.client, 'HTTPConnection') as http:
                http.return_value.getresponse.return_value = response
                with self.assertRaises(m.InventoryError):
                    client.request('GET', '/security/config')
                response.read1.assert_not_called()
        client = FakeAPI()
        original = client.request
        calls = 0
        def drift(method, path):
            nonlocal calls
            if path == '/security/config':
                calls += 1
                if calls == 2:
                    client.config['auth_token_exp_timeout'] = 123
            return original(method, path)
        client.request = drift
        with self.assertRaisesRegex(m.InventoryError, 'CONTEXT_DRIFT'):
            m.collect(client, 'SERVER-OPERATOR-SECRET')

    def test_manifest_runbook_and_local_inventory_guard(self):
        manifest = PATH.with_name('SERVER-AUTH-SHA256SUMS').read_text(encoding='ascii').splitlines()
        self.assertEqual(manifest, [hashlib.sha256(PATH.read_bytes()).hexdigest() + '  ' + PATH.name])
        attributes = (ROOT / '.gitattributes').read_text(encoding='utf-8')
        for name in ('collect_server_inventory.py', 'SERVER-AUTH-SHA256SUMS'):
            self.assertIn('siem/rbac/' + name + ' text eol=lf', attributes)
        text = (ROOT / 'docs/runbooks/rbac-server-authenticated-inventory.md').read_text(encoding='utf-8')
        for phrase in ('NOT EXECUTABLE UNTIL REVIEWED', 'not an atomic snapshot', 'not secure erasure',
                       'No fabricated run-as context', 'localhost', 'No application runtime change'):
            self.assertIn(phrase, text)
        original = (ROOT / 'docs/runbooks/rbac-server-dashboard-readonly.md').read_text(encoding='utf-8')
        self.assertIn('sudo test -f "$PY"', original)
        self.assertIn('sudo test -x "$PY"', original)


if __name__ == '__main__':
    unittest.main()
