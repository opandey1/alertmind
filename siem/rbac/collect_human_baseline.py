"""Review-gated, read-only human permission baseline; never applies mappings.

Indexer GETs plus the unchanged Server administrator inventory. Direct Indexer
account data is NOT proof of Dashboard-generated context or broker execution.
Secrets stay in memory; no redirects, proxy, DNS, retries or output of raw data.
"""
import base64
import getpass
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import sys
import time
import warnings

HERE = Path(__file__).resolve().parent
SERVER_SHA = '08ff077faa6f33a1e6bcd431c1f059ded3b753c63e975127451d5a4771e7aef5'
CA = Path('/etc/wazuh-indexer/certs/root-ca.pem')
CA_SHA = 'eb98a4af38cda550d473e5659a4375905334041fab4597f39c4f191d9e6f5e1d'
LEAF_SHA = 'bc90aaa91888394165a33fc8be9fc667ca6f0a08f5de202c62a0e089262332fb'
CLIENT_KEYS = Path('/var/ossec/etc/client.keys')
BINDINGS = {'001': ('win-victim', 'ce6dbeeff3df5ffef33e643ea36b60ffaf4f9b73577bf8c68789c867d672a5b7'),
            '002': ('linux-victim', '483a8b3caa8e9a252aa8ea632d7a5c1ab04358c170f314ec01f1d696dfffdebf')}
PRINCIPALS = {'socanalyst': 'socanalyst_ro', 'assistant-svc': 'assistant_alerts_ro'}
ROLES = {name: 'alertmind_' + suffix for name, suffix in PRINCIPALS.items()}
AUTHINFO = '/_plugins/_security/authinfo'
ACCOUNT = '/_opendistro/_security/api/account'  # Installed factory's exact route.
GROUPS = '/_plugins/_security/api/actiongroups'
AGENTS = ('000', '001', '002')
SEARCH = {agent: '/wazuh-alerts-4.x-*/_search?size=0&track_total_hits=true&q=agent.id%3A' + agent
          for agent in AGENTS}
ADMIN_READS = (GROUPS, '/_plugins/_security/api/rolesmapping/own_index') + tuple(
    '/_plugins/_security/api/' + kind + '/' + name
    for user, role in ROLES.items()
    for kind, name in (('roles', role), ('rolesmapping', role), ('internalusers', user)))
PUBLIC_READS = (AUTHINFO, ACCOUNT) + tuple(SEARCH.values())


class BaselineError(ValueError):
    """Static diagnostic codes only."""


def require(condition, code):
    if not condition:
        raise BaselineError(code)


def load_server():
    """Load only the exact reused, root-staged public reader after byte check.

    Trust is conventional lab root administration, not a custom import boundary.
    This does not authenticate the interpreter, stdlib or running vendor code.
    """
    raw = (HERE / 'collect_server_inventory.py').read_bytes()
    require(hashlib.sha256(raw.replace(b'\r\n', b'\n')).hexdigest() == SERVER_SHA,
            'SERVER_READER_CHANGED')
    spec = importlib.util.spec_from_file_location('human_baseline_server', HERE / 'collect_server_inventory.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def public_inputs(server):
    """Read staged public expectations, never private config or user records."""
    expected = {}
    for user, suffix in PRINCIPALS.items():
        expected[user] = {kind: server.decode((HERE / ('indexer-' + kind + '_' + suffix + '.json')).read_bytes())
                          for kind in ('role', 'role-mapping')}
    scope = server.decode((HERE / 'scope-contract.json').read_bytes())
    require(scope.get('schema_version') == 2 and
            scope.get('index_pattern') == 'wazuh-alerts-4.x-*' and
            scope.get('dls_query') == {'terms': {'agent.id': ['001', '002']}}, 'SCOPE_CONTRACT')
    preserved = scope['inherited_role_hardening']['preserved_users']
    require(preserved == ['admin', 'anomalyadmin', 'kibanaro', 'kibanaserver',
                          'logstash', 'readall', 'snapshotrestore'], 'OWN_INDEX_CONTRACT')
    require(scope.get('agent_bindings') == [
        {'agent_id': agent, 'agent_name': name, 'enrollment_sha256': digest}
        for agent, (name, digest) in BINDINGS.items()], 'AGENT_BINDING_CONTRACT')
    return expected, preserved


def enrollment_bindings():
    """Compare only two existing bindings locally; never emit enrollment keys."""
    with CLIENT_KEYS.open('rb') as handle:
        raw = handle.read(131073)
    require(len(raw) <= 131072, 'ENROLLMENT_SIZE')
    observed = {}
    for line in raw.splitlines():
        fields = line.split()
        if not fields or fields[0].decode('ascii') not in BINDINGS:
            continue
        require(len(fields) == 4, 'ENROLLMENT_SHAPE')
        agent, name = fields[0].decode('ascii'), fields[1].decode('ascii')
        require(agent not in observed, 'ENROLLMENT_DUPLICATE')
        observed[agent] = (name, hashlib.sha256(fields[3]).hexdigest())
    require(observed == BINDINGS, 'ENROLLMENT_DRIFT')
    return {'agent_001_002_existing_enrollment_bindings_match': True}


def tls_context():
    with CA.open('rb') as handle:
        raw = handle.read(65537)
    require(0 < len(raw) <= 65536, 'CA_SIZE')
    pem = raw.decode('ascii').strip()
    require(re.fullmatch(r'-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+\s+-----END CERTIFICATE-----', pem),
            'CA_FORMAT')
    require(hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest() == CA_SHA, 'CA_CHANGED')
    # Explicit context rather than ambient trust/key logging or relaxed hostname.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cadata=pem)
    require(context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname, 'TLS_POLICY')
    return context


class IndexerClient:
    def __init__(self, server, context, username, password):
        require(username in ('admin',) + tuple(PRINCIPALS) and type(password) is str
                and 0 < len(password) <= 4096, 'CREDENTIAL_SHAPE')
        self.server, self.context, self.username = server, context, username
        self.basic = base64.b64encode((username + ':' + password).encode()).decode('ascii')
        self.reader = server.Client(context)  # Reuse reviewed bounded HTTP body reader only.

    def connect(self, hostname='127.0.0.1'):
        require(self.context.verify_mode == ssl.CERT_REQUIRED and self.context.check_hostname, 'TLS_POLICY')
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            raw.settimeout(self.reader.timeout())
            raw.connect(('127.0.0.1', 9200))
            peer = self.context.wrap_socket(raw, server_hostname=hostname)
        except BaseException:
            raw.close()
            raise
        try:
            require(hashlib.sha256(peer.getpeercert(binary_form=True)).hexdigest() == LEAF_SHA,
                    'INDEXER_PEER_CHANGED')
            return peer
        except BaseException:
            peer.close()
            raise

    def wrong_hostname_probe(self):
        try:
            peer = self.connect('alertmind-indexer-hostname-check.invalid')
        except ssl.SSLCertVerificationError as exc:
            require(exc.verify_code == 62, 'NEGATIVE_TLS_CAUSE')
            return
        peer.close()
        raise BaselineError('NEGATIVE_TLS_ACCEPTED')

    def request(self, method, path):
        require(method == 'GET' and (path in PUBLIC_READS or
                (self.username == 'admin' and path in ADMIN_READS)), 'ROUTE_DENIED')
        self.reader.requests += 1
        require(self.reader.requests <= 48, 'REQUEST_LIMIT')
        peer = self.connect()  # CA/name/exact pin BEFORE Authorization headers.
        connection, response = None, None
        try:
            connection = http.client.HTTPConnection('127.0.0.1', 9200, timeout=self.reader.timeout())
            connection.sock = peer
            connection.request('GET', path, headers={
                'Host': '127.0.0.1:9200', 'Authorization': 'Basic ' + self.basic,
                'Accept': 'application/json', 'Accept-Encoding': 'identity', 'Connection': 'close'})
            response = connection.getresponse()
            require(response.status == 200, 'INDEXER_HTTP_STATUS')
            require(response.getheader('Content-Encoding', 'identity') == 'identity' and
                    response.getheader('Content-Type', '').split(';')[0].strip().lower() == 'application/json',
                    'INDEXER_CONTENT_TYPE')
            return self.server.decode(self.reader.read_body(response, peer))
        finally:
            if response is not None:
                response.close()
            if connection is not None:
                connection.close()
            else:
                peer.close()

    def clear(self):
        self.basic = None  # Reference release only, not secure memory erasure.


def exact(value, expected, metadata, code):
    require(type(value) is dict and set(value) <= set(expected) | set(metadata) and
            all(value.get(key) == content for key, content in expected.items()), code)


def selectors(mapping, users, code):
    exact(mapping, {'users': users, 'backend_roles': [], 'hosts': []},
          ('hidden', 'reserved', 'static', 'description', 'and_backend_roles'), code)
    require(mapping.get('and_backend_roles', []) == [], code)


def expand(groups, name, stack=()):
    require(type(name) is str and len(name) <= 256 and len(stack) < 16 and name not in stack,
            'ACTION_GROUP_GRAPH')
    if name not in groups:
        require(':' in name, 'ACTION_GROUP_MISSING')
        return {name}
    definition = groups[name]
    require(type(definition) is dict and type(definition.get('allowed_actions')) is list and
            0 < len(definition['allowed_actions']) <= 128, 'ACTION_GROUP_SHAPE')
    result = set()
    for child in definition['allowed_actions']:
        result.update(expand(groups, child, stack + (name,)))
        require(len(result) <= 512, 'ACTION_GROUP_SIZE')
    return result


def readonly_action(action):
    return (action == 'indices:data/read*' or action.startswith('indices:data/read/') or
            action in ('indices:admin/aliases/exists*', 'indices:admin/aliases/get*',
                       'indices:admin/resolve/index', 'indices:admin/mappings/fields/get*'))


def administrative_baseline(client, expected, preserved):
    first = {path: client.request('GET', path) for path in ADMIN_READS}
    for user, role in ROLES.items():
        role_path = '/_plugins/_security/api/roles/' + role
        exact(first[role_path].get(role), expected[user]['role'], ('hidden', 'reserved', 'static'), 'ROLE_DRIFT')
        selectors(first['/_plugins/_security/api/rolesmapping/' + role].get(role), [user], 'MAPPING_DRIFT')
        record = first['/_plugins/_security/api/internalusers/' + user].get(user)
        require(type(record) is dict and record.get('backend_roles') == [] and
                record.get('opendistro_security_roles', []) == [] and record.get('attributes') == {} and
                record.get('reserved', False) is False and record.get('hidden', False) is False,
                'USER_GRANT_DRIFT')
    selectors(first['/_plugins/_security/api/rolesmapping/own_index'].get('own_index'),
              preserved, 'OWN_INDEX_DRIFT')
    groups = first[GROUPS]
    require(type(groups) is dict and len(groups) <= 256, 'ACTION_GROUP_SHAPE')
    actions = set()
    for data in expected.values():
        role = data['role']
        for name in role['cluster_permissions'] + [action for permission in role['index_permissions']
                                                  for action in permission['allowed_actions']]:
            actions.update(expand(groups, name))
    require(all(readonly_action(action) for action in actions), 'INHERITED_WRITE_ACTION')
    second = {path: client.request('GET', path) for path in ADMIN_READS}
    require(first == second, 'INDEXER_BASELINE_DRIFT')
    return {'exact_roles_mappings_users': True, 'own_index_preserved_users': len(preserved),
            'inherited_read_actions': sorted(actions), 'two_pass_observation_equal': True}


def authinfo_snapshot(info):
    """Ignore only the source TCP port, retaining the address and all other fields.

    authinfo remote_address describes this individual HTTP connection, not a
    grant. Each request uses a fresh connection. Do not discard tenant, role,
    attribute or unknown fields when comparing the two authorization snapshots.
    """
    stable = dict(info)
    if 'remote_address' in stable:
        address = stable['remote_address']
        require(type(address) is str and len(address) <= 128, 'REMOTE_ADDRESS_SHAPE')
        match = re.fullmatch(r'(\[[0-9A-Fa-f:.]+\]|[0-9.]+):([0-9]{1,5})', address)
        require(match is not None and 1 <= int(match[2]) <= 65535, 'REMOTE_ADDRESS_SHAPE')
        host = match[1]
        try:
            parsed = ipaddress.ip_address(host[1:-1] if host.startswith('[') else host)
        except ValueError:
            raise BaselineError('REMOTE_ADDRESS_SHAPE') from None
        require(parsed.version == (6 if host.startswith('[') else 4), 'REMOTE_ADDRESS_SHAPE')
        stable['remote_address'] = host
    return stable


def identity(client):
    expected_role = ROLES[client.username]
    info = client.request('GET', AUTHINFO)
    account = client.request('GET', ACCOUNT)
    require(type(info) is dict and info.get('user_name') == client.username and
            info.get('backend_roles') == [] and info.get('roles') == [expected_role], 'EFFECTIVE_ROLE_DRIFT')
    require(type(account) is dict and account.get('user_name') == client.username and
            account.get('backend_roles') == [] and account.get('roles') == [expected_role], 'ACCOUNT_DRIFT')
    return authinfo_snapshot(info), account


def count(response):
    require(type(response) is dict and response.get('timed_out') is False and
            type(response.get('_shards')) is dict and type(response['_shards'].get('failed')) is int and
            response['_shards']['failed'] == 0, 'SEARCH_PARTIAL')
    require(type(response.get('hits')) is dict, 'SEARCH_METADATA')
    total = response['hits'].get('total')
    require(type(total) is dict and type(total.get('value')) is int and total['value'] >= 0 and
            total.get('relation') == 'eq' and response['hits'].get('hits') == [], 'SEARCH_METADATA')
    return total['value']


def principal_baseline(client, admin_zero):
    before = identity(client)
    counts = {agent: count(client.request('GET', path)) for agent, path in SEARCH.items()}
    require(admin_zero > 0 and counts['000'] == 0 and counts['001'] > 0 and counts['002'] > 0,
            'DLS_CONTROL')
    require(identity(client) == before, 'IDENTITY_DRIFT')
    return {'identity': client.username, 'effective_roles': [ROLES[client.username]],
            'backend_roles_empty': True, 'direct_indexer_account_user_name_matches': True,
            'agent_000_excluded_with_admin_positive_control': True,
            'agent_001_and_002_positive_reads': True, 'identity_two_pass_equal': True,
            'actual_dashboard_context_observed': False}


def assemble(indexer, principals, server):
    return {'baseline_version': 1, 'scope': 'read-only permission baseline; NOT actual Dashboard context or mapping approval',
            'indexer': indexer, 'principals': principals, 'server': server,
            'actual_dashboard_context_observed': False, 'matching_server_rules_reviewed': False,
            'server_mapping_payload': None, 'mutation_authorized': False,
            'owner_scope_consent_attested_by_collector': False,
            'outstanding': ['focused_tls_refresh_acceptance', 'actual_socanalyst_dashboard_context',
                            'all_matching_server_predicates_review',
                            'reviewed_mapping_ui_recovery_and_denial_package']}


def secret(prompt):
    with warnings.catch_warnings():
        warnings.simplefilter('error', getpass.GetPassWarning)
        return getpass.getpass(prompt)


def main():
    clients, server_client, password = [], None, None
    stage = 'preflight'
    try:
        require(len(sys.argv) == 1 and os.geteuid() == 0 and sys.stdin.isatty() and sys.stdout.isatty(),
                'CONSOLE_REQUIRED')
        require(input('Type REVIEWED-BASELINE only after package review and separate read-only release: ')
                == 'REVIEWED-BASELINE', 'REVIEW_GATE')
        server = load_server()
        expected, preserved = public_inputs(server)
        bindings = enrollment_bindings()
        context = tls_context()
        probe = IndexerClient(server, context, 'admin', 'unused-not-sent')
        probe.wrong_hostname_probe()
        peer = probe.connect()
        peer.close()
        probe.clear()
        print('PASS this client: Indexer CA/name/exact peer verified; wrong hostname rejected; no credentials sent')
        stage = 'Indexer administrator'
        password = secret('Existing INDEXER admin password: ')
        admin = IndexerClient(server, context, 'admin', password)
        clients.append(admin)
        password = None
        indexer = administrative_baseline(admin, expected, preserved)
        admin_zero = count(admin.request('GET', SEARCH['000']))
        principals = []
        for user in PRINCIPALS:
            stage = user + ' Indexer'
            password = secret('Existing ' + user + ' INDEXER password: ')
            client = IndexerClient(server, context, user, password)
            clients.append(client)
            password = None
            principals.append(principal_baseline(client, admin_zero))
        stage = 'Server TLS'
        server_client = server.Client(server.make_context())
        server_client.request('GET', '/')
        server_client.wrong_hostname_probe()
        print('PASS this client: separate pinned localhost Server TLS; no Server credentials sent yet')
        stage = 'Server inventory'
        username = secret('Existing SERVER administrator username (not Indexer admin): ')
        password = secret('Existing SERVER administrator password: ')
        server_client.deadline = time.monotonic() + 120
        server_client.authenticate(username, password)
        password = None
        summary = server.collect(server_client, username)
        # Recheck the authoritative Indexer grants after the cross-plane observation.
        # Credential typing belongs outside each bounded network phase.
        for client in clients:
            client.reader.deadline = time.monotonic() + 120
        require(administrative_baseline(admin, expected, preserved) == indexer, 'FINAL_BASELINE_DRIFT')
        for client in clients[1:]:
            identity(client)
        require(enrollment_bindings() == bindings, 'FINAL_ENROLLMENT_DRIFT')
        indexer.update(bindings)
        print(json.dumps(assemble(indexer, principals, summary), indent=2, sort_keys=True))
        print('STOP POINT: read-only baseline only; no actual Dashboard-context or mapping acceptance')
        return 0
    except (Exception, KeyboardInterrupt):
        # No exception/HTTP body, partial summary, token or password escapes.
        print('STOP: human baseline failed at ' + stage + '; no result accepted; no mapping or service action issued')
        return 1
    finally:
        password = None
        for client in clients:
            client.clear()
        if server_client is not None:
            server_client.token = None


if __name__ == '__main__':
    sys.exit(main())
