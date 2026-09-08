#!/usr/bin/env python3
"""Review-gated, VM-local Server RBAC inventory. Not an application client.

One authentication POST, then allowlisted GETs only. No run-as impersonation,
mutation, retries, redirects, proxy, external DNS or secret persistence.
"""
import base64
import getpass
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import ssl
import sys
import time
import warnings

CERT = Path('/var/ossec/api/configuration/ssl/server.crt')
FINGERPRINT = '5037899c0818f8332b09fc144bd7bd72a3b2ca033f46dad56c67c284d611ce87'
HOSTNAME = 'localhost'
ADDRESS = ('127.0.0.1', 55000)
MAX_BYTES = 1024 * 1024
MAX_ITEMS = 1000
PAGE_SIZE = 100
AUTH = '/security/user/authenticate'
COLLECTIONS = ('users', 'roles', 'policies', 'rules')
SINGLE_READS = ('/', '/security/config', '/security/users/me',
                '/security/users/me/policies')


class InventoryError(Exception):
    """Messages are static codes only, never API/configuration content."""


def require(condition, code='INVALID_SHAPE'):
    if not condition:
        raise InventoryError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def unique_object(pairs):
    out = {}
    for key, value in pairs:
        require(key not in out, 'DUPLICATE_JSON_KEY')
        out[key] = value
    return out


def decode(raw):
    def bad_constant(_):
        raise InventoryError('INVALID_JSON_NUMBER')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object,
                      parse_constant=bad_constant)


def envelope(raw):
    value = decode(raw)
    require(isinstance(value, dict) and type(value.get('error')) is int
            and value['error'] == 0 and isinstance(value.get('data'), dict), 'API_ERROR')
    return value['data']


def make_context():
    with CERT.open('rb') as handle:
        raw = handle.read(65537)
    require(len(raw) <= 65536, 'CERT_SIZE')
    pem = raw.decode('ascii').strip()
    require(re.fullmatch(r'-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+\s+-----END CERTIFICATE-----', pem), 'CERT_FORMAT')
    der = ssl.PEM_cert_to_DER_cert(pem)
    require(hashlib.sha256(der).hexdigest() == FINGERPRINT, 'CERT_CHANGED')
    # Do not load OS defaults, environment CA paths or SSLKEYLOGFILE.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cadata=pem)
    require(context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname, 'TLS_POLICY')
    return context


class Client:
    def __init__(self, context):
        self.context = context
        self.deadline = time.monotonic() + 120
        self.requests = 0
        self.auth_attempted = False
        self.token = None

    def timeout(self):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, 'DEADLINE')
        return min(10, remaining)

    def connect(self, name=HOSTNAME):
        require(self.context.verify_mode == ssl.CERT_REQUIRED
                and self.context.check_hostname, 'TLS_POLICY')
        # Numeric AF_INET connection prevents DNS and proxy routing entirely.
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            raw.settimeout(self.timeout())
            raw.connect(ADDRESS)
            peer = self.context.wrap_socket(raw, server_hostname=name)
        except BaseException:
            raw.close()
            raise
        try:
            require(hashlib.sha256(peer.getpeercert(binary_form=True)).hexdigest()
                    == FINGERPRINT, 'PEER_CERT_CHANGED')
            return peer
        except BaseException:
            peer.close()
            raise

    def wrong_hostname_probe(self):
        try:
            peer = self.connect('alertmind-server-hostname-check.invalid')
        except ssl.SSLCertVerificationError as exc:
            # OpenSSL X509_V_ERR_HOSTNAME_MISMATCH; generic TLS failure is insufficient.
            require(exc.verify_code == 62, 'NEGATIVE_TLS_CAUSE')
            return
        peer.close()
        raise InventoryError('NEGATIVE_TLS_ACCEPTED')

    def request(self, method, path, basic=None):
        paged = re.fullmatch(r'/security/(users|roles|policies|rules)\?limit=100&offset=([0-9]+)&sort=id', path)
        if method == 'POST':
            require(path == AUTH and basic is not None and not self.auth_attempted
                    and self.token is None, 'ROUTE_DENIED')
            self.auth_attempted = True
        else:
            require(method == 'GET' and basic is None and
                    (path in SINGLE_READS or (paged and int(paged[2]) < MAX_ITEMS)), 'ROUTE_DENIED')
            require(self.token is not None or path == '/', 'AUTH_REQUIRED')
        self.requests += 1
        require(self.requests <= 100, 'REQUEST_LIMIT')
        peer = self.connect()  # Identity + exact peer pin checked BEFORE any HTTP headers.
        connection = http.client.HTTPConnection(HOSTNAME, ADDRESS[1], timeout=self.timeout())
        connection.sock = peer
        response = None
        try:
            headers = {'Host': 'localhost:55000', 'Accept': 'application/json',
                       'Accept-Encoding': 'identity', 'Connection': 'close'}
            if basic is not None:
                headers['Authorization'] = 'Basic ' + basic
            elif self.token is not None:
                headers['Authorization'] = 'Bearer ' + self.token
            connection.request(method, path, headers=headers)
            response = connection.getresponse()
            expected = 401 if path == '/' and self.token is None else 200
            require(response.status == expected, 'HTTP_STATUS')
            if expected == 401:
                return None  # Deliberately do not read an unauthenticated error body.
            require(response.getheader('Content-Encoding', 'identity') == 'identity', 'ENCODING')
            require(response.getheader('Content-Type', '').split(';')[0].strip().lower()
                    == 'application/json', 'CONTENT_TYPE')
            return envelope(self.read_body(response, peer))
        finally:
            if response is not None:
                response.close()
            connection.close()

    def read_body(self, response, peer):
        # HTTPResponse.read1 closes its file at the Content-Length boundary.
        # With Connection: close, that can release the final socket reference.
        # Never touch the peer again once all declared bytes have been read.
        transfer = response.getheader('Transfer-Encoding', None)
        length = response.getheader('Content-Length', None)
        require(transfer is None or (transfer.strip().lower() == 'chunked'
                and length is None), 'HTTP_FRAMING')
        declared = None
        if length is not None:
            require(re.fullmatch(r'[0-9]{1,20}', length.strip()) is not None, 'HTTP_FRAMING')
            declared = int(length.strip())
            require(declared <= MAX_BYTES, 'RESPONSE_SIZE')
        chunks, total = [], 0
        while declared is None or total < declared:
            amount = min(65536, MAX_BYTES + 1 - total)
            if declared is not None:
                amount = min(amount, declared - total)
            try:
                peer.settimeout(self.timeout())
                chunk = response.read1(amount)
            except TimeoutError:
                raise InventoryError('RESPONSE_TIMEOUT') from None
            except (http.client.HTTPException, OSError):
                raise InventoryError('RESPONSE_IO') from None
            if not chunk:
                require(declared is None or total == declared, 'TRUNCATED_RESPONSE')
                break
            total += len(chunk)
            require(total <= MAX_BYTES, 'RESPONSE_SIZE')
            chunks.append(chunk)
        # For chunked bodies, HTTPResponse must reach its terminal chunk; for
        # unframed bodies, only EOF delimits the message. Neither permits an
        # early return merely because a prefix already parses as valid JSON.
        return b''.join(chunks)

    def authenticate(self, username, password):
        require(type(username) is str and 1 <= len(username) <= 128
                and ':' not in username and all(ord(c) >= 32 for c in username), 'USERNAME')
        require(type(password) is str and 1 <= len(password) <= 4096, 'PASSWORD')
        basic = base64.b64encode((username + ':' + password).encode()).decode('ascii')
        data = self.request('POST', AUTH, basic=basic)
        token = data.get('token')
        require(type(token) is str and len(token) <= 8192
                and re.fullmatch(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', token), 'TOKEN_SHAPE')
        self.token = token


def rows(data):
    require(type(data.get('total_failed_items')) is int
            and data['total_failed_items'] == 0 and data.get('failed_items') == [], 'PARTIAL_RESULT')
    total = data.get('total_affected_items')
    items = data.get('affected_items')
    require(type(total) is int and 0 <= total <= MAX_ITEMS and isinstance(items, list), 'PAGE_SHAPE')
    return total, items


def identifiers(value):
    require(isinstance(value, list) and all(type(x) is int and 0 < x < 2**31 for x in value), 'ID_LIST')
    require(len(value) == len(set(value)), 'DUPLICATE_ID')
    return sorted(value)


def fetch_collection(client, kind):
    require(kind in COLLECTIONS, 'ROUTE_DENIED')
    found, expected, last = [], None, 0
    while True:
        total, batch = rows(client.request('GET', '/security/' + kind +
                         f'?limit={PAGE_SIZE}&offset={len(found)}&sort=id'))
        if expected is None:
            expected = total
        require(total == expected and len(batch) <= PAGE_SIZE, 'PAGINATION_DRIFT')
        require(batch or len(found) == total, 'EMPTY_PAGE')
        for item in batch:
            require(isinstance(item, dict), 'ITEM_SHAPE')
            identifier = item.get('id')
            require(type(identifier) is int and last < identifier < 2**31, 'PAGE_ORDER')
            last = identifier
            found.append(item)
        require(len(found) <= total, 'PAGE_OVERFLOW')
        if len(found) == total:
            return found


# Versioned v4.14.7 default policy actions/resources, not numeric database IDs.
# Sources: framework/wazuh/rbac/default/{policies,relationships}.yaml.
READONLY = {
    'agents_read_agents': (['agent:read'], ['agent:id:*', 'agent:group:*']),
    'agents_read_groups': (['group:read'], ['group:id:*']),
    'ciscat_read_ciscat': (['ciscat:read'], ['agent:id:*']),
    'cluster_read_resourceless': (['cluster:status', 'manager:read', 'manager:read_api_config'], ['*:*:*']),
    'cluster_read_nodes': (['cluster:read_api_config', 'cluster:read'], ['node:id:*']),
    'decoders_read_decoders': (['decoders:read'], ['decoder:file:*']),
    'lists_read_rules': (['lists:read'], ['list:file:*']),
    'rootcheck_read_rootcheck': (['rootcheck:read'], ['agent:id:*']),
    'rules_read_rules': (['rules:read'], ['rule:file:*']),
    'mitre_read_mitre': (['mitre:read'], ['*:*:*']),
    'sca_read_sca': (['sca:read'], ['agent:id:*']),
    'syscheck_read_syscheck': (['syscheck:read'], ['agent:id:*']),
    'syscollector_read_syscollector': (['syscollector:read'], ['agent:id:*']),
}


def strings(value):
    require(isinstance(value, list) and value and
            all(type(x) is str and 0 < len(x) <= 512 for x in value), 'STRING_LIST')
    return sorted(set(value))  # Upstream contains a repeated cluster action.


def policy_shape(value):
    require(isinstance(value, dict) and set(value) == {'actions', 'resources', 'effect'}, 'POLICY_SHAPE')
    require(value['effect'] in ('allow', 'deny'), 'POLICY_EFFECT')
    return {'actions': strings(value['actions']), 'resources': strings(value['resources']), 'effect': value['effect']}


def named(items, key, name):
    matches = [item for item in items if item[key] == name]
    require(len(matches) == 1, 'NAMED_RESOURCE')
    return matches[0]


def summarize(catalog, current, processed, config, username):
    require(config.get('rbac_mode') == 'white' and processed.get('rbac_mode') == 'white', 'RBAC_MODE')
    # Name membership alone cannot establish an unfiltered security inventory.
    for action, resources in (
        ('security:read', ('user:id:*', 'role:id:*', 'policy:id:*', 'rule:id:*')),
        ('security:read_config', ('*:*:*',)),
    ):
        grants = processed.get(action)
        require(isinstance(grants, dict) and all(grants.get(r) == 'allow' for r in resources)
                and all(v == 'allow' for v in grants.values()), 'ADMIN_READ_SCOPE')
    maps = {}
    for kind in COLLECTIONS:
        items = catalog[kind]
        maps[kind] = {x['id']: x for x in items}
        key = 'username' if kind == 'users' else 'name'
        names = [x.get(key) for x in items]
        require(all(type(n) is str and 0 < len(n) <= 128 for n in names)
                and len(names) == len(set(names)), 'NAMES')
    # Verify every edge in both directions, not just the selected readonly role.
    for kind in ('users', 'policies', 'rules'):
        for item in catalog[kind]:
            for role_id in identifiers(item.get('roles')):
                require(role_id in maps['roles'] and item['id'] in
                        identifiers(maps['roles'][role_id].get(kind)), 'RELATIONSHIP')
        for role in catalog['roles']:
            for item_id in identifiers(role.get(kind)):
                require(item_id in maps[kind] and role['id'] in
                        identifiers(maps[kind][item_id].get('roles')), 'RELATIONSHIP')
    admin = named(catalog['roles'], 'name', 'administrator')
    readonly = named(catalog['roles'], 'name', 'readonly')
    identity = named(catalog['users'], 'username', username)
    total, me = rows(current)
    require(total == 1 and len(me) == 1 and me[0].get('id') == identity['id']
            and me[0].get('username') == username
            and admin['id'] in identity['roles'], 'ADMIN_IDENTITY')
    require(not any(u['username'] == 'assistant-svc' for u in catalog['users']), 'SERVICE_SERVER_IDENTITY')
    require(not any(r['name'] == 'alertmind_socanalyst_server_ro' for r in catalog['rules']), 'MAPPING_COLLISION')
    broker = named(catalog['users'], 'username', 'wazuh-wui')
    require(all(type(u.get('allow_run_as')) is bool for u in catalog['users']), 'RUN_AS_SHAPE')
    require(broker['allow_run_as'], 'BROKER_RUN_AS_DISABLED')
    selected = [maps['policies'][i] for i in readonly['policies']]
    require({p['name'] for p in selected} == set(READONLY), 'READONLY_POLICY_SET')
    for p in selected:
        actions, resources = READONLY[p['name']]
        require(policy_shape(p['policy']) == {'actions': sorted(actions),
                'resources': sorted(resources), 'effect': 'allow'}, 'READONLY_POLICY_DRIFT')
    # Never echo arbitrary usernames, rule predicates, policy resources or errors.
    roles = [{'id': r['id'], 'label': r['name'] if r['name'] in ('administrator', 'readonly') else 'other',
              **{k: identifiers(r[k]) for k in ('users', 'policies', 'rules')}} for r in catalog['roles']]
    rules = []
    for r in catalog['rules']:
        require(isinstance(r.get('rule'), dict), 'RULE_SHAPE')
        classification = 'unreviewed_predicate'
        if r['rule'] == {'FIND': {'username': 'elastic'}}:
            classification = 'versioned_elastic_admin_predicate'
        elif r['rule'] == {'FIND': {'user_name': 'admin'}}:
            classification = 'versioned_opensearch_admin_predicate'
        rules.append({'id': r['id'], 'roles': identifiers(r['roles']),
                      'predicate_class': classification, 'predicate_sha256': digest(r['rule'])})
    return {
        'inventory_version': 1, 'scope': 'Server administrator inventory; NOT analyst authorization or mutation approval',
        'tls': {'hostname': HOSTNAME, 'destination': '127.0.0.1:55000', 'peer_der_sha256': FINGERPRINT},
        'counts': {k: len(v) for k, v in catalog.items()}, 'rbac_mode': 'white',
        'admin_identity_verified': True, 'admin_processed_policy_sha256': digest(processed),
        'readonly_role_id': readonly['id'], 'readonly_policies_match_v4_14_7': True,
        'readonly_policies': [{'id': p['id'], 'name': p['name'], **policy_shape(p['policy'])} for p in selected],
        'roles': roles, 'rules': rules,
        'users': [{'id': u['id'], 'label': 'broker' if u['id'] == broker['id'] else
                   'operator' if u['id'] == identity['id'] else 'other',
                   'allow_run_as': u['allow_run_as'], 'roles': identifiers(u['roles'])} for u in catalog['users']],
        'policies': [{'id': p['id'], 'roles': identifiers(p['roles']),
                      'definition_sha256': digest(policy_shape(p['policy']))} for p in catalog['policies']],
        'broker_allow_run_as_configured': True, 'assistant_server_user_absent': True,
        'target_mapping_name_absent': True, 'mutation_authorized': False,
        'outstanding': ['actual_dashboard_context_and_broker_execution', 'predicate_matching_review',
                        'fresh_indexer_baseline', 'dashboard_admin_and_saved_object_baseline',
                        'analyst_acceptance_and_safe_denials'],
    }


def collect(client, username):
    version = client.request('GET', '/')
    require(version.get('api_version') == '4.14.7', 'SERVER_VERSION')
    current = client.request('GET', '/security/users/me')
    processed = client.request('GET', '/security/users/me/policies')
    config = client.request('GET', '/security/config')
    first = {k: fetch_collection(client, k) for k in COLLECTIONS}
    summary = summarize(first, current, processed, config, username)
    # Re-read the whole graph/config/current-policy; counts alone miss replacements.
    second = {k: fetch_collection(client, k) for k in COLLECTIONS}
    require(canonical(first) == canonical(second), 'CATALOG_DRIFT')
    require(config == client.request('GET', '/security/config') and
            processed == client.request('GET', '/security/users/me/policies') and
            current == client.request('GET', '/security/users/me'), 'CONTEXT_DRIFT')
    summary['two_pass_observation_equal'] = True  # Not an atomic server snapshot.
    return summary


def main():
    client, password, username = None, None, None
    stage = 'preflight'
    try:
        require(len(sys.argv) == 1 and os.geteuid() == 0 and sys.stdin.isatty()
                and sys.stdout.isatty(), 'CONSOLE_REQUIRED')
        if input('Type REVIEWED only after independent approval of this package: ') != 'REVIEWED':
            raise InventoryError('REVIEW_GATE')
        client = Client(make_context())
        stage = 'TLS'
        client.request('GET', '/')
        client.wrong_hostname_probe()
        print('PASS this client: verified/pinned localhost TLS and hostname rejection; no credentials sent yet.')
        stage = 'authentication'
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            username = getpass.getpass('Existing SERVER administrator username (not assumed Indexer admin): ')
            password = getpass.getpass('Existing SERVER administrator password: ')
        # Human typing time is not charged against the bounded network observation.
        client.deadline = time.monotonic() + 120
        client.authenticate(username, password)
        password = None
        stage = 'inventory'
        summary = collect(client, username)
        print(json.dumps(summary, indent=2, sort_keys=True))
        print('STOP POINT: sanitized Server inventory only; no roles, users, settings or services changed.')
        return 0
    except InventoryError as exc:
        # InventoryError carries only a source-literal code, never remote content.
        print('STOP: Server inventory failed at ' + stage + '; code=' + str(exc)
              + '; no result accepted. Do not paste credentials or raw responses.')
        return 1
    except (Exception, KeyboardInterrupt):
        print('STOP: Server inventory failed at ' + stage + '; no result accepted. Do not paste credentials or raw responses.')
        return 1
    finally:
        password = username = None
        if client is not None:
            client.token = None  # Reference release, NOT a secure-memory-erasure claim.


if __name__ == '__main__':
    sys.exit(main())
