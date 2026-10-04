#!/usr/bin/env python3
"""Owner-attested Dashboard account/context and current matching-rule review aid.

One Server-admin authentication, allowlisted reads via the unchanged reader,
two browser account GETs. No run-as synthesis, grants, UI edit or restart.
The browser summary is owner-carried evidence, not cryptographic attestation.
"""
import getpass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import stat
import sys
import time
import warnings

HERE = Path(__file__).resolve().parent
SERVER_SHA = '5cccc906dbf4f5470f10814f37ccc4ca849e76c36d0b45c441da95357b911e77'
SOURCE_NAMES = ('observe_dashboard_context.py', 'collect_server_inventory.py',
                'dashboard_context_observation.js')
STAGE = Path('/root/alertmind-dashboard-context')
PLUGIN_ROOT = Path('/usr/share/wazuh-dashboard/plugins')
# Public, version-matched vendor .deb bytes. The patched broker client is NOT
# pinned to its pre-remediation image here. These unchanged derivation routes
# are checked without executing JS or reading broker configuration/credentials.
CODE_PINS = {
    'wazuhCore/server/services/security-factory/factories/opensearch-dashboards-security-factory.js':
        '1e01310dfb72263372db90706cdce7d7128773537d68ca4d0c4d16f4ba26c530',
    'securityDashboards/common/index.js':
        '4d0770aefbc9f05a7308935a09158e4bbed55e455d71f42cd26211a80be80bfe',
    'securityDashboards/server/routes/index.js':
        '95b07e863d3b8beb3d9d0d1e57faa61a394740cccee6ba8cdc2288a4d960222e',
    'securityDashboards/server/backend/opensearch_security_configuration_plugin.js':
        'a00973469ef08e0698a8f7b405b771700fc96b5307a52109227c716473c7af62',
}
PREDICATES = {
    'versioned_elastic_admin_predicate': {'FIND': {'username': 'elastic'}},
    'versioned_opensearch_admin_predicate': {'FIND': {'user_name': 'admin'}},
}
CODES = frozenset('CONSOLE RELEASE STAGE STAGE_FILES STAGE_BYTES SERVER_READER CODE_METADATA '
                  'CODE_BYTES CATALOG_RULES CATALOG_ROLES BROKER_ID CATALOG_DRIFT SUMMARY '
                  'CHALLENGE BROWSER_ATTESTATION MATCH_OVERLAP INPUT_SIZE'.split())


class ObservationError(ValueError):
    """Static codes only; no private data is an exception argument."""


def need(ok, code):
    if not ok:
        raise ObservationError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stamp(info):
    # Reading a file may update atime; it must not invalidate a byte identity.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def verify_stage(root=STAGE):
    info = root.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
         and stat.S_IMODE(info.st_mode) == 0o700, 'STAGE')
    need({p.name for p in root.iterdir()} == set(SOURCE_NAMES) | {'SHA256SUMS'}, 'STAGE_FILES')
    files = {}
    for name in SOURCE_NAMES + ('SHA256SUMS',):
        path = root / name
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
             and stat.S_IMODE(info.st_mode) == 0o400 and 0 < info.st_size <= 131072, 'STAGE')
        with path.open('rb') as stream:
            raw = stream.read(131073)
        need(0 < len(raw) <= 131072 and b'\r' not in raw and raw.endswith(b'\n'), 'STAGE_BYTES')
        files[name] = raw
    manifest = ''.join(sha(files[n]) + '  ' + n + '\n' for n in SOURCE_NAMES).encode('ascii')
    need(files['SHA256SUMS'] == manifest, 'STAGE_BYTES')
    need(sha(files['collect_server_inventory.py']) == SERVER_SHA, 'SERVER_READER')
    return files


def load_server(files):
    need(sha(files['collect_server_inventory.py']) == SERVER_SHA, 'SERVER_READER')
    # Conventional root-private staged source, not a new runtime-attestation loader.
    spec = importlib.util.spec_from_file_location('dashboard_context_server', HERE / 'collect_server_inventory.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def code_snapshot():
    import pwd  # Linux-only local identity lookup, not needed for offline tests.
    service = pwd.getpwnam('wazuh-dashboard')
    allowed = {(0, 0), (service.pw_uid, service.pw_gid)}
    out = {}
    for relative, expected in CODE_PINS.items():
        path = PLUGIN_ROOT / relative
        for parent in path.parents:
            info = parent.lstat()
            owner = allowed if parent == PLUGIN_ROOT.parent or PLUGIN_ROOT.parent in parent.parents else {(0, 0)}
            need(stat.S_ISDIR(info.st_mode) and (info.st_uid, info.st_gid) in owner
                 and not info.st_mode & 0o022, 'CODE_METADATA')
        before = path.lstat()
        need(stat.S_ISREG(before.st_mode) and (before.st_uid, before.st_gid) in allowed
             and not before.st_mode & 0o022 and 0 < before.st_size <= 524288, 'CODE_METADATA')
        with path.open('rb') as stream:
            opened = os.fstat(stream.fileno())
            need(stamp(opened) == stamp(before), 'CODE_METADATA')
            raw = stream.read(524289)
            need(stamp(os.fstat(stream.fileno())) == stamp(opened), 'CODE_METADATA')
        need(stamp(path.lstat()) == stamp(before) and len(raw) <= 524288 and sha(raw) == expected, 'CODE_BYTES')
        out[relative] = expected
    return out  # Service-owned code remains mutable; no atomic/loaded-code claim.


def catalog_contract(server, summary):
    rules = summary['rules']
    need(summary['two_pass_observation_equal'] is True and len(rules) == 2
         and {r['predicate_class'] for r in rules} == set(PREDICATES), 'CATALOG_RULES')
    roles = summary['roles']
    admins = [r for r in roles if r['label'] == 'administrator']
    readonly = [r for r in roles if r['label'] == 'readonly']
    need(len(admins) == len(readonly) == 1 and readonly[0]['id'] == summary['readonly_role_id']
         and readonly[0]['rules'] == [] and readonly[0]['users'] == [], 'CATALOG_ROLES')
    for rule in rules:
        need(rule['predicate_sha256'] == server.digest(PREDICATES[rule['predicate_class']])
             and rule['roles'] == [admins[0]['id']], 'CATALOG_RULES')
    brokers = [u for u in summary['users'] if u['label'] == 'broker']
    # v4.14.7 RBAChecker permits reserved predicates for broker ID 2; do not
    # pretend a renamed/replaced broker ID has identical reserved-rule semantics.
    need(len(brokers) == 1 and brokers[0]['id'] == 2 and brokers[0]['allow_run_as'] is True, 'BROKER_ID')
    return rules


def browser_summary(server, raw, challenge):
    need(len(raw.encode('utf-8')) <= 4096, 'INPUT_SIZE')
    value = server.decode(raw.encode('utf-8'))
    expected = {'schema': 1, 'challenge': challenge, 'endpoint': '/api/v1/configuration/account',
                'source': 'dashboard-scoped-account', 'user_name_is_socanalyst': True,
                'exact_indexer_role': True, 'backend_roles_empty': True, 'account_shape_version': 1,
                'two_reads_equal': True, 'top_level_username_present': False,
                'broker_run_as_body_observed': False, 'server_effective_policy_observed': False,
                'mutation_authorized': False}
    need(type(value) is dict and set(value) == set(expected) | {'matches'}, 'SUMMARY')
    need(value.get('challenge') == challenge, 'CHALLENGE')
    need(all(type(value[k]) is type(v) and value[k] == v for k, v in expected.items()), 'SUMMARY')
    matches = value['matches']
    need(type(matches) is dict and set(matches) == set(PREDICATES)
         and all(type(x) is bool for x in matches.values()), 'SUMMARY')
    need(not any(matches.values()), 'MATCH_OVERLAP')
    return value


def observe(server, client, username, challenge, read_browser, code_read=code_snapshot):
    before_code = code_read()
    first = server.collect(client, username)
    rules = catalog_contract(server, first)
    # Waiting for the owner is outside the network deadline, not a retry or
    # unlimited observation. New reads are still bounded by the reused client.
    raw = read_browser(challenge)
    browser_summary(server, raw, challenge)
    client.deadline = time.monotonic() + 120
    second = server.collect(client, username)
    catalog_contract(server, second)
    need(first == second, 'CATALOG_DRIFT')
    need(code_read() == before_code, 'CODE_BYTES')
    return {'observation_version': 1, 'scope': 'owner-attested Dashboard-scoped account and exact current predicate observation',
            'actual_dashboard_scoped_account_observed': True,
            'observation_source_attested_by_owner_not_cryptographically_proven': True,
            'broker_run_as_body_observed': False, 'server_effective_policy_observed': False,
            'context_binding': {'field': 'user_name', 'value': 'socanalyst', 'location': 'top-level'},
            'browser_account_reads_equal': True, 'current_server_catalog_equal_before_after': True,
            'installed_derivation_code_pins_equal_before_after': True,
            'current_server_inventory_sha256': server.digest(second),
            'factory_context_equivalence_review_required': True,
            'rules': [{**r, 'matches_observed_account': False} for r in rules],
            'matching_role_ids': [], 'readonly_role_id_observed': second['readonly_role_id'],
            'readonly_policies_match_v4_14_7': True,
            'atomic_or_continuous_snapshot_proven': False, 'loaded_code_proven': False,
            'matching_rule_review_required': True, 'server_mapping_payload': None,
            'mutation_authorized': False}


def main():
    server = client = password = username = None
    phase = 'preflight'
    try:
        need(len(sys.argv) == 1 and os.geteuid() == 0 and sys.stdin.isatty() and sys.stdout.isatty(), 'CONSOLE')
        need(HERE == STAGE, 'STAGE')
        need(input('Type REVIEWED-ORIGINAL-CONTEXT only after focused approval and this one-run release: ')
             == 'REVIEWED-ORIGINAL-CONTEXT', 'RELEASE')
        files = verify_stage()
        server = load_server(files)
        phase = 'TLS'
        client = server.Client(server.make_context())
        client.request('GET', '/')
        client.wrong_hostname_probe()
        print('PASS separate pinned Server TLS and hostname rejection; no Server credentials sent yet')
        phase = 'authentication'
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            username = getpass.getpass('Existing SERVER administrator username (not Indexer admin): ')
            password = getpass.getpass('Existing SERVER administrator password: ')
        client.deadline = time.monotonic() + 120
        client.authenticate(username, password)
        password = None
        phase = 'observation'
        def read_browser(challenge):
            print('PUBLIC observation challenge: ' + challenge)
            print('Current two versioned administrator predicates verified; no matching rule is assumed')
            need(input('Type FRESH-TRUSTED-SOC after the reviewed warning-free lab-profile login and browser observation: ')
                 == 'FRESH-TRUSTED-SOC', 'BROWSER_ATTESTATION')
            print('Paste ONLY the one sanitized browser JSON line (no credentials, raw account, cookies or JWT):')
            raw = sys.stdin.readline(4098)
            need(raw.endswith('\n') and len(raw.encode('utf-8')) <= 4097, 'INPUT_SIZE')
            return raw.rstrip('\n')
        result = observe(server, client, username, secrets.token_hex(32), read_browser)
        print(json.dumps(result, indent=2, sort_keys=True))
        print('STOP POINT: observation only; matching-rule review, Server mapping and read-only UI remain on hold')
        return 0
    except (Exception, KeyboardInterrupt) as exc:
        code = exc.args[0] if isinstance(exc, ObservationError) and len(exc.args) == 1 else None
        detail = 'code=' + code if type(code) is str and code in CODES else (
            server.failure_details(exc, client) if server is not None else 'category=UNEXPECTED')
        print('STOP Dashboard context at ' + phase + '; ' + detail + '; no observation accepted; no live change issued')
        return 1
    finally:
        password = username = None
        if client is not None:
            client.token = None  # Reference release, not guaranteed memory erasure.


if __name__ == '__main__':
    sys.exit(main())
