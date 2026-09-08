#!/usr/bin/env python3
"""Fixed-path, local-only Dashboard broker code inventory; never executes JS.

This reports literal source indicators, NOT effective authentication or TLS.
No credentials/configuration, network calls, package changes or file writes.
Every successful inventory still requires review before broker execution.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path('/usr/share/wazuh-dashboard/plugins')
UPSTREAM_COMMIT = '7659dead50782307faa1c0a313b1fd29d0b2c014'
MAX_BYTES = 512 * 1024
MAX_TOTAL_BYTES = 3 * 1024 * 1024
FILES = {
    'core_manifest': 'wazuhCore/opensearch_dashboards.json',
    'main_manifest': 'wazuh/opensearch_dashboards.json',
    'security_manifest': 'securityDashboards/opensearch_dashboards.json',
    'core_plugin': 'wazuhCore/server/plugin.js',
    'factory_selector': 'wazuhCore/server/services/security-factory/security-factory.js',
    'context_factory': 'wazuhCore/server/services/security-factory/factories/opensearch-dashboards-security-factory.js',
    'broker_client': 'wazuhCore/server/services/server-api-client.js',
    'login_route': 'wazuh/server/routes/wazuh-api.js',
    'login_controller': 'wazuh/server/controllers/wazuh-api.js',
}


class InventoryError(Exception):
    """Only source-literal diagnostic codes may leave this module."""


def require(condition, code):
    if not condition:
        raise InventoryError(code)


def metadata(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def trusted(st, directory=False):
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    require(kind(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022,
            'UNTRUSTED_FILE_METADATA')


def read_public(path):
    try:
        return _read_public(path)
    except FileNotFoundError:
        raise InventoryError('PUBLIC_FILE_MISSING') from None
    except PermissionError:
        raise InventoryError('PUBLIC_FILE_ACCESS_DENIED') from None
    except IsADirectoryError:
        raise InventoryError('PUBLIC_FILE_IS_DIRECTORY') from None


def decode_source(raw):
    require(b'\x00' not in raw, 'SOURCE_ENCODING')
    try:
        return raw.decode('utf-8')
    except UnicodeDecodeError:
        raise InventoryError('SOURCE_ENCODING') from None


def _read_public(path):
    # Fixed root-owned tree: reject symlink components and group/world writes.
    # O_NOFOLLOW plus descriptor/path equality guards the last component.
    # Root can still change files; two passes are not an atomic snapshot.
    require(path.is_absolute(), 'ABSOLUTE_PATH_REQUIRED')
    for parent in reversed(path.parents):
        trusted(parent.lstat(), directory=True)
    before = path.lstat()
    trusted(before)
    require(0 < before.st_size <= MAX_BYTES, 'FILE_SIZE')
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(path, flags)
    try:
        with os.fdopen(fd, 'rb') as source:
            fd = None
            trusted(os.fstat(source.fileno()))
            require(metadata(before) == metadata(os.fstat(source.fileno())), 'FILE_CHANGED')
            raw = source.read(MAX_BYTES + 1)
            require(metadata(before) == metadata(os.fstat(source.fileno())), 'FILE_CHANGED')
        require(metadata(before) == metadata(path.lstat()), 'FILE_CHANGED')
        require(len(raw) == before.st_size and len(raw) <= MAX_BYTES, 'FILE_SIZE')
        decode_source(raw)
        return raw
    finally:
        if fd is not None:
            os.close(fd)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def reject_constant(_):
    raise InventoryError('INVALID_JSON_NUMBER')


def parse_manifest(raw, expected_id, version=None):
    value = json.loads(decode_source(raw), object_pairs_hook=unique_object,
                       parse_constant=reject_constant)
    require(isinstance(value, dict) and value.get('id') == expected_id
            and value.get('server') is True, 'PLUGIN_MANIFEST')
    observed = value.get('version')
    require(isinstance(observed, str) and len(observed) <= 64
            and re.fullmatch(r'[0-9]+(?:\.[0-9]+){2,3}(?:-[0-9]+)?', observed),
            'PLUGIN_VERSION')
    if version is not None:
        require(observed == version, 'PLUGIN_VERSION')
    return value


def summarize(blobs):
    require(set(blobs) == set(FILES), 'FILE_SET')
    require(all(isinstance(b, bytes) and 0 < len(b) <= MAX_BYTES for b in blobs.values()), 'FILE_SIZE')
    require(sum(map(len, blobs.values())) <= MAX_TOTAL_BYTES, 'TOTAL_SIZE')
    texts = {name: decode_source(raw) for name, raw in blobs.items()}
    core = parse_manifest(blobs['core_manifest'], 'wazuhCore', '4.14.7-01')
    main = parse_manifest(blobs['main_manifest'], 'wazuh', '4.14.7-01')
    security = parse_manifest(blobs['security_manifest'], 'securityDashboards')
    optional = core.get('optionalPlugins')
    required = main.get('requiredPlugins')
    require(isinstance(optional, list) and all(type(x) is str for x in optional)
            and 'securityDashboards' in optional, 'PLUGIN_DEPENDENCIES')
    require(isinstance(required, list) and all(type(x) is str for x in required)
            and 'wazuhCore' in required, 'PLUGIN_DEPENDENCIES')
    client = texts['broker_client']
    false_count = len(re.findall(r'\brejectUnauthorized\s*:\s*false\b', client))
    true_count = len(re.findall(r'\brejectUnauthorized\s*:\s*true\b', client))
    # Literal indicators can occur in comments/unused code; never treat them
    # as a control-flow proof. A missing match cannot establish secure behavior.
    indicators = {
        'account_endpoint_literal': '/_opendistro/_security/api/account' in texts['context_factory'],
        'as_current_user_literal': 'asCurrentUser' in texts['context_factory'],
        'user_name_literal': 'user_name' in texts['context_factory'],
        'auth_context_literal': 'authContext' in client,
        'get_current_user_literal': 'getCurrentUser' in client,
        'run_as_suffix_literal': '/run_as' in client,
        'run_as_config_check_literal': 'isEnabledAuthWithRunAs' in client,
        'scoped_client_literal': 'asScoped' in texts['core_plugin'],
        'security_plugin_selector_literal': 'securityDashboards' in texts['factory_selector'],
        'login_route_literal': '/api/login' in texts['login_route'],
        'request_route_literal': '/api/request' in texts['login_route'],
        'scoped_authentication_literal': 'asCurrentUser.authenticate' in texts['login_controller'],
    }
    return {
        'inventory_version': 1,
        'scope': 'installed public code only; NOT actual Dashboard context or broker execution',
        'upstream_reference_commit': UPSTREAM_COMMIT,
        'plugin_versions': {'wazuh': main['version'], 'wazuhCore': core['version'],
                            'securityDashboards': security['version']},
        'files': [{'label': name, 'relative_path': FILES[name], 'bytes': len(blobs[name]),
                   'sha256': hashlib.sha256(blobs[name]).hexdigest()} for name in FILES],
        'literal_indicators_only': indicators,
        'tls_source_observation': {
            'reject_unauthorized_false_literal_count': false_count,
            'reject_unauthorized_true_literal_count': true_count,
            'classification': 'explicit_false_text_present' if false_count else 'unresolved',
            'effective_verification_proven': False,
        },
        'broker_execution_authorized': False,
        'mutation_authorized': False,
        'review_required': True,
        'outstanding': ['installed_control_flow_and_TLS_review',
                        'actual_dashboard_context_and_broker_execution',
                        'predicate_matching_review', 'fresh_indexer_baseline',
                        'dashboard_admin_and_saved_object_baseline',
                        'analyst_acceptance_and_safe_denials'],
    }


def collect(reader=read_public):
    def snapshot():
        blobs, total = {}, 0
        for name, relative in FILES.items():
            raw = reader(ROOT / relative)
            total += len(raw)
            require(total <= MAX_TOTAL_BYTES, 'TOTAL_SIZE')
            blobs[name] = raw
        return blobs
    first = snapshot()
    summary = summarize(first)
    require(first == snapshot(), 'SOURCE_DRIFT')
    summary['two_pass_bytes_equal'] = True
    return summary


def main():
    try:
        require(len(sys.argv) == 1 and sys.platform == 'linux' and os.geteuid() == 0,
                'ROOT_LINUX_NO_ARGS_REQUIRED')
        result = collect()
    except InventoryError as error:
        print('STOP: broker code inventory failed; code=' + str(error) + '; no result accepted.')
        return 1
    except (Exception, KeyboardInterrupt):
        # File paths, JSON/parser fragments and exception strings stay private.
        print('STOP: broker code inventory unavailable; no result accepted. Do not paste source or raw errors.')
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    print('STOP POINT: public code inventory complete; broker execution and live changes remain on hold.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
