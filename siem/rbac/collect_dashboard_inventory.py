#!/usr/bin/env python3
"""Local, read-only configuration inventory. No authentication or HTTP calls.

Run on the VM console with the packaged Wazuh Python (PyYAML required).
Only allowlisted classifications are emitted; configuration values and parser
errors may contain secrets and must never be echoed. This is not live proof.
"""
import json
from pathlib import Path
import sys

MAX_BYTES = 1024 * 1024
MISSING = object()
CONFIG_PATHS = (
    Path('/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml'),
    Path('/etc/wazuh-dashboard/opensearch_dashboards.yml'),
    Path('/var/ossec/api/configuration/api.yaml'),
)


def load_config(path):
    import yaml

    class UniqueLoader(yaml.SafeLoader):
        pass

    def unique_mapping(loader, node, deep=False):
        loader.flatten_mapping(node)
        result = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in result:
                raise ValueError('duplicate configuration key')
            result[key] = loader.construct_object(value_node, deep=deep)
        return result

    UniqueLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)
    with path.open('rb') as source:
        raw = source.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError('configuration size limit')
    document = yaml.load(raw.decode('utf-8'), Loader=UniqueLoader)
    if document is None:
        return {}  # Missing explicit settings remain unknown, not defaults.
    if not isinstance(document, dict):
        raise ValueError('configuration must be a mapping')
    return document


def resolve_setting(document, dotted_name):
    """Resolve dotted/nested combinations without guessing key precedence.

    Multiple representations of the same setting are ambiguous even if their
    values agree. A scalar where a parent mapping is needed is also rejected.
    Error messages stay static because keys and values may contain secrets.
    """
    def candidates(mapping, parts):
        found = []
        for length in range(1, len(parts) + 1):
            key = '.'.join(parts[:length])
            if key not in mapping:
                continue
            value = mapping[key]
            if length == len(parts):
                found.append(value)
            else:
                if not isinstance(value, dict):
                    raise ValueError('invalid configuration parent shape')
                found.extend(candidates(value, parts[length:]))
        return found

    found = candidates(document, dotted_name.split('.'))
    if len(found) > 1:
        raise ValueError('ambiguous configuration setting')
    return found[0] if found else MISSING


def bool_state(value):
    if type(value) is bool:
        return 'true' if value else 'false'
    return 'missing' if value is None or value is MISSING else 'invalid'


def summarize(wazuh, dashboard, api):
    if not all(isinstance(value, dict) for value in (wazuh, dashboard, api)):
        raise ValueError('invalid root shape')
    hosts = wazuh.get('hosts')
    if not isinstance(hosts, list) or not 1 <= len(hosts) <= 10:
        raise ValueError('missing or unsupported host inventory')
    summaries = []
    for position, entry in enumerate(hosts, 1):
        if not isinstance(entry, dict) or len(entry) != 1:
            raise ValueError('invalid host entry')
        config = next(iter(entry.values()))
        if not isinstance(config, dict):
            raise ValueError('invalid host configuration')
        url = config.get('url')
        local = isinstance(url, str) and url in (
            'https://localhost', 'https://127.0.0.1', 'https://[::1]')
        port = config.get('port')
        summaries.append({
            'ordinal': position,
            'run_as': bool_state(config.get('run_as')),
            'expected_broker': config.get('username') == 'wazuh-wui',
            'https_loopback_url': local,
            'port_55000': type(port) is int and port == 55000,
        })
    roles = resolve_setting(dashboard, 'opensearch_security.readonly_mode.roles')
    valid_roles = (None if roles is MISSING else
                   isinstance(roles, list) and all(type(r) is str for r in roles))
    https = api.get('https', {})
    if not isinstance(https, dict):
        raise ValueError('invalid HTTPS configuration')
    return {
        'inventory_version': 2,
        'scope': 'local explicit settings only; not effective permissions or TLS proof',
        'host_count': len(hosts),
        'hosts': summaries,
        'dashboard_multitenancy': bool_state(
            resolve_setting(dashboard, 'opensearch_security.multitenancy.enabled')),
        'readonly_role_list_valid': valid_roles,
        'readonly_ui_matches_socanalyst_role': 'alertmind_socanalyst_ro' in roles if valid_roles else None,
        'readonly_ui_matches_builtin_label': 'kibana_read_only' in roles if valid_roles else None,
        'api_https_enabled': bool_state(https.get('enabled')),
        'api_certificate_path_explicit': 'cert' in https,
        'api_ca_path_explicit': 'ca' in https,
        'api_private_key_path_explicit': 'key' in https,
    }


def main():
    try:
        if len(sys.argv) != 1:
            raise ValueError('no arguments supported')
        summary = summarize(*(load_config(path) for path in CONFIG_PATHS))
    except Exception:
        # Do not print exception text, YAML snippets, paths or raw settings.
        print('STOP: local inventory unavailable; check file access, YAML shape and packaged PyYAML at the console.')
        return 1
    print(json.dumps(summary, indent=2, sort_keys=True))
    print('STOP POINT: inventory only; no file, service, role or credential changed.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
