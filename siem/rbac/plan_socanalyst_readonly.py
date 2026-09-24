"""Offline-only preview of the human read-only change boundary.

This module performs no I/O and deliberately cannot emit a Wazuh Server API
payload, edit a Dashboard configuration, or authorize a live change. Inputs
are reviewed inventory summaries plus an in-memory role list, not live state.
"""

SERVER_SCOPE = 'Server administrator inventory; NOT analyst authorization or mutation approval'
DASHBOARD_SCOPE = 'local explicit settings only; not effective permissions or TLS proof'
TARGET_ROLE = 'alertmind_socanalyst_ro'
BUILTIN_UI_ROLE = 'kibana_read_only'
SERVER_ROLE = 'readonly'
SERVER_MAPPING = 'alertmind_socanalyst_server_ro'

BLOCKERS = (
    'broker_tls_deployment_and_actual_path_acceptance',
    'actual_dashboard_context_and_rule_predicate_review',
    'fresh_indexer_role_mapping_dls_and_own_index_readback',
    'fresh_admin_and_two_saved_dashboard_baselines',
    'explicit_acceptance_of_broader_server_read_scope',
    'independent_review_and_separate_live_change_approval',
)


class PreviewError(ValueError):
    """Static failure code; never include inventory/configuration contents."""


def require(condition, code):
    if not condition:
        raise PreviewError(code)


def preview(server, dashboard, readonly_roles):
    """Return a non-authorizing, non-deployable delta from reviewed summaries.

    The summaries are *historical* observations; passing these checks never
    establishes current permissions. In particular, the Server rule predicate
    and role ID are intentionally not rendered as an API payload.
    """
    require(type(server) is dict and type(dashboard) is dict, 'SUMMARY_SHAPE')
    require(type(server.get('inventory_version')) is int and
            server['inventory_version'] == 1 and
            server.get('scope') == SERVER_SCOPE and
            server.get('rbac_mode') == 'white' and
            server.get('readonly_policies_match_v4_14_7') is True and
            server.get('broker_allow_run_as_configured') is True and
            server.get('assistant_server_user_absent') is True and
            server.get('target_mapping_name_absent') is True and
            server.get('two_pass_observation_equal') is True and
            server.get('mutation_authorized') is False and
            type(server.get('readonly_role_id')) is int and
            server['readonly_role_id'] > 0, 'SERVER_SUMMARY')
    require(type(dashboard.get('inventory_version')) is int and
            dashboard['inventory_version'] == 2 and
            dashboard.get('scope') == DASHBOARD_SCOPE and
            type(dashboard.get('host_count')) is int and
            dashboard['host_count'] == 1 and
            type(dashboard.get('hosts')) is list and
            len(dashboard['hosts']) == 1 and
            type(dashboard['hosts'][0]) is dict and
            type(dashboard['hosts'][0].get('ordinal')) is int and
            dashboard['hosts'][0]['ordinal'] == 1 and
            dashboard['hosts'][0].get('run_as') == 'true' and
            dashboard['hosts'][0].get('expected_broker') is True and
            dashboard['hosts'][0].get('https_loopback_url') is True and
            dashboard['hosts'][0].get('port_55000') is True and
            dashboard.get('dashboard_multitenancy') == 'false' and
            dashboard.get('readonly_role_list_valid') is True and
            dashboard.get('readonly_ui_matches_builtin_label') is True,
            'DASHBOARD_SUMMARY')
    require(type(readonly_roles) is list and 1 <= len(readonly_roles) <= 64 and
            all(type(role) is str and 1 <= len(role) <= 256 and
                all(32 < ord(char) < 127 for char in role)
                for role in readonly_roles) and
            len(set(readonly_roles)) == len(readonly_roles) and
            BUILTIN_UI_ROLE in readonly_roles, 'ROLE_LIST')
    require(dashboard.get('readonly_ui_matches_socanalyst_role') is
            (TARGET_ROLE in readonly_roles), 'ROLE_LIST_DRIFT')

    proposed = list(readonly_roles)
    if TARGET_ROLE not in proposed:
        proposed.append(TARGET_ROLE)
    return {
        'status': 'OFFLINE_PREVIEW_ONLY',
        'mutation_authorized': False,
        'server_mapping_name': SERVER_MAPPING,
        'server_role_name': SERVER_ROLE,
        'server_rule_payload': None,
        'dashboard_readonly_roles_before': list(readonly_roles),
        'dashboard_readonly_roles_after': proposed,
        'dashboard_file_change_proposed': proposed != readonly_roles,
        'blockers': list(BLOCKERS),
    }
