"""Synthetic offline checks only: never call Wazuh or edit its configuration."""
import copy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / 'siem/rbac/plan_socanalyst_readonly.py'
spec = importlib.util.spec_from_file_location('socanalyst_preview', PATH)
preview_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preview_module)


def inputs():
    server = {
        'inventory_version': 1,
        'scope': preview_module.SERVER_SCOPE,
        'rbac_mode': 'white',
        'readonly_policies_match_v4_14_7': True,
        'broker_allow_run_as_configured': True,
        'assistant_server_user_absent': True,
        'target_mapping_name_absent': True,
        'two_pass_observation_equal': True,
        'mutation_authorized': False,
        'readonly_role_id': 83,  # synthetic; never emitted as an API payload
    }
    dashboard = {
        'inventory_version': 2,
        'scope': preview_module.DASHBOARD_SCOPE,
        'host_count': 1,
        'hosts': [{'ordinal': 1, 'run_as': 'true', 'expected_broker': True,
                   'https_loopback_url': True, 'port_55000': True}],
        'dashboard_multitenancy': 'false',
        'readonly_role_list_valid': True,
        'readonly_ui_matches_builtin_label': True,
        'readonly_ui_matches_socanalyst_role': False,
    }
    return server, dashboard, ['kibana_read_only', 'existing_custom_role']


class SocanalystPreviewTests(unittest.TestCase):
    def test_preview_preserves_existing_roles_and_is_never_authority(self):
        server, dashboard, roles = inputs()
        before = copy.deepcopy((server, dashboard, roles))
        result = preview_module.preview(server, dashboard, roles)
        self.assertEqual(result['dashboard_readonly_roles_before'], roles)
        self.assertEqual(result['dashboard_readonly_roles_after'], roles + [
            'alertmind_socanalyst_ro'])
        self.assertTrue(result['dashboard_file_change_proposed'])
        self.assertEqual(result['server_mapping_name'], 'alertmind_socanalyst_server_ro')
        self.assertEqual(result['server_role_name'], 'readonly')
        self.assertIsNone(result['server_rule_payload'])
        self.assertFalse(result['mutation_authorized'])
        self.assertIn('actual_dashboard_context_and_rule_predicate_review', result['blockers'])
        self.assertIn('explicit_acceptance_of_broader_server_read_scope', result['blockers'])
        self.assertEqual((server, dashboard, roles), before)

    def test_already_present_role_is_idempotent_but_still_blocked(self):
        server, dashboard, roles = inputs()
        roles.append('alertmind_socanalyst_ro')
        dashboard['readonly_ui_matches_socanalyst_role'] = True
        result = preview_module.preview(server, dashboard, roles)
        self.assertEqual(result['dashboard_readonly_roles_after'], roles)
        self.assertFalse(result['dashboard_file_change_proposed'])
        self.assertFalse(result['mutation_authorized'])
        self.assertIsNone(result['server_rule_payload'])

    def test_server_inventory_drift_fails_closed(self):
        for key, value in (
            ('inventory_version', 2), ('inventory_version', True),
            ('scope', 'unknown'), ('rbac_mode', 'black'),
            ('readonly_policies_match_v4_14_7', False),
            ('broker_allow_run_as_configured', False),
            ('assistant_server_user_absent', False),
            ('target_mapping_name_absent', False),
            ('two_pass_observation_equal', False),
            ('mutation_authorized', True),
            ('readonly_role_id', 0), ('readonly_role_id', True),
        ):
            server, dashboard, roles = inputs()
            server[key] = value
            with self.subTest(key=key, value=value), self.assertRaisesRegex(
                    preview_module.PreviewError, '^SERVER_SUMMARY$'):
                preview_module.preview(server, dashboard, roles)

    def test_dashboard_inventory_drift_fails_closed(self):
        for key, value in (
            ('inventory_version', 1), ('inventory_version', True),
            ('scope', 'unknown'), ('host_count', 2), ('host_count', True),
            ('hosts', []), ('dashboard_multitenancy', 'true'),
            ('readonly_role_list_valid', None),
            ('readonly_ui_matches_builtin_label', False),
        ):
            server, dashboard, roles = inputs()
            dashboard[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(
                    preview_module.PreviewError, '^DASHBOARD_SUMMARY$'):
                preview_module.preview(server, dashboard, roles)
        for key, value in (
            ('run_as', 'missing'), ('expected_broker', False),
            ('https_loopback_url', False), ('port_55000', False),
            ('ordinal', True),
        ):
            server, dashboard, roles = inputs()
            dashboard['hosts'][0][key] = value
            with self.subTest(host_key=key), self.assertRaisesRegex(
                    preview_module.PreviewError, '^DASHBOARD_SUMMARY$'):
                preview_module.preview(server, dashboard, roles)

    def test_roles_and_summary_must_agree_without_rewriting_existing_roles(self):
        invalid_lists = ([], ['other'], ['kibana_read_only', 'kibana_read_only'],
                         ['kibana_read_only', 'bad\nrole'],
                         ['kibana_read_only', None],
                         ['kibana_read_only'] + ['x' + str(i) for i in range(64)])
        for roles in invalid_lists:
            server, dashboard, _ = inputs()
            with self.subTest(roles=roles), self.assertRaisesRegex(
                    preview_module.PreviewError, '^ROLE_LIST$'):
                preview_module.preview(server, dashboard, roles)
        server, dashboard, roles = inputs()
        dashboard['readonly_ui_matches_socanalyst_role'] = True
        with self.assertRaisesRegex(preview_module.PreviewError, '^ROLE_LIST_DRIFT$'):
            preview_module.preview(server, dashboard, roles)
        roles.append('alertmind_socanalyst_ro')
        dashboard['readonly_ui_matches_socanalyst_role'] = False
        with self.assertRaisesRegex(preview_module.PreviewError, '^ROLE_LIST_DRIFT$'):
            preview_module.preview(server, dashboard, roles)

    def test_no_io_or_live_change_surface(self):
        source = PATH.read_text(encoding='utf-8')
        for forbidden in ('import socket', 'import requests', 'import subprocess',
                          'import urllib', 'import http', 'open(', '.write_text(',
                          '.write_bytes(', 'def main(', 'if __name__'):
            self.assertNotIn(forbidden, source)
        self.assertEqual(set(preview_module.BLOCKERS), {
            'broker_tls_deployment_and_actual_path_acceptance',
            'actual_dashboard_context_and_rule_predicate_review',
            'fresh_indexer_role_mapping_dls_and_own_index_readback',
            'fresh_admin_and_two_saved_dashboard_baselines',
            'explicit_acceptance_of_broader_server_read_scope',
            'independent_review_and_separate_live_change_approval',
        })


if __name__ == '__main__':
    unittest.main()
