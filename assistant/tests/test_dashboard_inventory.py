"""Offline tests for the VM-local, secret-suppressing inventory helper."""
import contextlib
import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / 'siem/rbac/collect_dashboard_inventory.py'
spec = importlib.util.spec_from_file_location('dashboard_inventory', PATH)
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


class DashboardInventoryTests(unittest.TestCase):
    def inputs(self):
        return (
            {'hosts': [{'default': {'url': 'https://localhost', 'port': 55000,
             'username': 'wazuh-wui', 'password': 'SECRET-SENTINEL', 'run_as': True}}]},
            {'opensearch_security.multitenancy.enabled': False,
             'opensearch_security.readonly_mode.roles': ['kibana_read_only']},
            {'https': {'enabled': True, 'key': 'SECRET-SENTINEL'}},
        )

    def test_sanitized_classifications_not_raw_values(self):
        result = inventory.summarize(*self.inputs())
        self.assertEqual(result['hosts'], [{'ordinal': 1, 'run_as': 'true',
            'expected_broker': True, 'https_loopback_url': True, 'port_55000': True}])
        self.assertFalse(result['readonly_ui_matches_socanalyst_role'])
        self.assertTrue(result['readonly_ui_matches_builtin_label'])
        self.assertNotIn('SECRET-SENTINEL', str(result))
        self.assertNotIn('wazuh-wui', str(result))

    def test_missing_invalid_and_multiple_hosts_are_not_passes(self):
        wazuh, dashboard, api = self.inputs()
        config = wazuh['hosts'][0]['default']
        config.update(run_as='true', url='https://SECRET-SENTINEL', port='55000')
        wazuh['hosts'].append({'SECRET-SENTINEL': {}})
        result = inventory.summarize(wazuh, {}, {})
        self.assertEqual(result['host_count'], 2)
        self.assertEqual(result['hosts'][0]['run_as'], 'invalid')
        self.assertEqual(result['hosts'][1]['run_as'], 'missing')
        self.assertFalse(result['hosts'][0]['https_loopback_url'])
        self.assertFalse(result['hosts'][0]['port_55000'])
        self.assertEqual(result['api_https_enabled'], 'missing')
        self.assertNotIn('SECRET-SENTINEL', str(result))
        for bad in ({}, {'hosts': []}, {'hosts': [{}]}, {'hosts': [{'x': 'secret'}]}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                inventory.summarize(bad, dashboard, api)

    def test_yaml_duplicates_unsafe_tags_and_size_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.yaml'
            for raw in (b'hosts: []\nhosts: []', b'!!python/object:secret {}',
                        b'[1, 2]', b'\xff', b' ' * (inventory.MAX_BYTES + 1)):
                path.write_bytes(raw)
                with self.subTest(raw_prefix=raw[:20]), self.assertRaises(Exception):
                    inventory.load_config(path)
            path.write_bytes(b'https:\n  enabled: true\n')
            self.assertEqual(inventory.load_config(path), {'https': {'enabled': True}})

    def test_main_suppresses_failures_and_emits_no_partial_inventory(self):
        with mock.patch.object(inventory.sys, 'argv', ['inventory']):
            for error in (ValueError('SECRET-SENTINEL'), PermissionError('SECRET-SENTINEL')):
                output = io.StringIO()
                with mock.patch.object(inventory, 'load_config', side_effect=error), contextlib.redirect_stdout(output):
                    self.assertEqual(inventory.main(), 1)
                self.assertNotIn('SECRET-SENTINEL', output.getvalue())
                self.assertNotIn('inventory_version', output.getvalue())
            output = io.StringIO()
            with mock.patch.object(inventory, 'load_config', side_effect=self.inputs()) as reader, contextlib.redirect_stdout(output):
                self.assertEqual(inventory.main(), 0)
            self.assertEqual([c.args[0] for c in reader.call_args_list], list(inventory.CONFIG_PATHS))
            self.assertNotIn('SECRET-SENTINEL', output.getvalue())
            self.assertIn('STOP POINT: inventory only', output.getvalue())

    def test_design_preserves_gates_and_no_live_http_in_collector(self):
        manifest = PATH.with_name('SERVER-DASHBOARD-SHA256SUMS').read_text(encoding='ascii').splitlines()
        self.assertEqual(len(manifest), 1)
        digest, name = manifest[0].split()
        self.assertEqual(name, PATH.name)
        self.assertEqual(digest, hashlib.sha256(PATH.read_bytes()).hexdigest())
        text = ' '.join((ROOT / 'docs/runbooks/rbac-server-dashboard-readonly.md').read_text(encoding='utf-8').split())
        for phrase in ('No live mutation is authorized by this package',
                       'not an Indexer identity', 'No active-response command',
                       'not behavioral write-denial proof',
                       'No monitoring-index grant', 'No application runtime change'):
            self.assertIn(phrase, text)
        source = PATH.read_text(encoding='utf-8')
        for forbidden in ('import requests', 'import subprocess', 'import socket', 'urllib', '.write_text(', '.write_bytes('):
            self.assertNotIn(forbidden, source)


if __name__ == '__main__':
    unittest.main()
