#!/usr/bin/env python3
"""Offline contract tests for the secret-free Phase 1 Wazuh RBAC package."""
import hashlib
import json
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
RBAC_DIR = REPO_ROOT / "siem" / "rbac"

INDEX_PATTERN = "wazuh-alerts-4.x-*"
DLS_QUERY = {"terms": {"agent.id": ["001", "002"]}}
EXPECTED_BINDINGS = [
    {
        "agent_id": "001",
        "agent_name": "win-victim",
        "enrollment_sha256": (
            "ce6dbeeff3df5ffef33e643ea36b60ff"
            "af4f9b73577bf8c68789c867d672a5b7"
        ),
    },
    {
        "agent_id": "002",
        "agent_name": "linux-victim",
        "enrollment_sha256": (
            "483a8b3caa8e9a252aa8ea632d7a5c1a"
            "b04358c170f314ec01f1d696dfffdebf"
        ),
    },
]
EXPECTED_OWN_INDEX_USERS = [
    "admin",
    "anomalyadmin",
    "kibanaro",
    "kibanaserver",
    "logstash",
    "readall",
    "snapshotrestore",
]


def load_json(name):
    return json.loads((RBAC_DIR / name).read_text(encoding="utf-8"))


class RbacTemplateContractTests(unittest.TestCase):
    def setUp(self):
        self.contract = load_json("scope-contract.json")
        self.soc_role = load_json("indexer-role_socanalyst_ro.json")
        self.assistant_role = load_json("indexer-role_assistant_alerts_ro.json")
        self.soc_mapping = load_json("indexer-role-mapping_socanalyst_ro.json")
        self.assistant_mapping = load_json(
            "indexer-role-mapping_assistant_alerts_ro.json"
        )
        self.own_index_scoped_patch = load_json(
            "indexer-role-mapping_own_index_scoped.patch.json"
        )
        self.own_index_rollback_patch = load_json(
            "indexer-role-mapping_own_index_rollback.patch.json"
        )

    def test_scope_contract_pins_inventory_and_principal_names(self):
        self.assertEqual(self.contract["schema_version"], 2)
        self.assertEqual(self.contract["index_pattern"], INDEX_PATTERN)
        self.assertEqual(self.contract["dls_query"], DLS_QUERY)
        self.assertEqual(self.contract["agent_bindings"], EXPECTED_BINDINGS)
        self.assertNotIn("000", json.dumps(self.contract["dls_query"]))
        self.assertEqual(
            self.contract["principals"],
            {
                "socanalyst": {
                    "indexer_role": "alertmind_socanalyst_ro",
                    "wazuh_server_role": "readonly",
                },
                "assistant-svc": {
                    "indexer_role": "alertmind_assistant_alerts_ro",
                    "wazuh_server_identity": False,
                    "dashboard_tenant": False,
                },
            },
        )
        self.assertEqual(
            self.contract["inherited_role_hardening"],
            {
                "mapping_name": "own_index",
                "expected_pre_apply_selectors": {
                    "users": ["*"],
                    "backend_roles": [],
                    "and_backend_roles": [],
                    "hosts": [],
                },
                "preserved_users": EXPECTED_OWN_INDEX_USERS,
                "excluded_principals": ["socanalyst", "assistant-svc"],
                "apply_payload": (
                    "indexer-role-mapping_own_index_scoped.patch.json"
                ),
                "rollback_payload": (
                    "indexer-role-mapping_own_index_rollback.patch.json"
                ),
                "rollback_requires_excluded_principals_revoked": True,
            },
        )

    def test_socanalyst_role_is_read_only_and_dls_bounded(self):
        self.assertEqual(
            self.soc_role["cluster_permissions"], ["cluster_composite_ops_ro"]
        )
        self.assertEqual(len(self.soc_role["index_permissions"]), 1)
        permission = self.soc_role["index_permissions"][0]
        self.assertEqual(permission["index_patterns"], [INDEX_PATTERN])
        self.assertEqual(json.loads(permission["dls"]), DLS_QUERY)
        self.assertEqual(permission["allowed_actions"], ["read"])
        self.assertEqual(permission["fls"], [])
        self.assertEqual(permission["masked_fields"], [])
        self.assertEqual(
            self.soc_role["tenant_permissions"],
            [{
                "tenant_patterns": ["global_tenant"],
                "allowed_actions": ["kibana_all_read"],
            }],
        )

    def test_assistant_role_has_only_search_and_get(self):
        self.assertEqual(self.assistant_role["cluster_permissions"], [])
        self.assertEqual(self.assistant_role["tenant_permissions"], [])
        self.assertEqual(len(self.assistant_role["index_permissions"]), 1)
        permission = self.assistant_role["index_permissions"][0]
        self.assertEqual(permission["index_patterns"], [INDEX_PATTERN])
        self.assertEqual(json.loads(permission["dls"]), DLS_QUERY)
        self.assertEqual(
            permission["allowed_actions"],
            ["indices:data/read/search", "indices:data/read/get"],
        )
        self.assertEqual(permission["fls"], [])
        self.assertEqual(permission["masked_fields"], [])

    def test_role_mappings_are_direct_user_only(self):
        self.assertEqual(
            self.soc_mapping,
            {"backend_roles": [], "hosts": [], "users": ["socanalyst"]},
        )
        self.assertEqual(
            self.assistant_mapping,
            {"backend_roles": [], "hosts": [], "users": ["assistant-svc"]},
        )

    def test_own_index_forward_patch_preserves_only_preexisting_users(self):
        self.assertEqual(
            self.own_index_scoped_patch,
            [{
                "op": "replace",
                "path": "/users",
                "value": EXPECTED_OWN_INDEX_USERS,
            }],
        )
        self.assertEqual(
            len(self.own_index_scoped_patch[0]["value"]),
            len(set(self.own_index_scoped_patch[0]["value"])),
        )
        self.assertNotIn("*", self.own_index_scoped_patch[0]["value"])
        self.assertNotIn("socanalyst", self.own_index_scoped_patch[0]["value"])
        self.assertNotIn("assistant-svc", self.own_index_scoped_patch[0]["value"])

    def test_own_index_rollback_patch_is_wildcard_restore_only(self):
        self.assertEqual(
            self.own_index_rollback_patch,
            [{"op": "replace", "path": "/users", "value": ["*"]}],
        )
        self.assertNotEqual(
            self.own_index_rollback_patch,
            self.own_index_scoped_patch,
        )

    def test_transfer_manifest_matches_exact_executable_payload_bytes(self):
        expected_names = {
            "indexer-role_socanalyst_ro.json",
            "indexer-role_assistant_alerts_ro.json",
            "indexer-role-mapping_socanalyst_ro.json",
            "indexer-role-mapping_assistant_alerts_ro.json",
            "indexer-role-mapping_own_index_scoped.patch.json",
            "indexer-role-mapping_own_index_rollback.patch.json",
        }
        recorded = {}
        for line in (RBAC_DIR / "SHA256SUMS").read_text(encoding="ascii").splitlines():
            digest, name = line.split(maxsplit=1)
            recorded[name] = digest

        self.assertEqual(set(recorded), expected_names)
        for name, expected_digest in recorded.items():
            actual_digest = hashlib.sha256((RBAC_DIR / name).read_bytes()).hexdigest()
            self.assertEqual(actual_digest, expected_digest)

    def test_payloads_contain_no_secret_bearing_fields_or_broad_index_grants(self):
        payloads = [
            self.contract,
            self.soc_role,
            self.assistant_role,
            self.soc_mapping,
            self.assistant_mapping,
            self.own_index_scoped_patch,
            self.own_index_rollback_patch,
        ]
        serialized = json.dumps(payloads).lower()
        for forbidden in (
            '"password"',
            '"hash"',
            '"token"',
            '"authorization"',
            '"private_key"',
            '"api_key"',
        ):
            self.assertNotIn(forbidden, serialized)

        for role in (self.soc_role, self.assistant_role):
            patterns = role["index_permissions"][0]["index_patterns"]
            self.assertEqual(patterns, [INDEX_PATTERN])
            self.assertNotIn("*", patterns)
            self.assertNotIn("wazuh-alerts-*", patterns)

    def test_denial_matrix_is_zero_state_change_and_prohibits_index_delete(self):
        matrix = (RBAC_DIR / "negative-test-matrix.md").read_text(encoding="utf-8")
        for required in (
            "existing concrete index and existing ID",
            "doc_as_upsert:false",
            "no** `upsert` field",
            "Original hash unchanged",
            "both random IDs remain absent",
            "Do not create or delete an index",
            "action.destructive_requires_name=false",
            "username-named index",
            "`own_index` is absent",
            "unexpected",
            "effective role",
            "empty wildcard `200` with zero shards and zero hits is vacuous",
            "Do not create an archive index",
        ):
            self.assertIn(required, matrix)

    def test_live_enforcement_evidence_records_boundary_and_caveats(self):
        evidence = (
            REPO_ROOT / "evidence" / "rbac" /
            "phase1b-indexer-enforcement-proof.md"
        ).read_text(encoding="utf-8")
        normalized = " ".join(evidence.split())
        for required in (
            "indices:data/write/bulk",
            "indices:data/write/reindex",
            "11,816",
            "security_exception",
            "zero visible state change",
            "No concrete `wazuh-archives-*` index existed",
            "that result is vacuous",
            "VERIFY_X509_STRICT",
            "CERT_REQUIRED",
            "hostname verification",
            "SSH remains disabled",
            "application integration remain unimplemented",
        ):
            self.assertIn(required, normalized)

    def test_runbook_orders_inherited_role_gate_before_project_mappings(self):
        runbook = (
            REPO_ROOT / "docs" / "runbooks" /
            "rbac-wazuh-read-only-setup.md"
        ).read_text(encoding="utf-8")
        correction = runbook.index(
            "Apply the reviewed `own_index` mapping correction"
        )
        project_mappings = runbook.index(
            "Apply the two AlertMind direct-user mappings"
        )
        self.assertLess(correction, project_mappings)
        for required in (
            "only basic internal HTTP authentication is enabled",
            "every other",
            "`own_index` selector is empty",
            "both credentials fail authentication",
            "Rollback-only",
            "DLS-scoped",
        ):
            self.assertIn(required, runbook)


if __name__ == "__main__":
    unittest.main(verbosity=2)
