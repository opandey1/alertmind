#!/usr/bin/env python3
"""Offline contract tests for the secret-free Phase 1 Wazuh RBAC package."""
import hashlib
import json
import re
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

    def test_ssh_transport_manifest_matches_lf_stable_public_inputs(self):
        expected_names = {
            "sshd-alertmind.conf",
            "ssh-authorized-key-options.txt",
        }
        recorded = {}
        for line in (RBAC_DIR / "SSH-SHA256SUMS").read_text(
            encoding="ascii"
        ).splitlines():
            digest, name = line.split(maxsplit=1)
            recorded[name] = digest

        self.assertEqual(set(recorded), expected_names)
        for name, expected_digest in recorded.items():
            payload = (RBAC_DIR / name).read_bytes()
            self.assertNotIn(b"\r\n", payload)
            self.assertTrue(payload.endswith(b"\n"))
            self.assertEqual(hashlib.sha256(payload).hexdigest(), expected_digest)

    def test_sshd_dropin_is_host_only_public_key_only_and_sessionless(self):
        lines = [
            line.strip()
            for line in (RBAC_DIR / "sshd-alertmind.conf").read_text(
                encoding="utf-8"
            ).splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertEqual(
            lines,
            [
                "Port 22",
                "AddressFamily inet",
                "ListenAddress 192.168.56.102",
                "HostKey /etc/ssh/ssh_host_ed25519_key",
                "PermitRootLogin no",
                "PubkeyAuthentication yes",
                "PasswordAuthentication no",
                "KbdInteractiveAuthentication no",
                "AuthenticationMethods publickey",
                "PermitEmptyPasswords no",
                "AuthorizedKeysFile .ssh/authorized_keys",
                "AllowUsers notroot@192.168.56.1",
                "X11Forwarding no",
                "AllowAgentForwarding no",
                "AllowStreamLocalForwarding no",
                "GatewayPorts no",
                "PermitTunnel no",
                "PermitUserEnvironment no",
                "PermitUserRC no",
                "AllowTcpForwarding no",
                "PermitOpen none",
                "ForceCommand /bin/false",
                "PermitTTY no",
                "MaxSessions 0",
                "Match User notroot Address 192.168.56.1",
                "AllowTcpForwarding local",
                "PermitOpen 127.0.0.1:9200",
                "ForceCommand /bin/false",
                "PermitTTY no",
                "MaxSessions 0",
                "Match all",
            ],
        )
        serialized = "\n".join(lines)
        for forbidden in (
            "ListenAddress 0.0.0.0",
            "ListenAddress 10.0.2.15",
            "ListenAddress ::",
            "HostKey /etc/ssh/ssh_host_rsa_key",
            "HostKey /etc/ssh/ssh_host_ecdsa_key",
            "PasswordAuthentication yes",
            "KbdInteractiveAuthentication yes",
            "AllowTcpForwarding yes",
            "PermitOpen any",
            "AllowUsers *",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_ssh_authorized_key_prefix_has_no_key_and_is_doubly_bounded(self):
        prefix = (RBAC_DIR / "ssh-authorized-key-options.txt").read_text(
            encoding="ascii"
        ).strip()
        self.assertEqual(
            prefix,
            'from="192.168.56.1",restrict,port-forwarding,'
            'permitopen="127.0.0.1:9200",command="/bin/false"',
        )
        for forbidden in (
            "ssh-ed25519",
            "ssh-rsa",
            "AAA",
            "PRIVATE KEY",
            "permitopen=\"*",
            "from=\"*",
        ):
            self.assertNotIn(forbidden, prefix)

    def test_ssh_runbook_keeps_install_inert_and_proves_before_enable(self):
        runbook = (
            REPO_ROOT / "docs" / "runbooks" /
            "rbac-wazuh-ssh-transport.md"
        ).read_text(encoding="utf-8")
        normalized = " ".join(runbook.split())
        for required in (
            "do not execute until an independent reviewer approves",
            "Do not run `apt autoremove`",
            "openssh-server=1:10.2p1-2ubuntu3.5",
            "openssh-sftp-server=1:10.2p1-2ubuntu3.5",
            "apt-get --simulate install --no-install-recommends",
            "send the complete simulation output for review",
            "--no-install-recommends",
            "ln -s /dev/null",
            "ssh.service ssh.socket",
            "both SSH activation paths remained inert",
            "sshd.service: masked alias; no active sshd@ instance",
            "hostkey /etc/ssh/ssh_host_ed25519_key",
            "host-key policy: exactly one effective ED25519 key",
            "sshd -T -C",
            "user=notroot,host=wazuh-siem,addr=192.168.56.1",
            "user=root,host=wazuh-siem,addr=192.168.56.1",
            "allowtcpforwarding local",
            "STOP POINT: do not unmask or enable SSH",
            "ssh.socket remains masked",
            "expected exactly one ED25519 key record",
            "Git for Windows OpenSSH 10.2 scanner",
            "ssh-keyscan.exe",
            "-q -T 10 -p 22 -t ed25519",
            "KexAlgorithms=curve25519-sha256",
            "HostKeyAlgorithms=ssh-ed25519",
            "StrictHostKeyChecking=yes",
            "UserKnownHostsFile=$KnownHosts",
            "127.0.0.1:19200:127.0.0.1:9200",
            "Windows PowerShell 5.1 returns a single matching CIM instance as a scalar",
            "normalize the result with `@(...)` before checking `Count`",
            "a `STOP` invalidates the proof and the trailing PASS must not be entered separately",
            "--ssl-revoke-best-effort",
            "expected hostname mismatch exit 60",
            "Curl exit 60 is a generic peer-certificate authentication failure",
            "negative leg alone does not isolate hostname verification",
            "same tunnel, CA and revocation policy",
            "PASS TLS negative leg: peer authentication rejected with curl exit 60",
            "PASS TLS positive leg: correct certificate identity 127.0.0.1 accepted",
            "Only when both PASS lines are present",
            "If the negative leg returns 60 but the positive leg fails, hostname verification has not been isolated.",
            "PowerShell removed its embedded field-name quotes",
            "HTTP 400 `json_parse_exception` at column 2",
            "temporary UTF-8 file without a byte-order mark",
            "pass curl an `@file` argument instead",
            "The `finally` block removes that file on both success and failure",
            "Paste and execute this entire invoked script block as one unit",
            "Do not merge native stderr into the success stream with `2>&1`",
            "terminate this invoked block before it can inspect curl's expected exit code",
            "The wrapper deliberately does not set `$ErrorActionPreference = 'Stop'`",
            "These denial wrappers do not set `$ErrorActionPreference = 'Stop'`",
            "An explicit `throw` still exits the complete invoked block",
            "prevents every later denial or PASS in that block from running",
            "diagnostic log removed",
            "variables created inside the foreground wrapper do not escape its child scope",
            "Paste every PowerShell fence that starts with `& {` as one complete unit",
            "Never re-enter statements from the remainder of a block after a STOP",
            "accepts unknown revocation status on every use for the life of the chain",
            "not a transient outage",
            "Never substitute `--ssl-no-revoke`, `--insecure` or `-k`",
            "administratively prohibited",
            "authentication failure as a forwarding-policy proof",
            "Immediate rollback",
            "packages remain inert",
        ):
            self.assertIn(required, normalized)
        self.assertNotIn("allowtcpforwarding yes", normalized)

        powershell_blocks = re.findall(
            r"```powershell\n(.*?)\n```",
            runbook,
            flags=re.DOTALL,
        )

        def proof_block(marker):
            matches = [block for block in powershell_blocks if marker in block]
            self.assertEqual(len(matches), 1, marker)
            return matches[0]

        key_generation = proof_block("STOP: dedicated tunnel key already exists")
        host_key_pinning = proof_block("$ScanExit = $LASTEXITCODE")
        listener_proof = proof_block(
            "Get-NetTCPConnection -State Listen -LocalPort 19200"
        )
        ca_proof = proof_block("$Fingerprint = (& $OpenSsl")
        mismatch_proof = proof_block("$MismatchExit = $LASTEXITCODE")
        positive_proof = proof_block("$ResponseText = @(")
        denial_matrix = proof_block("$ShellExit = $LASTEXITCODE")
        alternate_setup = proof_block("STOP: diagnostic port 19201 is already in use")
        alternate_verifier = proof_block("$Denied = Select-String")
        password_denial = proof_block("$PasswordExit = $LASTEXITCODE")

        self.assertEqual(len(powershell_blocks), 13)
        throwing_blocks = [
            block for block in powershell_blocks
            if re.search(r"(?m)^\s*throw ", block)
        ]
        self.assertEqual(len(throwing_blocks), 10)
        for throwing_block in throwing_blocks:
            self.assertTrue(throwing_block.startswith("& {\n"))
            self.assertTrue(throwing_block.rstrip().endswith("}"))

        for atomic_proof in (
            listener_proof,
            ca_proof,
            mismatch_proof,
            positive_proof,
        ):
            self.assertTrue(atomic_proof.startswith("& {\n"))
            self.assertTrue(atomic_proof.rstrip().endswith("}"))
            self.assertIn("$ErrorActionPreference = 'Stop'", atomic_proof)

        for additional_atomic_proof in (
            key_generation,
            host_key_pinning,
            denial_matrix,
            alternate_setup,
            alternate_verifier,
            password_denial,
        ):
            self.assertTrue(additional_atomic_proof.startswith("& {\n"))
            self.assertTrue(additional_atomic_proof.rstrip().endswith("}"))

        for stderr_compatible_proof in (
            host_key_pinning,
            denial_matrix,
            alternate_setup,
            password_denial,
        ):
            self.assertNotIn(
                "$ErrorActionPreference = 'Stop'",
                stderr_compatible_proof,
            )

        for pass_block in (
            block for block in powershell_blocks if "PASS " in block
        ):
            self.assertTrue(pass_block.startswith("& {\n"))
            self.assertTrue(pass_block.rstrip().endswith("}"))

        self.assertIn("$Listener = @(", listener_proof)
        self.assertIn("Set-Location .\\assistant -ErrorAction Stop", key_generation)
        self.assertIn("-Force -ErrorAction Stop | Out-Null", key_generation)
        self.assertIn("Set-Content -LiteralPath $Candidate", host_key_pinning)
        self.assertIn("Move-Item -LiteralPath $Candidate", host_key_pinning)
        self.assertGreaterEqual(host_key_pinning.count("-ErrorAction Stop"), 2)
        for tls_proof in (mismatch_proof, positive_proof):
            self.assertIn("--cacert $Ca --ssl-revoke-best-effort", tls_proof)
            self.assertIn("--noproxy '*'", tls_proof)
            self.assertNotIn("--ssl-no-revoke", tls_proof)
            self.assertNotIn("--insecure", tls_proof)
            self.assertNotIn(" -k", tls_proof)
        self.assertIn("$MismatchExit -ne 60", mismatch_proof)
        self.assertNotIn("2>&1", mismatch_proof)
        self.assertIn("ConvertFrom-Json", positive_proof)
        self.assertIn("$Metadata._shards.failed", positive_proof)
        self.assertIn("$Metadata.hits.total.value", positive_proof)
        self.assertIn("$FailedShards -ne 0", positive_proof)
        self.assertIn(
            "$QueryJson = "
            "'{\"size\":0,\"query\":{\"terms\":{\"agent.id\":[\"001\",\"002\"]}}}'",
            positive_proof,
        )
        self.assertIn(
            "$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)",
            positive_proof,
        )
        self.assertIn(
            "[System.IO.File]::WriteAllText($QueryFile, $QueryJson, $Utf8NoBom)",
            positive_proof,
        )
        self.assertIn('$BodyArgument = "@$QueryFile"', positive_proof)
        self.assertIn("--data-binary $BodyArgument", positive_proof)
        self.assertIn("} finally {", positive_proof)
        self.assertIn("Remove-Item -LiteralPath $QueryFile -Force", positive_proof)
        self.assertNotIn("--data-binary '{", positive_proof)
        self.assertLess(
            positive_proof.index("$CurlExit -ne 0"),
            positive_proof.index("$Metadata = $ResponseText"),
        )
        self.assertNotIn("2>&1", positive_proof)
        self.assertIn("$ShellOutput", denial_matrix)
        self.assertIn("$PtyOutput", denial_matrix)
        self.assertIn("$RemoteOutput", denial_matrix)
        self.assertEqual(denial_matrix.count("2>&1"), 3)
        self.assertIn("STOP: diagnostic port 19201 is already in use", alternate_setup)
        self.assertIn("STOP: prior diagnostic log exists", alternate_setup)
        self.assertIn("-Force -ErrorAction Stop | Out-Null", alternate_setup)
        self.assertIn("2>&1 | Tee-Object", alternate_setup)
        self.assertIn("Tee-Object -LiteralPath $AltLog -ErrorAction Stop", alternate_setup)
        self.assertIn("$Runtime = Join-Path (Get-Location) '.runtime'", alternate_verifier)
        self.assertIn(
            "$AltLog = Join-Path $Runtime 'ssh-alternate-destination.log'",
            alternate_verifier,
        )
        self.assertIn("STOP: alternate-destination diagnostic log is absent", alternate_verifier)
        self.assertGreaterEqual(alternate_verifier.count("-ErrorAction Stop"), 2)
        self.assertLess(
            alternate_verifier.index("Remove-Item -LiteralPath $AltLog"),
            alternate_verifier.index("PASS denied alternate local destination"),
        )
        self.assertIn("2>&1", password_denial)
        self.assertNotIn(
            "PASS TLS hostname mismatch rejected with curl exit 60",
            runbook,
        )

        plan = (
            REPO_ROOT / "docs" / "rbac-wazuh-read-only-implementation-plan.md"
        ).read_text(encoding="utf-8")
        plan_normalized = " ".join(plan.split())
        for required in (
            "permanent for this chain rather than a transient outage",
            "accepts unknown revocation status on every use for the life of the chain",
            "revocation check provides no protection here",
            "does not settle the later application's certificate-chain or Python-context decision",
            "Windows PowerShell 5.1 behaviours",
            "normalized with `@(...)` before its count is checked",
            "JSON is never supplied to native curl as an inline argument",
            "HTTP 400 with a `json_parse_exception` at column 2",
            "written as UTF-8 without a byte-order mark",
            "passed with curl's `@file` form and removed in `finally`",
            "Each listener, CA and TLS proof is one invoked script block",
            "a `STOP` cannot fall through to a later PASS",
            "leaves native stderr unmerged",
            "`2>&1` converts native stderr into an error record",
            "observes curl's native exit code directly",
            "atomic-block rule applies to every PowerShell sequence that can throw and then continue",
            "including key generation, host-key pinning and every SSH denial or denial precondition",
            "do not set `$ErrorActionPreference = 'Stop'`",
            "an explicit `throw` still terminates the invoked block",
            "preserves its diagnostic log when the denial marker is absent",
            "removes it before emitting PASS",
            "verifier independently recomputes the fixed ignored log path",
            "variables from the foreground invoked block do not persist",
            "paste each invoked PowerShell fence as one complete unit",
            "must not re-enter remainder statements after a STOP",
        ):
            self.assertIn(required, plan_normalized)

        self.assertEqual(runbook.count("KexAlgorithms=curve25519-sha256"), 4)
        self.assertEqual(runbook.count("HostKeyAlgorithms=ssh-ed25519"), 4)

        control_start = runbook.index(
            "echo 'PASS host-key policy: exactly one effective ED25519 key'"
        )
        control_end = runbook.index(
            "if grep -Fxq 'allowtcpforwarding local' \"$CONTROL\"",
            control_start,
        )
        control_proof = runbook[control_start:control_end]
        for denial in (
            "allowtcpforwarding no",
            "permitopen none",
            "maxsessions 0",
            "permittty no",
            "forcecommand /bin/false",
        ):
            self.assertIn(f"'{denial}'", control_proof)
        self.assertIn('require_line "$CONTROL" "$line"', control_proof)

        simulation = runbook.index(
            "apt-get --simulate install --no-install-recommends"
        )
        mask = runbook.index("ln -s /dev/null")
        install = runbook.index("apt-get install --yes --no-install-recommends")
        target_proof = runbook.index("user=notroot,host=wazuh-siem")
        stop = runbook.index("STOP POINT: do not unmask or enable SSH")
        enable = runbook.index("sudo systemctl unmask ssh.service")
        self.assertLess(simulation, mask)
        self.assertLess(mask, install)
        self.assertLess(install, target_proof)
        self.assertLess(target_proof, stop)
        self.assertLess(stop, enable)

    def test_phase1c_prerequisite_records_clean_package_stop_point(self):
        evidence = (
            REPO_ROOT / "evidence" / "rbac" /
            "phase1c-ssh-prerequisite-check.md"
        ).read_text(encoding="utf-8")
        normalized = " ".join(evidence.split())
        for required in (
            "Postfix is absent",
            "without `autoremove`",
            "`dpkg --audit` produced no finding",
            "`openssh-server` remains not installed",
            "no TCP 22, 25, 465 or 587 listener exists",
            "Wazuh Manager, Indexer, Filebeat and Dashboard remain active",
            "No OpenSSH package, key, daemon configuration or listener has been installed or enabled",
        ):
            self.assertIn(required, normalized)

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
        normalized = " ".join(matrix.split())
        for required in (
            "existing concrete index and existing ID",
            "same positively read concrete index",
            "require `404`, not `403`",
            "doc_as_upsert:false",
            "no** `upsert` field",
            "isolates the denied update action",
            "isolates the denied delete action",
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
            self.assertIn(required, normalized)

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
            "Future reruns must use a concrete archive index when one exists",
            "did not demonstrate that alert content had been copied or that DLS had been bypassed",
            "returned `404`, not `403`, in the same positively read concrete index",
            "isolate denied write actions rather than an out-of-scope index boundary",
            "The original document hash was identical before and after all denials",
            "VERIFY_X509_STRICT",
            "disabled `VERIFY_X509_STRICT` wholesale",
            "this was not a targeted key-usage exception",
            "CERT_REQUIRED",
            "hostname verification",
            "This is not authority to disable TLS verification",
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
