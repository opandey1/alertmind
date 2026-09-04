#!/usr/bin/env python3
"""Offline contract tests for the secret-free Phase 1 Wazuh RBAC package."""
import hashlib
import importlib.util
import io
import json
import re
import unittest
from unittest import mock
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

    def test_phase1c_rotation_helper_and_rollback_drill_are_fail_closed(self):
        helper_name = "build_assistant_svc_rotation_payload.py"
        helper_path = RBAC_DIR / helper_name
        manifest_path = RBAC_DIR / "ROLLBACK-SHA256SUMS"
        manifest = manifest_path.read_bytes()
        self.assertNotIn(b"\r\n", manifest)
        self.assertTrue(manifest.endswith(b"\n"))
        recorded_digest, recorded_name = manifest.decode("ascii").strip().split()
        self.assertEqual(recorded_name, helper_name)
        self.assertEqual(
            hashlib.sha256(helper_path.read_bytes()).hexdigest(),
            recorded_digest,
        )

        helper_source = helper_path.read_text(encoding="utf-8")
        for required in (
            "getpass.getpass",
            "require_pipe_output()",
            "stat.S_ISFIFO(output_mode)",
            'warnings.simplefilter("error", getpass.GetPassWarning)',
            "replacement_password == current_password",
            '"password": replacement_password',
            '"backend_roles": []',
            '"opendistro_security_roles": []',
            '"attributes": {}',
            "json.dump(",
            "sys.stdout",
        ):
            self.assertIn(required, helper_source)
        for forbidden in (
            "os.environ",
            "argparse",
            "tempfile",
            "subprocess",
            "open(",
            "Path(",
        ):
            self.assertNotIn(forbidden, helper_source)

        spec = importlib.util.spec_from_file_location(
            "alertmind_rotation_payload", helper_path
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        output = io.StringIO()
        with mock.patch.object(module, "require_pipe_output"), mock.patch.object(
            module.getpass,
            "getpass",
            side_effect=["current-secret", "replacement-secret", "replacement-secret"],
        ), mock.patch.object(module.sys, "stdout", output):
            self.assertEqual(module.main(), 0)
        self.assertEqual(
            json.loads(output.getvalue()),
            {
                "password": "replacement-secret",
                "backend_roles": [],
                "opendistro_security_roles": [],
                "attributes": {},
            },
        )
        for answers, message in (
            (["", "replacement", "replacement"], "current password"),
            (["current", "", ""], "replacement password"),
            (["current", "one", "two"], "confirmation differs"),
            (["same", "same", "same"], "must differ"),
        ):
            failed_output = io.StringIO()
            with mock.patch.object(module, "require_pipe_output"), mock.patch.object(
                module.getpass, "getpass", side_effect=answers
            ), mock.patch.object(module.sys, "stdout", failed_output), \
                    self.assertRaisesRegex(SystemExit, message):
                module.main()
            self.assertEqual(failed_output.getvalue(), "")

        fake_stdout = mock.Mock()
        fake_stdout.fileno.return_value = 1
        for mode in (0o100000, 0o020000):  # Regular file, character device/TTY.
            with mock.patch.object(module.sys, "stdout", fake_stdout), \
                    mock.patch.object(module.os, "fstat", return_value=mock.Mock(st_mode=mode)), \
                    mock.patch.object(module.getpass, "getpass") as prompt, \
                    self.assertRaisesRegex(SystemExit, "pipe, not a terminal or file"):
                module.main()
            prompt.assert_not_called()
        with mock.patch.object(module.sys, "stdout", fake_stdout), \
                mock.patch.object(module.os, "fstat", return_value=mock.Mock(st_mode=0o010000)):
            module.require_pipe_output()
        with mock.patch.object(module, "require_pipe_output"), mock.patch.object(
            module.getpass, "getpass", side_effect=module.getpass.GetPassWarning
        ), self.assertRaisesRegex(SystemExit, "private terminal prompt"):
            module.main()

        runbook_path = (
            REPO_ROOT / "docs" / "runbooks" /
            "rbac-phase1c-rollback-revocation-drill.md"
        )
        runbook = runbook_path.read_text(encoding="utf-8")
        normalized = " ".join(runbook.split())
        for required in (
            "Secret-free drill package; not yet executed",
            "must receive independent review before the owner runs Stage 1",
            "no implemented profile to disable or restore",
            "cannot establish rollback of the future OIDC/application/live-reader layer",
            "The drill is probe-free",
            "The only Indexer mutations are deletion/restoration of the one service mapping",
            "the scoped `own_index` mapping do not change",
            "`socanalyst` user/mapping and the scoped `own_index` mapping do not change",
            "The safe failure state is",
            "remain in that disabled state",
            "must never be redirected, inspected, copied or logged",
            "PASS old assistant-svc credential rejected after deletion: HTTP 401",
            "PASS old assistant-svc credential remains rejected after recreation: HTTP 401",
            "PASS replacement credential authenticates with zero effective roles",
            "PASS exact restored mapping: assistant-svc only",
            "PASS revoked SSH key denied by server",
            "a generic nonzero exit is insufficient",
            "The replacement key must complete the positive local forward",
            "deletion is revocation hygiene, not a claim of forensic erasure",
            "wazuh-indexer wazuh-manager filebeat wazuh-dashboard",
            "Do not overwrite the template",
            "must not call `securityadmin.sh`",
        ):
            self.assertIn(required, normalized)

        ordered_markers = (
            "## 4. Stage 1 — read-only preflight",
            "## 5. Stage 2 — prepare the replacement SSH key",
            "## 6. Stage 3 — disable the live transport",
            "## 7. Stage 4 — revoke and rotate `assistant-svc`",
            "### 7.1 Remove the mapping, then delete the user",
            "PASS old assistant-svc credential rejected after deletion: HTTP 401",
            "### 7.2 Recreate with a distinct password and no direct grant",
            "PASS old assistant-svc credential remains rejected after recreation: HTTP 401",
            "PASS replacement credential authenticates with zero effective roles",
            "### 7.3 Restore the reviewed direct-user mapping",
            "PASS replacement assistant-svc effective role is exact",
            "## 8. Stage 5 — restore SSH with the replacement client key",
            "## 9. Stage 6 — prove old-key denial and replacement-key success",
            "### 9.1 Deny the old SSH key",
            "### 9.2 Start a tunnel with the replacement key",
            "### 9.3 Promote the replacement key only after all proofs pass",
            "## 10. Final state and evidence",
        )
        positions = [runbook.index(marker) for marker in ordered_markers]
        self.assertEqual(positions, sorted(positions))

        rotation_section = runbook[
            runbook.index("### 7.2 Recreate with a distinct password"):
            runbook.index("### 7.3 Restore the reviewed direct-user mapping")
        ]
        self.assertIn(
            'python3 "$DRILL_STAGE/build_assistant_svc_rotation_payload.py" |',
            rotation_section,
        )
        self.assertIn('"--request","PUT","--data-binary","@-"', rotation_section)
        consumers = re.findall(
            r"python3 -c '\n(import json,subprocess,sys\n.*?)\n'",
            rotation_section, re.DOTALL,
        )
        self.assertEqual(len(consumers), 1)
        consumer = compile(consumers[0], "<rotation-pipe-consumer>", "exec")
        # Validate the real documented consumer, with no sudo/curl process run.
        valid_payload = {
            "password": 'synthetic-"quoted"-value',
            "backend_roles": [],
            "opendistro_security_roles": [],
            "attributes": {},
        }
        with mock.patch("sys.stdin", io.StringIO(json.dumps(valid_payload))), \
                mock.patch("subprocess.run", return_value=mock.Mock(returncode=0)) as send, \
                self.assertRaises(SystemExit) as finished:
            exec(consumer, {})
        self.assertEqual(finished.exception.code, 0)
        arguments = send.call_args.args[0]
        self.assertEqual(arguments[:5], ["sudo", "curl", "--disable", "--noproxy", "*"])
        self.assertEqual(
            arguments[-1],
            "https://127.0.0.1:9200/_plugins/_security/api/internalusers/assistant-svc",
        )
        self.assertEqual(arguments[arguments.index("--data-binary")+1], "@-")
        self.assertNotIn(valid_payload["password"], " ".join(arguments))
        self.assertEqual(json.loads(send.call_args.kwargs["input"]), valid_payload)
        self.assertFalse(send.call_args.kwargs.get("shell", False))
        for invalid in (
            "", "{", "[]", "{}",
            json.dumps({**valid_payload, "password": ""}),
            json.dumps({**valid_payload, "password": 1}),
            json.dumps({**valid_payload, "backend_roles": ["admin"]}),
            json.dumps({**valid_payload, "opendistro_security_roles": ["all_access"]}),
            json.dumps({**valid_payload, "attributes": {"unexpected": "value"}}),
            json.dumps({**valid_payload, "extra": "value"}),
        ):
            with mock.patch("sys.stdin", io.StringIO(invalid)), \
                    mock.patch("subprocess.run") as send, \
                    self.assertRaisesRegex(SystemExit, "no request sent"):
                exec(consumer, {})
            send.assert_not_called()
        with mock.patch("sys.stdin", io.StringIO(json.dumps(valid_payload))), \
                mock.patch("subprocess.run", return_value=mock.Mock(returncode=22)), \
                self.assertRaises(SystemExit) as failed:
            exec(consumer, {})
        self.assertEqual(failed.exception.code, 22)
        self.assertIn("expected absent resource before recreation", rotation_section)
        self.assertLess(
            rotation_section.index("expected absent resource before recreation"),
            rotation_section.index('python3 "$DRILL_STAGE/build_assistant_svc_rotation_payload.py" |'),
        )
        self.assertIn('test "$status" = \'201\'', rotation_section)
        for forbidden in (
            "tee ",
            "PASSWORD=",
            "export PASSWORD",
            "--user assistant-svc:",
            "--data-binary '{\"password\"",
            "securityadmin.sh",
        ):
            self.assertNotIn(forbidden, rotation_section)

        revoke_section = runbook[
            runbook.index("### 7.1 Remove the mapping"):
            runbook.index("### 7.2 Recreate with a distinct password")
        ]
        self.assertLess(
            revoke_section.index(
                "rolesmapping/alertmind_assistant_alerts_ro"
            ),
            revoke_section.index("internalusers/assistant-svc"),
        )
        self.assertNotRegex(
            revoke_section,
            r"--request DELETE[^\n]*(?:\n[^\n]*){0,8}(?:socanalyst|own_index)",
        )
        self.assertNotIn(
            "indexer-role-mapping_own_index_rollback.patch.json", runbook
        )
        for required in (
            "## 11. Stop conditions and containment",
            "Stopping a failing script does not itself undo",
            "PASS containment: service user authenticates with zero effective roles",
            "Offering public key:.*SHA256:",
            "(Authenticated to|Server accepts key:)",
            "IdentityAgent=none",
            "own_index",
            "First repeat the entire VM/Indexer preflight in Section 4.2",
            "canonical key path, which still refers to the old key",
            "if [ \"$state\" != 'active' ]; then",
            "STOP service health:",
        ):
            self.assertIn(required, runbook)
        self.assertNotIn("sudo systemctl is-active \\", runbook)
        self.assertNotIn("\n! systemctl is-active", runbook)
        for line in runbook.splitlines():
            if "sudo curl " in line:
                self.assertIn("sudo curl --disable --noproxy '*'", line)
        # Compile embedded Python without executing any VM or credential path.
        for source in re.findall(r"python3 -c '([^']*)'", runbook, re.DOTALL):
            compile(source, "<rollback-runbook-python>", "exec")

        template = (
            REPO_ROOT / "evidence" / "rbac" /
            "phase1c-rollback-revocation-proof-template.md"
        ).read_text(encoding="utf-8")
        template_normalized = " ".join(template.split())
        for required in (
            "Unexecuted template. This file is not evidence that the drill ran",
            "must say no live analyst/Wazuh profile existed",
            "Old service password rejected after deletion",
            "Old password rejected after recreation",
            "Old SSH key denied with no authentication marker",
            "Allowed conclusion after independent approval",
            "**Not established:** application-profile rollback",
            "do not claim forensic erasure",
        ):
            self.assertIn(required, template_normalized)
        for forbidden in (
            "BEGIN PRIVATE KEY",
            "Authorization: Basic",
            '"password":',
            '"hash":',
        ):
            self.assertNotIn(forbidden, runbook)
            self.assertNotIn(forbidden, template)

        siem_readme = (RBAC_DIR / "README.md").read_text(encoding="utf-8")
        self.assertIn(
            "Executed and independently reviewed Phase 1C transport inputs",
            siem_readme,
        )
        self.assertIn("Unexecuted Phase 1C rollback/revocation inputs", siem_readme)
        self.assertNotIn("OpenSSH remains uninstalled", siem_readme)
        self.assertNotIn("Unexecuted Phase 1C transport inputs", siem_readme)

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
            "independently approved and merged through PR #16 at `0ebc665`",
            "not authority to repeat or alter the transport without a new review",
            "rollback/revocation drill remains pending",
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
            "leaves OpenSSL's native stderr unmerged",
            "explicit native exit-code check remains reachable",
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
            self.assertNotIn("2>&1", atomic_proof)
            self.assertNotIn("2>$null", atomic_proof)

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
        self.assertIn("$OpenSslExit = $LASTEXITCODE", ca_proof)
        self.assertIn("if ($OpenSslExit -ne 0)", ca_proof)
        self.assertIn("see native diagnostic above", ca_proof)
        self.assertLess(
            ca_proof.index("if ($OpenSslExit -ne 0)"),
            ca_proof.index("$Fingerprint -notmatch"),
        )
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
            "CA fingerprint proof follows the same native-command boundary",
            "leaves OpenSSL native stderr unmerged",
            "checks `$LASTEXITCODE` before parsing that output",
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

    def test_phase1c_evidence_records_prerequisite_and_bounded_live_proof(self):
        prerequisite = (
            REPO_ROOT / "evidence" / "rbac" /
            "phase1c-ssh-prerequisite-check.md"
        ).read_text(encoding="utf-8")
        normalized = " ".join(prerequisite.split())
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

        proof = (
            REPO_ROOT / "evidence" / "rbac" /
            "phase1c-ssh-transport-proof.md"
        ).read_text(encoding="utf-8")
        proof_normalized = " ".join(proof.split())

        manifest_hashes = {}
        for line in (RBAC_DIR / "SSH-SHA256SUMS").read_text(
            encoding="ascii"
        ).splitlines():
            digest, name = line.split(maxsplit=1)
            manifest_hashes[name] = digest
        evidence_hashes = dict(re.findall(
            r"^\| `([^`]+)` \| `([0-9a-f]{64})` \|$",
            proof,
            flags=re.MULTILINE,
        ))
        self.assertEqual(evidence_hashes, manifest_hashes)

        for required in (
            "Sanitized owner-executed live proof, independently reviewed",
            "approved and merged through PR #16 at `0ebc665`",
            "it does not claim application integration or completion of Phase 1C",
            "accepted final proof was run from merged `main` at `7d0d6dc`",
            "one IPv4 listener at `192.168.56.102:22`",
            "only `ssh.service` was unmasked and enabled; `ssh.socket` remained masked",
            "SHA256:+DDAvCldN5xpP0spEP3ClVsmhnhhQtcvJpD3GRyTaDo",
            "SHA256:vfpeVCeBJ6AVO0lcvoN0bpIUwXkX6N2n7hZ7asBJ1Ag",
            "EB98A4AF38CDA550D473E5659A4375905334041FAB4597F39C4F191D9E6F5E1D",
            "`127.0.0.1:19200` → host-only SSH → VM `127.0.0.1:9200`",
            "`alertmind-hostname-check.invalid`",
            "curl exit `60`",
            "negative leg deliberately failed before HTTP and sent no credential or query",
            "`failed_shards=0`, `visible_hits=10000`, `relation=gte`",
            "`10000` is a lower bound, not an exact corpus or Indexer total",
            "requested no `_source` and returned no raw alert",
            "`--ssl-revoke-best-effort`",
            "received no effective revocation protection",
            "No `--ssl-no-revoke`, `--insecure` or `-k` bypass was used",
            "Shell/command execution | denied; Windows wrapper exit `-1`; marker absent",
            "PTY/session allocation | denied; Windows wrapper exit `-1`; marker absent",
            "Remote forwarding | denied; SSH exit `255`",
            "alternate destination `127.0.0.1:443` | denied",
            "Password-only authentication | denied; SSH exit `255`; zero password prompts allowed",
            "The `-1` values are recorded as the observed Windows process-wrapper results, not generalized as portable SSH exit codes",
            "The difference between the observed `-1` and `255` results was not investigated",
            "The conclusion does not rely on exit-code parity",
            "matrix is not a vacuous authentication-failure test",
            "All four Wazuh services remained active after the matrix",
            "initial positive TLS request that returned HTTP `400`",
            "including all null-derived statements entered after that stop",
            "closes the transport evidence gate but does not complete Phase 1C",
            "rollback/revocation drill remains pending",
            "No live alert was sent through the LLM assistant",
        ):
            self.assertIn(required, proof_normalized)

        reader_status = {
            "README.md": (REPO_ROOT / "README.md").read_text(encoding="utf-8"),
            "assistant/README.md": (
                REPO_ROOT / "assistant" / "README.md"
            ).read_text(encoding="utf-8"),
            "architecture/soc-architecture.md": (
                REPO_ROOT / "architecture" / "soc-architecture.md"
            ).read_text(encoding="utf-8"),
            "evidence/rbac/README.md": (
                REPO_ROOT / "evidence" / "rbac" / "README.md"
            ).read_text(encoding="utf-8"),
            "setup runbook": (
                REPO_ROOT / "docs" / "runbooks" /
                "rbac-wazuh-read-only-setup.md"
            ).read_text(encoding="utf-8"),
            "SSH runbook": (
                REPO_ROOT / "docs" / "runbooks" /
                "rbac-wazuh-ssh-transport.md"
            ).read_text(encoding="utf-8"),
            "implementation plan": (
                REPO_ROOT / "docs" /
                "rbac-wazuh-read-only-implementation-plan.md"
            ).read_text(encoding="utf-8"),
        }
        normalized_status = {
            name: " ".join(text.split())
            for name, text in reader_status.items()
        }
        for name, text in normalized_status.items():
            self.assertIn("PR #16", text, name)
            self.assertIn("rollback/revocation drill", text, name)

        self.assertIn(
            "Implemented and independently reviewed — restricted transport",
            reader_status["README.md"],
        )
        self.assertIn(
            "Phase 0 inventory captured before the Phase 1C transport",
            normalized_status["setup runbook"],
        )
        self.assertIn(
            "Phase 1C transport package — executed and evidenced",
            reader_status["setup runbook"],
        )
        self.assertIn(
            "does not retrieve live Wazuh alerts",
            normalized_status["assistant/README.md"],
        )

        stale_status = {
            "README.md": (
                "Live-proven, evidence review pending",
                "sanitized evidence is not yet committed or independently reviewed",
            ),
            "assistant/README.md": ("only `admin` exists today",),
            "setup runbook": (
                "The Phase 1C SSH transport remains disabled",
                "review of the unexecuted Phase 1C SSH package",
                "Phase 1C transport package — not yet executed",
            ),
            "SSH runbook": ("do not execute until an independent reviewer",),
        }
        for name, phrases in stale_status.items():
            for phrase in phrases:
                self.assertNotIn(phrase, reader_status[name], name)

        for forbidden in (
            "BEGIN PRIVATE KEY",
            "Authorization: Basic",
            '"_source":',
            "PID 41780",
            "PID 17632",
        ):
            self.assertNotIn(forbidden, proof)

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
            "independently reviewed and merged through PR #10 at `f20800d`",
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
