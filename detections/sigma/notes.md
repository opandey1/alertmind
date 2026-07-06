# Sigma rule pack — notes & Sigma → Wazuh crosswalk

This directory holds the **portable, source-of-truth detections** for AlertMind, authored in Sigma. The deployed, SIEM-native form is `siem/wazuh/local_rules.xml` (Linux) plus Wazuh's built-in ruleset (Windows). This file documents the pack and maps each Sigma rule to its Wazuh implementation and verification status.

- **25 rules** — 8 Windows, 17 Linux.
- **All 25 validate** against the Sigma spec (`pysigma` / `SigmaCollection.from_yaml`).
- **Coverage:** all five tactics named in the brief (initial access, execution, persistence, lateral movement, exfiltration) plus credential access, defense evasion, privilege escalation, and command-and-control.

## Authoring model & why translation is manual

Wazuh does **not** natively consume Sigma, and the `sigma-cli`/pySigma Wazuh backend is immature, so rules are **hand-translated** to Wazuh XML (instructor-approved). The translation is deterministic per platform:

- **Linux (auditd).** The Sigma rule matches the auditd **`key`** field. That key is set by the watch/syscall rules in `detections/auditd/alertmind.rules` — i.e. the key is the *contract* between the collection policy (which paths/syscalls to watch) and the alerting layer. The Wazuh rule matches the same key via `<field name="audit.key">…</field>`, chained off base rule **80700** with `<if_sid>`. Sigma `key` ↔ Wazuh `audit.key` is a clean 1:1 map. *(Portability note: on an environment without these specific keys, each rule's intent is recoverable from its title/description — the underlying path/syscall — and could be re-expressed against raw auditd fields.)*
- **Windows.** Sigma rules match standard Sysmon / Windows event-log fields. Some map to Wazuh **built-in** rules (e.g. service creation → rule 61138); the rest are authored as custom Wazuh rules or rely on Wazuh's Sysmon eventchannel ruleset.

## Status key
✅ Verified (alert observed in Wazuh, evidence captured) · 🟡 Configured (telemetry + rule path in place, individual test pending) · ⏳ Planned (designed; Wazuh side not yet built)

## Crosswalk — Linux (auditd)

Every Linux Sigma rule maps to a deployed Wazuh rule in `siem/wazuh/local_rules.xml` — directly via the auditd `key` for all but rule 100116, which is a Wazuh child rule (see caveats).

| Sigma file | ATT&CK | Wazuh rule | Status |
|---|---|---|---|
| `lnx_t1003_008_shadow_read.yml` | T1003.008 | 100100 | ✅ (EVID-LIN-002) |
| `lnx_t1136_accounts.yml` | T1136 / T1098 | 100101 | 🟡 |
| `lnx_t1548_003_sudoers.yml` | T1548.003 | 100102 | 🟡 |
| `lnx_t1053_003_cron.yml` | T1053.003 | 100103 | 🟡 |
| `lnx_t1543_002_systemd.yml` | T1543.002 | 100104 | 🟡 |
| `lnx_t1037_init.yml` | T1037 | 100105 | 🟡 |
| `lnx_t1546_004_shell_init.yml` | T1546.004 | 100106 | 🟡 |
| `lnx_t1574_006_ldpreload.yml` | T1574.006 | 100107 | 🟡 |
| `lnx_t1547_006_kmod.yml` | T1547.006 / T1014 | 100108 | 🟡 |
| `lnx_t1548_001_setuid.yml` | T1548.001 / T1222.002 | 100109 | 🟡 |
| `lnx_t1562_001_audit_tamper.yml` | T1562.001 | 100110 | 🟡 |
| `lnx_t1070_logs.yml` | T1070 | 100111 | 🟡 |
| `lnx_t1070_006_timestomp.yml` | T1070.006 | 100112 | 🟡 |
| `lnx_t1552_004_ssh_keys.yml` | T1552.004 | 100113 | 🟡 |
| `lnx_ssh_daemon_config_change.yml` | T1098 *(broad; see caveats)* | 100114 | 🟡 |
| `lnx_apt_repo_config.yml` | T1195.001 *(tentative)* | 100115 | 🟡 |
| `lnx_t1098_004_authorized_keys.yml` | T1098.004 | 100116 *(child of 100113)* | ✅ (EVID-LIN-003) |

`alertmind.rules` also sets `t1059_exec`, but that key is intentionally **not** part of the levelled Linux alert pack. It is high-volume execution substrate telemetry reserved for future targeted command-pattern detections (suspicious `curl|bash`, reverse-shell commands, suspicious `chmod`/`chown`). Alerting on every `execve` event would create excessive noise. (`noise` is a suppression key and likewise not an alert.)

### Linux mapping caveats

- **`lnx_apt_repo_config.yml`** — APT-config tampering is not cleanly any single ATT&CK technique; mapped to **T1195.001 (tentative)** as the closest fit (the original T1105 mapping was wrong). Kept as a low-confidence hygiene monitor (Wazuh level 5).
- **`lnx_ssh_daemon_config_change.yml`** — watches `/etc/ssh/sshd_config`, which is useful SSH access-configuration telemetry but is **not** T1098.004 (that sub-technique is specifically `authorized_keys`). Mapped to the broad **T1098** as tentative. Precise T1098.004 coverage is provided separately by `lnx_t1098_004_authorized_keys.yml` (rule 100116).
- **`lnx_t1098_004_authorized_keys.yml`** — auditd cannot reliably key `authorized_keys` separately from the broad `/root/.ssh` watch: two overlapping watches collapse to one key, so an `authorized_keys` write is emitted under `t1552_004_ssh_keys`, not a dedicated key. The detection therefore matches the broad key **plus** the `authorized_keys` path, and the deployed Wazuh rule 100116 is a **child of 100113** (`<if_sid>100113</if_sid>` + path narrowing) rather than a direct `audit.key` rule. Because it chains off the broad `-p rwa` watch it can also catch *reads* of `authorized_keys` (e.g. a root key-based SSH login), but those are rare in the lab and already covered by 100113 — acceptable, and noted as a false positive in the rule.
- **`lnx_t1548_001_setuid.yml`** — detects chmod-family activity by interactive users; it does **not** itself confirm a setuid/setgid bit was set. Triage must verify the resulting mode. Broad permission changes are tagged T1222.002 alongside the T1548.001 intent.

## Crosswalk — Windows

| Sigma file | ATT&CK | Wazuh implementation | Status |
|---|---|---|---|
| `win_persistence_new_service_7045.yml` | T1543.003 | built-in rule 61138 | ✅ (EVID-WIN-002) |
| `win_initial_access_office_spawns_shell.yml` | T1566 / T1059 | rule 100200 (if_sid 61603, EID 1) | 🟡 deployed; Office/simulation dependency |
| `win_execution_powershell_encoded.yml` | T1059.001 | rule 100201 (if_sid 61603, EID 1) | ✅ (EVID-WIN-003) |
| `win_defense_evasion_lolbin_execution.yml` | T1218 | rule 100202 (if_sid 61603, EID 1) | ✅ (EVID-WIN-004) |
| `win_credential_access_lsass_access.yml` | T1003.001 | rule 100203 (if_sid 61612, EID 10) | ✅ (EVID-WIN-006) |
| `win_persistence_run_key.yml` | T1547.001 | rule 100205 (if_sid 92300, built-in Run-key parent) | ✅ (EVID-WIN-005)  |
| `win_lateral_movement_psexec_service.yml` | T1021.002 / T1569.002 | rule 100204 (if_sid 61603, EID 1) | 🟡 deployed; test pending |
| `win_exfiltration_dns_tunneling.yml` | T1048 / T1071.004 | rule 100206 (if_sid 61624, EID 22) | ⏳ heuristic; needs allowlist tuning |

**Testability note:** `win_initial_access_office_spawns_shell.yml` is portable Sigma coverage for malicious-macro behaviour, but validating it in the Win11 evaluation VM requires Office installed or a controlled simulation; status stays *configured* until a real event is captured.

### Windows tuning caveats

- **`100205` (Run-key)** — chaining off the built-in 92300 inherits a prefix match: 92300 matches `CurrentVersion\Run`, so it also matches `CurrentVersion\RunNotification` (a shell startup-notification key Windows writes *when* a Run key is added), producing a duplicate false-positive alert. Observed in testing (a single `reg add` fired 100205 twice). Fixed by re-narrowing 100205 with a `targetObject` filter (`CURRENTVERSION\\Run(Once)?\\`, in Wazuh's doubled-backslash format) so only genuine Run/RunOnce writes fire.
- **`100203` (LSASS)** — required three tuning rounds. (1) Untuned rule fired ~557 times on benign query-only reads (`0x1000`, AV/svchost). (2) Positive allowlist only covered `0x1xxx` masks and missed dump-grade `0x0xxx` masks like `0x0410`. (3) Final: negative exclusion on the three confirmed-benign masks (`0x1000`/`0x1400`/`0x3000`, none include `PROCESS_VM_READ`) plus sourceImage exclusion for `wazuh-agent.exe` and `MsMpEng.exe`. Verified on `rundll32.exe` at `0x1fffff` (comsvcs MiniDump, EVID-WIN-006). Lab pre-condition: `RunAsPPL=0`; with PPL the OS blocks dump-grade handles, though Sysmon may still log the denied access attempt.

## Hand-translation notes (per reproducibility requirement)

- **Linux 100100–100115:** direct translation — `<if_sid>80700</if_sid>` + `<field name="audit.key">{key}</field>` + `<mitre>` tag. No semantic loss.
- **Rule 100116 (authorized_keys) is the one exception** — it is *not* a direct `audit.key` translation. Overlapping `/root/.ssh` watches mean the write is keyed `t1552_004_ssh_keys`, so 100116 chains from 100113 (`<if_sid>100113</if_sid>`) and narrows on `audit.file.name` containing `authorized_keys`. This is the "broad sensor, specific SIEM rule" pattern.
- **Windows 7045 → 61138:** no custom rule needed; Wazuh's built-in rule already fires on the System EID 7045 event the Sigma rule targets.
- **Windows Sysmon rules:** implemented as custom rules **100200–100206** in `local_rules.xml`, narrowing on `win.eventdata.*` fields with `type="pcre2"`. Most chain off the relevant Wazuh built-in Sysmon base rule (EID 1 = 61603, EID 10 = 61612, EID 22 = 61624). Rule **100205** is the exception: the Sysmon EID 13 base rule (61615) is level 0 and Wazuh already ships a Run-key parent, so 100205 chains off the built-in **92300** instead. Verified: 100201, 100202, 100205; the rest move to ✅ as individual tests are captured. Service creation (T1543.003) stays on built-in rule 61138 (already ✅).
- **Exfil DNS tunneling** is a heuristic (long-label regex on Sysmon EID 22); it needs threshold tuning and a domain allowlist before it is alert-worthy — kept `experimental`.

## Validate locally

```bash
pip install pysigma
python3 - << 'EOF'
import glob
from sigma.collection import SigmaCollection
for f in glob.glob("detections/sigma/**/*.yml", recursive=True):
    SigmaCollection.from_yaml(open(f).read())
print("all Sigma rules parse OK")
EOF
```
