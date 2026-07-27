# Sigma rule pack — notes & Sigma → Wazuh crosswalk

This directory holds the **portable detection-intent source** for AlertMind, authored in Sigma. The deployed, SIEM-native form is `siem/wazuh/local_rules.xml`, containing 17 Linux and 7 Windows custom rules, plus Wazuh built-in rule 61138 for Windows service creation. This file documents the pack and maps each Sigma rule to its Wazuh implementation and verification status.

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
| `lnx_t1136_accounts.yml` | T1136 / T1098 | 100101 | ✅ (EVID-LIN-004) |
| `lnx_t1548_003_sudoers.yml` | T1548.003 | 100102 | ✅ (EVID-LIN-005) |
| `lnx_t1053_003_cron.yml` | T1053.003 | 100103 | ✅ (EVID-LIN-006) |
| `lnx_t1543_002_systemd.yml` | T1543.002 | 100104 | ✅ (EVID-LIN-007) |
| `lnx_t1037_init.yml` | T1037 | 100105 | ✅ (EVID-LIN-008) |
| `lnx_t1546_004_shell_init.yml` | T1546.004 | 100106 | ✅ (EVID-LIN-009) |
| `lnx_t1574_006_ldpreload.yml` | T1574.006 | 100107 | ✅ (EVID-LIN-010) |
| `lnx_t1547_006_kmod.yml` | T1547.006 / T1014 | 100108 | ✅ (EVID-LIN-011) |
| `lnx_t1548_001_setuid.yml` | T1548.001 / T1222.002 | 100109 | ✅ (EVID-LIN-012) |
| `lnx_t1562_001_audit_tamper.yml` | T1562.001 | 100110 | ✅ (EVID-LIN-013) |
| `lnx_t1070_logs.yml` | T1070 | 100111 | ✅ (EVID-LIN-014) |
| `lnx_t1070_006_timestomp.yml` | T1070.006 | 100112 | ✅ (EVID-LIN-015) |
| `lnx_t1552_004_ssh_keys.yml` | T1552.004 | 100113 | ✅ (EVID-LIN-016) |
| `lnx_ssh_daemon_config_change.yml` | T1098 *(broad; see caveats)* | 100114 | ✅ (EVID-LIN-017) |
| `lnx_apt_repo_config.yml` | T1195.001 *(tentative)* | 100115 | ✅ (EVID-LIN-018) |
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
| `win_initial_access_office_spawns_shell.yml` | T1566 / T1059 | rule 100200 (if_sid 61603, EID 1) | ✅ (EVID-WIN-007) |
| `win_execution_powershell_encoded.yml` | T1059.001 | rule 100201 (if_sid 61603, EID 1) | ✅ (EVID-WIN-003) |
| `win_defense_evasion_lolbin_execution.yml` | T1218 | rule 100202 (if_sid 61603, EID 1) | ✅ (EVID-WIN-004) |
| `win_credential_access_lsass_access.yml` | T1003.001 | rule 100203 (if_sid 61612, EID 10) | ✅ (EVID-WIN-006) |
| `win_persistence_run_key.yml` | T1547.001 | rule 100205 (if_sid 92300, built-in Run-key parent) | ✅ (EVID-WIN-005)  |
| `win_lateral_movement_psexec_service.yml` | T1021.002 / T1569.002 | rule 100204 (if_sid 61603, EID 1) | ✅ (EVID-WIN-008) |
| `win_exfiltration_dns_tunneling.yml` | T1048 / T1071.004 | rule 100206 (if_group sysmon_event_22, EID 22) | ✅ (EVID-WIN-009) |

**Testability note:** `win_initial_access_office_spawns_shell.yml` was validated with a controlled Office-spawn simulation in the lab rather than a real malicious document. The alert is therefore marked verified for detection-path coverage, with the simulation method documented in evidence.

### Windows tuning caveats

- **`100205` (Run-key)** — chaining off the built-in 92300 inherits a prefix match: 92300 matches `CurrentVersion\Run`, so it also matches `CurrentVersion\RunNotification` (a shell startup-notification key Windows writes *when* a Run key is added), producing a duplicate false-positive alert. Observed in testing (a single `reg add` fired 100205 twice). Fixed by re-narrowing 100205 with a `targetObject` filter (`CURRENTVERSION\\Run(Once)?\\`, in Wazuh's doubled-backslash format) so only genuine Run/RunOnce writes fire.
- **`100203` (LSASS)** — required three tuning rounds. (1) Untuned rule fired ~557 times on benign query-only reads (`0x1000`, AV/svchost). (2) Positive allowlist only covered `0x1xxx` masks and missed dump-grade `0x0xxx` masks like `0x0410`. (3) Final: negative exclusion on the three confirmed-benign masks (`0x1000`/`0x1400`/`0x3000`, none include `PROCESS_VM_READ`) plus sourceImage exclusion for `wazuh-agent.exe` and `MsMpEng.exe`. Verified on `rundll32.exe` at `0x1fffff` (comsvcs MiniDump, EVID-WIN-006). Lab pre-condition: `RunAsPPL=0`; with PPL the OS blocks dump-grade handles, though Sysmon may still log the denied access attempt.
- **`100204` (PsExec)** — matches the default `PSEXESVC.exe` service binary, so it fires on Sysinternals PsExec (verified, EVID-WIN-008) but **impacket-psexec evades it** by uploading a randomly-named binary (e.g. `lmsfVTrk.exe`) and creating a randomly-named service. The behavioural built-ins **92218** (admin-share binary), **92307**/**92650** (service creation from systemroot) catch the impacket variant regardless of name — a concrete indicator-vs-behavioural detection lesson.

## Hand-translation notes (per reproducibility requirement)

- **Linux 100100–100115:** direct audit-key and condition translation — `<if_sid>80700</if_sid>` + `<field name="audit.key">{key}</field>` + `<mitre>` metadata. ATT&CK metadata is generally retained; rule 100109 records T1548.001 in Wazuh while the portable Sigma rule additionally records T1222.002 for the broader permission-change behaviour. This is a metadata difference, not a rule-firing difference.
- **Rule 100116 (authorized_keys) is the one exception** — it is *not* a direct `audit.key` translation. Overlapping `/root/.ssh` watches mean the write is keyed `t1552_004_ssh_keys`, so 100116 chains from 100113 (`<if_sid>100113</if_sid>`) and narrows on `audit.file.name` containing `authorized_keys`. This is the "broad sensor, specific SIEM rule" pattern.
- **Windows 7045 → 61138:** no custom rule needed; Wazuh's built-in rule already fires on the System EID 7045 event the Sigma rule targets.
- **Windows Sysmon rules:** implemented as custom rules **100200–100206** in `local_rules.xml`, narrowing on `win.eventdata.*` fields with `type="pcre2"`. Most chain off the relevant Wazuh built-in Sysmon base rule (EID 1 = 61603, EID 10 = 61612).
- **Rule 100205 exception:** the Sysmon EID 13 base rule (61615) is level 0 and Wazuh already ships a Run-key parent, so 100205 chains off the built-in **92300** instead.
- **Rule 100206 exception:** it chains from `sysmon_event_22` rather than direct `if_sid 61624`; this mirrors the final working pattern for Sysmon DNS Query events.
- **Intentional Windows narrowing:** rule 100201 requires an encoded-command switch followed by at least 20 base64-like characters in Wazuh, while the portable Sigma rule detects the switch itself. Rule 100206 is also lab-narrowed: Wazuh requires a label of at least 45 characters under `alertmind-lab.invalid`, while the portable Sigma heuristic detects generic labels of 30 or more characters. These differences reduce lab noise and are intentional semantic narrowing, not exact translations.
- **Verification:** all of 100200–100206 are verified firing (EVID-WIN-003 through EVID-WIN-009). Service creation (T1543.003) stays on built-in rule 61138 (already ✅).
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
