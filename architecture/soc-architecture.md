# SOC Architecture — AlertMind

**Document owner:** AlertMind (CAP-SCE-3W) · **Scope:** Solo build · **Status:** Week-1 baseline, maintained as the system evolves
**Companion diagram:** [`diagram.drawio`](diagram.drawio) (editable) → export to `diagram.png`

---

## 1. Purpose & scope

This document is the authoritative description of the AlertMind mini-SOC: what telemetry is collected, how it flows from endpoint to alert, how detections are organised, how data is retained, who can access what, and how the LLM tier-1 assistant attaches to the pipeline without weakening it. It is written so a reader with the repository can rebuild and reason about the environment in under an hour.

### Current vs. target state

This document describes both what is implemented now and the intended end state. The table below is the quick reference; sections flag *target* items inline where relevant so the doc never reads as overclaiming.

| Capability | Current state | Target by final submission |
|---|---|---|
| Wazuh SIEM (manager/indexer/dashboard) | Implemented | Maintain |
| Windows telemetry (Sysmon, System, Security) | Implemented; EID 1 + 7045 verified | Verify LSASS/Run-key alerts |
| Linux auditd ingestion | Implemented | Tune noisy rules (e.g. 100100) |
| Linux Wazuh-native rule pack (100100–100115) | Implemented | Verify remaining rules individually |
| Sigma YAML source | In progress (XML authored first; Sigma backfilling) | Complete 7+ portable rules |
| Cloud sample source | Planned | Optional / instructor-dependent |
| RBAC users (`socanalyst`, `assistant-svc`) | Planned (only `admin` exists) | Created before Week-3 assistant |
| Retention ISM policies | Documented, not yet enforced | Enforce or note as production-intent |
| Dashboard interface restriction | Not enforced (binds 0.0.0.0:443) | Bind Host-Only or add firewall rule |
| LLM assistant + guardrails | Planned | Streamlit app + redaction + logging |

## 2. Design principles

- **High-signal over high-volume.** Endpoint configs (Sysmon, auditd) are scoped to the ATT&CK techniques the detection pack covers, not maximal collection. Noise is filtered at the rule layer, not by alerting on raw telemetry.
- **Portable detections.** Detection logic is authored in Sigma (vendor-neutral) and converted to Wazuh-native rules; the Sigma YAML is the source of truth.
- **Least privilege everywhere**, including the assistant — which reaches the SIEM through a read-only API identity and can never act.
- **Reproducibility.** Every component is config-as-code in this repo; the lab is snapshot-restorable.
- **Honest measurement.** Detection latency (MTTD) and analyst triage time are treated as separate metrics with separate owners.

## 3. Lab environment & network architecture

The lab runs on VirtualBox on a Windows 11 host. The host is **never a monitored endpoint** — it runs the hypervisor and holds the repository only.

### Network design

All VMs sit on a single VirtualBox **NAT Network** named `LabNet` (`10.0.2.0/24`). This gives the VMs intra-lab connectivity and outbound internet for tool downloads, while isolating attack traffic from the physical LAN. The SIEM host carries a **second Host-Only adapter** so the dashboard can be reached from the host browser. Note that the dashboard *intent* is host-only access, but by default Wazuh Dashboard binds to `0.0.0.0:443` (all interfaces, including NAT) — interface restriction is a planned hardening item (see ports table).

| Role | VM | OS | IP (NAT) | Adapters | Status |
|---|---|---|---|---|---|
| SIEM host | `wazuh-siem` | Ubuntu | 10.0.2.15 | NAT + Host-Only | ✅ Deployed |
| Windows endpoint | `win-victim` | Windows 11 | 10.0.2.4 | NAT | ✅ Deployed (agent 001) |
| Linux endpoint | `linux-victim` | Ubuntu | 10.0.2.7 | NAT | ✅ Deployed (agent 002) |
| Attacker | `attacker` | Kali | 10.0.2.x | NAT | ⏳ Week 2 |

**Isolation posture:** outbound internet is enabled on `LabNet` for package installation and Atomic Red Team content retrieval. Atomic techniques write real system changes (registry keys, services, scheduled tasks); every VM is snapshotted clean post-setup and again before each attack run so changes can be rolled back.

### Open ports (SIEM host)

| Port | Service | Exposure |
|---|---|---|
| 1514/TCP | `wazuh-remoted` — agent event channel | LabNet |
| 1515/TCP | `wazuh-authd` — agent enrollment | LabNet |
| 55000/TCP | `wazuh-apid` — REST API | LabNet (planned: restrict to assistant host) |
| 9200/TCP | `wazuh-indexer` (OpenSearch) | localhost only |
| 443/TCP | `wazuh-dashboard` | Binds 0.0.0.0 by default; host-only access intended, interface restriction is a planned hardening item |

## 4. Log sources & telemetry

Two endpoint sources are live; a cloud sample source is planned to satisfy the optional third-source requirement.

| Source | Host | Channel / path | Format | Primary ATT&CK relevance | Status |
|---|---|---|---|---|---|
| Sysmon | `win-victim` | `Microsoft-Windows-Sysmon/Operational` | eventchannel | Execution, persistence, credential access, C2 (EID 1/3/7/8/10/11/13/22) | ✅ |
| Windows System | `win-victim` | `System` | eventchannel | Service install (EID 7045 → T1543.003) | ✅ |
| Windows Security | `win-victim` | `Security` | eventchannel | Service install (EID 4697), logon, account events | ✅ |
| auditd | `linux-victim` | `/var/log/audit/audit.log` | audit | Cred access, persistence, priv-esc, defense evasion (custom keys) | ✅ |
| Cloud trail | manager | sample file → custom decoder | json | Cloud identity / API abuse | ⏳ Planned |

**Endpoint configuration notes:**

- **Sysmon** uses the SwiftOnSecurity config, with one required edit: the `ProcessAccess` (EID 10) block — empty by default — was populated to capture access to `lsass.exe`, restoring the T1003.001 credential-access detection.
- **auditd** uses the custom `alertmind.rules` (deployed to `/etc/audit/rules.d/`), scoped to the technique set in §6 and free of the absent-software watches that made the stock "best practice" ruleset error-prone and noisy. Each rule sets a key that encodes its ATT&CK technique.

## 5. Ingestion pipeline

```
endpoint agent ──(1514/TLS)──► wazuh-remoted ──► wazuh-analysisd
                                                    │  decode (decoders)
                                                    │  match (rules + local_rules)
                                                    ▼
                                          /var/ossec/logs/alerts/alerts.json
                                                    │
                                                Filebeat
                                                    ▼
                                          wazuh-indexer (OpenSearch)
                                                    ▼
                                          wazuh-dashboard  ◄── analyst (Host-Only :443)
```

1. **Collection.** Each endpoint's Wazuh agent tails its configured `localfile` sources (Sysmon/System/Security channels on Windows; `audit.log` on Linux) and ships events to the manager over TLS on 1514.
2. **Decode + match.** `wazuh-analysisd` runs events through decoders (e.g. the `auditd` and `windows_eventchannel` decoders) and then the rule engine. The base auditd rule **80700** is level 0 (no alert); AlertMind's custom child rules (§6) chain off it and raise alerts.
3. **Index.** Matching alerts are written to `alerts.json`, picked up by Filebeat, and indexed into daily `wazuh-alerts-4.x-YYYY.MM.DD` indices.
4. **Present.** The dashboard reads the indexer and renders search, dashboards, and the ATT&CK view.

**Key onboarding fix captured for reproducibility:** the Linux agent does not read `audit.log` by default — it must be given an explicit `<localfile><log_format>audit</log_format><location>/var/log/audit/audit.log</location></localfile>` block. Without it, only the journald copy of events is ingested (low fidelity), and auditd SYSCALL records never reach the manager.

## 6. Detection architecture

**Authoring model (target):** Sigma YAML (`detections/sigma/`) is the portable source of truth; each rule is converted to its Wazuh-native form and deployed to the manager, with any hand-translation logged.

**Current state:** the Wazuh-native Linux rules are implemented in `siem/wazuh/alertmind_local_rules.xml`, deployed under `/var/ossec/etc/rules/` as a separate file (so AlertMind rules stay isolated from any other local rules; files in `etc/rules/` are auto-loaded by the `rule_dir`). The matching Sigma YAML source is being **backfilled** so the portable source and converted output remain auditable — the XML was authored first.

**Validation:** rules are checked with `xmllint --noout siem/wazuh/alertmind_local_rules.xml` before deployment, and `sudo tail -50 /var/ossec/logs/ossec.log` after restart confirms the manager loaded the file without XML or rule-parser errors. (Double-hyphen sequences inside XML comments are illegal and will fail this check — comments are kept minimal for that reason.)

**Rule organisation:**

- **Linux custom pack — IDs 100100–100115 (16 rules).** Each rule chains off base rule 80700 via `<if_sid>`, matches a single `audit.key`, raises a severity level, and tags MITRE ATT&CK. Because the key already encodes the technique, the ATT&CK mapping is deterministic. One mapping (rule 100115, package-manager config change) is marked **tentative** — APT config edits are not cleanly Ingress Tool Transfer; it is retained as a low-confidence hygiene monitor with a candidate T1195.001 mapping.
- **Windows.** Detections lean on Wazuh's Sysmon-EID ruleset and Security/System channel rules (e.g. rule 61138 for EID 7045 → T1543.003), supplemented by custom rules where coverage gaps exist.

**Severity scheme (Wazuh levels):** informational telemetry stays at level 0–3; meaningful persistence/priv-esc at 7–10; high-confidence credential access and defense-evasion (e.g. `ld.so.preload` modification, auditd tampering) at 12–13. Levels drive dashboard prioritisation and the alert thresholds used in the triage measurement.

**Telemetry vs. detection boundary:** high-volume substrate such as `execve` (key `t1059_exec`) is collected but intentionally **not** alerted on directly — it is the raw feed that targeted command-pattern rules match against. Alerting on every process execution would bury the console and pollute the triage measurement.

**Known tuning items (tracked openly):** the `/etc/shadow` read rule (100100) currently also fires on legitimate `cron` PAM reads (`auid` unset). Planned tune: scope the audit rule to `auid>=1000 -F auid!=unset` so interactive `sudo cat` is still caught while daemon noise drops out. This baseline→FP→tuned-rule progression is documented as part of the detection-engineering narrative.

## 7. Data retention plan

The lab's working life is three weeks; the plan below states both the lab setting and the production intent it models.

| Data class | Index / location | Lab setting | Production intent |
|---|---|---|---|
| Alerts | `wazuh-alerts-4.x-*` | Retain full project window | ISM rollover; delete > 90 days |
| Archives (all events) | `wazuh-archives-*` / `archives.json` | **Off by default;** enabled only during attack-simulation windows for forensic depth | Delete > 7–14 days (volume-heavy with execve auditing) |
| Audit raw logs | `/var/log/audit/audit.log` | auditd rotation defaults | Size-based rotation + offload |
| Assistant call logs | `assistant/logging/` | Retain full project window (evidence) | Retain per audit policy |

**Rationale:** archives are disabled normally because full-event capture with `execve` auditing grows the indexer rapidly on a constrained lab host; they are switched on deliberately around the Atomic runs so the measurement and any forensic review have complete data, then switched off. **Current state:** the ISM (Index State Management) policies below are *documented as production intent but not yet enforced* in the Week-1 lab; the lab's three-week life never reaches the deletion windows.

## 8. RBAC & access control — current and target state

**Current lab state:** only `admin` exists and is used for setup and validation. The `socanalyst` and `assistant-svc` identities below are **planned** and will be created before the Week-3 assistant integration.

Target model — least privilege across three identities:

| Identity | Used by | Privileges | State |
|---|---|---|---|
| `admin` | Setup / maintenance only | Full dashboard + indexer + API | ✅ Exists |
| `socanalyst` | Day-to-day triage | Read-only on alerts, dashboards, and the ATT&CK view; no config rights | ⏳ Planned |
| `assistant-svc` | LLM assistant integration | Read-only API access scoped to alert data; **no write, no active-response, no agent control** | ⏳ Planned |

**Controls (target):**

- Dashboard access is intended from the host over the Host-Only adapter; today it binds `0.0.0.0:443`, so an interface bind or firewall rule is a planned hardening item (§3).
- The indexer binds to localhost and is not exposed on the network.
- Wazuh API RBAC (roles → policies) will enforce the `assistant-svc` read-only scope, which is the technical backbone of the assistant's "never acts" guardrail — once created, the integration *cannot* act because its credentials forbid it, not merely because the code chooses not to.
- All inter-component traffic (agent↔manager, Filebeat↔indexer, dashboard↔indexer) uses the certificates generated at install.

## 9. LLM assistant integration architecture

The assistant attaches to the SIEM in a **pull** model and never sits inline with enforcement.

```
read-only Wazuh API :55000        ──► redaction layer ──► LLM
  (or local alerts.json export)                              │
                                            structured output (summary,
                                            ATT&CK tag, suggested queries,
                                            draft message)
                                                             ▼
                                                    human review (analyst)
                                                             │
                                                    full call logging
```

**Data path (resolved).** The indexer (9200) binds to localhost, so it is *not* the assistant's interface unless the assistant runs on `wazuh-siem` itself. The chosen path is the **read-only Wazuh API on 55000** via the `assistant-svc` identity, which works whether the assistant runs on-box or on a separate host; a local `alerts.json` export is the simpler fallback if the assistant runs directly on the SIEM VM.

- **Input boundary.** The assistant retrieves a selected alert via the read-only `assistant-svc` identity. A redaction layer strips credential/token/secret patterns before any prompt leaves the runner; IPs are retained (needed for triage). Lab alerts are synthetic.
- **No autonomy.** Output is text only — a summary, an ATT&CK tag, suggested investigation queries, and a draft user message. Nothing is executed; the analyst reviews every output.
- **Auditability.** Every call logs prompt, response, model, and version to `assistant/logging/`. Kept outputs are verifiable against the raw alert.

See the README §8 for the measurement design that quantifies the assistant's effect on triage time.

## 10. Security & operational considerations

- **Snapshots** are taken after a clean setup and before each attack run; a documented recovery procedure exists in [`docs/runbooks/wazuh-recovery.md`](../docs/runbooks/wazuh-recovery.md) (authored after a real host crash during the build).
- **Secrets** (the generated `admin` password, certificates) are never committed; status notes redact them.
- **Resource management:** on a constrained host, VMs are staggered — the SIEM plus one endpoint at a time — to stay within RAM.

## 11. Assumptions & limitations

- Single-node Wazuh (no clustering/HA) — appropriate for a lab, not production scale.
- Cloud telemetry is a static sample, pending instructor confirmation that live ingestion is out of scope for the solo build.
- Synthetic alerts only; no production traffic, so detection precision is characterised against known Atomic ground truth rather than real-world base rates.
- Measurement is within-subject (single analyst) with the learning-effect controls described in the README; threats to validity are reported in `report.md`.
