# SOC Architecture — AlertMind

**Document owner:** AlertMind (CAP-SCE-3W) · **Scope:** Solo build · **Status:** Final lab state, 31 Jul 2026
**Companion diagram:** [`diagram.drawio`](diagram.drawio) (editable) → export to `diagram.png`

---

## 1. Purpose & scope

This document is the authoritative architecture description of the AlertMind mini-SOC: what telemetry is collected, how it flows from endpoint to alert, how detections are organised, how data is retained, who can access what, and how the LLM tier-1 assistant operates in the measured lab.

It distinguishes three things explicitly:

1. **Implemented SIEM path** — endpoint telemetry through Wazuh to dashboards and retained alerts.
2. **Implemented assistant paths** — the frozen-corpus batch evaluator and the local Streamlit **Paste & inspect** workflow.
3. **Target integration** — future read-only Wazuh API ingestion through least-privilege RBAC identities.

The measured assistant is **not connected live to Wazuh**. It consumes the frozen corpus or analyst-pasted JSON. The target API connection is documented, not implemented.

### Current vs. target state

| Capability | Final lab state | Production / next-step target |
|---|---|---|
| Wazuh SIEM (manager, indexer, dashboard) | ✅ Implemented and healthy | Add HA, capacity planning and production hardening |
| Windows telemetry | ✅ Sysmon and System verified; Security EID 4697 configured but verification pending | Complete Security-channel validation |
| Linux auditd ingestion | ✅ Implemented with explicit `audit.log` collection | Tune remaining known noise |
| Custom Wazuh detection pack | ✅ 24 rules (17 Linux + 7 Windows), all verified firing | Validate against larger production-like traffic |
| Sigma source | ✅ 25 YAML rules validated; translation notes retained | Automate more of the Sigma→Wazuh conversion |
| Dashboards and playbooks | ✅ Two dashboards and three IR playbooks | Migrate playbooks from NIST SP 800-61r2 to r3 |
| Cloud telemetry | Static sample demonstrated; no live cloud feed | Optional live third source |
| LLM assistant | ✅ Batch evaluator + Streamlit UI + Paste & inspect | Repeat hosted evaluation and production hardening |
| Live Wazuh→assistant ingestion | ❌ Not implemented | Read-only pull through `assistant-svc` |
| RBAC (`socanalyst`, `assistant-svc`) | ❌ Not implemented; only `admin` exists | Create and validate least-privilege roles |
| Alert-retention ISM policy | ✅ Implemented 29 Jul 2026: `wazuh-alert-retention-policy` manages `wazuh-alerts-4.x-*`; 90-day delete configured | Monitor transitions; validate expiry when an index reaches 90 days; define snapshot/legal-hold requirements |
| Dashboard interface restriction | Not enforced; dashboard binds `0.0.0.0:443` | Bind Host-Only or enforce firewall restrictions |

## 2. Design principles

- **High signal over high volume.** Endpoint collection is scoped to the ATT&CK behaviours the detection pack covers; raw high-volume telemetry is not automatically promoted to alerts.
- **Portable detections.** Sigma YAML is the portable source, with deployed Wazuh-native rules and hand-translation notes retained for auditability.
- **Least privilege, stated honestly.** The current assistant has no tools, write credentials or send path. DRAFT labelling and analyst review are procedural controls. A future read-only `assistant-svc` identity adds defense in depth; it is not credited as an implemented control.
- **Redaction before model use.** Tested credential classes are removed before prompt construction. Redaction is risk reduction, not a guarantee for unknown or encoded secrets.
- **No inline enforcement.** The assistant produces text-only drafts and never sits in the detection or response enforcement path.
- **Reproducibility.** Configurations, prompts, tests, audit logs and measurement artifacts are retained in the repository.
- **Honest measurement.** Detection latency, inference latency and analyst triage time are separate metrics with different owners.

## 3. Lab environment & network architecture

The lab runs on VirtualBox on a physical Windows 11 host. The physical host is **not a monitored endpoint**; it runs the hypervisor, browser, repository and local assistant UI.

### Network design

All VMs sit on the VirtualBox NAT Network `LabNet` (`10.0.2.0/24`). This provides intra-lab connectivity and outbound access for controlled tool downloads while isolating attack traffic from the physical LAN. The SIEM VM also has a Host-Only adapter for dashboard access from the host browser.

The dashboard currently binds `0.0.0.0:443`, including the NAT interface. Host-Only access is the intended posture, but interface binding or a firewall rule remains a documented hardening item.

| Role | VM | OS | IP (NAT) | Adapters | Final state |
|---|---|---|---|---|---|
| SIEM host | `wazuh-siem` | Ubuntu | 10.0.2.15 | NAT + Host-Only | ✅ Deployed |
| Windows endpoint | `win-victim` | Windows 11 | 10.0.2.4 | NAT | ✅ Deployed (agent 001) |
| Linux endpoint | `linux-victim` | Ubuntu | 10.0.2.7 | NAT | ✅ Deployed (agent 002) |
| Attacker / validation host | `attacker` | Kali | 10.0.2.x | NAT | ✅ Used for controlled validation |

**Isolation posture.** Outbound internet is enabled for package installation and test-content retrieval. Several validation procedures make real system changes. VMs are snapshotted before attack runs and restored after validation; commands are restricted to the isolated lab.

### Open ports on `wazuh-siem`

| Port | Service | Final lab exposure |
|---|---|---|
| 1514/TCP | `wazuh-remoted` — agent event channel | LabNet |
| 1515/TCP | `wazuh-authd` — agent enrolment | LabNet |
| 55000/TCP | `wazuh-apid` — REST API | LabNet; used for administration/validation, **not by the assistant** |
| 9200/TCP | `wazuh-indexer` / OpenSearch | Localhost only |
| 443/TCP | `wazuh-dashboard` | Binds `0.0.0.0`; Host-Only access intended |

## 4. Log sources & telemetry

Two endpoint sources are live. A static cloud sample was demonstrated as an optional third-source exercise; there is no live cloud integration.

| Source | Host | Channel / path | Format | Primary ATT&CK relevance | Final state |
|---|---|---|---|---|---|
| Sysmon | `win-victim` | `Microsoft-Windows-Sysmon/Operational` | eventchannel | Execution, persistence, credential access, C2 | ✅ Verified |
| Windows System | `win-victim` | `System` | eventchannel | Service installation (EID 7045) | ✅ Verified |
| Windows Security | `win-victim` | `Security` | eventchannel | EID 4697, logon and account events | 🟡 Configured; verification pending |
| auditd | `linux-victim` | `/var/log/audit/audit.log` | audit | Credential access, persistence, privilege escalation, defense evasion | ✅ Verified |
| Cloud trail sample | manager | sample file → custom decoder | JSON | Cloud identity / API activity | 🟡 Static sample only |

### Endpoint configuration notes

- **Sysmon** uses the SwiftOnSecurity configuration with an added `ProcessAccess` (EID 10) include for `lsass.exe`, enabling the T1003.001 detection.
- **auditd** uses `detections/auditd/alertmind.rules`, with ATT&CK-oriented keys for the paths and actions monitored by the Wazuh child rules.
- **Required Linux onboarding fix:** the Wazuh agent does not read `/var/log/audit/audit.log` by default. An explicit `audit` `localfile` block is required; otherwise only the lower-fidelity journald copy is collected.
- High-volume `execve` telemetry is collected as substrate for targeted rules, not alerted on indiscriminately.

## 5. Implemented SIEM ingestion path

```text
Windows / Linux endpoint
        │ Wazuh agent — TLS :1514
        ▼
wazuh-remoted
        ▼
wazuh-analysisd
  decode → base rules → AlertMind custom rules
        ▼
/var/ossec/logs/alerts/alerts.json
        ▼
Filebeat → Wazuh Indexer / OpenSearch
        ▼
Wazuh Dashboard → analyst
```

1. **Collection.** Endpoint agents read the configured Windows event channels or Linux `audit.log` and ship events over TLS.
2. **Decode and match.** Wazuh decoders normalise the events. Custom rules narrow the relevant base events and attach severity and ATT&CK metadata.
3. **Persist and index.** Matching alerts are written to `alerts.json`, collected by Filebeat and indexed into `wazuh-alerts-4.x-*`.
4. **Present.** Analysts use the Daily SOC Briefing and ATT&CK Heatmap dashboards for triage and coverage review.

The LLM assistant is not part of this path and cannot affect whether an alert is generated. Consequently, it cannot change MTTD.

## 6. Detection architecture

### Authoring and deployment

- **Portable source:** `detections/sigma/` — 25 validated Sigma YAML rules.
- **Deployed custom rules:** `siem/wazuh/local_rules.xml` — 24 custom Wazuh rules.
- **Translation record:** `detections/sigma/notes.md` documents manual translations, broad or tentative mappings and the one child-rule exception.
- **Linux sensor rules:** `detections/auditd/alertmind.rules`.

### Rule organisation

- **Linux — 17 rules, IDs 100100–100116.** Most chain from base auditd rule 80700 and match an ATT&CK-oriented audit key. Rule 100116 is a child of 100113 because overlapping auditd path watches cannot reliably retain two keys for `/root/.ssh/`.
- **Windows — 7 rules, IDs 100200–100206.** These cover Office-parent execution, encoded PowerShell, LOLBin execution, LSASS access, PsExec-style service execution, Run-key persistence and long-label DNS activity.
- The Wazuh built-in service-creation rule for Windows EID 7045 is retained as platform coverage and is not counted among the 24 custom rules.

All 24 custom rules were verified firing end-to-end. The attack runbook distinguishes direct technique behaviour from path-write, heuristic and parent-name simulations; rule firing does not automatically prove full real-world technique execution.

### Severity and tuning

Informational telemetry remains at low Wazuh levels; meaningful persistence and privilege-escalation events are raised to the operational queue; high-confidence credential-access or defense-evasion patterns receive the highest custom levels.

Known and documented tuning findings include:

- Rule 100100 also catches benign `cron` PAM reads of `/etc/shadow`; an `auid>=1000` tune remains planned.
- Rule 100203 required three rounds to separate dump-grade LSASS access from benign query-only and security-tool reads.
- Rule 100205 excludes a `RunNotification` prefix-match false positive.
- Rule 100204 detects the default Sysinternals `PSEXESVC.exe` name; randomly named impacket variants require behavioural coverage.
- Rule 100206 is a long-label heuristic, not evidence of actual DNS tunnelling or exfiltration.

## 7. Data retention

| Data class | Location | Final lab setting | Production intent |
|---|---|---|---|
| Wazuh alerts | `wazuh-alerts-4.x-*` | ISM policy `wazuh-alert-retention-policy`; delete transition configured after 90 days | Monitor transition history; validate expiry; add snapshot/legal-hold controls if required |
| Full-event archives | `wazuh-archives-*` / `archives.json` | Off by default; enabled around selected validation windows | Retain 7–14 days |
| Raw audit logs | `/var/log/audit/audit.log` | auditd defaults | Size-based rotation and offload |
| Batch assistant audit logs | `assistant/outputs/runs/<run_id>/audit-log*.jsonl` | Retained as measurement evidence; runs never overwrite | Retain per audit policy |
| Paste & inspect audit | `assistant/outputs/adhoc/adhoc-audit.jsonl` | Saved only on explicit request; idempotent | Retain per audit policy |

The alert policy was implemented on **29 Jul 2026**. At evidence capture, the Wazuh Indexer showed **21 policy-managed daily alert indices** in `retention_state`; the action was `Transition`, the job status was `Running`, and the UI reported that transition conditions were being evaluated. Daily indices dated 30 and 31 Jul were also attached, showing that post-update daily indices were covered by the policy. This validates policy presence, attachment and scheduling. It does **not** demonstrate actual deletion after 90 days, because the lab had not existed long enough for any managed index to reach the threshold. Evidence: `EVID-WAZUH-RET-001` and `EVID-WAZUH-RET-002` in `evidence/week3/`.

Full-event archives stay off by default because `execve` collection is volume-heavy on the constrained single-node SIEM. Their proposed 7–14-day window remains production intent, not an implemented archive policy.

Paste & inspect does not persist raw pasted input. Its optional audit record contains a correlation hash and sanitised metadata; tested secret values and unsalted secret hashes are excluded.

## 8. RBAC & access control

### Final lab state

Only `admin` exists and is used for setup and validation. `socanalyst` and `assistant-svc` were not created, and live Wazuh API ingestion was not implemented.

### Target least-privilege model

| Identity | Used by | Intended privileges | State |
|---|---|---|---|
| `admin` | Setup and maintenance | Full dashboard, indexer and API administration | ✅ Exists |
| `socanalyst` | Day-to-day SOC triage | Read alerts, dashboards and ATT&CK views; no configuration rights | ⏳ Planned |
| `assistant-svc` | Future live assistant ingestion | Alert-scoped read-only API; no writes, active response or agent control | ⏳ Planned |

### Control boundaries

- The current assistant's no-action property comes from its implemented architecture: it has no tools, no Wazuh credentials, no write path and no message-send integration.
- Every response is labelled DRAFT and requires analyst review. This is a procedural safeguard, not proof that every analyst will always catch an incorrect recommendation.
- The planned `assistant-svc` role would add credential-level defense in depth to the future ingestion path; it is not credited as an implemented safeguard.
- The indexer remains localhost-only.
- Dashboard interface restriction and API-source restriction remain production-hardening tasks.

## 9. LLM tier-1 assistant architecture

### 9.1 Implemented batch path

```text
measurement/alert-corpus.json
        ▼
redact tested secret classes
        ▼
apply operational or strict label-reduced view
        ▼
build untrusted-data prompt
        ▼
mock / Ollama / hosted provider
        ▼
parse → schema validate → audit → score
```

The frozen 20-alert corpus is the measured input. Batch outputs are generated before the timed analyst pass, so model inference latency is measured separately from analyst triage time.

### 9.2 Implemented Paste & inspect path

```text
analyst-pasted JSON or plain text
        ▼
parse → size/depth/node limits
        ▼
redact with trace → apply view
        ▼
scan instruction-shaped keys and values
        ▼
reserved-delimiter boundary gate
        ▼
hosted-provider egress consent
        ▼
one model call → schema validation
        ▼
DRAFT result + optional sanitised audit save
```

Paste & inspect shares the batch path's redaction implementation and model boundary but is not the same pipeline. It adds input limits, a trace, injection visibility, delimiter blocking, hosted-provider consent and explicit one-shot audit persistence. It is operational functionality and is excluded from the frozen benchmark.

### 9.3 Shared guardrails

- **Redaction first:** tested credential classes are removed before model-bound text is built; 0/7 planted secrets survived the regression proof.
- **No tools or action path:** providers return text only.
- **Prompt boundary:** alert content is placed inside an `ALERT_DATA` untrusted-data block.
- **Injection handling:** tested instruction-shaped markers are surfaced and reserved delimiter attempts are blocked before a call. Other marked content may still reach and influence the model; general prevention is not claimed.
- **Output validation:** required fields, types, dispositions, confidence values, ATT&CK syntax and summary length are checked.
- **Auditability:** batch calls write 25-field, non-overwriting records; ad hoc audit saving is explicit and sanitised.
- **Human decision:** all model output remains a DRAFT for analyst review.

### 9.4 Planned Wazuh integration

```text
Wazuh Indexer API :9200  (wazuh-alerts-4.x-*)
        │ target: alert-scoped read-only search/get
        │ identity: assistant-svc  (DLS: agent.id 001, 002)
        ▼
the same redaction and model boundary
```

This connection is a target state only. No report result, live demonstration or no-action claim depends on it being implemented.

**Correction to the submitted baseline.** The `v1.0` report and diagrams named the Wazuh Server API on `:55000` as this planned path. That was wrong in one respect: Wazuh stores alerts in `wazuh-alerts-*` on the Indexer, so alert retrieval belongs to the Indexer API on `:9200`. Port `:55000` is a management plane used for administration and validation, and the assistant is deliberately given no Server API identity at all. The submitted `v1.0` artifacts are preserved unedited; this section records the corrected target.

**Post-v1 progress.** The `assistant-svc` and `socanalyst` identities named above now exist with least-privilege Indexer roles, and their read/write boundary has been verified against the live cluster — see `evidence/rbac/`. A restricted host-only SSH forward that keeps the Indexer bound to loopback has since been demonstrated end to end by the project owner; that run is owner-executed and its sanitized evidence is not yet committed or independently reviewed. The ingestion path itself remains unimplemented: there is no OIDC/application authentication or authorization, no constrained reader module and no live-alert UI, and no application code reads from Wazuh. SSH public-key authentication and the Indexer's own basic-auth identities are separate, lower layers and do exist. The live lab has also been upgraded to Wazuh 4.14.7 since the 4.14.5 submission baseline.

## 10. Security & operational considerations

- **Snapshots and cleanup:** clean snapshots are taken before controlled validation; the attack runbook includes teardown procedures and distinguishes thin simulations from direct behaviour.
- **Secrets:** generated credentials and certificates are not committed. Redaction covers tested patterns but cannot guarantee removal of unknown, encoded or unlabelled secrets.
- **Prompt injection:** detection and containment reduce risk but do not prove semantic resistance. No-tools architecture and analyst review limit machine-level impact.
- **Hosted egress:** hosted providers receive only redacted synthetic lab data and require explicit consent in Paste & inspect.
- **Resource management:** VMs are staggered on the constrained host; the SIEM plus one endpoint is the normal operating set.
- **Recovery:** the Wazuh recovery procedure is documented in `docs/runbooks/wazuh-recovery.md`.

## 11. Assumptions & limitations

- Single-node Wazuh with no clustering or HA.
- Two live endpoint sources; cloud telemetry is a static sample, not production ingestion.
- Synthetic controlled simulations and historical lab false positives, not production base rates.
- Some triggers validate a monitored path or heuristic rather than complete technique execution.
- Known `/etc/shadow` false-positive tuning remains planned.
- RBAC identities and live Wazuh API ingestion remain target architecture.
- Paste & inspect is localhost-oriented and single-user; it is not a multi-tenant SOC service.
- Redaction, injection scanning and schema validation reduce risk but do not prove semantic correctness or universal secret removal.
- Measurement uses one analyst, a small frozen corpus and one stochastic hosted run per view; full threats to validity are reported in `report.md`.

