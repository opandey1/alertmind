# AlertMind — AI-Assisted Mini SOC
## Technical Report

**Author:** Ojas Pandey · **Mode:** Solo · **Track:** EC-Council SOC Essentials (SCE) · **Project:** CAP-SCE-3W
**Program:** PG Certificate in AI/GenAI Powered Cybersecurity — IIT Roorkee × Futurense, Cohort 1
**Repository:** https://github.com/opandey1/alertmind 

---

## Table of contents
1. Executive summary
2. Introduction & problem statement
3. SOC architecture
4. SIEM build & log coverage
5. Detection engineering
6. Dashboards & IR playbooks
7. Attack simulation & baseline
8. LLM tier-1 assistant
9. Impact measurement
10. AI disclosure
11. Limitations & threats to validity
12. Conclusion & future work
13. References
14. Appendices

---

## 1. Executive summary

AlertMind is a mini-SOC pilot testing whether a guardrailed LLM tier-1 assistant improves alert triage before a SaaS company commits to a commercial SOAR. It comprises a Wazuh SIEM with Windows (Sysmon) and Linux (auditd) telemetry, an ATT&CK-mapped detection pack (24 custom rules, all verified firing), two dashboards, three NIST SP 800-61r2 playbooks, and an LLM assistant whose guardrails are enforced in code and proved by reproducible tests. Impact was measured against an unassisted baseline over a 20-alert corpus salted with six real false positives from the lab's tuning history.

**The headline is conditional, and the aggregate figure misleads.** Median triage time fell 10.5→8.0 min (−24%) — but that averages two opposite effects. Split by whether the assistant was correct, all 14 attacks (assistant correct) were triaged faster and all six false positives (assistant wrong) slower. Because alert class and assistant correctness coincide in this sample, this is an **association**, not an isolated causal effect — but the association is categorical (20/20). Analyst accuracy held at 20/20 in both conditions: in this single-analyst study, mandatory review absorbed all six wrong dispositions, at a measured cost of a paired-median **+1.68 min** per false positive.

**The observed failure was model- and inference-configuration-dependent in this exploratory comparison, not intrinsic to LLM triage.** In the operational view, both local 8B conditions (`llama3.1:8b` and post-v1 `qwen3:8b`) cleared 0/6 false positives; hosted `gpt-5.5-2026-04-23` cleared 5/6 without confidently misclassifying a benign alert. Under a **strict label-reduced evaluation view**, ATT&CK exact/relaxed scores are 1/14 · 1/14 for llama, 2/14 · 5/14 for Qwen and 8/14 · 12/14 for GPT-5.5. Strict benign outcomes are 0/6, 1/6 and 3/6 respectively. The operational free-text grounding review began with a human-authored pass and received a provenance-recorded Codex audit against the complete prompts. One human approved every changed verdict on 2026-08-31: GPT-5.5 retains 20/20 supported summaries and calibrated confidence with 15/20 runnable query sets; llama has 12/20 fully supported summaries, nine unsupported statements and 0/20 runnable sets; Qwen has 12/20, eight and 0/20 (§9.5).

**Recommendation.** Do not deploy either tested local 8B configuration for false-positive triage from this evidence: llama clears 0/6 and Qwen only 1/6 in the strict view (0/6 operationally). GPT-5.5 is a promising candidate for further evaluation, not deployment approval: it clears 3/6 strict and 5/6 operationally, but represents one stochastic pair and was not included in the assisted-timing pass. All model outputs remain draft-only under mandatory analyst review.

## 2. Introduction & problem statement

A growing SaaS company's three-person SOC processes ~1,200 alerts per day at a mean time-to-triage of ~35 minutes. Leadership has three goals: consolidate logging, reduce alert fatigue, and prototype an LLM-powered tier-1 assistant ahead of a SOAR purchase. This project plays the in-house pilot crew, delivering an end-to-end mini-SOC in a virtual lab and an honest assessment of where an LLM assistant helps, where it does not, and what risks it introduces.

**Objectives.** (1) Stand up a SIEM with heterogeneous, healthy log sources. (2) Author ATT&CK-mapped detections in Sigma and deploy them. (3) Build operational dashboards and IR playbooks. (4) Build a guardrailed LLM tier-1 assistant. (5) Measure its real impact on triage time and accuracy.

**Scope (solo, confirmed with instructor).** The solo requirement is **2 endpoint log sources (Windows + Linux) and 7 detection rules**, expanding to 10 rules / 3 sources (adding cloud) only if time permits. The implemented rule pack already exceeds the minimum. Other solo parameters: alert-summarisation assistant scope, one tabletop scenario, 15-page report.

---

## 3. SOC architecture

The lab runs on VirtualBox with all VMs on an isolated NAT Network (`LabNet`, 10.0.2.0/24); the physical Windows host is hypervisor-only and never monitored. The SIEM host (`wazuh-siem`) carries a second Host-Only adapter for dashboard access. Telemetry flows: endpoint agent → `wazuh-remoted` (1514) → `wazuh-analysisd` (decode + rules) → `alerts.json` → Filebeat → indexer → dashboard. Detections are authored in Sigma (source of truth) and converted to Wazuh rules. The measured assistant is **not connected to Wazuh**: it consumes the frozen corpus or analyst-pasted JSON. The documented production target is pull-based, read-only Wazuh API ingestion through an `assistant-svc` identity; the assistant never sits inline with enforcement.

*See `architecture / diagram.drawio / diagram.png / architecture-trust-boundary.png` for the topology and data-flow diagram.*

**Design principles:** high-signal-over-high-volume collection, portable (Sigma-first) detections, least privilege including the assistant, config-as-code reproducibility, and separation of detection latency from triage time as distinct metrics.

---

## 4. SIEM build & log coverage

**Platform.** Wazuh 4.14.5, all-in-one (manager + indexer + dashboard) on Ubuntu. All services confirmed active and the agent (1514/1515), API (55000), indexer (9200, localhost), and dashboard (443) ports confirmed listening. _Evidence: EVID-WAZUH-001 (service status + port listing)._

**Endpoints onboarded.** (All endpoints verified with evidence unless noted.)

| Source           | Host           | Channel / path                         | Format       | Status           |
| ---------------- | -------------- | -------------------------------------- | ------------ | ---------------- |
| Sysmon           | `win-victim`   | `Microsoft-Windows-Sysmon/Operational` | eventchannel | ✅ (EVID-WIN-001) |
| Windows System   | `win-victim`   | `System` (EID 7045)                    | eventchannel | ✅ (EVID-WIN-002) |
| Windows Security | `win-victim`   | `Security` (EID 4697)                  | eventchannel | ✅ (EVID-WIN-010) |
| auditd           | `linux-victim` | `/var/log/audit/audit.log`             | audit        | ✅ (EVID-LIN-002) |
| Cloud trail      | manager        | sample → custom decoder                | json         | Sample ingested  |

**A reproducibility-relevant fix.** The Linux agent does not read `audit.log` by default; an explicit `audit` `localfile` block was required. Before this, only the journald copy of events was ingested (low fidelity) and auditd SYSCALL records never reached the manager. This is documented so the lab is rebuildable without rediscovering it.

**Retention (implemented 29 Jul 2026).** Wazuh Indexer policy `wazuh-alert-retention-policy` now manages the `wazuh-alerts-4.x-*` daily alert indices and is configured to transition them to deletion at a minimum index age of **90 days**. The managed-index view showed **21 indices** in `retention_state`, with the transition action evaluating and job status `Running`; indices dated 30 and 31 Jul, after the policy update at 21:57 on 29 Jul, demonstrate coverage of subsequently created daily indices. This verifies policy creation, index attachment and active transition evaluation—not execution of the 90-day delete, because no managed index had yet reached that age. Full-event archives remain off by default and are enabled only around selected attack runs because `execve` auditing is volume-heavy. _EVID-WAZUH-RET-001/002; detail in `architecture/soc-architecture.md` §7._

**RBAC target state.** A production integration would use three least-privilege identities: `admin` (setup only), `socanalyst` (read-only triage), and `assistant-svc` (read-only, alert-scoped API). The current no-action property comes from the implemented no-tools, text-only architecture; DRAFT labelling and mandatory analyst review add a procedural guardrail. The planned service identity would add defense in depth for read-only ingestion. _Final lab state: only `admin` exists for setup and validation; `socanalyst`, `assistant-svc`, and live Wazuh API ingestion remain documented but unimplemented. Detail in §8 of the architecture doc._

---

## 5. Detection engineering

**Authoring model.** Sigma YAML is the portable source of truth (`detections/sigma/`, 25 rules, all validated with pySigma); each rule is converted to Wazuh-native form and any hand-translation logged in `detections/sigma/notes.md`. The Wazuh-native rules were authored first in `siem/wazuh/local_rules.xml`, with the Sigma source now complete and mapped 1:1 (one child-rule exception, documented).

**Linux pack — implemented and fully verified (all 17 rules).** Custom Wazuh rules 100100–100116 (17 rules) chain off base rule 80700 (with one child-rule exception, below), each matching one ATT&CK-encoded auditd key and tagging MITRE. Coverage spans credential access (T1003.008, T1552.004), persistence (T1136/T1098, T1053.003, T1543.002, T1037, T1546.004, T1098.004 authorized-keys), defense evasion (T1562.001, T1070/T1070.006), priv-esc (T1548.003, T1548.001/T1222.002), exec-flow hijack (T1574.006), rootkit/LKM (T1547.006/T1014), and config tampering (T1098 sshd_config and a tentatively-mapped package-config monitor). All 17 rules are now verified firing end-to-end (per-rule evidence EVID-LIN-002 and EVID-LIN-004…018 for 100101–100115, EVID-LIN-003 for 100116) — exercised on `linux-victim` on 8 Jul via targeted triggers on each watched path. _Full table: README §5._

**Notable issue (100116, authorized-keys T1098.004).** An auditd limitation — two `-w` watches on the same path cannot both apply their keys — meant `authorized_keys` writes surfaced only under rule 100113. The fix followed the standard "collect broadly, differentiate in the SIEM" pattern: 100116 was re-implemented as a child of 100113 narrowing on the path, now verified (EVID-LIN-003). *Full detail: Appendix F.*

**Windows.** Process create (EID 1, EVID-WIN-001) and service creation (EID 7045 → rule 61138 → T1543.003, EVID-WIN-002) are verified. **All seven custom Windows Sysmon rules (100200–100206) are now verified firing:** Office-spawns-shell (100200, EVID-WIN-007), encoded PowerShell (100201, EVID-WIN-003), LOLBins (100202, EVID-WIN-004), LSASS access (100203, EVID-WIN-006), PsExec service execution (100204, EVID-WIN-008), Run-key persistence (100205, EVID-WIN-005), and the DNS-tunnelling heuristic (100206, EVID-WIN-009). Each narrows on `win.eventdata.*` fields; most chain off the relevant built-in Sysmon base rule (EID 1 = 61603, EID 10 = 61612), with two exceptions — 100205 chains off the built-in Run-key parent 92300, and 100206 chains off the `sysmon_event_22` group rather than a direct `if_sid 61624`. Three tuning findings are recorded in full in **Appendix F**, each a standard detection-engineering lesson: Run-key 100205 needed a prefix-match FP (`RunNotification`) excluded; LSASS 100203 took three rounds to separate dump-grade access from benign query-only reads (and from the security tooling's own reads); and PsExec 100204 catches the default `PSEXESVC.exe` but not impacket's randomised name, which the behavioural built-ins cover — an indicator-vs-behavioural lesson that recurs in the assistant evaluation.

**Detection-engineering note (kept deliberately).** `execve` is collected but not alerted on directly — it is the substrate for targeted command-pattern rules; blanket exec alerting would bury the console. Rule 100100 was observed firing on legitimate `cron` PAM reads (a false positive); the planned tune scopes the audit rule to interactive users (`auid>=1000`). This baseline→FP→tuned progression is the detection-engineering story.

---

## 6. Dashboards & IR playbooks

| Deliverable                 | Purpose                           | Key contents                       | Evidence                                                                                                                                                                                     |
| --------------------------- | --------------------------------- | ---------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Daily SOC dashboard         | Operational situational awareness | volume, severity, top rules, hosts | screenshot - evidence/week3/dashboards_alertmind-daily SOC briefing_1.png<br>dashboards_alertmind-daily SOC briefing_2.png<br>export - siem/dashboards/AlertMind — Daily SOC Briefing.ndjson |
| ATT&CK dashboard            | Technique coverage and activity   | tactics/techniques by alerts       | screenshot - evidence/week3/dashboards_alertmind-ATT&CK-heatmap.png<br>export - siem/dashboards/AlertMind — ATT&CK Heatmap.ndjson                                                             |
| Phishing playbook           | NIST-aligned response             | roles, queries, containment        | playbooks/phishing.md                                                                                                                                                                        |
| Malware playbook            | NIST-aligned response             | host investigation and containment | playbooks/malware.md                                                                                                                                                                         |
| Account compromise playbook | Identity response                 | account validation/reset/recovery  | playbooks/account-compromise.md                                                                                                                                                              |

---

## 7. Attack simulation & baseline
*(Feeds Rubric: 15% measured impact.)*

**Method.** Detection coverage was validated with **controlled adversary-simulation and detection-validation runs, including selected Atomic Red Team tests** — not a single automated Atomic chain. Each of the 24 custom rules (7 Windows, 17 Linux) was exercised by a targeted trigger on the path/behaviour it watches, and confirmed firing end-to-end with CLI output and a dashboard screenshot retained as evidence. Reproducer commands, command provenance, and validation-scope labels live in `attack/runbook.md`; this section summarises method and results.

**Windows chain (7 steps, `win-victim`).** Initial-access→execution→persistence→credential-access→lateral-movement→exfil was exercised as: Office-spawns-shell (100200), encoded PowerShell (100201), LOLBin `mshta`/Atomic T1218.005 (100202), Run-key persistence (100205), LSASS access via `comsvcs MiniDump` (100203), PsExec service execution (100204), and the DNS-tunnelling heuristic (100206). All seven verified firing.

**Linux coverage (`linux-victim`).** All **17** rules (100100–100116) verified firing via targeted triggers on each watched path — credential access, persistence, defense evasion, privilege escalation, exec-flow hijack, rootkit/LKM, and config tampering. Per-rule evidence EVID-LIN-002…018.

**What the simulations do and do not prove.** Several triggers validate the *rule logic* without reproducing the full real-world technique — an honest distinction that matters under questioning. The table highlights three especially easy-to-overstate Windows cases; `attack/runbook.md` labels direct-behaviour, path-write, heuristic, and reconstructed-command scope for all 24 rules:

| Rule | What was run | What it proves | Honest label |
|---|---|---|---|
| 100200 | Copied `cmd.exe`→`winword.exe`, spawned a child | Parent-image name matching | **controlled Office-parent-name simulation** (not a real malicious macro) |
| 100204 | PsExec against `\localhost` | `PSEXESVC.exe` service-execution detection | **local loopback simulation of PsExec-style service execution** (not remote lateral movement) |
| 100206 | A single long DNS label | The heuristic fires on long labels | **long-label DNS-tunnelling heuristic simulation** (not actual tunnelling/exfil) |

Some remaining triggers reproduce the relevant behaviour directly (for example, `comsvcs MiniDump` of LSASS, encoded PowerShell, account creation, and auditd-watched file access). Others deliberately validate a write to a technique-relevant path without activating a functional persistence, privilege-escalation, or defense-evasion payload. Those cases prove the detection path and rule logic, not full technique execution.

**No CVEs are cited because no known software vulnerability was exploited.** The simulations exercised legitimate operating-system features and dual-use administrative tooling — including encoded PowerShell, `comsvcs.dll MiniDump`, Run-key and scheduled-task persistence, PsExec-style service execution, and auditd-monitored file access. These behaviours are therefore mapped to **MITRE ATT&CK techniques**, rather than CVEs; all 24 custom rules and all 20 scored alerts carry ATT&CK mappings (§5, §9). The LSASS dump required `RunAsPPL=0`, a protection deliberately lowered in the isolated lab, not a software defect that was exploited. None of the 60 operational model outputs manually reviewed in §9.5 contained a CVE identifier, so there was no CVE-formatted model claim to verify or correct in that reviewed set.

**MTTD.** Median attack-to-alert latency across the corpus is **2.32 s** (§9.2) — a property of the detection rules and real-time agent forwarding, not the assistant.

**Baseline (unassisted).** The unassisted baseline used the frozen 20-alert corpus — 14 controlled attack alerts and six historical benign false positives (§9.1). For each alert the analyst recorded alert-open and disposition-complete timestamps, the disposition, supporting evidence and notes in `measurement/timing-log.csv`. The same frozen corpus was later re-triaged with the assistant after a washout; full protocol and threats to validity are in §9.

---

## 8. LLM tier-1 assistant

### 8.1 Design and data path
Given a single Wazuh alert, the assistant returns four artifacts: a ≤5-line summary, a MITRE ATT&CK technique tag, two to three suggested investigation queries, and a draft message to the affected user or system owner. Output is strict JSON, so it can be schema-validated and scored rather than read impressionistically.

The assistant is a **pull** consumer that never sits inline with enforcement: the measured implementation reads the frozen corpus (`measurement/alert-corpus.json`); the production path is read-only Wazuh API access via the planned `assistant-svc` identity (§8.3). The deliverable is a runnable Python package (`assistant/`) plus a Streamlit UI, with an offline `mock` provider so an examiner can reproduce the pipeline with no key or network.

Streamlit also provides **Paste & inspect** for one ad hoc JSON Wazuh alert: limits, redaction with trace, injection markers, the exact model-bound message, and a schema-validated draft for mandatory review. Raw input is not persisted; only a correlation hash and sanitized audit metadata are retained.

### 8.2 Pipeline
Per alert: **redact → apply view → build prompt → call LLM → parse → validate → log → score.** Redaction runs **first**, before any prompt is constructed, so downstream stages receive only redacted content; the view transform is applied after redaction, as an experimental control rather than a security one. (Full diagram: `assistant/README.md`.)

Ad hoc path: **parse → limits → redact/trace → view → scan keys and values → boundary gate → egress consent → one model call → validate → draft/audit.** It is operational functionality, excluded from the frozen 20-alert benchmark; §9 is unchanged.

### 8.3 Guardrails and their evidence
The design principle is that every guardrail is **enforced in code and proved by a reproducible artifact**, not asserted in a prompt.

| Guardrail | Enforcement in code | Proof artifact |
|---|---|---|
| Tested credential classes redacted before prompt construction | `redact_alert()` runs before prompt construction | `assistant/outputs/redaction_proof.md` — **0/7 planted secrets leaked**; unsupported formats are residual risk |
| Never takes autonomous action | **Implemented + tested:** model has no tools, text-only response, every output stamped `analyst_review_required: true`. **Planned (production):** an alert-scoped read-only `assistant-svc` API identity (not yet created — see §3, §4). | Code + UI banner |
| Injection detection and containment | Tested markers surfaced from keys/values; reserved `<ALERT_DATA>` delimiter blocked pre-call; no Wazuh write/action path, no response tools and no enforcement integration | `assistant/outputs/injection_proof.md`, `assistant/outputs/paste_demo_injection_proof.md` — detection/blocking verified; one model did not comply with a planted instruction, but general prevention is not claimed |
| Human review on every output | All output labelled DRAFT; UI banner; draft message editable | Streamlit UI |
| Output validated | `schema.py` — keys, types, enums, ATT&CK-ID syntax, ≤5 summary lines | `parse_status` per call |
| Full, persistent logging | Runner creates a new per-run directory; 25 fields per call; offline reconstruction writes separately by default | `outputs/runs/<run_id>/audit-log.jsonl` |

Two proofs deserve emphasis.

**Redaction.** `tests/test_redact.py` plants seven fake secrets — a password, AWS access and secret keys, a bearer token, an `sk-` API key, an OpenSSH private key, and a sensitive-key field — into a realistic alert, then asserts none survive into the object the model would receive. Result: **0/7 leaked**, with the SHA-256 file hash deliberately *preserved*, because file hashes are IOCs the analyst needs, not credentials. The instructor's requirement was a before/after demonstration; implementing it as a test rather than a screenshot means an examiner can re-run it, and redaction regressions fail loudly.

**Prompt-injection handling.** Attacker-controlled fields may contain instructions. A deterministic scan flags tested markers in keys and values; the reserved delimiter is blocked pre-call. Other marked content is preserved as evidence and may reach the model inside an untrusted-data block, which reduces ambiguity but cannot guarantee semantic compliance. Schema validation checks format, not correctness. Impact is contained through redaction, no Wazuh write/action path, no response tools or enforcement integration, draft-only output and human review. In one LSASS test the model rejected the planted instruction; that is one observation, not general resistance.

**Scope of the redaction claim.** The layer removes tested classes of common credentials and materially reduces disclosure risk. It is **not** a guarantee that every possible secret is removed; residual risk remains for unknown, encoded, or unlabelled secrets. Broadening coverage (Basic auth, JWTs, `ghp_`/`xoxb-` tokens, URL credentials, decode-then-redact for encoded PowerShell) and context-aware hash handling are identified follow-ups (§12).

### 8.4 Prompt library and auditability
Two system-prompt variants are maintained and selectable at run time (`--prompt baseline|benign_aware`; see §9.6). Both are retained deliberately: reporting a before/after is honest, whereas silently substituting the better-performing prompt would be metric-gaming.

Every call is logged to a per-run directory (never overwritten) with the provider/model/view/prompt, **prompt- and redaction-version hashes**, git commit, input/prompt/response hashes, latency, parse status, and raw + parsed output — so any reported number is attributable to an exact prompt, redaction layer, model and commit. For hosted runs the log also carries the effective request config and the model actually served.

A design consequence worth recording: **the audit log is the source of truth**, so scoring can be re-derived offline without re-invoking the model (`rebuild_from_audit.py`). This paid off twice — once when a Windows `MAX_PATH` limit crashed the summary-file writes of an otherwise-complete run, and once when a defect in our own schema validator (§8.6) required re-scoring a 30-minute run, which took seconds instead. Reconstruction is non-destructive by default: `--score-only` writes nothing; otherwise derived files go to `assistant/outputs/rebuilt/<run_id>/`, and replacement requires explicit `--overwrite`. The ground-truth path is resolved from the repository and a missing timing log fails clearly rather than silently producing empty labels.

### 8.5 Model and provider choice
The client is provider-agnostic (`mock` / `ollama` / `openai` / `anthropic`) over plain `requests`, so there is no SDK version drift. The **measured artifact is `ollama/llama3.1:8b`, temperature 0, running locally** — no alert content left the lab during the measured runs.

Llama 4 was evaluated and rejected: a 100B+ mixture-of-experts model, it exceeded a 300-second per-alert timeout on local CPU inference. `llama3.1:8b` — the Llama 3 family the brief suggests — completes an alert in about 60 seconds on the strict-view run (median 60.4 s). Hosted APIs are supported and, per instructor guidance, acceptable *provided the redaction guardrail is in place*; a hosted GPU endpoint is materially faster — the measured GPT-5.5 median was **~11 seconds** (§9.8), not negligible but far below local CPU — and is the next production-candidate configuration to evaluate, not a deployment-approved choice. `preflight.py` validates provider configuration in about 20 seconds, which matters because the most common failure is a stale `OPENAI_BASE_URL` (the variable is shared by the local and hosted OpenAI-compatible providers).

### 8.6 Output validation and reliability
`schema.py` validates required keys, field types, permitted dispositions and confidence levels, ATT&CK-ID syntax and the ≤5-line summary bound. Invalid output is recorded as `schema_invalid` rather than silently scored.

This caught a defect in our own method. Two alerts were initially marked invalid because the model returned **correct multi-technique answers** (`T1136/T1098` and `T1021.002/T1569.002`, both matching ground truth) that a single-ID schema rejected. The JSON parser had extracted both values correctly; the then-current validator marked them `bad_syntax`, and the historical scoring export recorded empty assistant tags. The model was right; the validator was wrong. Re-scoring the unchanged `20260713T115729Z_ollama_operational` audit log with the current validator moves technique exact 11→13, relaxed 12→14, consistency 18→20, overall 12→14 and schema-invalid 2→0; disposition remains 14/20. On the 14 attack alerts this is **13/14 exact and 14/14 relaxed**, with A10 the sole exact miss. Its original CSV remains an as-run provenance artifact; the re-score is a derived interpretation under current code, and neither is substituted for the matched `20260715_060542` operational baseline used in §9.3.

Reliability controls: configurable timeout, response-token cap, and retry with exponential backoff on transient errors. An earlier llama3.1 run and the retained Qwen pilots exposed malformed/truncated-output risk. The accepted matched operational+evaluation pairs are **40/40 schema-valid for all three models**; Qwen used an Ollama-compatible structured-output schema while the canonical runtime validator still enforced the full ATT&CK-ID rule. No post-hoc JSON retry was applied to a measured run.

---

## 9. Impact measurement

### 9.1 Definitions and protocol
Per instructor clarification, the clock starts from **when the attack actually occurred as recorded in the logs**, not from log ingestion. Each alert carries four timestamps: (1) attack occurred, (2) alert fired in Wazuh, (3) analyst opened the alert, (4) disposition reached. From these, **MTTD = (2) − (1)** and **time-to-triage = (4) − (3)**. Timestamps are captured manually in `measurement/timing-log.csv`, which the instructor confirmed is sufficient.

**Model inference latency is excluded from triage time and reported separately.** The experiment asks whether the assistant's *output* helps an analyst triage faster, not how fast an 8B model runs on a laptop CPU. Local llama3.1 inference took ~60 seconds per alert (strict run); the hosted GPT-5.5 median was ~11 seconds (§9.8). Counting that latency as "triage time" would measure the test hardware rather than the assistant. Accordingly, assistant outputs were **pre-generated in batch** and the analyst was timed reading them — which also means the timed pass required no new inference.

**Corpus design.** Twenty alerts drawn from controlled adversary-simulation and detection-validation runs, including selected Atomic Red Team tests: **14 attack alerts and 6 real false positives** (`measurement/alert-corpus.json`, frozen before measurement). The six false positives are genuine historical alerts from the tuning history (security-tooling LSASS reads, an Edge Run-key write, a dconf setuid change, a snapd unit write, a cron `/etc/shadow` read). **This salt is the methodological core of the experiment:** without false positives, an assistant that confirms everything scores 100% and the measurement is worthless.

### 9.2 What the assistant cannot change
MTTD median is **2.32 seconds** across the 20 unique alerts. In a single-host lab with real-time agent forwarding, detection latency is essentially instantaneous and is a property of the *detection rules*, not the assistant. The assistant cannot alter the attack timestamp or the alert-generation timestamp, and this report makes no claim that it improves MTTD. Its measurable value lies entirely in the analyst workflow after the alert is seen.

*(One alert, A10, shows a sub-second negative MTTD caused by clock skew between `win-victim` and `wazuh-siem`; it is floored to zero and annotated in the timing log. NTP synchronisation would remove it.)*

### 9.3 Two views — and the label leakage we removed
The corpus alert carries the rule's own ATT&CK label in three places: `mitre.id`, a T-code inside `rule_description`, and detection-authored key fields such as `audit.key = "t1053_003_cron"`. If the model sees any of these, "did it return the right technique?" only tests whether it can **copy a label**. The assistant therefore supports two views, applied after redaction:

- **operational** — the full alert including rule metadata. Realistic for a Wazuh-integrated assistant; the technique metric here is *ATT&CK metadata consistency*, not classification.
- **evaluation** — a strict, label-reduced view that removes the detection-authored label fields (`mitre`, `rule_id`, `rule_description`, `evidence_file`, and the `audit.key` detection label), strips technique codes from remaining strings, and drops any other key-shaped field only when its value is itself a technique code — so legitimate raw evidence such as a `registry.key` is preserved. A regression test (`tests/test_views_leakage.py`) asserts that the tested ATT&CK-code and detection-label classes are removed from all 20 corpus alerts (zero technique codes, any case or separator, survive); raw evidence (executable, command, path, user, registry object, access mask, syscall) is retained. *This removes the tested leakage classes for these 20 alerts; it is not a proof of semantic label-freeness for arbitrary future alerts. An earlier version leaked through `audit.key` and `rule_description`; the figures below are from the corrected strict label-reduced view.*

Technique accuracy on the 14 attack alerts:

| Model | exact — operational | exact — reduced | relaxed — operational | relaxed — reduced |
|---|---|---|---|---|
| llama3.1:8b | **14/14** | **1/14** | 14/14 | **1/14** |
| qwen3:8b | **14/14** | **2/14** | 14/14 | **5/14** |
| gpt-5.5 | 11/14 | **8/14** | 14/14 | **12/14** |

**Removing the label is decisive, and model-dependent.** llama3.1's exact and relaxed technique accuracy both fall from 14/14 to **1/14**; qwen3:8b falls from 14/14 to **2/14 exact and 5/14 relaxed**. Both local 8B models therefore relied heavily on rule-authored metadata under their tested configurations. GPT-5.5 falls only 11→8 exact and 14→12 relaxed. The methodological point is the stronger one: **our first "evaluation" figure (7/14 for llama) was itself inflated by residual leakage we had not caught**, and only a strict label-reduced view, verified for the tested alert classes, exposed how total the reliance was. These are one accepted matched pair per comparison model, not causal estimates of model capability.

The matched llama3.1 automated comparison uses operational run `20260715_060542_ollama_oper_baseline` and strict run `20260718_180713_ollama_eval_baseline`; both record prompt version `23185744b88f77b7` and redaction version `3a527e33fa159616`. The accepted post-v1 qwen3:8b extension uses `20260830_054251_ollama_oper_baseline` and `20260830_070142_ollama_eval_baseline`, executed on commit `7ca2543` with the same prompt version and redaction version `cf0549f832d13b7f`. This is distinct from the earlier llama operational run used for the manual grounding worksheet (§9.5).

*(Technique credit is **exact-ID overlap** — the assistant's technique set overlaps the ground-truth set — not full-set exact matching.)*

### 9.4 Disposition on the benign salt — the decisive comparison
Disposition assigned to the six benign false positives, strict label-reduced view:

| Model | confidently wrong (`likely_true_positive`) | hedged (`needs_investigation`) | correct (`likely_benign`) | disposition (all 20) |
|---|---|---|---|---|
| llama3.1:8b | 4 | 2 | **0** | 14/20 |
| qwen3:8b | 2 | 3 | **1** | 14/20 |
| gpt-5.5 | 0 | 3 | **3** | **16/20** |

**llama3.1 never returns "benign"** (0/6), confidently confirming four of the six outright. Qwen clears one, hedges three and confidently misclassifies two; its sole strict-view attack false negative is A10. **GPT-5.5 confidently clears three and refers the other three to "needs investigation," confidently misclassifying none.** A `needs_investigation` call is *not* a correct benign disposition under our scoring — it is safer than a confident true-positive but leaves the alert unresolved. In the operational view, Qwen clears 0/6 and GPT-5.5 clears 5/6. Strict disposition is 14/20 for both local 8B models and 16/20 for GPT-5.5.

**Interpretation, bounded.** The benign result is **not an inherent property of LLM triage**; it varies by model, view and inference configuration. The experiment does not isolate model capability as the sole cause — the three conditions differ in scale, training, reasoning configuration, hosting and sampling, and each comparison is one accepted pair rather than a distribution (§9.8 caveat).

This inverts the pilot's purpose: false positives *are* the alert-fatigue workload the brief set out to cut. An assistant that rubber-stamps them works against that goal; one that clears or flags them without false confidence supports it.

### 9.5 Grounding of the free-text deliverables
Automated scoring (§9.2–9.4) covers only the technique tag and disposition. A grounding review scored all 20 **operational** outputs of each model on six dimensions: whether every summary line is supported by the alert, the number of unsupported statements, whether the investigation queries are valid (runnable) and relevant, whether the draft user message is appropriate, and whether stated confidence is calibrated to the evidence. `queries_valid` is an all-or-nothing, target-aware set verdict: every suggested query must be executable against its stated target as written. For Wazuh/OpenSearch Discover, indexed alert fields use `data.audit.*` / `data.win.*`; rule-decoder names (`audit.*` / `win.*`), prose, undefined pseudo-SQL, and incomplete or unsafe shell fragments fail. This tightens the initial syntax-only interpretation and was applied uniformly across all three worksheets. The source runs are `20260713T115729Z_ollama_operational` for llama3.1 (legacy prompt version `88b9c3f1656b683b`), `20260717_073045_openai_oper_baseline` for GPT-5.5 (prompt version `23185744b88f77b7`) and `20260830_054251_ollama_oper_baseline` for qwen3:8b (the same prompt version but redaction version `cf0549f832d13b7f`). The llama worksheet therefore evaluates an earlier operational output sample than the matched 14/14→1/14 automated comparison in §9.3; its free-text verdicts must not be attributed to the later `20260715_060542` run.

| Dimension | llama3.1:8b | qwen3:8b | gpt-5.5 |
|---|---:|---:|---:|
| Summary fully supported | 12/20 (8 partial) | 12/20 (8 partial) | **20/20** |
| Unsupported statements (total) | 9 | 8 | **0** |
| Investigation queries valid / runnable | **0/20** | **0/20** | **15/20** |
| Investigation queries relevant | 20/20 | 20/20 | 20/20 |
| Draft user message appropriate | 17/20 | 18/20 | **20/20** |
| Confidence calibrated | 13/20 | 18/20 | **20/20** |

All three worksheets began as human-authored reviews and then received the same evidence-led Codex second pass against the complete operational prompt. Each CSV and Markdown worksheet records the dimensions changed per alert. On 2026-08-31, the human reviewer explicitly approved every second-pass change: four llama rows (A07, A08, A16 and A20), five GPT rows (A01, A04, A08, A16 and A17), and the previously reviewed Qwen corrections. The tallies above are therefore final for these retained samples. This agent-assisted audit remains one human adjudication process, not an independent second human review.

The gap remains decision-relevant. **llama3.1's investigation queries are 0/20 runnable** and nine unsupported statements appear across eight partial summaries, including incorrect syscall semantics, an unsupported LSASS-memory-read claim and a misdescription of `/var/log/btmp` as an audit log. GPT-5.5 keeps 20/20 supported summaries, appropriate drafts and calibrated confidence, but five investigation sets use rule-language `audit.*` or `win.*` names instead of the indexed Wazuh `data.audit.*` / `data.win.*` paths, reducing runnable sets to **15/20**. Qwen has 12/20 fully supported summaries and 0/20 runnable query sets. The worksheets and per-alert provenance are in `measurement/grounding/`.

### 9.6 Prompt mitigation experiment — and its cost
A second system prompt (`benign_aware`) adds explicit *disposition discipline*: it legitimises `likely_benign` as an expected outcome and asks the model to weigh a benign explanation — acting process, account context, expected behaviour, parameter plausibility — before deciding, with a balance clause forbidding it from explaining away real threats. It teaches **general tradecraft and names no corpus alert**, which is the line between prompt engineering and teaching to the test. Both prompts are retained and each run logs a distinct prompt-version hash, so the A/B is auditable.

**View-version caveat.** This A/B used the recorded operational view and the first evaluation transform, before the stricter leakage correction described in §9.3. Its within-transform prompt comparison remains informative, but its evaluation figures are **not strict label-reduced results** and should not be compared directly with the corrected strict-view technique figures in §9.3.

**Result: partial improvement, with a real cost.** Confident over-confirmation on the benign set fell from 6/6 to 2/6 (operational) and 6/6 to 1/6 (evaluation). But in the evaluation view the prompt also produced a **false negative — A06, a genuine attack, classified `likely_benign`**. Pushing a small model toward benign recall began costing attack recall, which in a SOC is the worse error. The prompt also introduced one additional invalid-JSON response.

This is reported as a no-free-lunch trade-off rather than a fix. On this evidence, neither prompt is deployable for false-positive triage: the baseline never identifies a false positive, and the benign-aware variant only starts to do so at the price of missing an attack.

### 9.7 Triage-time impact
Twenty alerts triaged unassisted, then re-triaged after a washout with the pre-generated `llama3.1` output visible, in randomised order (protocol and threats to validity: `measurement/assisted-timing-protocol.md`).

| | n | unassisted median | assisted median | paired delta (median / mean / range) | faster on |
|---|---|---|---|---|---|
| Attacks (assistant correct) | 14 | 11.43 min | 8.00 min | **−3.43 / −3.58 / [−7.50, −2.10]** | 14 of 14 |
| Benign FPs (assistant wrong) | 6 | 5.58 min | 7.70 min | **+1.68 / +1.59 / [+0.97, +2.47]** | 0 of 6 |
| Aggregate | 20 | 10.50 min | 8.00 min | — | 14 of 20 |

**The aggregate −24% is the average of two opposite effects and is not reported alone.** In this sample all 14 attack alerts — on which the assistant's disposition was correct — were triaged faster, while all six benign alerts — on which it was incorrect — were triaged more slowly. **Because alert class and assistant correctness coincide, this demonstrates an association, not an independent causal effect of correctness.** The per-alert paired cost on false positives is a **median +1.68 min** (mean +1.59), distinct from the +2.12 difference of group medians.

The analyst's contemporaneous notes corroborate the split independently: every "AI reduced triage time" note is an attack and every "AI increased triage time" note is a false positive, with the same mechanism — the assistant asserted a confident true-positive the analyst then had to *disprove*.

**Accuracy did not degrade: 20/20 in both conditions.** In this single-analyst study, mandatory review absorbed all six incorrect dispositions, at the measured paired cost above. This observation does not establish how reliably the safeguard would perform under production workload or with a less environment-familiar analyst. No timed assisted pass was run with Qwen or GPT-5.5, so no triage-time figure is claimed for either; what the timing establishes is the conditional *structure* (assistant value tracks assistant correctness), not a per-model number.

### 9.8 Summary of measured impact

| Measure | Unassisted | Assisted (`llama3.1`) | Verdict |
|---|---|---|---|
| MTTD (median, 20 unique alerts) | 2.32 s | 2.32 s | Unchanged — not the assistant's to move |
| Triage time, attacks (median) | 11.43 min | 8.00 min | Assistant helps (−30%) |
| Triage time, false positives (median) | 5.58 min | 7.70 min | Assistant hurts (paired +1.68 min) |
| Analyst disposition accuracy | 20/20 | 20/20 | Unchanged — human review absorbed 6 AI errors |

| Assistant quality (strict label-reduced view) | `llama3.1:8b` | `qwen3:8b` | `gpt-5.5-2026-04-23` |
|---|---|---|---|
| Technique, attacks — exact / relaxed | 1/14 · 1/14 | 2/14 · 5/14 | **8/14 · 12/14** |
| Disposition (all 20) | 14/20 | 14/20 | **16/20** |
| Benign FPs cleared (strict view) | **0/6** | **1/6** (+3 hedged, 2 wrong) | **3/6** (+3 hedged, 0 wrong) |
| Free-text summary fully supported (grounding) | 12/20 (8 partial) | 12/20 (8 partial) | **20/20** |
| Investigation queries runnable (grounding) | **0/20** | **0/20** | **15/20** |
| Attacks classified benign (false negatives) | 0 | 1 (A10) | 1 (A18 — §11) |
| Valid JSON, matched operational+eval runs | **40/40** | **40/40** | **40/40** |

The grounding rows are from the separately identified **operational-view** review (§9.5). They are not strict-view grounding scores, and the llama grounding worksheet uses the earlier `20260713T115729Z` output sample rather than the matched operational comparison run. All second-pass grounding changes were explicitly approved by the human reviewer on 2026-08-31.

#### Usage and latency — matched strict-view runs

| Strict label-reduced view (20 calls per model) | `llama3.1:8b` local | `qwen3:8b` local | `gpt-5.5-2026-04-23` hosted |
|---|---:|---:|---:|
| Prompt tokens, median | 963.5 | 1,522.0 | 970.0 |
| Completion tokens, median | 218.5 | 306.0 | 786.5 |
| Reasoning-token subset, median | Not separately reported | Not separately reported | 337.5 |
| Estimated visible completion tokens, median | 218.5 | 306.0 | 419.5 |
| Total tokens, median | 1,182.5 | 1,811.0 | 1,708.5 |
| End-to-end call latency, median | 60.37 s | 168.21 s | **10.66 s** |
| Sum of call latency, 20 alerts | 21.18 min | 59.83 min | **3.81 min** |

For GPT-5.5, `completion_tokens` includes the separately reported reasoning-token subset; “estimated visible completion” is therefore calculated as completion minus reasoning. Ollama reported `reasoning_tokens: null` for both local models, so their visible estimates use the completion count unchanged. That means **not separately reported**, not “the model did not reason.” Token counts are provider-tokenizer-specific usage measures and should not be compared as if one token had identical meaning across models.

**Comparison fairness.** Across all three strict runs, all 20 `input_hash` and serialized `redacted_prompt_hash` values match and use prompt version `23185744b88f77b7`. Llama and GPT record redaction version `3a527e33fa159616`; Qwen records `cf0549f832d13b7f`, but the matching prompt hashes establish that this version change did not alter these 20 serialized model inputs. Token counts do not establish equivalence. This remains an **exploratory system-level comparison, not a controlled model benchmark**: model scale, architecture, training, tokenizer, reasoning configuration, hosting, output budgets and sampling behaviour differ simultaneously. Qwen's explicit seed did not make outputs invariant across retained candidate/final runs. The association between reported token use and quality is not causal. Latency is the observed end-to-end call time on this laptop CPU and hosted service, not an intrinsic model-speed ranking. Full derivation and re-runnable computation: `measurement/analysis.ipynb` and `measurement/verify_frozen_evidence.py`.

## 10. AI disclosure

| Tool / model | Used for | How output was verified |
|---|---|---|
| **`llama3.1:8b` via Ollama** (local, `temperature=0`) — primary measured artifact | The assistant: alert summarisation, ATT&CK tagging, suggested queries, draft user messages; and the assisted-timing pass | Every output scored against frozen corpus ground truth (controlled simulations and historical false positives) on separated technique/disposition/consistency metrics; all responses retained verbatim in per-run audit logs and re-derivable offline. Ran locally — **no alert content left the lab**. The two recorded runs were byte-identical. |
| **`qwen3:8b` via Ollama** (local, `temperature=0.6`, `top_p=0.95`, seed 42, structured output) — post-v1 comparison artifact | The same four outputs on the same frozen corpus and both views, adding a second local 8B condition | The accepted pair ran on committed code, produced 40/40 schema-valid responses, and is pinned by normalized audit hashes, manifests, model digest and effective request configuration. The explicit seed did not establish determinism across retained candidate/final runs. No alert content left the lab. |
| **`gpt-5.5-2026-04-23` via OpenAI** (hosted, pinned snapshot, `max_completion_tokens=25000`, vendor-default reasoning effort) — comparison artifact | Same four outputs, on the same frozen corpus, in both views, to test whether the disposition bias was model-dependent | Scored identically. Temperature is unsupported on reasoning models, so these runs are **stochastic single samples**, reported as such. Redacted alerts (synthetic lab data, no real secrets) were sent to a hosted API — permitted per instructor guidance conditional on the redaction guardrail (§8.3). The audit log records the effective request configuration and the model actually served. |
| **Claude (Anthropic)** | Pair-programming and review aid during development of the assistant package, the measurement design, and drafting of this report | All code executed and tested by the author; every technical claim validated against system behaviour and re-runnable artifacts. No result in this report is an AI assertion — each derives from a committed audit log or timing record. |
| **OpenAI Codex** | Evidence-led second-pass audit of the three operational grounding worksheets, questionnaire update and documentation reconciliation | Every changed verdict dimension is recorded per alert and all were explicitly approved by the human reviewer on 2026-08-31. The agent pass is not represented as an independent human review. |

No real credentials, customer data, or copyrighted content was provided to any model. Lab alerts are synthetic, and the redaction layer (§8.3) strips tested credential patterns before any prompt is constructed. An account-level billing observation of **$1.11** was recorded for the original operational + superseded evaluation pair (42 requests including two preflight calls; 42,562 prompt tokens). Amortised across the 40 scored alert-view calls, that is about **$0.028 per scored call**, or **$0.056 per unique corpus alert across two views**. It does **not** price the later corrected strict-view rerun, and the repository logs do not retain the historical tariff or an invoice line item, so this cost is not independently reconstructible from token counts alone. Prompts, prompt-version hashes, model versions and raw responses for every reported number are committed under `assistant/outputs/runs/` and integrity-checked by SHA-256 (run manifest, Appendix A.1).

---

## 11. Limitations & threats to validity

**Measurement**

- **ATT&CK label leakage (identified in our own method).** The operational view shows the model the rule's own label, so 14/14 operational exact scores for llama3.1 and qwen3:8b do not establish independent classification. A first llama "evaluation" view still leaked labels through `audit.key` and `rule_description`; only a strict label-reduced view (verified for the tested alert classes) exposed the honest figures — **1/14 for llama3.1, 2/14 for qwen3:8b and 8/14 for GPT-5.5**. This report leads with the label-reduced number. §9.3.
- **Self-generation bias.** The analyst authored the attacks and therefore knew the ground truth. The unassisted 20/20 disposition accuracy is an optimistic ceiling that a real Tier-1 analyst on unfamiliar traffic would not reach, and it means the assistant could only match or worsen accuracy, never improve it. The six deliberately deceptive false positives partially counter this, but do not eliminate it.
- **Learning effect — with its bias direction stated.** The assisted pass is a second exposure to the same corpus; a washout period and randomised order mitigate but do not eliminate familiarity. Critically, this confound biases **toward** an apparent assistant speed-up — so the finding that the assistant *slowed down* false-positive triage is robust despite a learning tailwind. The categorical 14-of-14 versus 0-of-6 split is also not explicable by memory, which would not align itself with assistant correctness.
- **Small n, single analyst, single environment; three models, one accepted pair per comparison condition.** The `llama3.1` outputs were byte-identical across the two recorded runs at `temperature=0`; the hosted GPT-5.5 runs are one stochastic sample per view; qwen3:8b used an explicit seed but retained candidate/final runs still differed. Seeded or temperature-zero inference does not guarantee determinism. Results are directional, not statistically powered.
- **Inference latency excluded from triage time** by design (§9.1) and reported separately. Defensible, but it means the reported triage times assume production-grade inference the lab did not have.

**Assistant**

- **Corpus construct validity — A18.** Under the frozen ground truth, A18 is a scored false negative for GPT-5.5: a real encoded-PowerShell attack it classified `likely_benign`. Manual adjudication indicates a likely simulation artifact — the model decoded the Base64 itself (the plaintext was never in the prompt) and reported that the payload decodes to *"AlertMind Encoded PowerShell Test"*. It was correct about the artifact in front of it; the alert is labelled an attack only because we generated it as a simulation, and our payload announces itself as a test. `llama3.1` called A18 an attack but could not decode the payload — arguably right for the wrong reason. **This must not be read as evidence that GPT-5.5 would safely handle a genuinely malicious encoded-PowerShell payload**, since a real adversary would not label the payload a test. It is direct evidence for the self-generation bias above, and at least one of our 14 "attack" labels is arguably contestable.
- **Qwen strict-view false negative — A10.** qwen3:8b classified the Word-to-command attack as benign under the strict view, so the accepted result includes one attack false negative. Unlike A18, this is not treated as a construct-ambiguous sensitivity case.
- **Scoring convention penalises defensible behaviour.** A correctly-identified benign alert that still names the matching technique fails **both** `technique_relaxed_correct` (benign rows require a null technique) **and** `response_consistent` (`likely_benign` + a technique is defined as contradictory). The two rules jointly preclude overall credit — relaxing either alone changes nothing. GPT-5.5 does exactly this five times (e.g. `T1547.001` + `likely_benign` for the Edge Run-key write), which is arguably what a good analyst does and was never forbidden by the prompt. The convention was fixed before results and is reported as defined rather than adjusted post-hoc, but it means the headline `overall` metric under-represents GPT-5.5's disposition gain.
- **Hosted runs are stochastic single samples.** Reasoning models reject `temperature`, so the GPT-5.5 figures are one draw per view, not a distribution. The snapshot is pinned so the model version is held constant, but sampling variance is uncharacterised.
- **Redaction is risk reduction, not a guarantee.** Tested credential classes are removed (0/7 planted secrets leaked); unknown, encoded or unlabelled secrets remain a residual risk. Encoded PowerShell is not decoded before redaction, and hash handling is not yet context-aware.
- **Prompt injection remains a model-layer risk.** Markers are visible and delimiter injection is blocked, but legitimate fields can still influence the model. Schema validation cannot prove a correct disposition; redaction, no-action architecture and human review contain rather than eliminate this risk.
- **Hallucination scope.** The ATT&CK tag and disposition are scored automatically; the summary, queries and draft message received a human-authored first pass plus a provenance-recorded agent-assisted second pass (§9.5). One human remains the final adjudicator, so this does not supply inter-rater reliability; automation and a second independent human reviewer remain future work.
- **Small-model JSON reliability.** An earlier llama3.1 run and the retained Qwen pilots show malformed/truncated-output risk. The accepted matched pairs are 40/40 valid for all three models, with Qwen using an Ollama-compatible structured-output schema plus unchanged runtime validation. No post-hoc retry was added to the measured runs.
- **Automation bias.** The assistant's confident-but-wrong dispositions cost the analyst ~2 minutes each to overturn. An analyst under production time pressure, or one less familiar with the environment, might accept them — in which case accuracy, not just speed, would degrade. This experiment cannot measure that risk with a single expert analyst who built the lab.

**Build**

- **Single-node SIEM** — no HA or clustering; lab-appropriate, not production scale.
- **Synthetic alerts only** — detection precision is characterised against frozen corpus ground truth (controlled simulations and historical false positives), not real-world base rates; false-positive behaviour on production traffic is unknown.
- **Known false positive** — rule 100100 fires on legitimate `cron` reads of `/etc/shadow`; the tune (scoping to `auid>=1000`) is planned and reported rather than hidden.
- **Cloud source** — a static sample rather than live ingestion; confirmed acceptable, and part of the optional 3-source stretch rather than the solo minimum.

---

## 12. Conclusion & future work

**What was built.** An end-to-end mini-SOC in an isolated lab: Wazuh with Windows Sysmon and Linux auditd telemetry, an ATT&CK-mapped detection pack verified firing end-to-end with its tuning history documented, two dashboards, three NIST SP 800-61 playbooks, and a guardrailed LLM tier-1 assistant whose guardrails are enforced in code and proved by re-runnable tests rather than asserted in prose. Streamlit **Paste & inspect** adds ad hoc, redacted triage with injection visibility, egress consent and sanitized audit evidence; it remains outside the frozen benchmark.

**What the measurement showed.** The assistant's value is **conditional on its correctness, and its failures are not neutral — they are actively costly**. Speed tracked correctness exactly: −30% on all 14 alerts it got right, +38% on all 6 it got wrong, 20 out of 20 with no exceptions. The aggregate "−24% faster" that a less careful evaluation would have reported is the average of two opposite effects.

**And the observed failure mode changed materially with model and inference configuration.** The submitted llama3.1 condition never returned "benign" (0/6). The post-v1 Qwen extension also cleared 0/6 operationally and only 1/6 strict, while hosted GPT-5.5 cleared 5/6 operationally and 3/6 strict, hedging the other three without confidently misclassifying a benign alert. Thus the failure is **model-, view- and configuration-dependent, not intrinsic to LLM triage**. The result exists because the corpus was salted with real false positives and scored on separated metrics. Each comparison is one accepted pair, and the assisted-timing pass was not repeated with Qwen or GPT, so no timing benefit is claimed for either.

**What a real SOC should take from this pilot.** Four things.

1. **The deployment gate is not "is it fast?" — it is "is it right on the alerts you would otherwise dismiss?"** Measured on that gate, the three conditions diverge: llama3.1 clears 0/6 strict, Qwen 1/6, and GPT-5.5 3/6 plus three hedged (5/6 operationally). Choose a candidate on the false-positive test, not the headline aggregate.
2. **Evaluate on a benign-salted corpus, or you will measure nothing.** Had the corpus contained only real attacks, the 8B assistant would have scored ~100% and been judged a success. The six false positives are what exposed the failure — and what later showed the GPT-5.5 configuration substantially reducing it in this sample.
3. **Human review is not free, and it can be priced.** In this single-analyst study, review absorbed all six model errors, so observed accuracy did not degrade. It cost about two minutes per false positive: the number to weigh against the time saved elsewhere.
4. **A rigorous evaluation audits itself, not just the model.** This one caught two defects in its own instruments: an ATT&CK label leaking into the input and inflating accuracy (14/14 → 1/14 once rigorously removed), and a synthetic corpus whose payload announced itself as a test — which only became visible when a model capable enough to decode it disagreed with our ground truth (A18, §11). Both were reported rather than repaired after the fact.

**Future work.**

- **Close the measurement's own gaps first.** A larger, independently-generated corpus — with payloads that do not self-identify as tests — would remove the self-generation bias and the A18 construct-validity problem; the learning effect additionally requires fresh alerts per condition, a between-subject design, or a properly counterbalanced crossover (a second analyst alone does not remove it). These are the biggest threats to validity in this report.
- **Test model-family generality at comparable local scale.** Pre-register a second 7–9B local instruct model and run the same corpus, strict/operational views, prompt, sampling setting, hardware, automated scoring and six-dimension manual grounding rubric. That experiment would test whether llama3.1's 0/6 benign result is model-specific; adding an ungrounded third column late would create apparent breadth without equivalent evidence.
- **Characterise the frontier result properly.** Repeat the hosted runs to estimate sampling variance, re-run the assisted-timing pass with that model to test whether the +38% false-positive penalty disappears as the mechanism predicts, and reconsider the pre-registered convention that a benign disposition must carry no technique tag.
- **Harden the assistant:** broaden redaction (Basic auth, JWTs, `ghp_`/`xoxb-` tokens, URL credentials, decode-then-redact for encoded PowerShell), make hash handling context-aware, automate the output-grounding rubric across all four deliverables, and repeat it with an independent human reviewer.
- **Enforce an injection-response policy:** quarantine high-confidence detections by default; require an explicit, reasoned and audited analyst override before model submission.
- **Stretch goals:** an ML severity scorer with LLM-explained scores; one approval-gated auto-remediation action; live cloud ingestion as a third source.

---

## 13. References
- MITRE ATT&CK (Enterprise matrix) — https://attack.mitre.org
- NIST SP 800-61 Rev. 2, *Computer Security Incident Handling Guide* — https://csrc.nist.gov/pubs/sp/800/61/r2/final
- NIST Cybersecurity Framework 2.0 — https://www.nist.gov/cyberframework
- Wazuh 4.14 documentation — https://documentation.wazuh.com
- Sysmon (Sysinternals) — https://learn.microsoft.com/sysinternals/downloads/sysmon
- SwiftOnSecurity `sysmon-config` — https://github.com/SwiftOnSecurity/sysmon-config
- Sigma / pySigma detection format — https://github.com/SigmaHQ/sigma
- Atomic Red Team — https://github.com/redcanaryco/atomic-red-team
- Ollama (v0.32.1) — https://ollama.com · Llama 3.1 model card — https://ollama.com/library/llama3.1
- OpenAI GPT-5.5 (snapshot `gpt-5.5-2026-04-23`) — https://developers.openai.com/api/docs/models/gpt-5.5
- Streamlit — https://streamlit.io

---

## 14. Appendices

### A. Evidence index
Every ✅ claim in this report maps to a captured artifact. (Consistent with README §7a.)

| Evidence ID    | What it proves                                                      | File / screenshot                                                |
| -------------- | ------------------------------------------------------------------- | ---------------------------------------------------------------- |
| EVID-WAZUH-001 | Wazuh services + ports healthy                                      | `evidence/week1/wazuh-services-ports.png`                        |
| EVID-WIN-001   | Sysmon EID 1 process creation ingested                              | `evidence/week1/win-sysmon-eid1-whoami.png`                      |
| EVID-WIN-002   | Windows service creation (7045 → rule 61138, T1543.003)             | `evidence/week1/win-system-7045-service.png`                     |
| EVID-LIN-001   | Linux user creation detected                                        | `evidence/week1/linux-useradd-t1136.png`                         |
| EVID-LIN-002   | auditd `/etc/shadow` rule 100100 fired (T1003.008)                  | `evidence/week1/linux-shadow-t1003-008.png`                      |
| EVID-LIN-004   | User/group DB modification, rule 100101 (T1136 / T1098)             | `evidence/week2/lin_100101-useradd-T1136-T1098.png`              |
| EVID-LIN-005   | sudoers tampering, rule 100102 (T1548.003)                          | `evidence/week2/lin_100102-priv_escalation-T1548_003.png`        |
| EVID-LIN-006   | Cron persistence, rule 100103 (T1053.003)                           | `evidence/week2/lin_100103-scheduled_task-T1053_003.png`         |
| EVID-LIN-007   | systemd persistence, rule 100104 (T1543.002)                        | `evidence/week2/lin_100104-systemd_persistence-T1543_002.png`    |
| EVID-LIN-008   | Init-script modification, rule 100105 (T1037)                       | `evidence/week2/lin_100105-init_script_modification-t1037.png`   |
| EVID-LIN-009   | Shell-init modification, rule 100106 (T1546.004)                    | `evidence/week2/lin_100106-shell_init-T1546_004.png`             |
| EVID-LIN-010   | LD_PRELOAD hijack (ld.so.preload), rule 100107 (T1574.006)          | `evidence/week2/lin_100107-ld_preload-T1574_006.png`             |
| EVID-LIN-011   | Kernel module / LKM rootkit, rule 100108 (T1547.006 / T1014)        | `evidence/week2/lin_100108-lkm_rootkit-T1547_006-T1014.png`      |
| EVID-LIN-012   | setuid/setgid change, rule 100109 (T1548.001 / T1222.002)           | `evidence/week2/lin_100109-setuid_bit_change-T1548_001.png`      |
| EVID-LIN-013   | auditd config tampering, rule 100110 (T1562.001)                    | `evidence/week2/lin_100110-auditd_config_T1562_001.png`          |
| EVID-LIN-014   | Session-log tampering, rule 100111 (T1070)                          | `evidence/week2/lin_100111-session_log_modification-t1070.png`   |
| EVID-LIN-015   | Timestomping, rule 100112 (T1070.006)                               | `evidence/week2/lin_100112-timestamp_modification-t1070_006.png` |
| EVID-LIN-016   | SSH key access, rule 100113 (T1552.004)                             | `evidence/week2/lin_100113-authorized_keys_access-t1552_004.png` |
| EVID-LIN-017   | sshd_config change, rule 100114 (T1098 broad)                       | `evidence/week2/lin_100114-sshd_access-t1098.png`                |
| EVID-LIN-018   | Package/repo config change, rule 100115 (T1195.001)                 | `evidence/week2/lin_100115-update_repo_config-t1195_001.png`     |
| EVID-LIN-003   | SSH `authorized_keys` persistence, rule 100116 fired (T1098.004)    | `evidence/week2/linux-authorized-keys-t1098-004.png`             |
| EVID-WIN-003   | Encoded PowerShell, rule 100201 fired (T1059.001)                   | `evidence/week2/win_100201-powershell-T1059-001.png`             |
| EVID-WIN-004   | LOLBin execution, rule 100202 fired (T1218)                         | `evidence/week2/win_100202-lolbin-T1218.png`                     |
| EVID-WIN-005   | Run-key persistence, rule 100205 fired (T1547.001)                  | `evidence/week2/win_100205-runkey-T1547-001.png`                 |
| EVID-WIN-006   | LSASS dump-grade access, rule 100203 fired (T1003.001)              | `evidence/week2/win_100203-Lsass_Access-T1003_001.png`           |
| EVID-RULES-001 | `local_rules.xml` validates + loads clean                           | `evidence/week1/wazuh-rules-load.png`                            |
| EVID-WIN-007   | Office spawns shell, rule 100200 fired (T1566 / T1059)              | `evidence/week2/win_100200-office_shell-T1566_T1059.png`         |
| EVID-WIN-008   | PsExec service execution, rule 100204 fired (T1021.002 / T1569.002) | `evidence/week3/win_100204-PsExec-T1021_002.png`                 |
| EVID-WIN-009   | DNS tunneling, rule 100206 fired (T1048 /T1071.004)                 | `evidence/week3/win_100206-DNS_tunneling-T1071_004.png`          |
| EVID-WIN-010   | Windows service creation (4697)                                     | `evidence/week1/win-system-4697-service.png`                     |

**SIEM, assistant, dashboard, playbook and measurement evidence:**

| Evidence ID | What it proves | File / screenshot |
|---|---|---|
| EVID-WAZUH-RET-001 | `wazuh-alert-retention-policy` exists; 90-day alert-retention policy updated 29 Jul 2026 | `evidence/week3/wazuh-alert-retention-policy-90d.png` |
| EVID-WAZUH-RET-002 | 21 `wazuh-alerts-4.x-*` indices attached in `retention_state`; transition evaluation running | `evidence/week3/wazuh-alert-retention-managed-indices.png` |
| EVID-DASH-001 | Daily SOC-briefing dashboard | `evidence/week3/dashboards_alertmind-daily-brief.png` |
| EVID-DASH-002 | ATT&CK heatmap dashboard | `evidence/week3/dashboards_alertmind-ATT&CK-heatmap.png` |
| EVID-PLAYBOOK-001 | Phishing playbook (NIST 800-61r2) | `playbooks/phishing.md` |
| EVID-PLAYBOOK-002 | Malware playbook | `playbooks/malware.md` |
| EVID-PLAYBOOK-003 | Account-compromise playbook | `playbooks/account-compromise.md` |
| EVID-AI-REDACT-001 | 0/7 planted secrets leak; file-hash IOC preserved | `assistant/outputs/redaction_proof.md` |
| EVID-AI-INJECT-001 | Injection indicators detected; one recorded model response did not comply with the planted instruction (not a general prevention claim) | `assistant/outputs/injection_proof.md` |
| EVID-AI-PASTE-001 | Paste pipeline: limits, redaction trace, endpoint-aware consent, schema/audit semantics and no raw-input persistence | `assistant/tests/test_paste_pipeline.py`, `assistant/tests/test_adhoc_audit.py` |
| EVID-AI-PASTE-002 | Instruction markers detected in keys and values; reserved boundary-delimiter attempts blocked before a model call | `assistant/tests/test_injection_markers.py`, `assistant/outputs/paste_demo_injection_proof.md` |
| EVID-AI-PASTE-003 | Redaction trace covers tested secret patterns and non-string sensitive values without retaining unsalted secret hashes | `assistant/tests/test_redaction_trace.py`, `assistant/outputs/paste_demo_redaction_proof.md` |
| EVID-AI-PASTE-004 | Paste-tab stale-state, consent-reset and invalid-input behaviour | `assistant/tests/test_paste_ui.py` |
| EVID-AI-UI-001 | Analyst vs Evaluator UI modes | `evidence/week3/assistant-ui-analyst-mode.png` |
| EVID-AI-LLAMA-OP-001 | llama3.1 matched operational baseline: 14/14 exact, 14/14 relaxed, 14/20 disposition | `assistant/outputs/runs/20260715_060542_ollama_oper_baseline/` |
| EVID-AI-LLAMA-STRICT-001 | llama3.1 strict label-reduced run | `assistant/outputs/runs/20260718_180713_ollama_eval_baseline/` |
| EVID-AI-LLAMA-GROUND-001 | Earlier llama3.1 operational output sample used by the manual grounding worksheet | `assistant/outputs/runs/20260713T115729Z_ollama_operational/` |
| EVID-AI-GPT-OP-001 | GPT-5.5 operational baseline run | `assistant/outputs/runs/20260717_073045_openai_oper_baseline/` |
| EVID-AI-GPT-STRICT-001 | GPT-5.5 strict label-reduced run | `assistant/outputs/runs/20260718_183704_openai_eval_baseline/` |
| EVID-AI-QWEN-OP-001 | Accepted qwen3:8b operational extension | `assistant/outputs/runs/20260830_054251_ollama_oper_baseline/` |
| EVID-AI-QWEN-STRICT-001 | Accepted qwen3:8b strict label-reduced extension | `assistant/outputs/runs/20260830_070142_ollama_eval_baseline/` |
| EVID-AI-QWEN-MANIFEST-001 | Qwen run provenance, normalized hashes, model digest and effective request configuration | `measurement/run-manifests/` |
| EVID-MEASURE-001 | Timing log + analysis notebook | `measurement/timing-log.csv`, `measurement/analysis.ipynb` |

### A.1 Run manifest (reproducibility)

| Field                   | llama3.1 (strict-reduced) | qwen3:8b (strict-reduced) | gpt-5.5 (strict-reduced) |
| ----------------------- | ------------------------- | ------------------------- | ------------------------ |
| Provider / model        | ollama / llama3.1:8b | ollama / qwen3:8b (`Q4_K_M`) | openai / gpt-5.5-2026-04-23 (pinned snapshot) |
| Run ID                  | `20260718_180713_ollama_eval_baseline` | `20260830_070142_ollama_eval_baseline` | `20260718_183704_openai_eval_baseline` |
| View / prompt           | evaluation / baseline | evaluation / baseline | evaluation / baseline |
| Prompt version hash     | `23185744b88f77b7` | `23185744b88f77b7` | `23185744b88f77b7` |
| Redaction version hash  | `3a527e33fa159616` | `cf0549f832d13b7f` | `3a527e33fa159616` |
| Runtime provenance      | Ollama 0.32.1; historical run-to-commit not claimed | Ollama 0.33.2 observed; commit `7ca2543`; model + audit hashes pinned | Hosted snapshot; historical run-to-commit not claimed |
| Corpus SHA-256 (frozen) | `4e842637f3cbcbb6e0704320824b64bdeb63c7d7ee7e22db0278e4d96c58b929` | (same) | (same) |
| Timing-log SHA-256      | `9ceba8e2468f44e879fa7929e528cfeaaef034ae363ffb66e98f57a21761cb9a` | (same) | (same) |

The historical matched operational runs are `20260715_060542_ollama_oper_baseline` and `20260717_073045_openai_oper_baseline`; both use prompt version `23185744b88f77b7` and redaction version `3a527e33fa159616`. Their audit records contain `git_commit: unknown`, so run-to-commit provenance is not claimed. The accepted Qwen operational run is `20260830_054251_ollama_oper_baseline`; both Qwen manifests pin commit `7ca2543`, newline-normalized audit hashes, the model digest and effective request configuration. The earlier llama grounding source uses prompt version `88b9c3f1656b683b` and is retained separately.

The corpus is frozen (`frozen_at_utc: 2026-07-12T15:30:00Z`, all 20 `t1_attack_utc` populated); the SHA-256 above is over that frozen file. Run directories for all reported runs are committed to the repository.

### A.2 Model cost & privacy comparison

| Property | llama3.1:8b (local) | qwen3:8b (local) | gpt-5.5 (hosted) |
|---|---|---|---|
| Benign FPs cleared (strict-reduced) | 0/6 | 1/6 (+3 hedged, 2 wrong) | 3/6 (+3 hedged) |
| Technique, attacks (strict-reduced, exact-ID/relaxed) | 1/14 · 1/14 | 2/14 · 5/14 | 8/14 · 12/14 |
| Prompt tokens, median (strict run) | 963.5 | 1,522.0 | 970.0 |
| Completion tokens, median (strict run) | 218.5 | 306.0 | 786.5 |
| Reasoning-token subset, median (strict run) | Not separately reported | Not separately reported | 337.5 |
| Estimated visible completion tokens, median (strict run) | 218.5 | 306.0 | 419.5 |
| Total tokens, median (strict run) | 1,182.5 | 1,811.0 | 1,708.5 |
| End-to-end call latency, median / 20-call total (strict run) | 60.37 s / 21.18 min | 168.21 s / 59.83 min | 10.66 s / 3.81 min |
| Data egress | None (local) | None (local) | Redacted synthetic alerts sent to hosted API |
| Direct API cost | $0; local compute/electricity not measured | $0; local compute/electricity not measured | Strict-rerun cost not retained; $1.11 account observation applies to the earlier 42-request pair described in §10 |
| JSON validity (matched operational+eval runs) | 40/40 | 40/40 | 40/40 |
| Reproducibility | Historical local digest; temp=0 pair byte-identical | Digest/config pinned; seed did not make candidate/final outputs invariant | Pinned snapshot; stochastic single sample |
| Deployment implication | Private but weak on FPs | Private; slower here and still weak on FPs | Stronger, but externally hosted |

### A.3 A18 sensitivity analysis

A18 is a scored false negative for GPT-5.5 under the frozen ground truth (a real encoded-PowerShell alert it judged `likely_benign` after decoding the payload to *"AlertMind Encoded PowerShell Test"* — a corpus construct-validity issue, §11). The primary result retains the frozen label. Excluding A18 as construct-ambiguous, GPT-5.5's disposition rises to **18/19 (operational)** and **16/19 (strict label-reduced)**, with **zero attack false negatives in both views**; the model comparison is unchanged in direction and magnitude. A18 is therefore reported as a scored FN, and the conclusion does not depend on it.

### B. Detection rule pack
`siem/wazuh/local_rules.xml` (deployed Wazuh-native rules) · `detections/auditd/alertmind.rules` (auditd ruleset) · `detections/sigma/` (portable Sigma source, 25 rules validated).

### C. Configurations
Agent `ossec.conf` blocks (audit + Windows channels), Sysmon config edit (EID 10), and the implemented 90-day alert-retention ISM policy (EVID-WAZUH-RET-001/002).

### D. Runbooks
`docs/runbooks/wazuh-recovery.md`.

### E. Assistant
Prompt library, redaction module, call logs, redaction proof-test output.

### F. Detection-tuning notes (full detail)

**100116 — authorized-keys (T1098.004).** The rule initially did not fire. Cause: an auditd limitation, not a Wazuh error — two `-w` watches covering the same path (`/root/.ssh/`) cannot both apply their keys, so writes to `authorized_keys` were emitted under the broader `t1552_004_ssh_keys` key and matched only rule 100113. Rather than fight auditd with overlapping watches, 100116 was re-implemented as a child of 100113 (`<if_sid>100113</if_sid>`) narrowing on the `authorized_keys` path. Verified firing end-to-end (EVID-LIN-003).

**100205 — Run-key persistence (T1547.001).** Re-narrowed to exclude `CurrentVersion\RunNotification`, a prefix-match false positive observed in testing.

**100203 — LSASS access (T1003.001).** Three tuning rounds: (1) untuned, it fired ~557 FPs on benign query-only reads; (2) a positive access-mask allowlist missed `0x0xxx` dump masks; (3) the final form excludes the confirmed-benign masks (`0x1000`/`0x1400`/`0x3000`) plus `wazuh-agent.exe` and `MsMpEng.exe` source images. Verified on `rundll32.exe`/comsvcs at `0x1fffff` after setting `RunAsPPL=0` (a real-world pre-condition). *These same benign LSASS reads became false positives A08/A11 in the assistant corpus — the detection tuning and the assistant evaluation are testing the same hard cases.*

**100204 — PsExec service execution (T1021.002/T1569.002).** Detects the default `PSEXESVC.exe` service name and fires on Sysinternals PsExec, but impacket-psexec evades it with a randomly-named binary; the behavioural built-ins 92218/92307/92650 catch that variant. An indicator-vs-behavioural detection lesson.

**100100 — `/etc/shadow` reads (T1003.008).** Fires on legitimate `cron` PAM reads (a false positive); the planned tune scopes the audit rule to interactive users (`auid>=1000`). Retained as the baseline→FP→tuned progression.
