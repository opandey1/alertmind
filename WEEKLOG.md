# WEEKLOG — AlertMind (CAP-SCE-3W)

A short status note per week (written each Saturday, per the program cadence): what shipped, what was blocked and how it resolved, and what carries forward. Chronological — oldest week first.

---

## Week 1 — SOC Foundation
**Dates:** 22–28 Jun 2026 (status as of 26 Jun, week in progress) · **Effort:** ~12h · **Status:** ✅ Infrastructure foundation complete; Linux Wazuh-native rules implemented; Sigma source and cloud sample carried forward

### Shipped
- **Wazuh 4.14.5 SIEM** deployed all-in-one on `wazuh-siem` (Ubuntu). Manager, indexer, and dashboard all healthy; agent/API/indexer/dashboard ports verified listening. Dashboard reachable from the host via the Host-Only adapter; interface binding/hardening (it currently binds `0.0.0.0:443`) is a planned cleanup item. _Evidence: EVID-WAZUH-001._
- **Windows endpoint (`win-victim`)** onboarded: Sysmon 15.21 with the SwiftOnSecurity config + Wazuh agent. Process-create telemetry confirmed (EID 1 → rule 92032). _Evidence: EVID-WIN-001._
- **Linux endpoint (`linux-victim`)** onboarded: auditd + Wazuh agent, both Active.
- **Linux detection pack** authored and deployed: lean `alertmind.rules` (auditd, ATT&CK-keyed) + custom Wazuh rules **100100–100115** chaining off base rule 80700, each MITRE-tagged.
- **End-to-end detection verified:** `cat /etc/shadow` → auditd → Wazuh `auditd` decoder → rule **100100** fires at level 12, tagged **T1003.008**. _Evidence: EVID-LIN-002._
- **Windows telemetry gaps closed:** Sysmon **EID 10 (LSASS)** include populated for T1003.001 and **System/Security** channels enabled (LSASS and 4697 alert validation still pending); service-creation confirmed via **EID 7045 → rule 61138 (T1543.003)**. _Evidence: EVID-WIN-002._
- VMs renamed to the clean scheme (`wazuh-siem` / `win-victim` / `linux-victim`) and **snapshotted clean** (25 Jun, 01:20).
- Repo scaffolded: `README.md`, `architecture/soc-architecture.md`, `architecture/diagram.drawio`, this log, and `report.md` started. _Rules file validates clean: EVID-RULES-001._

### Blocked → resolved
| Issue | Root cause | Resolution |
|---|---|---|
| auditd events not reaching Wazuh | Agent had no `audit` localfile; only journald was ingested | Added `<localfile><log_format>audit</log_format>…</localfile>`; restarted agent |
| Custom auditd events decoded but never alerted | Base rule 80700 is level 0; no child rule matched custom keys | Authored custom child rules 100100–100115 (`if_sid` 80700 + key match) |
| No LSASS / credential-access detection | SwiftOnSecurity EID 10 block is an empty `include` (logs nothing) | Populated `ProcessAccess` include for `lsass.exe` |
| Service-creation (T1543.003) thin | Sysmon doesn't cleanly cover it | Enabled System/Security channels + auditpol for 4697/7045 |
| auditd `No buffer space available` | Stock "best practice" ruleset too heavy (watched absent software, `-S all`) | Replaced with lean, scoped `alertmind.rules`; `lost 0` after |
| Wazuh down after host crash (`CLOCK_WATCHDOG_TIMEOUT`) | Host hardware crash mid-build | Documented recovery sequence → `docs/runbooks/wazuh-recovery.md` |

### Known items carried forward
- **Tune rule 100100:** currently also fires on legitimate `cron` PAM reads of `/etc/shadow` (`auid` unset). Plan: scope the audit rule to `auid>=1000 -F auid!=unset`.
- Sigma YAML source for the rule pack not yet written (at Week 1 close. Resolved in Week 2).
- Cloud telemetry sample source not yet ingested.

### Instructor questions — resolved (clarified 26 Jun)
- **Solo scope:** 7 rules / 2 sources is the requirement; 10 rules / 3 sources (add cloud) only if time permits. → implemented pack already exceeds the minimum.
- **Sigma workflow:** author Sigma YAML for the rubric and manually implement the equivalent Wazuh rules in `local_rules.xml` — approved as a "very good approach."
- **Cloud telemetry:** a static sample file (e.g. from a public dataset) is acceptable; live AWS ingestion is an optional enhancement.
- **Atomic scenarios:** self-chosen (suggested: PowerShell execution, credential dumping, DNS tunnelling).
- **MTTD/MTTR:** manual timestamp tracking acceptable (attack started → alert generated → analyst saw → investigation completed); MTTD counts from the attack time *in the logs*, not ingestion. AI eases reporting/consistency, not the metric values. TheHive optional.
- **Negative results:** honestly-reported negative/neutral findings are expected and acceptable; flag any hallucination transparently. RAG/feedback loop optional.
- **Redaction proof:** stated policy is not enough — a before/after demonstration (original alert with secret → redacted prompt, screenshots) is required.
- **Reproducibility:** graders will `git clone` and rebuild (<1 hr, no troubleshooting). Docker recommended; a clear rebuild guide will accompany the repo.
- **Stretch goals:** no bonus points, but improve project quality, oral defense, and portfolio value.

### Next week (Week 2)
Dashboards (daily SOC briefing + ATT&CK heatmap) · three NIST 800-61 IR playbooks · stand up the Kali attacker · build + run the Atomic Red Team chain · capture the unassisted baseline (after locking the measurement protocol) · write the Sigma YAML sources · apply the 100100 tune.

---

## Week 2 — Dashboards, Playbooks, Baseline
**Dates:** 29 Jun – 8 Jul 2026 (status as of 8 Jul) · **Effort:** ~16h (detection debugging ran long) · **Status:** 🚧 In progress — detection layer complete and fully verified (all Windows + Linux rules); dashboards + IR playbooks shipped; unassisted baseline triage in progress

### Shipped
- **Sigma rule pack** authored and validated: 25 rules (8 Windows + 17 Linux), all pass pySigma; `detections/sigma/notes.md` holds the Sigma → Wazuh crosswalk with honest Verified/Configured status.
- **Detection mappings tightened** after review: keys renamed to precise ATT&CK IDs (`t1195_001_apt_repo_config`, `t1098_sshd_config`), T1222.002 added to the setuid rule, T1569.002 to the PsExec rule, encoded-PowerShell flags expanded.
- **Seven custom Windows Sysmon rules (100200–100206)** authored — each chaining off the relevant built-in Sysmon base rule (EID 1 = 61603, EID 10 = 61612), with 100205 on the Run-key parent 92300 and 100206 on the `sysmon_event_22` group — and **all seven verified firing** (office-spawn, encoded PowerShell, LOLBin, LSASS, PsExec, Run-key, DNS tunnelling). _Evidence: EVID-WIN-003 … EVID-WIN-009._
- **Full Linux custom-rule pack (100100–100116) verified end-to-end** — all 17 rules confirmed firing on 8 Jul via targeted triggers on each watched path, each with a per-rule screenshot + CLI capture. _Evidence: EVID-LIN-002, EVID-LIN-004 … EVID-LIN-018, EVID-LIN-003._
- **Two ATT&CK-aligned dashboards:** a MITRE Navigator layer covering all 30 detected techniques (status-scored) plus a build guide for the Daily SOC Briefing and the in-SIEM ATT&CK heatmap (`siem/dashboards/`).
- **Three NIST SP 800-61 IR playbooks** (phishing, malware, account-compromise): four-phase, role-specific, each mapped to AlertMind rule IDs and Discover queries (`playbooks/`).
- **Atomic attack-chain plan** (`attack/atomic-plan.md`) mapping every rule to a concrete trigger, plus measurement scaffolding (`measurement/timing-log.csv`, `alert-corpus.json`) and the baseline protocol (four timestamps, benign-salted corpus, A/B counterbalancing).

### Blocked → resolved
| Issue | Root cause | Resolution |
|---|---|---|
| Rule 100116 (authorized_keys) not firing | Two overlapping `-w` watches on `/root/.ssh/` collapse to one key; writes were keyed `t1552_004_ssh_keys` | Re-implemented 100116 as a child of 100113 (`if_sid 100113` + `authorized_keys` path narrow) — broad sensor, specific SIEM rule |
| Windows Run-key 100205 not firing (~7 iterations) | Wazuh stores registry paths with doubled backslashes; built-in 92302 outranked it; flaky agent connectivity + duplicate localfile lost test events | Chain off built-in Run-key parent 92300 at level 10; dedupe agent localfile + stabilise connectivity; re-narrow to exclude the `RunNotification` prefix-match FP |
| LSASS 100203 — ~557 false positives, then real dump missed (3 rounds) | Untuned fired on all LSASS access; a positive `0x1xxx` mask allowlist missed common `0x0xxx` dump masks (e.g. `0x0410`) | Negative exclusion of benign masks (`0x1000`/`0x1400`/`0x3000`) + sourceImage exclusion (`wazuh-agent.exe`, `MsMpEng.exe`); `RunAsPPL=0` required for the dump to succeed |
| PsExec 100204 not firing on impacket-psexec | impacket uploads a randomly-named binary/service (not `PSEXESVC.exe`), evading the name-based indicator | 100204 verified on Sysinternals PsExec; behavioural built-ins 92218/92307/92650 catch the impacket variant — indicator-vs-behavioural detection |
| DNS 100206 chain | Direct `if_sid 61624` did not match reliably | Chain from the `sysmon_event_22` group (final working pattern for Sysmon DNS-query events) |

### Known items carried forward
- **Unassisted baseline triage in progress:** freeze `alert-corpus.json` (attacks + salted benign FPs from `Alert_corpus_linux.txt` / `Alert_corpus_windows.txt`) and populate `measurement/timing-log.csv`.
- **Dashboards:** build both in the Wazuh UI and capture screenshots (Navigator layer + build guide done; in-SIEM build pending).
- Rule 100100 `/etc/shadow` `auid` tune still to apply.
- Cloud telemetry sample not yet ingested (optional 3rd source).

### Next week (Week 3)
- LLM assistant + guardrails (redaction before/after proof), assisted measurement vs. this baseline, final report + defense deck.

---

## Week 3 — LLM Assistant + Impact Measurement
**Dates:** 6–19 Jul 2026 · **Effort:** ~20h (measurement + two-model comparison ran long) · **Status:** ✅ Complete — assistant + guardrails shipped, impact measured, label-leakage and two-model findings established

### Shipped
- **Guardrailed LLM tier-1 assistant** built as a dependency-light Python package (providers: mock / ollama / openai / anthropic) with a Streamlit analyst UI. Per-alert pipeline: **redact → apply view → build prompt → call → parse → validate → log (25 fields) → score**, redaction first. Offline `mock` provider runs the whole pipeline with no key/network.
- **Guardrails enforced in code and proved by tests:** redaction before prompt construction (**0/7 planted secrets leaked**), no tools / text-only / analyst-review-required, alert wrapped in an `<ALERT_DATA>` untrusted-data block, and per-run non-overwriting audit logs. _Evidence: EVID-AI-REDACT-001, EVID-AI-INJECT-001._
- **Redaction before/after proof** produced as the instructor required (original secret → redacted prompt), plus an injection-resistance record.
- **Two methodological moves that make the evaluation honest:** a benign-salted corpus (14 attacks + 6 real false positives) and a strict **label-reduced view** that strips the rule's own ATT&CK label. A regression test proves 0/20 alerts leak a technique code.
- **Impact measured vs. the Week-2 unassisted baseline** (pre-generated outputs, washout, randomised order): **MTTD 2.32 s** (detection property, unchanged by the assistant); triage time −30% on attacks, +1.68 min paired on false positives; analyst accuracy 20/20 in both conditions.
- **Two-model comparison** (`llama3.1:8b` local vs `gpt-5.5-2026-04-23` hosted) on the frozen corpus, both views. Headline findings: label removal collapses llama's matched attack-technique score 14/14 → **1/14** (gpt 11/14 → 8/14); benign disposition **0/6** (llama) vs 5/6 operational / 3/6 strict (gpt); and a manual **grounding review** (gpt 20/20 all dimensions; llama 0/20 runnable queries, incl. a factual error). The llama grounding worksheet uses the separately retained earlier operational sample `20260713T115729Z_ollama_operational`, not the matched 14/14 run `20260715_060542_ollama_oper_baseline`. The matched strict logs add an efficiency view: median prompt tokens 963.5 vs 970.0, median completion tokens 218.5 vs 786.5 (GPT reasoning-token subset 337.5), and median call latency 60.37 s vs 10.66 s. All 20 input and redacted-prompt hashes match. The **$1.11** account observation applies only to the earlier 42-request operational + superseded-evaluation pair, not the later strict rerun.
- **15-page technical report** drafted and reviewed; `DESIGN_AND_CHANGELOG.md` reference doc written.

### Blocked → resolved
| Issue | Root cause | Resolution |
|---|---|---|
| First "evaluation" view still leaked the label (llama 7/14) | `audit.key` and `rule_description` carried technique codes | Rebuilt a leak-proof strict view (value-aware key drop + code stripping); re-ran both models → true 1/14 |
| Label-leakage bug in `views.py` | Leaky "evaluation" view | Strict label-reduced view; 0/20 leaks verified by test |
| GPT-5.5 empty responses / parameter errors | Reasoning models reject `temperature`; need `max_completion_tokens` | Provider branch for reasoning models; budget raised; effort left at vendor default |
| Windows MAX_PATH crash + a schema-validator defect | Long run-dir paths; validator edge case | `\\?\` long-path handling; validator fix; both regression-tested |

### Known items carried forward
- Manual grounding review is single-reviewer, operational-view only (automation + 2nd reviewer deferred).
- Hosted runs are single stochastic samples (temperature unsupported) — comparison labelled exploratory; no assisted-timing run for GPT-5.5.
- A18 is a scored false negative *and* a corpus construct-validity artifact (payload self-identifies as a test).

### Next week (Week 4)

---

## Week 4 — Hardening, Feature 2, Defense Materials
**Dates:** 20–26 Jul 2026 · **Effort:** ~15h · **Status:** ✅ Complete — Paste & inspect MVP shipped and adversarially tested; report/README/changelog reconciled; defense deck, transcript and Q&A pack finalised

### Shipped
- **Feature 2 — "Paste & inspect" local diagnostic (MVP)** built and wired into the Streamlit app: an analyst pastes one JSON alert (or plain text). The ad hoc path shares the batch path's redaction implementation and model boundary, while adding its own limits, redaction trace, injection scan, boundary gate, egress-consent check, single model call and schema validation. It surfaces the redaction trace, injection markers, the exact model-bound message, and a schema-validated draft. Six new modules (`paste_core`, `paste_tab`, `injection`, `samples`, `audit`, `ui_helpers`); `redact_alert_with_trace()` delegates to the same recursion as `redact_alert()` so proof and production cannot diverge. _Evidence: EVID-AI-PASTE-001…004._
- **Security-hardened after self-testing.** Adversarial testing on my own VM caught real bugs, all fixed and regression-tested: a P0 delimiter-gate bypass via a JSON **key** (the gate now serializes the whole object, keys included); non-string sensitive values leaking (sensitive keys now redact any JSON type); `sk-proj-` keys not matched; blocked requests mis-recorded as schema-valid; endpoint-aware egress consent (remote Ollama now requires consent); and Streamlit stale-state issues.
- **Documentation reconciled to the authoritative results** after several external review rounds: `report.md` (15 pages), `README.md`, and `DESIGN_AND_CHANGELOG.md` aligned on the strict label-reduced numbers, MTTD **2.32 s**, the paired false-positive cost **+1.68 min**, and the frozen-corpus SHA-256 (`4e842637…`). Injection and guardrail wording narrowed to what the implementation supports (detection + containment, not prevention).
- **CVE clarification added (§7):** no CVEs cited because no known software vulnerability was exploited — the simulations exercise legitimate OS features and dual-use tooling, so ATT&CK is the applicable identifier framework. None of the 40 operational outputs manually reviewed in §9.5 contained a CVE identifier. _Raised by an evaluator; answered in-report._
- **`attack/runbook.md`** authored — reproducer commands per rule, with rule-firing evidence separated from exact-command provenance and each trigger labelled by validation scope (direct behaviour, path-write only, heuristic or simulation).
- **Defense materials:** 14-slide deck (speaker notes on every slide, optional live-demo segment on the guardrails slide), full spoken **presentation transcript**.

### Blocked → resolved
| Issue | Root cause | Resolution |
|---|---|---|
| Paste tab could be bypassed by a delimiter hidden in a JSON key | Boundary gate scanned values, not keys | Gate now independently serializes the entire model-bound object (keys + values) before any call — verified by test |
| Blocked/failed calls reported `schema_valid = true` | Absence of errors was read as validity | Introduced `schema_valid = not-evaluated` when no response was validated; added `call_status` to the audit record |
| "Never transmitted / never stored" wording overclaimed | Docs written ahead of the key-bypass and non-string-secret fixes | Fixed the implementation first, then narrowed wording to tested cases |
| Notebook crashed on millisecond timestamps under pandas 2.x | Fixed datetime format string | `format="ISO8601"` on all parses; notebook runs clean, MTTD 2.32 s |

### Known items carried forward (documented, deferred)
- **RBAC** (`admin` / `socanalyst` / `assistant-svc`) and **live read-only Wazuh API ingestion** remain designed-and-documented target state, not implemented. Paste & inspect is localhost-only, single-user until then.
- Automate the (currently single-reviewer, operational-view) grounding rubric; add a second independent reviewer and strict-view coverage.
- Migrate the three IR playbooks from NIST 800-61 **r2** (four-phase lifecycle) to **r3** (CSF 2.0 functions), which superseded r2 in Apr 2025 — production follow-on.

### Submission-extension hardening — 29 Jul 2026
- **90-day Wazuh alert retention implemented.** Created Index State Management policy `wazuh-alert-retention-policy` for the `wazuh-alerts-4.x-*` daily alert indices, with a transition to deletion after a minimum index age of **90 days**. The policy was last updated at 21:57 on **29 Jul 2026**. _Evidence: EVID-WAZUH-RET-001._
- **Current and post-deployment attachment verified.** The policy-managed-index view showed **21 indices** in `retention_state`, action `Transition`, job status `Running`, and transition conditions being evaluated. It included daily indices dated 30 and 31 Jul, showing that post-deployment daily indices were covered by the policy. _Evidence: EVID-WAZUH-RET-002._
- **Validation boundary:** configuration, policy attachment and scheduler activity are verified; actual deletion at day 90 is not yet observed because no managed index had reached the threshold. Full-event archive retention remains a documented production target rather than an implemented policy.

### Final wrap-up
- Report finalised (15 pages; reported measurement and model figures traceable to retained artifacts); defense deck + transcript; frozen corpus and run directories committed; 90-day alert retention and supporting Wazuh evidence added during the submission extension. Lab snapshots archived clean.
