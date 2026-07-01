# WEEKLOG — AlertMind (CAP-SCE-3W)

A short status note per week (written each Saturday, per the program cadence): what shipped, what was blocked and how it resolved, and what carries forward. Newest week on top.

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
**Dates:** 29 Jun – 5 Jul 2026 · **Effort target:** ~12h · **Status:** 🚧 In progress — detection layer completed; dashboards/playbooks/baseline pending

### Shipped
- Sigma rule pack authored and validated: 25 rules (8 Windows + 17 Linux), all pass pySigma; `detections/sigma/notes.md` documents the Sigma → Wazuh crosswalk with honest Verified/Configured/Planned status.
- Detection mappings tightened after review: renamed keys to precise ATT&CK IDs (`t1195_001_apt_repo_config`, `t1098_sshd_config`), added T1222.002 to the setuid rule and T1569.002 to the PsExec rule, expanded encoded-PowerShell flags.
- Added a precise T1098.004 detection — SSH `authorized_keys` persistence (rule 100116) — and verified it firing end-to-end (EVID-LIN-003).

### Blocked → resolved
- **Rule 100116 not firing.** Root cause was an auditd limitation, not Wazuh: two `-w` watches on the same path (`/root/.ssh/`) can't both apply their keys, so `authorized_keys` writes were keyed `t1552_004_ssh_keys` and only matched rule 100113. Resolved by collecting broadly in auditd and adding specificity in the SIEM — 100116 re-implemented as a child of 100113 narrowing on the `authorized_keys` path. Verified (EVID-LIN-003).

### Known items carried forward
- Windows Sysmon detections (office-spawn, encoded PowerShell, LOLBin, LSASS, run-key) need dedicated custom Wazuh rules to move from 🟡 to ✅.
- Rule 100100 `/etc/shadow` auid tune still to apply.
- Still to do this week: dashboards (daily briefing + ATT&CK heatmap), three NIST 800-61 IR playbooks, stand up the Kali attacker, run the Atomic chain, capture the unassisted baseline.

### Next week (Week 3)
- LLM assistant + guardrails (redaction before/after proof), assisted measurement, final report + defense deck.

---

## Week 3 — LLM Assistant + Impact Measurement
**Dates:** 6–12 Jul 2026 · **Effort target:** ~14h · **Status:** ⏳ Not started

### Shipped
- _TODO_

### Blocked → resolved
- _TODO_

### Final wrap-up
- _TODO: report finalised, defense deck rehearsed, lab teardown / snapshots archived._
