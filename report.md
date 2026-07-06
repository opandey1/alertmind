# AlertMind — AI-Assisted Mini SOC
## Technical Report

**Author:** Ojas Pandey · **Mode:** Solo · **Track:** EC-Council SOC Essentials (SCE) · **Project:** CAP-SCE-3W
**Program:** PG Certificate in AI/GenAI Powered Cybersecurity — IIT Roorkee × Futurense, Cohort 1
**Repository:** https://github.com/opandey1/alertmind · **Report length target:** 10–12 pages

> **Living document.** Started Week 1 and updated daily. Sections are tagged ✅ complete / 🚧 in progress / ⏳ pending so the draft is always honest about its own state. Replace each `_TODO_` as the work lands.

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
*🚧 Draft — finalise in Week 3 once results exist. One paragraph, executive register.*

AlertMind is a mini-SOC pilot built to test whether a guardrailed LLM tier-1 assistant can measurably improve alert triage before a SaaS company commits budget to a commercial SOAR. The Week-1 build has established the Wazuh SIEM, Windows and Linux telemetry, and an initial pack of ATT&CK-mapped detections. The completed system will add operational dashboards, three NIST SP 800-61 incident-response playbooks, Atomic Red Team baseline testing, and an LLM assistant — constrained by explicit guardrails (no autonomous action, no secrets to the model, human review on every output) — whose impact is measured as the change in analyst time-to-triage across matched assisted and unassisted alert sets, reported with full threats-to-validity. _TODO: headline result — direction and magnitude of the triage-time effect, and the key caveat._

---

## 2. Introduction & problem statement
*✅ Week 1.*

A growing SaaS company's three-person SOC processes ~1,200 alerts per day at a mean time-to-triage of ~35 minutes. Leadership has three goals: consolidate logging, reduce alert fatigue, and prototype an LLM-powered tier-1 assistant ahead of a SOAR purchase. This project plays the in-house pilot crew, delivering an end-to-end mini-SOC in a virtual lab and an honest assessment of where an LLM assistant helps, where it does not, and what risks it introduces.

**Objectives.** (1) Stand up a SIEM with heterogeneous, healthy log sources. (2) Author ATT&CK-mapped detections in Sigma and deploy them. (3) Build operational dashboards and IR playbooks. (4) Build a guardrailed LLM tier-1 assistant. (5) Measure its real impact on triage time and accuracy.

**Scope (solo, confirmed with instructor).** The solo requirement is **2 endpoint log sources (Windows + Linux) and 7 detection rules**, expanding to 10 rules / 3 sources (adding cloud) only if time permits. The implemented rule pack already exceeds the minimum. Other solo parameters: alert-summarisation assistant scope, one tabletop scenario, 10–12 page report.

---

## 3. SOC architecture
*✅ Week 1. Full detail in `architecture/soc-architecture.md`; summary here.*

The lab runs on VirtualBox with all VMs on an isolated NAT Network (`LabNet`, 10.0.2.0/24); the Windows host is hypervisor-only and never monitored. The SIEM host (`wazuh-siem`) carries a second Host-Only adapter for dashboard access. Telemetry flows: endpoint agent → `wazuh-remoted` (1514) → `wazuh-analysisd` (decode + rules) → `alerts.json` → Filebeat → indexer → dashboard. Detections are authored in Sigma (source of truth) and converted to Wazuh rules. The LLM assistant attaches in a pull model through a read-only API identity and never sits inline with enforcement.

*See `architecture/diagram.drawio` / `diagram.png` for the topology and data-flow diagram.*

**Design principles:** high-signal-over-high-volume collection, portable (Sigma-first) detections, least privilege including the assistant, config-as-code reproducibility, and separation of detection latency from triage time as distinct metrics.

---

## 4. SIEM build & log coverage
*✅ Week 1. (Rubric: 15% — clean ingestion, healthy logs, sensible retention.)*

**Platform.** Wazuh 4.14.5, all-in-one (manager + indexer + dashboard) on Ubuntu. All services confirmed active and the agent (1514/1515), API (55000), indexer (9200, localhost), and dashboard (443) ports confirmed listening. _Evidence: EVID-WAZUH-001 (service status + port listing)._

**Endpoints onboarded.** (Status key: ✅ Verified with evidence · 🟡 Configured, test pending · ⏳ Planned.)

| Source | Host | Channel / path | Format | Status |
|---|---|---|---|---|
| Sysmon | `win-victim` | `Microsoft-Windows-Sysmon/Operational` | eventchannel | ✅ (EVID-WIN-001) |
| Windows System | `win-victim` | `System` (EID 7045) | eventchannel | ✅ (EVID-WIN-002) |
| Windows Security | `win-victim` | `Security` (EID 4697) | eventchannel | 🟡 Configured; verification pending |
| auditd | `linux-victim` | `/var/log/audit/audit.log` | audit | ✅ (EVID-LIN-002) |
| Cloud trail | manager | sample → custom decoder | json | ⏳ |

**A reproducibility-relevant fix.** The Linux agent does not read `audit.log` by default; an explicit `audit` `localfile` block was required. Before this, only the journald copy of events was ingested (low fidelity) and auditd SYSCALL records never reached the manager. This is documented so the lab is rebuildable without rediscovering it.

**Retention.** Alerts (`wazuh-alerts-4.x-*`) retained for the project window; full-event archives kept off by default and enabled only around attack runs (execve auditing makes them volume-heavy). ISM policies expressing the modelled production windows (alerts 90d, archives 7–14d) are **documented but not yet enforced** in the Week-1 lab. _Detail in `architecture/soc-architecture.md` §7._

**RBAC target state.** The final assistant integration will use three least-privilege identities: `admin` (setup only), `socanalyst` (read-only triage), `assistant-svc` (read-only, alert-scoped API — the technical basis of the assistant's "never acts" guarantee). _Current Week-1 state: only `admin` exists, used for setup and validation; `socanalyst` and `assistant-svc` will be created before the assistant is connected. Detail in §8 of the architecture doc._

---

## 5. Detection engineering
*✅ Sigma source complete; Linux Wazuh-native pack implemented; rules 100100 and 100116 verified · 🚧 remaining Linux validation + Windows custom rules.*

**Authoring model.** Sigma YAML is the portable source of truth (`detections/sigma/`, 25 rules, all validated with pySigma); each rule is converted to Wazuh-native form and any hand-translation logged in `detections/sigma/notes.md`. The Wazuh-native rules were authored first in `siem/wazuh/local_rules.xml`, with the Sigma source now complete and mapped 1:1 (one child-rule exception, documented).

**Linux pack — implemented; 100100 and 100116 verified end-to-end.** Custom Wazuh rules 100100–100116 (17 rules) chain off base rule 80700 (with one child-rule exception, below), each matching one ATT&CK-encoded auditd key and tagging MITRE. Coverage spans credential access (T1003.008, T1552.004), persistence (T1136/T1098, T1053.003, T1543.002, T1037, T1546.004, T1098.004 authorized-keys), defense evasion (T1562.001, T1070/T1070.006), priv-esc (T1548.003, T1548.001/T1222.002), exec-flow hijack (T1574.006), rootkit/LKM (T1547.006/T1014), and config tampering (T1098 sshd_config and a tentatively-mapped package-config monitor). Rule 100100 verified firing end-to-end at level 12 on a real `/etc/shadow` read (EVID-LIN-002) and rule 100116 verified on an SSH `authorized_keys` write (T1098.004, EVID-LIN-003); the remaining rules are deployed and will be individually tested during the Atomic/baseline phase. _Full table: README §5._

**Notable detection-engineering issue (100116).** The authorized-keys persistence rule (T1098.004) initially did not fire. The cause was an auditd limitation, not a Wazuh error: two `-w` watches covering the same path (`/root/.ssh/`) cannot both apply their keys, so writes to `authorized_keys` were emitted under the broader `t1552_004_ssh_keys` key and matched only rule 100113. Rather than fight auditd with overlapping watches, the fix follows a standard SOC pattern — collect broadly at the sensor, differentiate in the SIEM: 100116 was re-implemented as a child of 100113 (`<if_sid>100113</if_sid>`) that narrows on the `authorized_keys` path. This is now verified firing end-to-end (EVID-LIN-003).

**Windows.** Process create (EID 1, EVID-WIN-001) and service creation (EID 7045 → rule 61138 → T1543.003, EVID-WIN-002) are verified in Wazuh. Seven custom Windows Sysmon rules (**100200–100206**) are deployed, each chaining off the relevant Wazuh built-in Sysmon base rule (EID 1 = 61603, EID 10 = 61612, EID 13 = 61615, EID 22 = 61624) and narrowing on `win.eventdata.*` fields: Office-spawns-shell (T1566/T1059), encoded PowerShell (T1059.001), LOLBins (T1218), LSASS access (T1003.001), PsExec service execution (T1021.002/T1569.002), Run-key persistence (T1547.001), and a DNS-tunnelling heuristic (T1048/T1071.004). **Three are verified firing:** encoded PowerShell (EVID-WIN-003), LOLBin execution (EVID-WIN-004), Run-key persistence (EVID-WIN-005), and LSASS credential dump (EVID-WIN-006). Office-spawn, PsExec, and the DNS heuristic are scheduled for the Atomic phase. Two tuning notes: **(a)** Run-key rule 100205 chains off 92300 and was re-narrowed to exclude `CurrentVersion\RunNotification` (a prefix-match FP observed in testing); **(b)** LSASS rule 100203 required three tuning rounds — untuned fired ~557 FPs on benign query-only reads, a positive mask allowlist missed `0x0xxx` dump masks, and the final form uses a negative exclusion for the three confirmed-benign masks (`0x1000`/`0x1400`/`0x3000`) plus sourceImage exclusions for `wazuh-agent.exe` and `MsMpEng.exe`. Verified on `rundll32.exe` at `0x1fffff` (comsvcs MiniDump) after setting `RunAsPPL=0`; the PPL pre-condition is documented as a real-world factor.

**Detection-engineering note (kept deliberately).** `execve` is collected but not alerted on directly — it is the substrate for targeted command-pattern rules; blanket exec alerting would bury the console. Rule 100100 was observed firing on legitimate `cron` PAM reads (a false positive); the planned tune scopes the audit rule to interactive users (`auid>=1000`). This baseline→FP→tuned progression is the detection-engineering story.

---

## 6. Dashboards & IR playbooks
*⏳ Week 2.* *(Rubric: 10% — useful, role-specific, NIST 800-61 aligned.)*

**Dashboards.** _TODO: (1) Daily SOC briefing — alert volume over time, severity breakdown, top rules, top hosts, open vs. closed. (2) ATT&CK heatmap — techniques lit by fired alerts; export the Navigator layer to `siem/dashboards/`._

**IR playbooks (NIST SP 800-61, four phases each).** _TODO: phishing, malware, account compromise — each covering Preparation → Detection & Analysis → Containment/Eradication/Recovery → Post-incident, written role-specifically (analyst vs. lead) rather than generically._

---

## 7. Attack simulation & baseline
*⏳ Week 2.* *(Feeds Rubric: 15% measured impact.)*

**Scenario (self-chosen, confirmed with instructor).** _TODO: Atomic Red Team chain exercising the rule pack end-to-end, e.g. T1566 → T1059.001 → T1547.001 → T1003.001 → T1021 → T1048. Record per-technique whether it fired, the rule ID, and detection latency._ Scenarios are self-selected (instructor suggested PowerShell execution, credential dumping, DNS tunnelling as good candidates).

**Baseline (unassisted).** _TODO: lock the measurement protocol (§9) before this run. Capture MTTD per technique and unassisted triage time over the alert corpus._

---

## 8. LLM tier-1 assistant
*⏳ Week 3.* *(Rubric: 20% — clear guardrails, no autonomous actions, prompts documented — the single heaviest criterion.)*

**Design.** _TODO: Output = {≤5-line summary, ATT&CK technique tag, suggested investigation queries, draft user message}. Built on the reused `AI-SOC-Assistant` summarisation core; new SOC prompt library in `assistant/prompts/`; thin Streamlit UI._ **Data path:** initial implementation reads selected alerts from a local `alerts.json` export on `wazuh-siem`; the target implementation uses read-only Wazuh API access (`:55000`) via the `assistant-svc` identity (the indexer on 9200 is localhost-only and not used directly unless the assistant runs on the SIEM host).

**Guardrails (document each with evidence).**
- _No autonomous actions_ — outputs text only; reaches the SIEM via the read-only `assistant-svc` identity (can't act by credential, not just by code).
- _No secrets to the model_ — redaction layer strips credential/token/secret patterns pre-prompt; IPs retained for triage. **The instructor confirmed a stated policy is not sufficient: a before/after demonstration is required** — show the original alert with a (planted, fake) secret visible, then the post-redaction prompt with it removed, captured as screenshots. _TODO: build the redaction proof test and save before/after evidence._
- _Human review_ on every output.
- _Full logging_ — prompt + response + model + version per call (`assistant/logging/`).

_Model/topology: a hosted API is acceptable provided the redaction guardrail is in place (the instructor's emphasis was that secrets/passwords/unneeded IPs must be redacted before anything reaches the model); a self-hosted open model (Ollama + Llama 3) is the alternative. TODO: finalise model choice._

---

## 9. Impact measurement
*🚧 Methodology designed (Week 1, confirmed with instructor) · ⏳ results Week 3.* *(Rubric: 15% — honest before/after, threats-to-validity acknowledged.)*

**Definitions (per instructor clarification).** The detection/response clock starts from **the time the attack actually occurs as recorded in the logs — not the time the log was ingested**. Each incident is tracked with four timestamps:

1. **Attack started** (timestamp in the log/event)
2. **Alert generated** (rule fires in Wazuh)
3. **Analyst saw the alert** (triage begins)
4. **Investigation completed** (disposition reached)

From these, MTTD = (2) − (1) and MTTR/time-to-triage = (4) − (3) (with (3) − (2) as analyst pickup latency).

**What the assistant is expected to change — and what it is not.** The assistant cannot change the attack timestamp or the alert-generation timestamp, so it does not improve MTTD. Its measurable value is in the analyst workflow after the alert is seen: summarisation, ATT&CK tagging, query suggestions, and draft reporting. The report therefore measures whether the assistant improves the human triage/reporting segment without reducing accuracy. It treats "does the assistant reduce triage time?" as an honest empirical question with a likely-neutral answer, rather than a result to be manufactured — which the instructor confirmed is the correct posture (an honest negative or neutral finding is expected and acceptable).

**Tracking method (manual is acceptable).** The four timestamps are captured manually in `measurement/timing-log.csv` (the instructor confirmed manual timestamped tracking is sufficient; TheHive/Cortex is an optional add-on, not required). The AI-assisted run is then **cross-checked against the manual timeline for consistency** — i.e. does the assistant's account agree with ground truth, or does it drift?

**Quality and the hallucination cost.** Speed alone is misleading. For each assisted triage, the assistant's ATT&CK tag and summary are compared against known Atomic ground truth and a **mis-tag / hallucination rate** is recorded. The instructor's own example: if the assistant mislabels a privilege-escalation as persistence, the analyst's response time can *increase* because the wrong lead must be unwound — a faster-but-wrong triage is worse than a slower correct one. Per his guidance, **any hallucination that could mislead the report is flagged transparently** rather than smoothed over.

**Beating n=1.** Rather than a single tabletop run, an alert corpus of ~15–20 alerts spanning the ATT&CK stages from the Atomic runs (`measurement/alert-corpus.json`) is split into matched sets A/B, counterbalanced (set A unassisted then B assisted, or randomised) to control the within-subject learning effect — yielding ~10 timed observations per condition.

**Reporting.** _TODO (Week 3): table of condition × {median triage time, tag accuracy, hallucination count}, plus the four-timestamp timeline per scenario, with explicit caveats — small n, single environment/analyst, synthetic alerts, within-subject learning — and a plain statement of whether the assistant helped, was neutral, or hurt._

---

## 10. AI disclosure
*🚧 Maintain throughout; finalise Week 3.* *(Program requirement.)*

| Tool / model | Used for | How output was verified |
|---|---|---|
| _TODO (e.g. assistant model + version)_ | Alert summarisation, ATT&CK tagging, draft comms | Checked against raw alert evidence; ATT&CK tag vs. Atomic ground truth |
| _TODO (any planning/drafting assistant)_ | Implementation planning, document drafting | Author-reviewed; technical claims validated against system behaviour |

All AI use is disclosed here per program policy. No real credentials, customer data, or copyrighted content was provided to any model; lab alerts are synthetic.

---

## 11. Limitations & threats to validity
*🚧 Seeded Week 1; grow as issues surface.* *(Rubric reward: limitations called out.)*

- **Single-node SIEM** — no HA/clustering; lab-appropriate, not production scale.
- **Synthetic alerts only** — detection precision is characterised against known Atomic ground truth, not real-world base rates; false-positive behaviour on production traffic is unknown.
- **Within-subject measurement** — one analyst; learning-effect controls (matched sets, counterbalancing) reduce but don't eliminate the confound. n is small.
- **Known false positive** — rule 100100 fires on legitimate `cron` reads of `/etc/shadow`; tuning planned and reported rather than hidden.
- **Cloud source** — a static sample (e.g. a public CloudTrail/Azure dataset) is used rather than live ingestion; the instructor confirmed this is acceptable, with live ingestion an optional enhancement. Cloud is part of the optional 10-rule / 3-source stretch, not the solo minimum.
- _TODO: add assistant-specific risks once built (hallucinated tags, over-trust / automation bias, review overhead potentially exceeding time saved)._

---

## 12. Conclusion & future work
*⏳ Week 3.*

_TODO: what was built, what the measurement showed (including a negative or mixed result if that's the truth), and what a real SOC should take from the pilot. Future work: ML severity scorer with LLM-explained scores; approval-gated auto-remediation; live cloud ingestion; second operator to remove the learning confound._

---

## 13. References
- MITRE ATT&CK — https://attack.mitre.org
- NIST SP 800-61, Computer Security Incident Handling Guide
- NIST Cybersecurity Framework 2.0 — https://www.nist.gov/cyberframework
- Wazuh documentation — https://documentation.wazuh.com
- _TODO: Sysmon config (SwiftOnSecurity), Atomic Red Team, LangChain/LangGraph, any datasets used._

---

## 14. Appendices

### A. Evidence index
Every ✅ claim in this report maps to a captured artifact. (Consistent with README §7a.)

| Evidence ID | What it proves | File / screenshot |
|---|---|---|
| EVID-WAZUH-001 | Wazuh services + ports healthy | `evidence/week1/wazuh-services-ports.png` |
| EVID-WIN-001 | Sysmon EID 1 process creation ingested | `evidence/week1/win-sysmon-eid1-whoami.png` |
| EVID-WIN-002 | Windows service creation (7045 → rule 61138, T1543.003) | `evidence/week1/win-system-7045-service.png` |
| EVID-LIN-001 | Linux user creation detected | `evidence/week1/linux-useradd-t1136.png` |
| EVID-LIN-002 | auditd `/etc/shadow` rule 100100 fired (T1003.008) | `evidence/week1/linux-shadow-t1003-008.png` |
| EVID-LIN-003 | SSH `authorized_keys` persistence, rule 100116 fired (T1098.004) | `evidence/week2/linux-authorized-keys-t1098-004.png` |
| EVID-WIN-003 | Encoded PowerShell, rule 100201 fired (T1059.001) | `evidence/week2/win-powershell-t1059-001.png` |
| EVID-WIN-004 | LOLBin execution, rule 100202 fired (T1218) | `evidence/week2/win-lolbin-t1218.png` |
| EVID-WIN-005 | Run-key persistence, rule 100205 fired (T1547.001) | `evidence/week2/win-runkey-t1547-001.png` |
| EVID-WIN-006 | LSASS dump-grade access, rule 100203 fired (T1003.001) | `evidence/week2/win-lsass-t1003-001.png` |
| EVID-RULES-001 | `local_rules.xml` validates + loads clean | `evidence/week1/wazuh-rules-load.png` |

_TODO: capture each screenshot into `evidence/week1/`; add Week 2–3 evidence (dashboards, Atomic runs, assistant, redaction proof test) as those land._

### B. Detection rule pack
`siem/wazuh/local_rules.xml` (deployed Wazuh-native rules) · `detections/auditd/alertmind.rules` (auditd ruleset) · `detections/sigma/` (portable Sigma source, 25 rules validated).

### C. Configurations
Agent `ossec.conf` blocks (audit + Windows channels), Sysmon config edit (EID 10), retention/ISM policies.

### D. Runbooks
`docs/runbooks/wazuh-recovery.md`.

### E. Assistant
Prompt library, redaction module, call logs, redaction proof-test output.
