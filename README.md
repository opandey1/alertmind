# AlertMind — AI-Assisted Mini SOC

> An end-to-end mini Security Operations Centre built around Wazuh: Windows and Linux telemetry, ATT&CK-mapped detections, SOC dashboards, incident-response playbooks, and a guardrailed LLM tier-1 assistant evaluated on a frozen benign-salted alert corpus.

**Capstone:** PG Certificate in AI/GenAI Powered Cybersecurity — IIT Roorkee × Futurense, Cohort 1 · EC-Council SOC Essentials track · Project `CAP-SCE-3W` · Solo mode

**Current status:** Complete and submitted. The SOC build, detections, dashboards, playbooks, 90-day Wazuh alert-retention policy, assistant, Paste & inspect, frozen-corpus evaluation, grounding review, technical report and defense presentation are all delivered. Live Wazuh-to-assistant integration and production RBAC remain documented target-state work, not completed features.

For the complete methodology, evidence index, limitations and results, see the **[technical report](report.md)**. The **[defense presentation](docs/AlertMind_Defense.pdf)** summarises the build, the four measured findings and the deployment recommendation in 14 slides.

## What was delivered

| Component | Delivered state |
|---|---|
| Wazuh SIEM | Wazuh 4.14.5 all-in-one manager, indexer and dashboard in an isolated VirtualBox lab |
| Endpoint telemetry | Windows 11 with Sysmon and Wazuh agent; Ubuntu with auditd and Wazuh agent |
| Detection engineering | 24 custom Wazuh rules verified firing: Linux `100100–100116` and Windows `100200–100206`; built-in rule 61138 covers Windows service creation |
| ATT&CK coverage | Execution, persistence, credential access, privilege escalation, defense evasion, lateral movement, exfiltration and command-and-control scenarios |
| Dashboards | Daily SOC Briefing and ATT&CK Heatmap, exported as Wazuh `.ndjson` objects under `siem/dashboards/` |
| Alert retention | `wazuh-alert-retention-policy` applied to `wazuh-alerts-4.x-*`; 90-day delete transition configured and 21 managed indices verified |
| IR playbooks | Phishing, malware and account-compromise playbooks following the NIST SP 800-61r2 four-phase lifecycle, as specified by the capstone brief |
| LLM assistant | Python/Streamlit assistant with local, hosted and deterministic mock providers; strict JSON output, redaction, views, audit logging and scoring |
| Paste & inspect | Ad hoc JSON or plain-text alert triage with limits, redaction trace, injection markers, boundary gate, endpoint-aware consent and sanitized proof/audit output |
| Evaluation | Frozen 20-alert corpus: 14 controlled attacks plus 6 historical benign false positives; paired timing, automated scoring and manual grounding review |

## Architecture and trust boundary

The lab VMs share an isolated VirtualBox NAT network (`LabNet`, `10.0.2.0/24`). The SIEM has a Host-Only adapter for dashboard access. The assistant is not inline with detection or enforcement.

![AlertMind architecture and trust boundary — detection plane above, draft-only assistant plane below](architecture/architecture-trust-boundary.png)

**Solid** lines are implemented flows, **dashed** lines are planned target state, and **dotted** lines are simulated adversary activity. Full architecture, log sources, retention and the RBAC model: **[`architecture/soc-architecture.md`](architecture/soc-architecture.md)** · editable diagram source [`architecture/diagram.drawio`](architecture/diagram.drawio) → [`architecture/diagram.png`](architecture/diagram.png).

Current assistant inputs are the frozen corpus and analyst-pasted JSON or plain text. The dashed Wazuh API path is the production target and is **not yet implemented**. Correspondingly, the target identities `socanalyst` and `assistant-svc` remain planned; the lab currently uses `admin` for setup and validation.

Alert retention is implemented separately in the Wazuh Indexer. The 90-day policy was configured on 29 Jul 2026 and verified attached to 21 daily alert indices, including indices created after the policy update. The evidence proves policy attachment and active transition evaluation; actual age-based deletion remains unobserved because no index had yet reached 90 days. See [`architecture/soc-architecture.md` §7](architecture/soc-architecture.md#7-data-retention), the [policy screenshot](evidence/week3/wazuh-alert-retention-policy-90d.png), and the [managed-index screenshot](evidence/week3/wazuh-alert-retention-managed-indices.png).

## Key measured findings

The project deliberately separates detection latency from analyst triage time:

- **MTTD:** attack timestamp → Wazuh alert timestamp. Median **2.32 seconds**; this is a property of detection and forwarding, not the assistant.
- **Time-to-triage:** analyst opens alert → disposition complete. Model inference was pre-generated and reported separately.

### Timed llama3.1-assisted pass

| Alert class | n | Unassisted median | Assisted median | Result |
|---|---:|---:|---:|---|
| Attacks, assistant disposition correct | 14 | 11.43 min | 8.00 min | **−30%**; all 14 faster |
| Benign false positives, assistant disposition wrong | 6 | 5.58 min | 7.70 min | **+38%**; paired median cost **+1.68 min** |
| All alerts | 20 | 10.50 min | 8.00 min | Aggregate −24% hides the opposite class effects |

Analyst disposition accuracy stayed **20/20** in both passes because every incorrect assistant disposition was independently reviewed and corrected by the analyst. This demonstrates that human review worked in this single-analyst study, but also that review has a measurable cost. No formal or audited override mechanism was implemented.

### Model comparison: strict scoring and operational grounding

The operational alert contains its rule-authored ATT&CK label. A separate evaluation view removes the tested label-bearing fields before scoring to avoid measuring label copying. The two free-text grounding rows below are labelled separately because that manual review used the operational outputs, not the strict-view outputs.

| Measure | `llama3.1:8b` | `gpt-5.5-2026-04-23` |
|---|---:|---:|
| Attack technique, operational exact / relaxed | **14/14 · 14/14** | 11/14 · 14/14 |
| Attack technique, strict exact / relaxed | 1/14 · 1/14 | **8/14 · 12/14** |
| Disposition, all alerts | 14/20 | **16/20** |
| Benign false positives cleared | **0/6** | **3/6**, with 3 hedged and 0 confidently wrong |
| Summaries fully supported (operational grounding) | 15/20 | **20/20** |
| Investigation queries runnable (operational grounding) | **0/20** | **20/20** |
| Valid JSON across matched operational + evaluation runs | 40/40 | 40/40 |
| Prompt tokens, median (strict run) | 963.5 | 970.0 |
| Completion tokens, median (strict run) | 218.5 | 786.5 |
| Reasoning-token subset, median (strict run) | Not separately reported | 337.5 |
| End-to-end call latency, median / 20-call total (strict run) | 60.37 s / 21.18 min | **10.66 s / 3.81 min** |

The automated operational/strict comparison uses llama3.1 runs `20260715_060542_ollama_oper_baseline` and `20260718_180713_ollama_eval_baseline`. The llama operational grounding worksheet uses an earlier output sample, `20260713T115729Z_ollama_operational`; its free-text verdicts are not attributed to the later 14/14 operational run. All 20 strict-view pairs have matching input and redacted-prompt hashes and use the same prompt and redaction versions. That establishes matched serialized inputs; the near-identical prompt-token medians do not, because token counts are tokenizer-specific. GPT-5.5 completion tokens include the separately reported reasoning-token subset. Ollama did not report a separate reasoning count, which must not be read as proof that the model performed no internal reasoning.

The earlier llama run's committed scoring CSV is preserved as an **as-run historical artifact** from the then-current single-ID validator: A13 and A19 were parsed correctly but marked `schema_invalid` because their slash-joined ATT&CK IDs were rejected. A retrospective re-score of the unchanged audit log with the current multi-ID validator yields **13/14 exact, 14/14 relaxed, 14/20 disposition, 20/20 consistent and 14/20 overall**; A10 is the sole exact-ID miss. Those derived figures describe the earlier grounding-source run and do not replace the matched `20260715_060542` automated result of 14/14 exact.

This is an exploratory system-level comparison, not a controlled model benchmark: model scale, training, hosting, tokenizer, reasoning configuration and sampling differ simultaneously. The extra GPT-5.5 reasoning tokens are an observed usage difference, not evidence that reasoning tokens caused the quality difference. Latency is the observed end-to-end call time on the measured laptop CPU and hosted service, not an intrinsic speed ranking. GPT-5.5 is one stochastic sample per view, and the timed assisted pass was not repeated with it.

The corpus is frozen at `measurement/alert-corpus.json`:

```text
SHA-256  4E842637F3CBCBB6E0704320824B64BDEB63C7D7EE7E22DB0278E4D96C58B929
```

## LLM assistant

The implementation is [`assistant/`](assistant/). The benchmark run logs used by the report are retained under `assistant/outputs/runs/`, one non-overwriting directory per run.

For each alert, the assistant returns:

1. A summary of at most five lines.
2. One or more MITRE ATT&CK technique IDs, or `null`, with an optional technique name.
3. A disposition suggestion and calibrated confidence.
4. Two or three suggested investigation queries.
5. A draft message to the affected user or system owner.
6. Caveats describing uncertainty and limitations.

**Batch path** — the measured pipeline over the prevalidated, controlled and frozen corpus. Linear and gate-free, because admission is settled before the run:

[![Batch path — redact, apply view, construct prompt, call model, parse, validate, audit, score](architecture/assistant-batch-path.png)](architecture/assistant-batch-path.png)

<details>
<summary>Text version</summary>

```text
redact → apply view → construct prompt → call model → parse → validate → audit → score
providers: mock · ollama · openai · anthropic
```

</details>

**Ad hoc Paste & inspect path** — one synthetic or approved alert, supplied as JSON or plain text, behind input limits, a redaction trace, an injection-marker scan and two gates:

[![Ad hoc Paste and inspect path — parse, limits, redact with trace, apply view, scan keys and values, boundary gate, egress consent, one model call, validate, draft and optional audit](architecture/assistant-adhoc-paste-inspect-path.png)](architecture/assistant-adhoc-paste-inspect-path.png)

<details>
<summary>Text version</summary>

```text
parse → limits → redact with trace → apply view → final model_bound object
        ├─ marker scan (side branch) → markers shown to analyst; visibility only, never gates
        └─ boundary gate → egress consent → one model call → validate → draft → optional audit
admission: parsing and input limits can reject the request before either labelled gate
gates: literal <ALERT_DATA> / </ALERT_DATA> delimiters are blocked; a non-loopback endpoint
       needs consent
independence: the boundary gate re-serialises model_bound and substring-tests it; it does not
       consume the marker-scan result, so a scanner miss cannot open the gate
```

</details>

Both paths use the same structured triage contract, redaction implementation, model-data boundary and draft-only review posture. Paste & inspect adds admission, injection-visibility and egress controls for untrusted ad hoc input.

[![Shared triage contract, what holds on both paths, and where the two paths diverge](architecture/assistant-paths-notes.png)](architecture/assistant-paths-notes.png)

<details>
<summary>Text version</summary>

```text
Shared triage contract — seven required fields, attack_technique_name optional:
  summary · attack_technique_id · disposition_suggestion · confidence
  investigation_queries (2–3 requested, validator accepts 1–4)
  draft_user_message · caveats

Both paths       same triage contract and validation; same redaction implementation;
                 same model-data boundary (no Wazuh write path, no response tools,
                 no enforcement, no autonomous action); draft-only output with
                 mandatory analyst review.

Paste & inspect  input limits; redaction trace; injection-marker scan over object keys
only             and string values; reserved-delimiter blocking; endpoint-aware egress
                 consent; raw input not persisted; audit record saved only when
                 explicitly requested; excluded from the frozen benchmark.

Scan vs gate     the marker scan is visibility; the boundary gate is enforcement. Both
                 inspect the model-bound object independently, so a scanner miss cannot
                 permit a literal reserved-delimiter breakout. Other instruction-shaped
                 markers may still reach the model; only literal reserved-delimiter
                 attempts are deterministically blocked.

Target state     a future read-only Wazuh ingestion path feeding the shared triage core.
```

</details>

Paste & inspect is an operational demonstration and was excluded from the frozen benchmark.

### Guardrail claims and boundaries

- **No autonomous action:** the model has no Wazuh write/action path, no response tools and no enforcement integration; every result is a draft requiring analyst review.
- **Redaction first:** tested credential classes and sensitive-key values are removed before prompt construction. File hashes remain available as investigation IOCs.
- **Redaction is risk reduction:** unknown, encoded or unlabelled secrets remain residual risk.
- **Prompt-injection handling in Paste & inspect:** tested instruction markers are surfaced from object keys and string values, including wrapped plain-text telemetry, and reserved `<ALERT_DATA>` delimiter attempts are blocked before a model call. The batch runner does not implement these runtime admission controls; it operates on the prevalidated frozen corpus.
- **No general injection-prevention claim:** other marked text may still reach the model as evidence inside an untrusted-data block and may influence its reasoning. Schema validation checks structure, not correctness.
- **Impact containment:** redacted input, no Wazuh write/action path, no response tools, no enforcement integration, draft-only output and mandatory review limit the consequence of a bad response.
- **Endpoint-aware consent in Paste & inspect:** non-loopback model endpoints require explicit consent before alert data is sent externally. Batch hosted-provider runs are explicitly initiated from the CLI and do not use this interactive consent gate.
- **Sanitized ad hoc evidence:** raw pasted input is not persisted; proof and audit records store sanitized data and a correlation hash. Optional trace correlation uses keyed HMAC via `ALERTMIND_TRACE_HMAC_KEY`.
- **Auditability:** batch calls record model/configuration, prompt and redaction hashes, latency, parse status, usage and raw/parsed responses in non-overwriting run directories.

## Repository map

```text
alertmind/
├── README.md                          # this file — repository landing page
├── report.md                          # final technical report and evidence index
├── WEEKLOG.md                         # week-by-week implementation chronology
├── .gitignore                         # excludes .env, venvs and runtime ad hoc audit output
│
├── architecture/
│   ├── soc-architecture.md            # authoritative architecture: flows, retention, RBAC, trust boundary
│   ├── diagram.drawio                 # editable source
│   ├── diagram.png                    # rendered diagram
│   ├── assistant-batch-path.png       # batch pipeline figure used in README.md
│   ├── assistant-adhoc-paste-inspect-path.png   # ad hoc pipeline figure used in README.md
│   └── assistant-paths-notes.png      # triage contract, shared guardrails, divergence
│
├── assistant/                         # assistant package, Paste & inspect UI, tests, run logs
│                                      # (see assistant/README.md for module-level detail)
│
├── detections/
│   ├── auditd/alertmind.rules         # Linux auditd collection rules
│   └── sigma/
│       ├── linux/ · windows/          # 25 portable Sigma YAML sources
│       └── notes.md                   # Sigma-to-Wazuh crosswalk and tuning notes
│
├── siem/
│   ├── wazuh/local_rules.xml          # 24 deployed custom Wazuh rules
│   └── dashboards/*.ndjson            # ATT&CK Heatmap · Daily SOC Briefing exports
│
├── attack/
│   └── runbook.md                     # per-rule trigger commands, provenance and teardown
│
├── playbooks/                         # phishing · malware · account-compromise (NIST 800-61r2)
│
├── measurement/
│   ├── alert-corpus.json              # frozen 20-alert corpus (hash below)
│   ├── timing-log.csv                 # unassisted and assisted triage timings
│   ├── assisted-timing-protocol.md    # timing protocol and its threats to validity
│   ├── analysis.ipynb                 # re-runnable metric derivation
│   └── grounding/                     # manual free-text review worksheets and rubric
│
├── docs/
│   ├── AlertMind_Defense.pdf          # defense presentation (14 slides)
│   ├── rebuild-guide.md               # rebuild the lab from a clean clone
│   ├── artifacts.md                   # artifact index
│   └── runbooks/
│       ├── wazuh-recovery.md          # SIEM recovery after host failure
│       └── wazuh-password-reset.md    # credential reset procedure
│
└── evidence/                          # screenshots and command-output evidence (EVID-* IDs)
```

## Run the assistant

The examples below use PowerShell from the repository root.

```powershell
cd assistant
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Run the offline smoke test and UI:

```powershell
python runner.py --provider mock --view operational --limit 1
python -m streamlit run app.py
```

Run with local Ollama (use the **exact** tag from `ollama list` — `llama3.1:8b`, with the colon):

```powershell
python preflight.py --provider ollama --model llama3.1:8b
python runner.py --provider ollama --model llama3.1:8b --view evaluation
```

Run with the pinned hosted model:

```powershell
$env:OPENAI_API_KEY="<your-key>"
$env:OPENAI_BASE_URL="https://api.openai.com/v1"
$env:ALERTMIND_MAX_TOKENS="25000"
python preflight.py --provider openai --model gpt-5.5-2026-04-23
python runner.py --provider openai --model gpt-5.5-2026-04-23 --view evaluation
```

Do not commit a populated `.env`; keep secrets outside the repository and use `.env.example` as the template.

## Tests and reproducibility

Run the assistant regression suite:

```powershell
cd assistant
python -m unittest discover -s tests -p "test_*.py"
```

The current suite contains **67 tests** covering provider request construction, schema/error metadata, runtime/formal-schema alignment, non-destructive audit reconstruction, redaction, strict-view label leakage, injection markers, boundary blocking, consent, ad hoc audit semantics and Streamlit state handling.

Re-score a retained audit log without changing committed evidence:

```powershell
cd assistant
python rebuild_from_audit.py outputs/runs/<run_id>/audit-log.jsonl --score-only
```

Omitting `--score-only` writes derived files under `assistant/outputs/rebuilt/<run_id>/`, not beside the source audit log. Existing derived files require an explicit `--overwrite`, and the timing-log default is resolved from the repository rather than the caller's working directory.

**Rebuilding the lab from a clean clone:** follow [`docs/rebuild-guide.md`](docs/rebuild-guide.md). Recovery and credential-reset procedures are in [`docs/runbooks/`](docs/runbooks/), and [`docs/artifacts.md`](docs/artifacts.md) indexes the produced artifacts.

Reproduce the analysis by running [`measurement/analysis.ipynb`](measurement/analysis.ipynb) top to bottom; it derives MTTD directly from the frozen-corpus timestamps, so the reported 2.32 s is re-derivable without any model access. The timing protocol and its limitations are in [`measurement/assisted-timing-protocol.md`](measurement/assisted-timing-protocol.md). Grounding worksheets and reviewer notes are under [`measurement/grounding/`](measurement/grounding/). The main result-bearing run directories are:

- `assistant/outputs/runs/20260715_060542_ollama_oper_baseline/` — matched llama3.1 operational baseline
- `assistant/outputs/runs/20260718_180713_ollama_eval_baseline/`
- `assistant/outputs/runs/20260713T115729Z_ollama_operational/` — earlier llama3.1 operational sample used for manual grounding
- `assistant/outputs/runs/20260718_183704_openai_eval_baseline/`
- `assistant/outputs/runs/20260717_073045_openai_oper_baseline/`
- `assistant/outputs/runs/20260717_074112_openai_eval_baseline/` — superseded, still-leaky evaluation view retained as history

## Detection and response content

- Architecture and trust boundary: [`architecture/soc-architecture.md`](architecture/soc-architecture.md)
- Attack-simulation runbook — per-rule trigger commands, provenance labels and teardown: [`attack/runbook.md`](attack/runbook.md)
- Portable Sigma sources (25 rules): [`detections/sigma/linux/`](detections/sigma/linux/) · [`detections/sigma/windows/`](detections/sigma/windows/)
- Detection crosswalk and tuning decisions: [`detections/sigma/notes.md`](detections/sigma/notes.md)
- Linux auditd collection: [`detections/auditd/alertmind.rules`](detections/auditd/alertmind.rules)
- Deployed Wazuh rules: [`siem/wazuh/local_rules.xml`](siem/wazuh/local_rules.xml)
- Wazuh dashboards: [`siem/dashboards/`](siem/dashboards/)
- Phishing playbook: [`playbooks/phishing.md`](playbooks/phishing.md)
- Malware playbook: [`playbooks/malware.md`](playbooks/malware.md)
- Account-compromise playbook: [`playbooks/account-compromise.md`](playbooks/account-compromise.md)

## Current limitations and remaining work

- The 20-alert, single-analyst lab study is directional rather than statistically powered; the assisted pass also followed the unassisted pass after a washout.
- Local and hosted model results are not a controlled capability comparison, and hosted results are single stochastic samples.
- The next informative model experiment is a pre-registered second 7–9B local instruct model under the same prompt, views, sampling and hardware, with the full manual grounding rubric; an ungrounded third column was not added late.
- One synthetic attack payload identifies itself as an AlertMind test after decoding, creating a documented construct-validity limitation.
- Redaction does not guarantee removal of unknown or encoded secrets.
- Prompt-injection markers provide detection and visibility; only reserved-boundary attempts are deterministically blocked. Semantic model influence remains possible.
- RBAC identities `socanalyst` and `assistant-svc` and live read-only Wazuh API ingestion remain target-state work.
- High-confidence injection quarantine with an explicit audited override remains future work.
- Live cloud ingestion is an optional stretch goal; the project uses the required Windows and Linux sources. A static cloud sample was demonstrated only.
- The IR playbooks follow NIST SP 800-61r2, which was superseded by r3 in April 2025; migration to the r3 CSF-aligned structure is follow-on work.

## Responsible AI, ethics and attribution

All attack simulation was confined to the isolated lab. The corpus contains synthetic lab events and historical lab false positives, not customer data. Redacted synthetic alerts were sent to the hosted model only for the disclosed comparison runs; the local measured runs had no alert-data egress.

The alert-summarization starting point was adapted from the author's prior [AI-SOC-Assistant](https://github.com/opandey1/AI-SOC-Assistant) project. AlertMind adds the SOC-specific prompts, provider abstraction, redaction, strict views, schema validation, audit/scoring pipeline, reproducible evaluation, grounding review and Streamlit workflows. Development-assistance use is disclosed in `report.md`; reported results derive from retained logs and re-runnable artifacts.

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [NIST SP 800-61r2](https://csrc.nist.gov/pubs/sp/800/61/r2/final) — the four-phase lifecycle the playbooks follow, as specified by the brief
- [NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) — superseded r2 in April 2025 and restructures incident response around the CSF 2.0 functions; migrating the playbooks is documented follow-on work
- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
- [Wazuh documentation](https://documentation.wazuh.com/)

---

*Built for the IIT Roorkee × Futurense PG Certificate in AI/GenAI Powered Cybersecurity, Cohort 1.*
