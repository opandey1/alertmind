# Grounding review — manual evaluation of the assistant's free-text outputs

Automated scoring (`scoring.py`) covers only the **technique tag** and **disposition**. It does *not* check whether the assistant's three free-text deliverables — the **summary**, the **investigation queries**, and the **draft user message** — are actually supported by the alert. This review closes that gap. It is the difference between "the assistant labelled it T1003.001" and "everything the assistant *said* about the alert is true and useful."

## What you're scoring

For each alert, judge the assistant output against the alert evidence on six dimensions:

| Dimension | Question | Values |
|---|---|---|
| `summary_supported` | Is every summary line traceable to the alert? | Y / partial / N |
| `unsupported_statement_count` | How many assertions are **not** backed by the alert? | integer |
| `queries_valid` | Are the investigation queries runnable / well-formed? | Y / N |
| `queries_relevant` | Would they actually advance *this* triage? | Y / N |
| `draft_appropriate` | Accurate, no overclaim, safe to send after review? | Y / N |
| `confidence_calibrated` | Does stated confidence match evidence strength? | Y / N |

A "hallucination" for this project is any **factual** claim in these three deliverables that the alert does not support — a fabricated file path, an invented account, a process that isn't in the telemetry, a CVE that doesn't apply. Those are the major-deduction items the rubric calls out.

## How to use the kit

Two files per run:

- **`grounding-review_<model>_<view>.csv`** — one row per alert, with the deliverables, `auto_*` hints, six verdict dimensions, reviewer notes and explicit review provenance.
- **`grounding-review_<model>_<view>.md`** — the same verdicts and provenance beside the alert evidence and assistant output. The CSV and Markdown tables are mechanically checked for parity.

Runs provided: **llama3.1 operational**, **GPT-5.5 operational**, and **qwen3:8b operational** — the three operational-view outputs used in the model comparison. Ground the strict-view runs too if needed, but the operational view is what the analyst actually sees and what the timing pass and deployment question rest on.

| Worksheet | Source run | Prompt version | Redaction version |
|---|---|---|---|
| llama3.1 operational | `assistant/outputs/runs/20260713T115729Z_ollama_operational/` | `88b9c3f1656b683b` | `3a527e33fa159616` |
| GPT-5.5 operational | `assistant/outputs/runs/20260717_073045_openai_oper_baseline/` | `23185744b88f77b7` | `3a527e33fa159616` |
| qwen3:8b operational | `assistant/outputs/runs/20260830_054251_ollama_oper_baseline/` | `23185744b88f77b7` | `cf0549f832d13b7f` |

The llama3.1 worksheet predates the later matched automated-comparison run `20260715_060542_ollama_oper_baseline` (14/14 operational exact-ID overlap). Its manual free-text verdicts apply only to the source run listed above and must not be attributed to that later output sample. The earlier run's committed scoring CSV is retained exactly as produced by the then-current single-ID validator. A13 and A19 were parsed correctly but rejected as `bad_syntax`; a non-writing re-score of the audit log with the current validator yields 13/14 attack exact, 14/14 attack relaxed, 14/20 disposition, 20/20 consistent and 14/20 overall. That retrospective score is provenance context, not the matched automated-comparison result.

## Review protocol and provenance

All three worksheets follow the same procedural sequence: an initial human-authored verdict pass, followed by an evidence-led Codex second pass against the **complete serialized operational prompt and response**, not only the compact `key_fields` excerpt. The CSV and Markdown worksheets record both `review_provenance` and `agent_second_pass_changes` for every alert, so factual corrections and judgement changes are visible rather than silently overwritten.

This does **not** create an independent second-reviewer result: one human remains the final adjudicator. Qwen's agent-corrected verdicts were explicitly approved by the human reviewer on 2026-08-31. The changed llama3.1 and GPT-5.5 rows are marked pending explicit human adjudication. Until that sign-off, their revised totals below are provisional.

| Worksheet | Fully supported summaries | Unsupported statements | Queries valid / relevant | Draft appropriate | Confidence calibrated | Adjudication status |
|---|---:|---:|---:|---:|---:|---|
| llama3.1 operational | 12/20 (8 partial) | 9 | 0/20 / 20/20 | 17/20 | 13/20 | Four changed rows pending human adjudication |
| GPT-5.5 operational | 20/20 | 0 | 15/20 / 20/20 | 20/20 | 20/20 | Five changed rows pending human adjudication |
| qwen3:8b operational | 12/20 (8 partial) | 8 | 0/20 / 20/20 | 18/20 | 18/20 | Human-approved |

### qwen3:8b operational review

For `20260830_054251_ollama_oper_baseline`, **12/20 summaries were fully supported** and eight were partial, with **eight unsupported statements total**. The partial summaries were A06, A07, A08, A09, A11, A12, A16 and A17. Investigation sets were **relevant in 20/20** but **runnable/well-formed in 0/20** because they used generic or undefined SQL, prose, or incomplete shell commands rather than concrete Wazuh/Discover queries. Drafts were appropriate in **18/20** (A16 and A19 failed), and confidence was calibrated in **18/20** (A12 and A20 failed). These verdicts use the complete prompt as the grounding source; the worksheet's `key_fields` excerpt is supporting context, not the full evidence boundary.

### Agent-assisted llama3.1 and GPT-5.5 corrections awaiting adjudication

The llama3.1 second pass changed A07, A08, A16 and A20. It identified unsupported username attribution, two unsupported A08 claims (including an LSASS-memory-read claim not established by access mask `0x3600`), `/var/log/btmp` being described as an audit log, and syscall 257 being described as `read` rather than `openat`. The current tally is **12/20 fully supported summaries**, **nine unsupported statements**, **0/20 valid and 20/20 relevant query sets**, **17/20 appropriate drafts** and **13/20 calibrated confidence verdicts**.

The GPT-5.5 second pass changed `queries_valid` for A01, A04, A08, A16 and A17. Those sets are relevant, but use rule-language `audit.*` or `win.*` fields rather than the indexed Wazuh `data.audit.*` / `data.win.*` paths. The current tally is **20/20 fully supported summaries**, **zero unsupported statements**, **15/20 valid and 20/20 relevant query sets**, and **20/20** for both draft appropriateness and confidence calibration.

## What the AUTO flags mean (and don't)

The `auto_*` columns are **hints to verify, never verdicts**:

- `auto_unknown_entities` — a process/path/IP/hex value named in the summary or draft that does **not** appear in the alert. This is the primary hallucination screen. **A flag is not a failure:** GPT-5.5 often names a correct standard path (e.g. a Defender directory) from domain knowledge. Check each against the alert *and* your own knowledge — legitimate context stays, invented specifics count as unsupported.
- `auto_queries_syntactic` — `k/n` queries that look like field/SQL/Wazuh syntax rather than prose. Low numbers flag vague natural-language "queries" that a SOC can't run as-is (a `queries_valid` concern).
- `auto_summary_over_5` / `auto_tid_in_summary` — the summary exceeded five lines, or asserts a T-code (check it's evidence-based, not stated).
- `auto_draft_present` — flags a missing draft message.

The auto layer does **not** judge relevance, appropriateness, or calibration — those are entirely yours.

## Suggested procedure (≈30–40 min per run)

1. Work the `.md` worksheet top to bottom; for each alert, read the evidence first, then the three deliverables.
2. Resolve every `⚑ AUTO` flag: is the named entity real, or invented?
3. Score the six dimensions in the CSV; note the specific unsupported claim in `reviewer_notes`.
4. If an agent-assisted evidence check changes a verdict, record the affected dimensions in `agent_second_pass_changes` and the author/adjudication state in `review_provenance`.
5. Pay special attention to the **six benign false positives** (A02, A07, A08, A11, A12, A20) and to **A18** — grounding failures there are the most decision-relevant.

## Reporting the result

Add one paragraph and a small table to report §9, e.g.:

> Across the 20 operational outputs, N/20 summaries were fully supported, with M unsupported statements total; queries were valid in P/20 and relevant in Q/20; draft messages were appropriate in R/20; confidence was calibrated in S/20.

Report per model, and call out any hallucination by alert ID. A faster-but-fabricating assistant is worse than a slower correct one — this is where you show whether the free-text outputs are trustworthy, not just the tag.
