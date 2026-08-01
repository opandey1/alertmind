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

- **`grounding-review_<model>_<view>.csv`** — one row per alert, with the deliverables and pre-filled `auto_*` columns. Open in Excel and fill the six blank `HUMAN` columns. This is your tally sheet.
- **`grounding-review_<model>_<view>.md`** — a readable worksheet: alert evidence beside the assistant output, with a blank verdict table per alert. Use this to *judge*; record the result in the CSV.

Runs provided: **llama3.1 operational** and **gpt-5.5 operational** — the two the analyst actually sees (operational view). Ground the strict-view runs too if you want, but operational is what the timing pass and the deployment question rest on.

| Worksheet | Source run | Prompt version | Redaction version |
|---|---|---|---|
| llama3.1 operational | `assistant/outputs/runs/20260713T115729Z_ollama_operational/` | `88b9c3f1656b683b` | `3a527e33fa159616` |
| GPT-5.5 operational | `assistant/outputs/runs/20260717_073045_openai_oper_baseline/` | `23185744b88f77b7` | `3a527e33fa159616` |

The llama3.1 worksheet predates the later matched automated-comparison run `20260715_060542_ollama_oper_baseline` (14/14 operational exact-ID overlap). Its manual free-text verdicts apply only to the source run listed above and must not be attributed to that later output sample.

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
4. Pay special attention to the **six benign false positives** (A02, A07, A08, A11, A12, A20) and to **A18** — grounding failures there are the most decision-relevant.

## Reporting the result

Add one paragraph and a small table to report §9, e.g.:

> Across the 20 operational outputs, N/20 summaries were fully supported, with M unsupported statements total; queries were valid in P/20 and relevant in Q/20; draft messages were appropriate in R/20; confidence was calibrated in S/20.

Report per model, and call out any hallucination by alert ID. A faster-but-fabricating assistant is worse than a slower correct one — this is where you show whether the free-text outputs are trustworthy, not just the tag.
