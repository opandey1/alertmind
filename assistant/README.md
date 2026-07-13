# AlertMind — LLM Tier-1 SOC Assistant

Given a single Wazuh alert, this assistant produces four things to speed up Tier-1 triage:

1. a **5-line summary** of what the alert means,
2. a **MITRE ATT&CK technique tag**,
3. **suggested investigation queries** (Wazuh/Discover), and
4. a **draft message** to the affected user or system owner.

It is built to be **safe** (secrets never reach the model), **honest** (its ATT&CK tag is scored against ground truth so hallucinations are measured, not hidden), and **reproducible** (an offline `mock` provider lets an examiner run the whole thing with zero setup).

> Everything the assistant outputs is a **DRAFT for a human analyst to review**. The assistant never takes an action.

---

## 1. How it works — the pipeline

For every alert the runner executes the same five steps:

```
alert ──▶ [1] redact ──▶ [2] build prompt ──▶ [3] call LLM ──▶ [4] parse JSON ──▶ [5] log + score
          (redact.py)     (prompts.py)         (llm.py)         (llm.py)          (runner.py)
             │                                    │                                   │
     secrets stripped                    hosted / Ollama / mock              audit-log.jsonl
     BEFORE any prompt                                                       + assistant_scoring.csv
```

1. **Redact** (`redact.py`) — the alert is passed through a deterministic redaction layer that strips passwords, API keys, tokens, and private keys. This happens **before a prompt is ever built**, so secrets never leave the environment. File hashes (IOCs) are kept.
2. **Build prompt** (`prompts.py`) — a fixed system prompt sets the assistant's role and guardrails; the redacted alert is embedded as JSON.
3. **Call the model** (`llm.py`) — provider-agnostic: hosted API, local Ollama, or an offline deterministic `mock`.
4. **Parse** — the model is asked for strict JSON; the response is parsed (tolerant of ```` ```json ```` fences), with a graceful fallback if it isn't valid JSON.
5. **Log + score** (`runner.py`) — the exact redacted prompt and raw response are written to `audit-log.jsonl`; the assistant's ATT&CK tag / disposition is compared to ground truth and written to `assistant_scoring.csv`.

## 2. Guardrails (rubric: 20% of the grade lives here)

| Guardrail | How it is enforced |
|---|---|
| **Never receives secrets** | `redact_alert()` runs before any prompt is built. Proven by `tests/test_redact.py`, which plants fake secrets and asserts none survive → `outputs/redaction_proof.md`. |
| **Never takes autonomous action** | The model has **no tools** — it can only return text. The system prompt forbids recommending auto-execution, and every output is stamped `analyst_review_required: true`. |
| **Human review on every output** | All output is labelled DRAFT; the Streamlit UI shows a review banner and makes the draft message editable. |
| **Full logging** | `audit-log.jsonl` records, per call: timestamp, provider, model, the **redacted** prompt actually sent, and the raw response — full traceability and proof of no-secrets. |
| **Hallucination is measured, not hidden** | `assistant_scoring.csv` scores the assistant's tag/disposition against ground truth, including whether it correctly calls the 6 benign alerts benign. |

## 3. Files

```
assistant/
├── redact.py            # redaction layer (deterministic, testable)
├── prompts.py           # system prompt + user-prompt builder
├── llm.py               # provider clients: mock | anthropic | openai | ollama
├── runner.py            # batch pipeline over the corpus
├── app.py               # Streamlit analyst UI
├── requirements.txt
├── .env.example         # which env vars each provider needs
├── tests/
│   └── test_redact.py   # redaction proof (plants secrets, asserts none leak)
└── outputs/             # generated
    ├── assistant_outputs.json   # 4 deliverables per alert (analyst reads these)
    ├── assistant_scoring.csv    # tag/disposition vs ground truth
    ├── audit-log.jsonl          # per-call redacted prompt + raw response
    └── redaction_proof.md       # before/after secret-stripping evidence
```

## 4. Run it

No setup needed for the offline path:

```bash
cd assistant
pip install -r requirements.txt          # requests + streamlit
python tests/test_redact.py              # redaction proof (exits non-zero if any secret leaks)
python runner.py --provider mock         # full pipeline, offline, deterministic
```

With a real model (this is what the measurement uses):

```bash
# Local Ollama (no key, private):
export OPENAI_BASE_URL=http://localhost:11434/v1
python runner.py --provider ollama --model llama3.1

# Anthropic:
export ANTHROPIC_API_KEY=...
python runner.py --provider anthropic --model claude-3-5-sonnet-latest

# OpenAI (or any OpenAI-compatible endpoint):
export OPENAI_API_KEY=...
python runner.py --provider openai --model gpt-4o-mini
```

Analyst UI:

```bash
streamlit run app.py
```

## 5. The `mock` provider (and why the demo shows 14/20, not 100%)

`mock` is an offline stub so the pipeline is runnable without any model. It naively reads the ATT&CK id straight from the alert and always answers `needs_investigation` — so it gets the 14 attacks "right" but **fails all 6 benign alerts** (it never says `likely_benign`). That 14/20 is intentional: it demonstrates the exact failure mode the scoring is built to catch — an assistant that parrots the rule's tag and can't tell a false positive from a real attack. A real model is expected to do better on the benign set; measuring that gap is the point.

## 6. How it plugs into the measurement (Week 3)

The unassisted baseline already exists in `measurement/timing-log.csv` (`condition=unassisted`). To produce the assisted results:

1. `python runner.py --provider <real>` → generates `assistant_outputs.json` (what the analyst reads) and `assistant_scoring.csv` (the assistant's tag accuracy + benign-discrimination = the hallucination measure).
2. Re-triage the same corpus **with the assistant's output visible**, timing t3→t4 again, and append those rows to `timing-log.csv` with `condition=assisted`. Copy `assistant_tag` / `assistant_tag_correct` from `assistant_scoring.csv`.
3. The analysis notebook then compares **condition × {median triage time, disposition accuracy, hallucination count}**.

Scoring rule for `assistant_tag_correct`: for an **attack** alert, the assistant's technique (sub- or parent-technique) must be in the ground-truth set; for a **benign** alert, the assistant must suggest `likely_benign`. A confident attack tag on a benign alert counts as a hallucination.

## 7. Attribution

The alert-summarization core is adapted from the author's prior **[AI-SOC-Assistant](https://github.com/opandey1/AI-SOC-Assistant)** repository (reuse permitted; disclosed for academic integrity). New for AlertMind: the redaction layer, the SOC prompt library, the audit logging, the provider abstraction, the corpus runner + scoring, and the Streamlit UI.
