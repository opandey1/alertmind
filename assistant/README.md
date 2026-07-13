# AlertMind — LLM Tier-1 SOC Assistant

Given a single Wazuh alert, this assistant produces four things to speed up Tier-1 triage:

1. a **5-line summary**, 2. a **MITRE ATT&CK technique tag**, 3. **suggested investigation queries**, and 4. a **draft message** to the affected user.

It is built to be **safe** (secrets redacted before the model; alert content treated as untrusted), **honest** (technique/disposition scored separately against ground truth, with an evaluation view that removes the answer from the input), and **reproducible** (an offline `mock` provider runs the whole thing with zero setup).

> Every output is a **DRAFT for a human analyst to review**. The assistant has no tools and takes no action.

---

## 1. Pipeline

```
alert ─▶ redact ─▶ apply view ─▶ build prompt ─▶ call LLM ─▶ parse ─▶ validate ─▶ log ─▶ score
        redact.py   views.py      prompts.py      llm.py      llm.py   schema.py  runner  scoring.py
           │           │             │                                    │           │
      secrets out   metadata     untrusted-data                     schema-checked   per-run
      (pre-prompt)  in/out       ALERT_DATA block                                    audit dir
```

## 2. Guardrails

| Guardrail | Enforcement |
|---|---|
| **No secrets to the model** | `redact_alert()` runs before any prompt. Proven by `tests/test_redact.py` → `outputs/redaction_proof.md`. Scope is *tested credential classes*, not a claim of completeness (see §6). |
| **No autonomous action** | The model has no tools — text only. System prompt forbids recommending auto-execution; every output stamped `analyst_review_required: true`. |
| **Prompt-injection resistance** | Alert wrapped in an `<ALERT_DATA>` untrusted-data block; system prompt says never obey instructions inside it. Proven by `tests/test_injection.py` → `outputs/injection_proof.md`. |
| **Human review** | All output is DRAFT; the UI shows a review banner and an editable draft message. |
| **Output validated** | `schema.py` checks required keys, types, allowed dispositions/confidence, ATT&CK-ID syntax, `<=5` summary lines. Invalid output is recorded, not silently scored. |
| **Full, persistent logging** | Each run writes `outputs/runs/<run_id>/audit-log.jsonl`: timestamp, provider, model, view, prompt/redaction versions, git commit, input/redacted-prompt/response hashes, latency, parse status, the redacted prompt sent, and the parsed output. Runs never overwrite each other. |
| **Measured, not hidden** | `assistant_scoring.csv` scores technique (exact + relaxed), disposition, and consistency separately vs ground truth. |

## 3. Files

```
assistant/
├── redact.py        prompts.py     llm.py       runner.py    app.py
├── views.py         # operational vs evaluation view of the alert
├── scoring.py       # separated technique / disposition / consistency metrics
├── schema.py        # output schema validation
├── requirements.txt · .env.example
├── tests/
│   ├── test_redact.py       # redaction proof (plants secrets, asserts none leak)
│   └── test_injection.py    # prompt-injection resistance proof
└── outputs/
    ├── redaction_proof.md · injection_proof.md
    └── runs/<run_id>/       # assistant_outputs.json, assistant_scoring.csv, audit-log.jsonl
```

## 4. Run it

```bash
cd assistant
pip install -r requirements.txt
python tests/test_redact.py                       # redaction proof (non-zero exit if a secret leaks)
python tests/test_injection.py                    # injection proof (mock resists by construction)
python runner.py --provider mock --view operational
python runner.py --provider mock --view evaluation
streamlit run app.py                              # analyst UI (Analyst / Evaluator modes)
```

Real model (this is what the measurement uses), e.g. local Ollama:

```bash
export OPENAI_BASE_URL=http://localhost:11434/v1
python runner.py --provider ollama --model llama3.1 --view operational
python runner.py --provider ollama --model llama3.1 --view evaluation
python tests/test_injection.py ollama llama3.1    # the REAL injection proof
```
(Anthropic: `--provider anthropic` + `ANTHROPIC_API_KEY`. OpenAI: `--provider openai` + `OPENAI_API_KEY`.)

## 5. Two views — why they matter

The corpus alert carries the rule's own ATT&CK label (`mitre.id`, and the T-code inside `rule_description`). If the model sees them, "did it return the right technique" only tests whether it can **copy** the label.

- **operational** — full alert incl. the rule's metadata. Realistic for a Wazuh-integrated assistant. The technique metric here is **ATT&CK metadata consistency**, not classification.
- **evaluation** — strips `mitre`, `rule_id`, and every T-code, so the model must infer from raw process/file/registry/audit fields. This is the defensible **classification accuracy** measurement.

The mock makes the point concretely: **operational 14/20 overall → evaluation 0/20** (technique 6/20), because the mock only copies the label and cannot classify once it is removed.

## 6. Scope of the redaction claim

The redaction layer removes tested classes of common credentials (passwords, AWS keys, bearer tokens, `sk-` API keys, PEM/OpenSSH private keys, connection-string passwords) and materially reduces disclosure risk. It is **not** a guarantee that every possible secret is removed — residual risk remains for unknown, encoded, or unlabelled secrets. Expanding coverage (Basic auth, JWTs, `ghp_`/`xoxb-` tokens, URL credentials, decode-then-redact for encoded PowerShell) and context-aware hash handling are tracked follow-ups.

## 7. Measurement integrity

- **Separated metrics** (`scoring.py`): `technique_exact`, `technique_relaxed` (parent/sub), `disposition_correct`, `response_consistent`, `overall`. A right technique with a contradictory benign disposition is no longer scored correct.
- **Analyst vs Evaluator UI modes**: Analyst mode hides ground truth (use during the assisted timing run); Evaluator mode reveals scoring (use only after).
- **Learning effect**: the assisted pass re-triages a **counterbalanced A/B split with a washout period**, and the residual learning effect is reported as a limitation.

## 8. Attribution

Alert-summarization core adapted from the author's prior **[AI-SOC-Assistant](https://github.com/opandey1/AI-SOC-Assistant)** (reuse permitted; disclosed). New for AlertMind: redaction, views, prompt library + injection defence, schema validation, audit logging, scoring, provider abstraction, corpus runner, and the Streamlit UI.
