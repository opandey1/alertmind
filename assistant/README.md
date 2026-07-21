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
│   ├── test_injection.py    # prompt-injection resistance proof
│   └── test_llm_providers.py # offline endpoint/payload regression tests
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
export OLLAMA_BASE_URL=http://localhost:11434/v1
python runner.py --provider ollama --model llama3.1:8b --view operational
python runner.py --provider ollama --model llama3.1:8b --view evaluation
python tests/test_injection.py ollama llama3.1:8b   # the REAL injection proof
```

Hosted OpenAI GPT-5.5:

```powershell
$env:OPENAI_BASE_URL="https://api.openai.com/v1"
$env:OPENAI_API_KEY="sk-proj-..."
$env:ALERTMIND_MAX_TOKENS="25000"          # reasoning tokens consume this budget
python preflight.py --provider openai --model gpt-5.5-2026-04-23
python runner.py --provider openai --model gpt-5.5-2026-04-23 --view evaluation --limit 1
```

**Pin the snapshot, not the alias.** Use `gpt-5.5-2026-04-23`; the bare `gpt-5.5` alias
floats and can change the underlying model between runs. Snapshots exist precisely to keep
behaviour consistent, and the served model is recorded per call as `model_actual` in the
audit log.

After the one-alert run succeeds, remove `--limit 1` for the frozen corpus.

**Three caveats that affect the measurement, not just the plumbing:**
- **Reasoning effort.** This client sends **no** `reasoning_effort` by default, so the
  model's own vendor default applies (gpt-5.5 supports `none|low|medium|high|xhigh` and
  defaults to **medium**). Set `ALERTMIND_OPENAI_REASONING_EFFORT` only as a deliberate,
  **disclosed** choice: forcing `none` changes the inference configuration and may reduce
  performance on this multi-step triage task — disclose it in any comparison. (`none` is a
  legitimate setting for latency-critical classification; it is simply not the default, and
  silently applying it would make a model-capability comparison unfair.)
- **Token budget.** Reasoning tokens consume the output budget and can exhaust it before any
  visible content is emitted. Reserve a generous `ALERTMIND_MAX_TOKENS` (OpenAI's reasoning
  guidance suggests starting around 25,000; gpt-5.5 permits up to 128,000 output tokens). A
  smaller budget may suffice for AlertMind's compact JSON — validate it with `preflight.py`,
  which now prints `reasoning_tokens` usage, and with a `--limit 1` run.
- **Determinism.** Official OpenAI reasoning models reject `temperature`, so hosted runs are
  **stochastic**; a single hosted run is one sample and should be reported as such. By
  contrast, the two recorded Ollama runs at `temperature=0` were empirically byte-identical
  — that observation, not the parameter alone, is the evidence for reproducibility there.

(Anthropic: `--provider anthropic` + `ANTHROPIC_API_KEY`.)

**Configuring keys.** Copy `.env.example` to `.env` and fill it in (loaded automatically;
shell env wins; `.env` is gitignored), or set the vars in your shell, or type them into the
Streamlit sidebar's **🔑 Connection** panel. Verify any provider before a batch run:

```bash
python preflight.py --provider openai --model gpt-5.5-2026-04-23
```
Preflight resolves the URL/key/model, lists available models, and does one tiny call with a
short timeout — so a misconfiguration fails in ~20s instead of hanging 300s per alert.

**Model name + performance notes:**
- Use the **exact** Ollama tag (`ollama list` / `GET /v1/models`): `llama3.1:8b`, or `llama4:latest` — *with a colon*. `llama4-latest` (hyphen) returns a 404.
- Keep provider base URLs at the API root: `https://api.openai.com/v1`, not
  `.../v1/responses` or `.../v1/chat/completions`.
- Prefer a **small, fast** model for a 20-alert experiment. `llama3.1:8b` runs in seconds locally; large MoE models like `llama4` are impractically slow and will hit the timeout. Raise `ALERTMIND_LLM_TIMEOUT` only if you truly need a big model.

## 4a. Paste & inspect (local diagnostic)

A second Streamlit tab, **🧪 Paste & inspect**, runs arbitrary *synthetic or approved* telemetry (JSON or plain text) through the **same** path as batch triage: `redact_alert_with_trace → apply_view → injection scan → boundary gate → prompt → one model call → schema`. It exists to make the redaction and injection claims inspectable live, not just via offline proof files.

- **Local, single-user only.** Bind to localhost. Not production- or multi-user-safe until the RBAC plan (`siem/rbac/…`, documented target state) is implemented.
- **Input limits:** ≤ 50,000 chars, depth ≤ 20, ≤ 10,000 nodes.
- **Hard boundary gate:** a literal `<ALERT_DATA>`/`</ALERT_DATA>` delimiter in any model-bound key or value **blocks the call**. Enforcement independently checks the complete serialized object immediately before the provider path.
- **Egress consent:** every non-loopback model endpoint requires an explicit confirmation bound to the current input, provider, model and endpoint. Mock and verified loopback endpoints do not require external-egress consent.
- **Sanitized evidence:** the redaction trace stores masks, lengths and an optional keyed HMAC fingerprint (`ALERTMIND_TRACE_HMAC_KEY`); it never stores an unsalted digest of the raw value. Proof download and a **one-shot idempotent** audit save (`outputs/adhoc/`) omit raw input and tested secret values.
- **State safety:** changing the input/sample clears the old result, editable draft and consent. Configuration changes mark a result stale and disable proof/audit actions until rerun.
- **Audit semantics:** `schema_valid` is tri-state — `true`/`false` only after validation and `null` when a request was blocked or not evaluated; `call_status` records why.
- **Excluded from the frozen benchmark.** Ad-hoc results and any reference label are exploratory and never combined with the §9 corpus results.

New modules: `paste_core.py` (pure pipeline, unit-tested), `paste_tab.py` (Streamlit render), `injection.py` (marker scan + boundary gate — *visibility, not the defence*), `samples.py` (synthetic demo fixtures), `audit.py` (shared record contract), `ui_helpers.py`. Added `redact.redact_alert_with_trace()` (delegates to the same recursion as `redact_alert()`, so proof and production paths cannot diverge). New tests: `test_injection_markers.py`, `test_redaction_trace.py`, `test_paste_pipeline.py`, `test_adhoc_audit.py`, `test_paste_ui.py`.

## 5. Two views — why they matter

The corpus alert carries the rule's own ATT&CK label (`mitre.id`, and the T-code inside `rule_description`). If the model sees them, "did it return the right technique" only tests whether it can **copy** the label.

- **operational** — full alert incl. the rule's metadata. Realistic for a Wazuh-integrated assistant. The technique metric here is **ATT&CK metadata consistency**, not classification.
- **evaluation** — strips `mitre`, `rule_id`, and every T-code, so the model must infer from raw process/file/registry/audit fields. This is the defensible **classification accuracy** measurement.

The mock makes the point concretely: **operational 14/20 overall → evaluation 0/20** (technique 6/20), because the mock only copies the label and cannot classify once it is removed.

## 6. Scope of the redaction claim

The redaction layer removes tested classes of common credentials (passwords, AWS keys, bearer tokens, `sk-`/`sk-proj-` API keys, PEM/OpenSSH private keys, connection-string passwords) and replaces the complete value of sensitive-key fields regardless of JSON type. This materially reduces disclosure risk but is **not** a guarantee that every possible secret is removed — residual risk remains for unknown, encoded, or unlabelled secrets. Expanding coverage (Basic auth, JWTs, `ghp_`/`xoxb-` tokens, URL credentials, decode-then-redact for encoded PowerShell) remains a tracked follow-up.

## 7. Measurement integrity

- **Separated metrics** (`scoring.py`): `technique_exact`, `technique_relaxed` (parent/sub), `disposition_correct`, `response_consistent`, `overall`. A right technique with a contradictory benign disposition is no longer scored correct.
- **Analyst vs Evaluator UI modes**: Analyst mode hides ground truth (use during the assisted timing run); Evaluator mode reveals scoring (use only after).
- **Learning effect**: the assisted pass re-triages a **counterbalanced A/B split with a washout period**, and the residual learning effect is reported as a limitation.

## 8. Attribution

Alert-summarization core adapted from the author's prior **[AI-SOC-Assistant](https://github.com/opandey1/AI-SOC-Assistant)** (reuse permitted; disclosed). New for AlertMind: redaction, views, prompt library + injection defence, schema validation, audit logging, scoring, provider abstraction, corpus runner, and the Streamlit UI.
