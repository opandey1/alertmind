# AlertMind — LLM Tier-1 SOC Assistant

Given a single Wazuh alert, the assistant returns a structured triage draft containing a summary, ATT&CK classification, disposition and confidence, investigation queries, a draft user message and caveats.

It is built to be **safe** (secrets redacted before the model; alert content treated as untrusted), **honest** (technique/disposition scored separately against ground truth, with an evaluation view that removes the answer from the input), and **reproducible** (an offline `mock` provider runs the whole thing with zero setup).

> Every output is a **DRAFT for a human analyst to review**. The assistant has no tools and takes no action.

---

## 1. Pipeline

**Transport maintenance (2026-09-05):** The lab's OpenSSH `.3.6` update requires
the separately reviewed [boot-order recovery and reboot proof](../docs/runbooks/rbac-phase1c-ssh-boot-order-recovery.md)
before the pending rollback drill resumes. Temporary owner recovery is not
reboot-persistence evidence. No live reader or application authentication is
implemented by this maintenance package.

**Batch evaluation path** (the measured artifact):

```
alert ─▶ redact ─▶ apply view ─▶ build prompt ─▶ call LLM ─▶ parse ─▶ validate ─▶ log ─▶ score
        redact.py   views.py      prompts.py      llm.py      llm.py   schema.py  runner  scoring.py
           │           │             │                                    │           │
      secrets out   metadata     untrusted-data                     schema-checked   per-run
      (pre-prompt)  in/out       ALERT_DATA block                                    audit dir
```

**Ad hoc path** (Paste & inspect, §4a) — shares the redaction implementation and the model
boundary, but is *not* the same pipeline; it adds input limits, a redaction trace, injection
visibility, delimiter blocking and egress consent, and it does not score:

```
pasted JSON ─▶ limits ─▶ redact+trace ─▶ apply view ─▶ scan keys/values ─▶ boundary gate
            ─▶ egress consent ─▶ one call ─▶ validate ─▶ DRAFT + optional sanitised audit
```

## 2. Guardrails

| Guardrail | Enforcement |
|---|---|
| **Tested secrets redacted before the model** | `redact_alert()` runs before any prompt is built, so downstream stages only ever see redacted content. Evidenced by `tests/test_redact.py` → `outputs/redaction_proof.md` (0/7 planted values survived). Scope is *tested credential classes*, not completeness (see §6). |
| **No autonomous action** | The model has no tools — text only. System prompt forbids recommending auto-execution; every output stamped `analyst_review_required: true`. |
| **Injection visibility & containment** | Alert wrapped in an `<ALERT_DATA>` untrusted-data block; the system prompt says analyse, never obey. `injection.py` surfaces tested instruction-shaped markers in **both keys and values**. This is detection, **not prevention** — other marked content still reaches the model and may influence it. Impact is contained by redaction, no tools, draft-only output and analyst review. One recorded run (`tests/test_injection.py` → `outputs/injection_proof.md`) shows the model not complying with the planted instruction; that is an observation, not a general guarantee. |
| **Reserved-delimiter boundary gate** | A literal `<ALERT_DATA>`/`</ALERT_DATA>` in any model-bound **key or value** blocks the call before the provider path. The gate independently serialises the complete object, so it does not depend on the marker scan being complete. `tests/test_injection_markers.py`. |
| **Egress consent** | Any non-loopback endpoint requires explicit confirmation bound to the current input, provider, model and endpoint. Mock and verified loopback endpoints proceed without external-egress consent. `tests/test_paste_pipeline.py`. |
| **Human review** | All output is DRAFT; the UI shows a review banner and an editable draft message. |
| **Output validated** | `schema.py` checks required keys, undeclared fields, types, allowed dispositions/confidence, ATT&CK-ID syntax and `<=5` summary lines. The prompt requests 2–3 investigation queries; the validator accepts 1–4. Invalid output is recorded; the CLI reports schema-valid coverage, and `valid_overall_correct` prevents schema-invalid output from receiving validity-gated overall credit while preserving the original metrics. |
| **Full, persistent batch logging** | Each run writes `outputs/runs/<run_id>/audit-log.jsonl` with **25 fields** per call: timestamp, provider, model *requested* and `model_actual` served, view, prompt/redaction version hashes, git commit, input/prompt/response hashes, the redacted prompt sent, raw and parsed output, latency, parse status, schema errors, the effective `request_config`, `response_id`, `system_fingerprint`, `finish_reason` and token `usage`. The runner creates a new directory per run. `rebuild_from_audit.py` reconstructs scoring using repository-relative timing-log ground truth without another model call; it writes to `outputs/rebuilt/<run_id>/` by default, supports `--score-only`, and refuses to replace derived files unless `--overwrite` is explicit. |
| **Sanitised ad hoc audit** | Paste & inspect saves one record only on explicit request, idempotent by result ID. Raw pasted input is never persisted; `schema_valid` is tri-state (`null` when a call was blocked or not evaluated) and `call_status` records why. `tests/test_adhoc_audit.py`. |
| **Measured, not hidden** | `assistant_scoring.csv` scores technique (exact + relaxed), disposition, and consistency separately vs ground truth. |

## 3. Files

```
assistant/
├── runner.py            # batch CLI; full corpus, --limit, or explicit --alert-ids subset
├── app.py               # Streamlit UI — Triage · Paste & inspect · Evaluator modes
├── preflight.py         # provider connectivity diagnostic (fails fast, prints effective config)
├── rebuild_from_audit.py# safely regenerate outputs/scoring or score only; no model re-run
│
├── redact.py            # secret stripping; redact_alert() and redact_alert_with_trace()
├── views.py             # operational vs strict label-reduced evaluation view
├── prompts.py           # system prompts + ALERT_DATA untrusted-data wrapper
├── llm.py               # providers: mock / ollama / openai / anthropic; .env loader; tolerant parse
├── schema.py            # output schema validation
├── scoring.py           # separated technique / disposition / consistency metrics
│
├── paste_core.py        # Paste & inspect pipeline (pure, no Streamlit import — unit-tested)
├── paste_tab.py         # Paste & inspect Streamlit render
├── injection.py         # instruction-marker scan + reserved-delimiter boundary gate
├── samples.py           # synthetic demo fixtures (planted secrets / planted injection)
├── audit.py             # shared audit-record contract + idempotent JSONL append
├── ui_helpers.py        # side-effect-free presentation helpers
│
├── requirements.txt · .env.example       # flexible user-install specification
├── requirements-ci.lock                  # hash-pinned Python 3.12 linux set used by offline CI
├── README.md · DESIGN_AND_CHANGELOG.md   # design decisions, review log, Q&A
│
├── tests/               # 110 unittest methods across 14 files
│   ├── test_redact.py            # redaction proof (plants secrets, asserts none leak)
│   ├── test_redaction_trace.py   # trace masks values; proof and production paths cannot diverge
│   ├── test_injection.py         # recorded injection scenario (mock + real provider)
│   ├── test_injection_markers.py # marker scan, corpus false-positive check, boundary blocking
│   ├── test_views_leakage.py     # strict view: 0/20 alerts leak a technique code
│   ├── test_paste_pipeline.py    # limits, parse modes, boundary gate, consent, no raw storage
│   ├── test_adhoc_audit.py       # one record, idempotent, sanitised, tri-state schema_valid
│   ├── test_paste_ui.py          # Streamlit state handling (uses AppTest; no live server required)
│   ├── test_llm_providers.py     # offline endpoint/payload regression tests
│   ├── test_schema.py            # runtime/formal schema alignment and query bounds
│   ├── test_rebuild_from_audit.py# non-destructive rebuild and ground-truth path handling
│   ├── test_runner_selection.py   # explicit subset selection; unknown IDs fail closed
│   ├── test_phase0_characterization.py  # pins current pipeline/provider behaviour before the RBAC refactor
│   └── test_rbac_templates.py     # offline contract for the committed RBAC/SSH templates and operator proofs
│
└── outputs/
    ├── redaction_proof.md · injection_proof.md
    ├── paste_demo_redaction_proof.md · paste_demo_injection_proof.md
    ├── runs/<run_id>/   # assistant_outputs.json, assistant_scoring.csv, audit-log.jsonl
    └── adhoc/           # ad hoc audit records (gitignored — runtime output, not evidence)
```

## 4. Run it

```bash
cd assistant
pip install -r requirements.txt
python -m unittest discover -s tests -p "test_*.py"   # full suite — 110 tests
python tests/test_redact.py                       # redaction proof (non-zero exit if a secret leaks)
python tests/test_injection.py                    # recorded injection scenario (mock)
python runner.py --provider mock --view operational
python runner.py --provider mock --view evaluation
streamlit run app.py                              # UI: Triage · Paste & inspect · Evaluator
```

Re-score a retained audit log without writing files:

```bash
python rebuild_from_audit.py outputs/runs/<run_id>/audit-log.jsonl --score-only
```

Without `--score-only`, regenerated files go to `outputs/rebuilt/<run_id>/`, which is
gitignored and separate from the committed source-run evidence. Use `--output-dir` to
choose another destination. Existing derived files are replaced only with an explicit
`--overwrite`; pointing `--output-dir` at the source run is therefore never implicit.

Real model (this is what the measurement uses), e.g. local Ollama:

```bash
export OLLAMA_BASE_URL=http://localhost:11434/v1
python runner.py --provider ollama --model llama3.1:8b --view operational
python runner.py --provider ollama --model llama3.1:8b --view evaluation
python tests/test_injection.py ollama llama3.1:8b   # the REAL injection proof
```

Selected Qwen3:8b provenance-rerun configuration (PowerShell):

```powershell
$env:OLLAMA_BASE_URL="http://localhost:11434/v1"
$env:ALERTMIND_OLLAMA_TEMPERATURE="0.6"
$env:ALERTMIND_OLLAMA_TOP_P="0.95"
$env:ALERTMIND_OLLAMA_SEED="42"
$env:ALERTMIND_OLLAMA_STRUCTURED_OUTPUTS="1"
$env:ALERTMIND_MAX_TOKENS="4096"
$env:ALERTMIND_LLM_TIMEOUT="900"

# Optional diagnostic subset; the frozen corpus file is not modified.
python runner.py --provider ollama --model qwen3:8b --view evaluation `
  --alert-ids A04,A06,A10,A12,A16,A18

# Result-bearing runs must use committed code and process all 20 alerts.
python runner.py --provider ollama --model qwen3:8b --view operational
python runner.py --provider ollama --model qwen3:8b --view evaluation
```

`--alert-ids` and `--limit` are mutually exclusive, and subset run IDs end in
`_subset<N>_<8-hex-ID-hash>` so equal-sized diagnostics remain distinguishable
and cannot be mistaken for a full benchmark. Qwen3's
`top_k=20` and `repeat_penalty=1` remain verified model defaults because Ollama's
OpenAI-compatible endpoint does not expose them as request fields. Keep
`ollama show qwen3:8b` with the run evidence. The fixed seed improves repeatability
but is not described as a determinism guarantee. For Ollama 0.33.x compatibility,
the provider-side grammar omits only the ATT&CK-ID regex and makes the optional
technique-name field required-but-nullable for strict-schema compatibility;
`schema.py` applies the canonical ATT&CK regex after generation and records a
schema-invalid result if it fails. If the subset still records
`finish_reason=length`, increase only `ALERTMIND_MAX_TOKENS` to `8192`, rerun the
entire subset, freeze the resulting configuration, and then run both full views.

The retained `20260827_180830`/`20260827_192445` pair is explicitly a
**pre-commit candidate**, not final evidence: its audit logs embed a commit that
predates the executing changes. External disclosures and normalized hashes are
under `measurement/run-manifests/`. The publishable pair is
`20260830_054251_ollama_oper_baseline` / `20260830_070142_ollama_eval_baseline`:
both ran on commit `7ca2543`, are 20/20 schema-valid per view, and have manifests
pinning normalized audit hashes, the model digest and effective request configuration.

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
- Prefer a **small, fast** model for a 20-alert experiment. `llama3.1:8b` took approximately 60 seconds per alert on the measured laptop CPU; performance is hardware-dependent. Large MoE models like `llama4` are impractically slow in this lab and will hit the timeout. Raise `ALERTMIND_LLM_TIMEOUT` only if you truly need a big model.

## 4a. Paste & inspect (local diagnostic)

A second Streamlit tab, **🧪 Paste & inspect**, runs arbitrary *synthetic or approved* telemetry (JSON or plain text) through `redact_alert_with_trace → apply_view → injection scan → boundary gate → prompt → one model call → schema`. It **shares the batch path's redaction implementation and model boundary, but is not the same pipeline** — it adds input limits, a redaction trace, injection visibility, delimiter blocking, egress consent and explicit one-shot audit persistence, and it does not score. It exists to make the redaction and injection claims inspectable live, not just via offline proof files.

- **Local, single-user only.** Bind to localhost. Post-v1 work has independently reviewed the least-privilege Indexer identities and restricted SSH transport described in `architecture/soc-architecture.md` §8; the transport proof was merged through PR #16, while its rollback/revocation drill remains pending. This UI still has no OIDC/application authorization and does not retrieve live Wazuh alerts, so it is not yet production- or multi-user-safe.
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
- **evaluation** — a **strict label-reduced** view. It removes the detection-authored label fields (`mitre`, `rule_id`, `rule_description`, `evidence_file`) and the `audit.key` detection label, strips technique codes from remaining strings, and drops any other key-shaped field *only when its value is itself a technique code* — so legitimate raw evidence such as a `registry.key` survives. The model must infer from raw process/file/registry/audit fields. This is the defensible **classification accuracy** measurement, and `tests/test_views_leakage.py` asserts that no technique code survives in any of the 20 corpus alerts.

> An earlier version of this view still leaked labels through `audit.key` and `rule_description`. The figures reported in `report.md` come from the corrected, test-verified view; the correction is documented in `DESIGN_AND_CHANGELOG.md`.

The mock makes the point concretely: **operational 14/20 overall → evaluation 0/20** (technique 6/20), because the mock only copies the label and cannot classify once it is removed.

## 6. Scope of the redaction claim

The redaction layer removes tested classes of common credentials (passwords, AWS keys, bearer tokens, `sk-`/`sk-proj-` API keys, PEM/OpenSSH private keys, connection-string passwords) and replaces the complete value of sensitive-key fields regardless of JSON type. This materially reduces disclosure risk but is **not** a guarantee that every possible secret is removed — residual risk remains for unknown, encoded, or unlabelled secrets. Expanding coverage (Basic auth, JWTs, `ghp_`/`xoxb-` tokens, URL credentials, decode-then-redact for encoded PowerShell) remains a tracked follow-up.

## 7. Measurement integrity

- **Separated metrics** (`scoring.py`): `technique_exact`, `technique_relaxed` (parent/sub), `disposition_correct`, `response_consistent`, `overall`. A right technique with a contradictory benign disposition is no longer scored correct.
- **Analyst vs Evaluator UI modes**: Analyst mode hides ground truth (use during the assisted timing run); Evaluator mode reveals scoring (use only after).
- **Learning effect**: the assisted pass re-triages the **same corpus after a washout, in randomised order**. This is *not* a counterbalanced crossover, and the residual learning effect is reported as a limitation. The bias points toward an apparent speed-up, so it cannot explain the observed slowdown on false positives.
- **Grounding review**: automated scoring covers only the technique tag and disposition. A human-authored first pass scored the summary, investigation queries and draft message across all 20 operational outputs per model on six dimensions; the same evidence-led Codex second pass was then applied to all three model worksheets. Every changed dimension and its provenance are recorded per alert in `measurement/grounding/`, and one human explicitly approved all changes on 2026-08-31. Query validity is target-aware and all-or-nothing: every suggested query must run against its stated target as written. This remains one human adjudication process, not an independent second-reviewer result.

## 8. Attribution

Alert-summarization core adapted from the author's prior **[AI-SOC-Assistant](https://github.com/opandey1/AI-SOC-Assistant)** (reuse permitted; disclosed). New for AlertMind: redaction (with trace), strict label-reduced views, the prompt library and untrusted-data boundary, injection visibility and the delimiter gate, schema validation, audit logging, separated scoring, provider abstraction, the corpus runner, Paste & inspect, and the Streamlit UI.
