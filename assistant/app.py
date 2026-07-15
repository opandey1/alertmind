#!/usr/bin/env python3
"""
app.py — AlertMind assistant, analyst-friendly Streamlit UI.

Run:  streamlit run app.py

Two modes (feedback #9 — experimental integrity):
  Analyst mode   (default) no ground truth, no correctness scores. This is what
                 you use during an ASSISTED triage timing run.
  Evaluator mode reveals ground truth + scoring. Use it only AFTER the assisted
                 run, never during it.

For a chosen alert it shows the RAW alert and the REDACTED + view-applied alert
side by side (redaction is visible), then the assistant's four deliverables with
a persistent DRAFT / no-action / no-secrets banner and the output schema status.
"""
import csv
import json
import os

import streamlit as st

from redact import redact_alert
from views import apply_view
from prompts import get_system_prompt, build_user_prompt
from llm import call_llm, parse_response
from schema import validate_output
from scoring import score_alert, aggregate

CORPUS = os.environ.get("ALERTMIND_CORPUS", "../measurement/alert-corpus.json")
TIMING = os.environ.get("ALERTMIND_TIMING", "../measurement/timing-log.csv")

st.set_page_config(page_title="AlertMind — SOC Assistant", page_icon="🛡️", layout="wide")


@st.cache_data
def load_corpus(path):
    data = json.load(open(path, encoding="utf-8"))
    return data["alerts"] if isinstance(data, dict) else data


def load_ground_truth(path):
    gt = {}
    if path and os.path.exists(path):
        with open(path, newline="", encoding="utf-8-sig") as f:
            for row in csv.DictReader(f):
                gt[row["alert_id"].strip()] = row.get("ground_truth", "").strip()
    return gt


def disposition_color(disp):
    return {"likely_true_positive": "red", "likely_benign": "green",
            "needs_investigation": "orange"}.get(disp, "gray")


# ----- sidebar -----
st.sidebar.title("🛡️ AlertMind")
st.sidebar.caption("Tier-1 SOC triage assistant")
mode = st.sidebar.radio("Mode", ["Analyst", "Evaluator"],
                        help="Analyst hides ground truth (use during assisted timing). "
                             "Evaluator reveals scoring (use only after the run).")
provider = st.sidebar.selectbox("Provider", ["mock", "ollama", "openai", "anthropic"])
default_model = {"mock": "mock", "ollama": "llama3.1:8b", "openai": "gpt-4o-mini",
                 "anthropic": "claude-3-5-sonnet-latest"}[provider]
model = st.sidebar.text_input("Model", value=default_model)

# --- connection settings (API key / base URL) ---
# Precedence: what you type here > shell env var > .env file (loaded by llm.py).
if provider != "mock":
    with st.sidebar.expander("🔑 Connection", expanded=False):
        key_var = "ANTHROPIC_API_KEY" if provider == "anthropic" else "OPENAI_API_KEY"
        default_base = {"ollama": "http://localhost:11434/v1",
                        "openai": os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
                        "anthropic": "(fixed)"}[provider]
        if provider != "anthropic":
            base = st.text_input("Base URL", value=default_base,
                                 help="Ollama: http://localhost:11434/v1 · "
                                      "NVIDIA: https://integrate.api.nvidia.com/v1 · "
                                      "OpenAI: https://api.openai.com/v1")
            if base:
                os.environ["OPENAI_BASE_URL"] = base.strip()
        existing = os.environ.get(key_var, "")
        api_key = st.text_input(f"{key_var}", value="", type="password",
                                placeholder="already set from env/.env" if existing else "paste key")
        if api_key:
            os.environ[key_var] = api_key.strip()
        src = ("typed here" if api_key else ("env/.env" if existing else "NOT SET"))
        if provider == "ollama" and not existing:
            st.caption("Ollama needs no key.")
        else:
            st.caption(f"Key source: **{src}**")
view = st.sidebar.selectbox("View", ["operational", "evaluation"],
                            help="operational = full alert (metadata consistency). "
                                 "evaluation = ATT&CK metadata stripped (true classification).")
prompt_name = st.sidebar.selectbox("Prompt", ["baseline", "benign_aware"],
                                   help="benign_aware adds disposition discipline to reduce over-confirmation.")
system = get_system_prompt(prompt_name)
st.sidebar.divider()
st.sidebar.info("Every output is a **DRAFT**. The assistant takes **no action** and "
                "receives **no secrets** (redacted first).")

try:
    alerts = load_corpus(CORPUS)
except Exception as e:
    st.error(f"Could not load corpus at `{CORPUS}`: {e}")
    st.stop()
by_id = {a["alert_id"]: a for a in alerts}

tabs = ["🔎 Triage one alert"] + (["📊 Evaluator scoring"] if mode == "Evaluator" else [])
rendered = st.tabs(tabs)

# ================= single-alert triage =================
with rendered[0]:
    ids = [f"{a['alert_id']} · rule {a.get('rule_id')} · {str(a.get('rule_description',''))[:55]}"
           for a in alerts]
    choice = st.selectbox("Alert", ids)
    aid = choice.split(" ")[0]
    alert = by_id[aid]
    viewed = apply_view(redact_alert(alert), view)

    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Raw alert")
        st.json(alert, expanded=False)
    with c2:
        st.subheader(f"Redacted · {view} view (what the model receives)")
        st.json(viewed, expanded=False)

    if st.button("🤖 Triage with assistant", type="primary"):
        with st.spinner(f"Calling {provider}/{model} …"):
            try:
                raw = call_llm(provider, system, build_user_prompt(viewed), model)
                out = parse_response(raw)
            except Exception as e:
                out = {"_error": str(e)}
        if out.get("_error"):
            st.error(f"Model call failed: {out['_error']}")
        elif out.get("_parse_error"):
            st.warning("Model did not return valid JSON:")
            st.code(out.get("_raw", ""))
        else:
            ok, errors, out = validate_output(out)
            st.warning("⚠️ DRAFT — analyst must review. The assistant took no action and received no secrets.")
            if not ok:
                st.error(f"Output failed schema validation: {errors}")
            disp = out.get("disposition_suggestion", "needs_investigation")
            m1, m2, m3 = st.columns(3)
            m1.metric("ATT&CK", out.get("attack_technique_id") or "—", out.get("attack_technique_name", ""))
            m2.markdown(f"**Disposition**  \n:{disposition_color(disp)}[{disp}]")
            m3.metric("Confidence", out.get("confidence", "—"))
            st.markdown("#### Summary")
            for line in (out.get("summary") or []):
                st.markdown(f"- {line}")
            st.markdown("#### Suggested investigation queries")
            queries = out.get("investigation_queries")
            if isinstance(queries, str):
                queries = [queries]
            if not queries:
                st.caption("_The model returned no investigation queries for this alert._")
            else:
                for q in queries:
                    st.code(q if isinstance(q, str) else json.dumps(q), language="text")
            st.markdown("#### Draft user message *(editable — review before sending)*")
            st.text_area("draft", value=out.get("draft_user_message", ""), height=100,
                         label_visibility="collapsed")
            if out.get("caveats"):
                st.markdown(f"**Caveats:** {out['caveats']}")
            with st.expander("Raw assistant JSON"):
                st.json(out)

# ================= evaluator scoring (hidden in Analyst mode) =================
if mode == "Evaluator":
    with rendered[1]:
        st.error("⚠️ Evaluator mode reveals ground truth. Do NOT use during an assisted-triage timing run.")
        st.caption("Runs the whole corpus and scores each output vs ground truth with separated "
                   "technique / disposition / consistency metrics.")
        if st.button("Run batch over corpus"):
            ground = load_ground_truth(TIMING)
            rows, prog = [], st.progress(0.0)
            for i, a in enumerate(alerts):
                viewed_a = apply_view(redact_alert(a), view)
                try:
                    out = parse_response(call_llm(provider, system, build_user_prompt(viewed_a), model))
                    _, _, out = validate_output(out)
                except Exception as e:
                    out = {"_error": str(e)}
                gt = ground.get(a["alert_id"], "")
                sc = score_alert(gt, out)
                rows.append({"alert_id": a["alert_id"], "ground_truth": gt, **sc})
                prog.progress((i + 1) / len(alerts))
            agg = aggregate(rows)
            n = agg["n"] or 1
            cols = st.columns(5)
            cols[0].metric("Technique exact", f"{agg['technique_exact_correct']}/{n}")
            cols[1].metric("Technique relaxed", f"{agg['technique_relaxed_correct']}/{n}")
            cols[2].metric("Disposition", f"{agg['disposition_correct']}/{n}")
            cols[3].metric("Consistent", f"{agg['response_consistent']}/{n}")
            cols[4].metric("Overall", f"{agg['overall_correct']}/{n}")
            st.dataframe(rows, use_container_width=True)
