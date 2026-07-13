#!/usr/bin/env python3
"""
app.py — AlertMind assistant, analyst-friendly Streamlit UI.

Run:  streamlit run app.py

Shows, for a chosen alert:
  - the RAW alert and the REDACTED alert side by side (redaction is visible),
  - the assistant's four deliverables (summary, ATT&CK tag, queries, draft msg),
  - a persistent DRAFT / human-review / no-action guardrail banner,
  - an optional batch tab that scores the whole corpus vs ground truth.

The default provider is `mock` so the UI runs with zero setup; pick a real
provider in the sidebar (set the relevant env var first — see .env.example).
"""
import csv
import json
import os

import streamlit as st

from redact import redact_alert
from prompts import SYSTEM_PROMPT, build_user_prompt
from llm import call_llm, parse_response
from runner import score, load_ground_truth

CORPUS = os.environ.get("ALERTMIND_CORPUS", "../measurement/alert-corpus.json")
TIMING = os.environ.get("ALERTMIND_TIMING", "../measurement/timing-log.csv")

st.set_page_config(page_title="AlertMind — SOC Assistant", page_icon="🛡️", layout="wide")


@st.cache_data
def load_corpus(path):
    data = json.load(open(path, encoding="utf-8"))
    return data["alerts"] if isinstance(data, dict) else data


def disposition_color(disp):
    return {"likely_true_positive": "red", "likely_benign": "green",
            "needs_investigation": "orange"}.get(disp, "gray")


# ----- sidebar: provider + model -----
st.sidebar.title("🛡️ AlertMind")
st.sidebar.caption("Tier-1 SOC triage assistant")
provider = st.sidebar.selectbox("Provider", ["mock", "ollama", "openai", "anthropic"],
                                help="mock runs offline with no key. Others read env vars (.env.example).")
default_model = {"mock": "mock", "ollama": "llama3.1", "openai": "gpt-4o-mini",
                 "anthropic": "claude-3-5-sonnet-latest"}[provider]
model = st.sidebar.text_input("Model", value=default_model)
st.sidebar.divider()
st.sidebar.info("Every output is a **DRAFT**. The assistant takes **no action** and "
                "receives **no secrets** (redacted first).")

try:
    alerts = load_corpus(CORPUS)
except Exception as e:
    st.error(f"Could not load corpus at `{CORPUS}`: {e}")
    st.stop()
by_id = {a["alert_id"]: a for a in alerts}

tab_triage, tab_batch = st.tabs(["🔎 Triage one alert", "📊 Batch scoring"])

# ================= single-alert triage =================
with tab_triage:
    ids = [f"{a['alert_id']} · rule {a.get('rule_id')} · {str(a.get('rule_description',''))[:60]}"
           for a in alerts]
    choice = st.selectbox("Alert", ids)
    aid = choice.split(" ")[0]
    alert = by_id[aid]
    redacted = redact_alert(alert)

    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Raw alert")
        st.json(alert, expanded=False)
    with c2:
        st.subheader("Redacted (what the model receives)")
        st.json(redacted, expanded=False)

    if st.button("🤖 Triage with assistant", type="primary"):
        with st.spinner(f"Calling {provider}/{model} …"):
            user = build_user_prompt(redacted)
            try:
                raw = call_llm(provider, SYSTEM_PROMPT, user, model)
                out = parse_response(raw)
            except Exception as e:
                out = {"_error": str(e)}

        if out.get("_error"):
            st.error(f"Model call failed: {out['_error']}")
        elif out.get("_parse_error"):
            st.warning("Model did not return valid JSON. Raw response:")
            st.code(out.get("_raw", ""))
        else:
            st.warning("⚠️ DRAFT — analyst must review. The assistant took no action and received no secrets.")
            disp = out.get("disposition_suggestion", "needs_investigation")
            m1, m2, m3 = st.columns(3)
            m1.metric("ATT&CK", out.get("attack_technique_id") or "—", out.get("attack_technique_name", ""))
            m2.markdown(f"**Disposition**  \n:{disposition_color(disp)}[{disp}]")
            m3.metric("Confidence", out.get("confidence", "—"))

            st.markdown("#### Summary")
            for line in (out.get("summary") or []):
                st.markdown(f"- {line}")

            st.markdown("#### Suggested investigation queries")
            for q in (out.get("investigation_queries") or []):
                st.code(q, language="text")

            st.markdown("#### Draft user message *(editable — review before sending)*")
            st.text_area("draft", value=out.get("draft_user_message", ""), height=100,
                         label_visibility="collapsed")

            if out.get("caveats"):
                st.markdown(f"**Caveats:** {out['caveats']}")
            with st.expander("Raw assistant JSON"):
                st.json(out)

# ================= batch scoring =================
with tab_batch:
    st.caption("Runs the whole corpus and scores the assistant's tag/disposition against "
               "the ground truth in timing-log.csv. Benign alerts count as correct only "
               "when the assistant says `likely_benign`.")
    if st.button("Run batch over corpus"):
        ground = load_ground_truth(TIMING)
        rows, prog = [], st.progress(0.0)
        for i, a in enumerate(alerts):
            red = redact_alert(a)
            try:
                out = parse_response(call_llm(provider, SYSTEM_PROMPT, build_user_prompt(red), model))
            except Exception as e:
                out = {"_error": str(e)}
            gt = ground.get(a["alert_id"], "")
            rows.append({"alert_id": a["alert_id"], "ground_truth": gt,
                         "assistant_tag": out.get("attack_technique_id"),
                         "disposition": out.get("disposition_suggestion"),
                         "confidence": out.get("confidence"),
                         "correct": score(gt, out)})
            prog.progress((i + 1) / len(alerts))
        ok = sum(1 for r in rows if r["correct"])
        benign = [r for r in rows if r["ground_truth"].lower() == "benign"]
        benign_ok = sum(1 for r in benign if r["correct"])
        a, b, c = st.columns(3)
        a.metric("Overall correct", f"{ok}/{len(rows)}", f"{100*ok//max(len(rows),1)}%")
        b.metric("Benign identified", f"{benign_ok}/{len(benign)}")
        c.metric("Provider", f"{provider}")
        st.dataframe(rows, use_container_width=True)
