"""
paste_tab.py — Streamlit UI for "Paste & inspect an alert".

Local, single-user use only. All pipeline logic lives in paste_core.py (which
has no Streamlit dependency and is unit-tested); this module only renders.
"""
import json

import streamlit as st

import paste_core as pc
from audit import ADHOC_LOG, append_jsonl_once, build_adhoc_audit_record
from samples import INJECTED_ALERT, PLANTED_SECRETS_ALERT
from ui_helpers import disposition_color


def _discard_result_state(*, clear_reference=False, reset_consent=True):
    old = st.session_state.pop("paste_result", None)
    if old:
        st.session_state.pop(f"paste_draft_{old.get('result_id')}", None)
    if clear_reference:
        st.session_state["paste_reference_label"] = ""
    if reset_consent:
        st.session_state["paste_consent"] = False
        st.session_state.pop("paste_consent_context", None)


def _input_changed():
    _discard_result_state(clear_reference=True)


def _config_changed(result, provider, model, view, prompt_name, raw_text) -> bool:
    c = result.get("config", {})
    return (c.get("provider") != provider or c.get("model_requested") != model
            or c.get("view") != view or c.get("prompt_name") != prompt_name
            or result.get("input_hash") != pc.input_fingerprint(raw_text))


def render(*, provider, model, view, prompt_name):
    st.subheader("Paste & inspect an alert")
    st.caption("Local diagnostic. Synthetic or approved telemetry only — "
               "excluded from the frozen 20-alert evaluation.")

    c1, c2 = st.columns(2)
    if c1.button("Load synthetic secrets example", key="paste_ex_secrets"):
        _discard_result_state(clear_reference=True)
        st.session_state["paste_input"] = json.dumps(PLANTED_SECRETS_ALERT, indent=2)
    if c2.button("Load synthetic injection example", key="paste_ex_inject"):
        _discard_result_state(clear_reference=True)
        st.session_state["paste_input"] = json.dumps(INJECTED_ALERT, indent=2)

    st.text_area("Alert JSON or plain text", key="paste_input", height=200,
                 placeholder='{"alert_id": "...", "key_fields": {...}}',
                 on_change=_input_changed)

    ref = st.text_input("Optional reference label (benign or ATT&CK code, "
                        "entered BEFORE the call)", key="paste_reference_label")

    raw_input = st.session_state.get("paste_input", "")
    endpoint = pc.provider_endpoint(provider)
    hosted = pc.requires_egress_consent(provider, endpoint)
    consent = False
    if hosted:
        context = pc.consent_context_hash(raw_input, provider, model)
        if st.session_state.get("paste_consent_context") != context:
            st.session_state["paste_consent"] = False
            st.session_state["paste_consent_context"] = context
        st.markdown(f"**External endpoint selected:** `{provider}` · model `{model}` · "
                    f"endpoint `{pc.display_endpoint(endpoint)}`")
        consent = st.checkbox(
            "I confirm this alert is synthetic or approved for processing by the "
            "selected external provider.", key="paste_consent")
    elif provider == "mock":
        st.caption("Mock provider — simulation only, not model-safety evidence.")
    else:
        st.caption(f"Loopback model endpoint: `{pc.display_endpoint(endpoint)}` — "
                   "real local inference, with no external data egress.")

    if st.button("Run paste & inspect", key="paste_run", type="primary"):
        # The consent widget has already been instantiated during this rerun, so
        # retain its value until an input/provider/model change resets it.
        _discard_result_state(clear_reference=False, reset_consent=False)
        try:
            result = pc.run_paste_pipeline(
                raw_input, provider=provider,
                model=model, view=view, prompt_name=prompt_name, consent=consent)
            result["reference_label"] = ref.strip()
            st.session_state["paste_result"] = result
        except pc.PasteInputError as e:
            st.error(str(e))

    result = st.session_state.get("paste_result")
    if not result:
        return

    stale = _config_changed(result, provider, model, view, prompt_name, raw_input)
    if stale:
        st.warning("Sidebar settings differ from the settings this result was "
                   "generated under, or the input has changed. Re-run to refresh; "
                   "proof download and audit save are disabled while stale.")

    status = result["call_status"]
    if result["boundary_status"] == "blocked":
        st.error("Request BLOCKED: a literal <ALERT_DATA> delimiter was found in "
                 "model-bound data. No model call was made.")
    elif status == "blocked_consent":
        st.warning("Hosted call blocked — data-egress consent not given.")
    elif status == "error":
        st.error(f"Provider/parse error: {result['schema_errors']}")

    st.markdown("**⚠️ DRAFT — mandatory analyst review. The assistant has no "
                "tools and takes no action.**")

    tabs = st.tabs(["Triage draft", "Redaction trace", "Injection markers",
                    "Model-bound message", "Proof / audit"])

    with tabs[0]:
        out = result.get("parsed_output", {})
        if out:
            disp = out.get("disposition_suggestion", "?")
            a, b, c = st.columns(3)
            a.markdown(f"**Technique**  \n{out.get('attack_technique_id', '—')}")
            b.markdown(f"**Disposition**  \n:{disposition_color(disp)}[{disp}]")
            c.markdown(f"**Confidence**  \n{out.get('confidence', '—')}")
            st.markdown("**Summary**")
            for line in (out.get("summary") or []):
                st.text(f"• {line}")
            st.markdown("**Investigation queries**")
            for q in (out.get("investigation_queries") or []):
                st.code(q, language="text")
            st.text_area("Draft user message (editable)",
                         value=out.get("draft_user_message", ""),
                         key=f"paste_draft_{result['result_id']}")
            if result.get("reference_label"):
                st.caption("Reference label (exploratory, non-benchmark):")
                st.code(result["reference_label"], language="text")
        else:
            st.caption("No draft output (request blocked or not called).")

    with tabs[1]:
        tr = result.get("redaction_trace", [])
        st.caption(f"{len(tr)} value(s) redacted — masked, never the original.")
        if tr:
            st.dataframe(tr, width="stretch")

    with tabs[2]:
        hits = result.get("injection_hits", [])
        st.caption("Visibility only — not the injection defence.")
        if hits:
            st.dataframe(hits, width="stretch")
        else:
            st.caption("No injection markers detected.")

    with tabs[3]:
        st.caption("The exact redacted user message. The provider also receives "
                   "the system message and request configuration.")
        st.code(result.get("redacted_user_message", ""), language="text")

    with tabs[4]:
        st.download_button("Download current proof (sanitized)",
                           data=pc.build_proof_markdown(result),
                           file_name=f"{result['result_id']}.md",
                           key="paste_download_proof", disabled=stale)
        if st.button("Save one audit record", key="paste_save_audit", disabled=stale):
            rec = build_adhoc_audit_record(result, source="paste")
            wrote = append_jsonl_once(ADHOC_LOG, rec, result["result_id"])
            if wrote:
                result["audit_saved"] = True
                st.success(f"Saved to {ADHOC_LOG}")
            else:
                st.info("Already saved (idempotent — duplicate ignored).")
