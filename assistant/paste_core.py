"""
paste_core.py — pure, Streamlit-free pipeline behind the "Paste & inspect" tab.

Runs arbitrary synthetic/approved telemetry through the SAME path as batch
triage: redact (with trace) -> apply view -> scan for injection markers ->
hard boundary gate -> build prompt -> one model call -> parse -> validate.

Guarantees:
  * raw pasted input is never stored in the result (only an input hash);
  * raw values matching the tested secret classes never appear (the trace uses
    masks and an optional keyed fingerprint; model-bound text is post-redaction);
  * a literal <ALERT_DATA> delimiter in model-bound data BLOCKS the call;
  * hosted providers require explicit data-egress consent before any call.

This module has no Streamlit dependency, so the whole pipeline is unit-testable.
"""
import datetime as _dt
import html
import json
import os
import re
from urllib.parse import urlsplit, urlunsplit

import injection
from audit import short_sha
from llm import call_llm_meta, parse_response
from prompts import build_user_prompt, get_system_prompt
from redact import redact_alert_with_trace
from schema import validate_output
from views import apply_view

MAX_PASTE_CHARS = 50_000
MAX_JSON_DEPTH = 20
MAX_JSON_NODES = 10_000

HOSTED_PROVIDERS = {"openai", "anthropic"}  # compatibility; use requires_egress_consent()


def provider_endpoint(provider: str) -> str:
    """Return the effective provider endpoint used for egress classification."""
    defaults = {
        "mock": "local://mock",
        "ollama": "http://localhost:11434/v1",
        "openai": "https://api.openai.com/v1",
        "anthropic": "https://api.anthropic.com/v1",
    }
    env_name = {"ollama": "OLLAMA_BASE_URL", "openai": "OPENAI_BASE_URL"}.get(provider)
    return os.environ.get(env_name, defaults.get(provider, "")) if env_name else defaults.get(provider, "")


def display_endpoint(endpoint: str) -> str:
    """Remove URL credentials before displaying or recording an endpoint."""
    try:
        p = urlsplit(endpoint)
        host = p.hostname or ""
        if p.port:
            host = f"{host}:{p.port}"
        return urlunsplit((p.scheme, host, p.path, "", ""))
    except Exception:
        return "(invalid endpoint)"


def _is_loopback_endpoint(endpoint: str) -> bool:
    try:
        p = urlsplit(endpoint)
        host = (p.hostname or "").lower().rstrip(".")
        if p.scheme not in {"http", "https"}:
            return endpoint == "local://mock"
        if host == "localhost" or host == "::1":
            return True
        parts = host.split(".")
        return len(parts) == 4 and parts[0] == "127" and all(
            part.isdigit() and 0 <= int(part) <= 255 for part in parts)
    except Exception:
        return False


def requires_egress_consent(provider: str, endpoint: str = "") -> bool:
    """Fail closed: only mock and verified loopback endpoints skip consent."""
    if provider == "mock":
        return False
    return not _is_loopback_endpoint(endpoint or provider_endpoint(provider))


def consent_context_hash(raw_text: str, provider: str, model: str) -> str:
    """Bind a consent checkbox to the exact input and egress destination."""
    endpoint = display_endpoint(provider_endpoint(provider))
    return short_sha(json.dumps([raw_text, provider, model, endpoint], ensure_ascii=False))


class PasteInputError(ValueError):
    """Raised for over-limit or unusable input (actionable message)."""


def input_fingerprint(raw_text: str) -> str:
    return short_sha(raw_text)


def _now():
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def _depth(obj, d=0):
    if d > MAX_JSON_DEPTH:
        return d
    if isinstance(obj, dict):
        return max([d] + [_depth(v, d + 1) for v in obj.values()])
    if isinstance(obj, list):
        return max([d] + [_depth(v, d + 1) for v in obj])
    return d


def _nodes(obj):
    if isinstance(obj, dict):
        return 1 + sum(_nodes(v) for v in obj.values())
    if isinstance(obj, list):
        return 1 + sum(_nodes(v) for v in obj)
    return 1


def parse_input(text: str):
    """Return (alert_obj, parse_mode). JSON object -> as-is; non-object JSON ->
    wrapped under raw_value; unparseable -> plain-text fallback."""
    if not isinstance(text, str) or not text.strip():
        raise PasteInputError("Empty input — paste a JSON alert or plain-text telemetry.")
    if len(text) > MAX_PASTE_CHARS:
        raise PasteInputError(
            f"Input too large ({len(text)} chars > {MAX_PASTE_CHARS}). Trim it and retry.")
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return {"alert_id": "PASTED-01", "raw_text": text}, "plain_text"
    if isinstance(parsed, dict):
        return parsed, "json_object"
    return {"alert_id": "PASTED-01", "raw_value": parsed}, "wrapped_json"


def _check_limits(obj):
    if _depth(obj) > MAX_JSON_DEPTH:
        raise PasteInputError(f"JSON nesting too deep (> {MAX_JSON_DEPTH}).")
    if _nodes(obj) > MAX_JSON_NODES:
        raise PasteInputError(f"JSON has too many nodes (> {MAX_JSON_NODES}).")


def run_paste_pipeline(raw_text, *, provider, model, view="operational",
                       prompt_name="baseline", consent=False, allow_call=True):
    """
    Run the full pipeline and return the result dict. Never raises for pipeline
    outcomes (blocked / no-consent / provider error) — those are recorded as
    status on the result. Raises PasteInputError only for unusable input.
    """
    alert, parse_mode = parse_input(raw_text)
    _check_limits(alert)

    system = get_system_prompt(prompt_name)
    endpoint = provider_endpoint(provider)
    result = {
        "result_id": "adhoc-" + short_sha(raw_text + _now()),
        "created_at": _now(),
        "input_hash": input_fingerprint(raw_text),
        "parse_mode": parse_mode,
        "config": {
             "provider": provider, "model_requested": model, "view": view,
             "prompt_name": prompt_name, "system_prompt_hash": short_sha(system),
             "endpoint": display_endpoint(endpoint),
             "egress_consent_required": requires_egress_consent(provider, endpoint),
         },
        "redacted_alert": {}, "model_bound_alert": {}, "redaction_trace": [],
        "injection_hits": [], "boundary_status": "clear",
        "redacted_user_message": "", "parsed_output": {}, "schema_errors": [],
        "call_meta": {}, "call_status": "not_called", "schema_valid": None,
        "audit_saved": False,
    }

    # redact FIRST, then apply the model-bound view
    redacted, trace = redact_alert_with_trace(alert)
    model_bound = apply_view(redacted, view)
    result["redacted_alert"] = redacted
    result["model_bound_alert"] = model_bound
    result["redaction_trace"] = trace

    # injection visibility + hard boundary gate on the exact model-bound data
    hits = injection.scan_alert(model_bound)
    result["injection_hits"] = hits
    user_msg = build_user_prompt(model_bound)
    result["redacted_user_message"] = user_msg

    if injection.contains_boundary(model_bound):
        result["boundary_status"] = "blocked"
        result["call_status"] = "blocked_boundary"
        return result  # documented boundary-breaking payload is never transmitted

    if requires_egress_consent(provider, endpoint) and not consent:
        result["call_status"] = "blocked_consent"
        return result

    if not allow_call:
        result["call_status"] = "not_called"
        return result

    try:
        raw, meta = call_llm_meta(provider, system, user_msg, model)
        result["call_meta"] = meta or {}
        result["call_status"] = "ok"
        parsed = parse_response(raw)
        ok, errors, parsed = validate_output(parsed)
        result["parsed_output"] = parsed
        result["schema_errors"] = [] if ok else errors
        result["schema_valid"] = ok
    except Exception as e:  # provider/parse failure — keep any metadata we have
        result["call_status"] = "error"
        result["schema_errors"] = [f"{type(e).__name__}: {e}"]
        meta = getattr(e, "meta", None)
        if isinstance(meta, dict):
            result["call_meta"] = meta
    return result


def _md_cell(value) -> str:
    """Render untrusted text safely inside a Markdown table cell."""
    return html.escape(str(value if value is not None else ""), quote=True).replace(
        "|", "&#124;").replace("\r", " ").replace("\n", " ")


def _fenced(text: str, language: str = "text") -> str:
    """Choose a fence longer than any attacker/model-supplied backtick run."""
    runs = [len(m.group(0)) for m in re.finditer(r"`+", text)]
    fence = "`" * max(3, (max(runs) + 1) if runs else 3)
    return f"{fence}{language}\n{text}\n{fence}"


def build_proof_markdown(result: dict) -> str:
    """Sanitized proof — raw values are structurally unavailable in `result`."""
    cfg = result.get("config", {})
    L = []
    L.append(f"# AlertMind — Paste & inspect proof\n")
    L.append(f"- result_id: `{result.get('result_id')}`")
    L.append(f"- created_at: {result.get('created_at')}")
    L.append(f"- input_hash: `{result.get('input_hash')}`  ·  parse_mode: {result.get('parse_mode')}")
    L.append(f"- provider/model: {cfg.get('provider')} / {cfg.get('model_requested')}")
    L.append(f"- view: {cfg.get('view')}  ·  prompt: {cfg.get('prompt_name')} (`{cfg.get('system_prompt_hash')}`)")
    L.append(f"- boundary_status: **{result.get('boundary_status')}**  ·  call_status: **{result.get('call_status')}**\n")
    L.append("> Exploratory reference-label comparison — excluded from the frozen 20-alert evaluation.\n")

    L.append("## Redaction trace (masked)\n")
    tr = result.get("redaction_trace", [])
    if tr:
        L.append("| field | rule | source | masked | len | keyed fingerprint | removed |")
        L.append("|---|---|---|---|---|---|---|")
        for r in tr:
            fingerprint = r.get("value_hash") or "disabled"
            L.append(f"| {_md_cell(r['field_path'])} | {_md_cell(r['rule'])} | "
                     f"{_md_cell(r['source'])} | {_md_cell(r['masked_value'])} | "
                     f"{r['value_length']} | {_md_cell(fingerprint)} | {r['removed']} |")
    else:
        L.append("_No secrets detected in this input._")
    L.append("")

    L.append("## Injection markers (visibility only)\n")
    hits = result.get("injection_hits", [])
    if hits:
        L.append("| field | rule | snippet |")
        L.append("|---|---|---|")
        for h in hits:
            L.append(f"| {_md_cell(h['field_path'])} | {_md_cell(h['rule'])} | "
                     f"{_md_cell(h['snippet'])} |")
    else:
        L.append("_No injection markers detected._")
    L.append("")

    L.append("## Exact redacted user message (sent as the user argument)\n")
    L.append(_fenced(result.get("redacted_user_message", ""), "text"))
    L.append("_Note: the provider also receives the system message and request configuration._\n")

    L.append("## Schema-validated draft output\n")
    safe_output = dict(result.get("parsed_output", {}) or {})
    if "_raw" in safe_output:
        safe_output.pop("_raw")
        safe_output["_raw_response_omitted"] = True
    L.append(_fenced(json.dumps(safe_output, indent=2, ensure_ascii=False), "json"))
    errs = result.get("schema_errors", [])
    schema_valid = result.get("schema_valid")
    schema_label = "not_evaluated" if schema_valid is None else str(schema_valid)
    L.append(f"\nschema_valid: **{schema_label}**" + (f" — {_md_cell(errs)}" if errs else ""))
    L.append("\n*Draft output — mandatory analyst review. The assistant has no tools and takes no action.*")
    return "\n".join(L)
