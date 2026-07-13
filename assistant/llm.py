"""
llm.py — provider-agnostic LLM client for the AlertMind assistant.

Providers:
  mock       - offline, deterministic; no API key or network. Lets graders run
               the whole pipeline with zero setup and lets CI test it.
  anthropic  - Anthropic Messages API (needs ANTHROPIC_API_KEY).
  openai     - any OpenAI-compatible /v1/chat/completions endpoint. Works for
               OpenAI (OPENAI_API_KEY) AND for a local Ollama server
               (base_url=http://localhost:11434/v1, key not required).

Only the standard library + `requests` are used, so there is no SDK-version drift.
The instructor confirmed a hosted API is acceptable PROVIDED redaction is in place
(it is — see redact.py, applied before this module is ever called).
"""
import os
import json
import re

try:
    import requests
except ImportError:  # requests only needed for the non-mock providers
    requests = None


def _mock(system: str, user: str, model: str) -> str:
    """
    Deterministic offline response derived from the alert's own fields. This is
    NOT a real inference — it exists so the pipeline is runnable without a model.
    It reads the ATT&CK id straight from the alert, so mock runs will show ~100%
    tag accuracy; use a real provider for the actual hallucination measurement.
    """
    m = re.search(r'"mitre":\s*{[^}]*"id":\s*\[\s*"([^"]+)"', user)
    tid = m.group(1) if m else None
    desc = ""
    dm = re.search(r'"rule_description":\s*"([^"]+)"', user)
    if dm:
        desc = dm.group(1)
    rid = ""
    rm = re.search(r'"rule_id":\s*"?(\d+)', user)
    if rm:
        rid = rm.group(1)
    return json.dumps({
        "summary": [
            f"[MOCK] Wazuh rule {rid} fired: {desc[:80]}",
            "Source, target and key fields are present in the alert.",
            "Review the redacted alert for the acting user/process and path.",
            "Confirm whether the activity is expected on this host.",
            "This is a mock inference — run a real model for measurement.",
        ],
        "attack_technique_id": tid,
        "attack_technique_name": "(from alert)",
        "disposition_suggestion": "needs_investigation",
        "confidence": "low",
        "investigation_queries": [
            f"rule.id:{rid}" if rid else "rule.id:*",
            "agent.name:\"<host>\" AND rule.mitre.id:*",
            "agent.name:\"<host>\" (widen the time window around the event)",
        ],
        "draft_user_message": "Draft: we observed activity on your host that our "
                              "monitoring flagged for review; please confirm if this was you.",
        "caveats": "Mock output; not a real model inference.",
        "_model": "mock",
    })


def _anthropic(system: str, user: str, model: str) -> str:
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError("ANTHROPIC_API_KEY not set")
    r = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                 "content-type": "application/json"},
        json={"model": model, "max_tokens": 1024, "system": system,
              "messages": [{"role": "user", "content": user}]},
        timeout=60,
    )
    r.raise_for_status()
    return r.json()["content"][0]["text"]


def _openai_compatible(system: str, user: str, model: str) -> str:
    base = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
    key = os.environ.get("OPENAI_API_KEY", "ollama")  # Ollama ignores the key
    r = requests.post(
        base.rstrip("/") + "/chat/completions",
        headers={"Authorization": f"Bearer {key}", "content-type": "application/json"},
        json={"model": model, "temperature": 0,
              "messages": [{"role": "system", "content": system},
                           {"role": "user", "content": user}]},
        timeout=120,
    )
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]


_PROVIDERS = {"mock": _mock, "anthropic": _anthropic, "openai": _openai_compatible, "ollama": _openai_compatible}


def call_llm(provider: str, system: str, user: str, model: str) -> str:
    if provider not in _PROVIDERS:
        raise ValueError(f"unknown provider {provider}; choose from {list(_PROVIDERS)}")
    if provider != "mock" and requests is None:
        raise RuntimeError("`requests` is required for non-mock providers (pip install requests)")
    return _PROVIDERS[provider](system, user, model)


def parse_response(raw: str) -> dict:
    """Extract the JSON object from the model response; tolerate ```json fences."""
    text = raw.strip()
    text = re.sub(r"^```(?:json)?", "", text).strip()
    text = re.sub(r"```$", "", text).strip()
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return {"_parse_error": True, "_raw": raw}
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return {"_parse_error": True, "_raw": raw}
