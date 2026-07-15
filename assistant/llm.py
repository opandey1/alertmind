"""
llm.py — provider-agnostic LLM client for the AlertMind assistant.

Providers:
  mock       - offline, deterministic; no API key or network.
  anthropic  - Anthropic Messages API (needs ANTHROPIC_API_KEY).
  openai     - any OpenAI-compatible /v1/chat/completions endpoint. Works for
               OpenAI (OPENAI_API_KEY) AND a local Ollama server
               (OPENAI_BASE_URL=http://localhost:11434/v1, key not required).

Reliability (feedback #12): configurable timeout + max tokens, retry with backoff
on transient errors, and clear messages for the two failures that actually bite —
a wrong model name (404) and a too-slow local model (timeout).

Env knobs:
  ALERTMIND_LLM_TIMEOUT   per-call timeout seconds (default 300)
  ALERTMIND_MAX_TOKENS    max response tokens      (default 1024)
  ALERTMIND_LLM_RETRIES   retries on transient err (default 2)
"""
import os
import json
import re
import time

try:
    import requests
except ImportError:
    requests = None


def load_env_file(path=None):
    """
    Minimal .env loader (no python-dotenv dependency).

    Reads KEY=VALUE lines from `.env` next to this module (or `path`) and puts them
    in os.environ WITHOUT overwriting variables already set in the shell — so an
    explicit `$env:OPENAI_API_KEY=...` always wins over the file.
    Called automatically on import, so runner.py and app.py both pick it up.
    """
    path = path or os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.exists(path):
        return {}
    loaded = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip().strip('"').strip("'")
            if k and k not in os.environ:      # shell env wins
                os.environ[k] = v
                loaded[k] = v
    return loaded


load_env_file()

_TIMEOUT = int(os.environ.get("ALERTMIND_LLM_TIMEOUT", "300"))
_MAX_TOKENS = int(os.environ.get("ALERTMIND_MAX_TOKENS", "1024"))
_RETRIES = int(os.environ.get("ALERTMIND_LLM_RETRIES", "2"))
_RETRYABLE = {429, 500, 502, 503, 504}


def _post(url, headers, payload):
    """POST with retry/backoff and actionable errors. Returns the response object."""
    delay = 1.0
    for attempt in range(_RETRIES + 1):
        try:
            r = requests.post(url, headers=headers, json=payload, timeout=_TIMEOUT)
        except requests.exceptions.Timeout:
            raise RuntimeError(
                f"LLM call timed out after {_TIMEOUT}s. The model is likely too large/slow "
                f"for local inference. Use a smaller model (e.g. 'llama3.1:8b') or raise "
                f"ALERTMIND_LLM_TIMEOUT.")
        except requests.exceptions.ConnectionError as e:
            if attempt < _RETRIES:
                time.sleep(delay); delay *= 2; continue
            raise RuntimeError(f"Could not connect to {url} ({e}). Is the server running?")
        if r.status_code == 404:
            raise RuntimeError(
                f"404 Not Found for {url}. Model '{payload.get('model')}' not found. "
                f"Check the exact tag with `ollama list` or GET /v1/models — use e.g. "
                f"'llama3.1:8b' or 'llama4:latest' (colon), not 'llama4-latest'. "
                f"Server said: {r.text[:200]}")
        if r.status_code in _RETRYABLE and attempt < _RETRIES:
            time.sleep(delay); delay *= 2; continue
        r.raise_for_status()
        return r
    raise RuntimeError("unreachable")


def _mock(system: str, user: str, model: str) -> str:
    """
    Deterministic offline response derived from the alert's own fields. NOT a real
    inference. It copies the ATT&CK id from the alert and always answers
    'needs_investigation', so in the OPERATIONAL view it gets attacks "right" but
    fails all benign alerts (~14/20); in the EVALUATION view the metadata is
    stripped, so it cannot tag at all. Use a real provider for measurement.
    """
    m = re.search(r'"mitre":\s*{[^}]*"id":\s*\[\s*"([^"]+)"', user)
    tid = m.group(1) if m else None
    dm = re.search(r'"rule_description":\s*"([^"]+)"', user)
    desc = dm.group(1) if dm else ""
    rm = re.search(r'"rule_id":\s*"?(\d+)', user)
    rid = rm.group(1) if rm else ""
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
    r = _post("https://api.anthropic.com/v1/messages",
              {"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
              {"model": model, "max_tokens": _MAX_TOKENS, "temperature": 0, "system": system,
               "messages": [{"role": "user", "content": user}]})
    return r.json()["content"][0]["text"]


def _openai_compatible(system: str, user: str, model: str) -> str:
    base = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
    key = os.environ.get("OPENAI_API_KEY", "ollama")  # Ollama ignores the key
    r = _post(base.rstrip("/") + "/chat/completions",
              {"Authorization": f"Bearer {key}", "content-type": "application/json"},
              {"model": model, "temperature": 0, "max_tokens": _MAX_TOKENS,
               "messages": [{"role": "system", "content": system},
                            {"role": "user", "content": user}]})
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
