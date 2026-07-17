"""
llm.py — provider-agnostic LLM client for the AlertMind assistant.

Providers:
  mock       - offline, deterministic; no API key or network.
  anthropic  - Anthropic Messages API (needs ANTHROPIC_API_KEY).
  openai     - OpenAI or a third-party OpenAI-compatible endpoint.
  ollama     - local OpenAI-compatible Ollama server.

Reliability (feedback #12): configurable timeout + max tokens, retry with backoff
on transient errors, and clear messages for the two failures that actually bite —
a wrong model name (404) and a too-slow local model (timeout).

Env knobs:
  ALERTMIND_LLM_TIMEOUT   per-call timeout seconds (default 300)
  ALERTMIND_MAX_TOKENS    max response tokens      (default 1024)
  ALERTMIND_LLM_RETRIES   retries on transient err (default 2)
  ALERTMIND_OPENAI_REASONING_EFFORT
                          GPT-5/o-series reasoning effort. UNSET by default, so the
                          model's own vendor default applies (gpt-5.5 defaults to
                          medium and supports none|low|medium|high|xhigh; the valid
                          set is model-dependent). Set it only as a deliberate,
                          disclosed choice: it changes the inference configuration
                          and may reduce quality on multi-step triage. Reasoning
                          tokens consume ALERTMIND_MAX_TOKENS.
"""
import os
import json
import re
import time
from contextlib import contextmanager
from urllib.parse import urlparse

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
# Unset by default: send no reasoning_effort so the model's vendor default applies.
# Overriding it silently would change measured accuracy without disclosure.
_OPENAI_REASONING_EFFORT = os.environ.get(
    "ALERTMIND_OPENAI_REASONING_EFFORT", ""
).strip()
_RETRYABLE = {429, 500, 502, 503, 504}


class ProviderError(RuntimeError):
    """
    A provider call failed. Carries whatever metadata was available at failure
    time — always the request config, plus response metadata (usage, reasoning
    tokens, finish_reason) when a response was actually received.

    Without this, the empty-content failure (reasoning consumed the whole output
    budget) raised an actionable message but discarded the very fields needed to
    diagnose it. runner.py reads `.meta`; preflight prints it.
    """

    def __init__(self, message, meta=None):
        super().__init__(message)
        self.meta = meta or {}


@contextmanager
def timeout_override(seconds):
    """
    Temporarily override the per-call timeout (used by preflight.py so that its
    --timeout applies to the completion request too, not just GET /models).
    Restores the previous value on exit, including on exception.
    """
    global _TIMEOUT
    previous = _TIMEOUT
    if seconds:
        _TIMEOUT = int(seconds)
    try:
        yield _TIMEOUT
    finally:
        _TIMEOUT = previous


def _server_error(response) -> str:
    """Return useful provider error text without exposing request headers."""
    try:
        body = response.json()
        error = body.get("error", body)
        if isinstance(error, dict):
            message = error.get("message")
            param = error.get("param")
            code = error.get("code")
            details = [str(message)] if message else []
            if param:
                details.append(f"parameter={param}")
            if code:
                details.append(f"code={code}")
            if details:
                return "; ".join(details)
        return json.dumps(error, ensure_ascii=False)[:500]
    except Exception:
        return (response.text or response.reason or "no response body")[:500]


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
        if r.status_code in _RETRYABLE and attempt < _RETRIES:
            time.sleep(delay); delay *= 2; continue
        if not r.ok:
            model = payload.get("model", "(unknown)")
            raise RuntimeError(
                f"HTTP {r.status_code} for {url} using model '{model}': "
                f"{_server_error(r)}"
            )
        return r
    raise RuntimeError("unreachable")


def _mock(system: str, user: str, model: str) -> tuple[str, dict]:
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
    }), {"model_actual": "mock", "request_config": {"provider": "mock"}}


def _anthropic(system: str, user: str, model: str) -> tuple[str, dict]:
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError("ANTHROPIC_API_KEY not set")
    payload = {"model": model, "max_tokens": _MAX_TOKENS, "temperature": 0, "system": system,
               "messages": [{"role": "user", "content": user}]}
    request_config = {"provider": "anthropic", "model_requested": model,
                      "endpoint": "https://api.anthropic.com/v1/messages",
                      "token_parameter": "max_tokens", "token_budget": _MAX_TOKENS,
                      "temperature": 0}
    try:
        r = _post("https://api.anthropic.com/v1/messages",
                  {"x-api-key": key, "anthropic-version": "2023-06-01",
                   "content-type": "application/json"},
                  payload)
    except Exception as exc:
        raise ProviderError(str(exc), meta={"request_config": request_config}) from exc
    body = r.json()
    meta = _anthropic_meta(body)
    meta["request_config"] = request_config
    try:
        text = body["content"][0]["text"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ProviderError("Anthropic returned an unexpected response shape.",
                            meta=meta) from exc
    return text, meta


def _api_root(base: str, variable: str) -> str:
    """Validate that a configured base URL stops at the API root."""
    root = base.rstrip("/")
    if root.endswith(("/chat/completions", "/responses")):
        raise RuntimeError(
            f"{variable} must stop at the API root (normally .../v1), not at "
            f"an endpoint. Current value: {root}"
        )
    return root


def _is_official_openai(base: str) -> bool:
    return (urlparse(base).hostname or "").lower() == "api.openai.com"


def _uses_reasoning_effort(model: str) -> bool:
    lowered = model.lower()
    return lowered.startswith(("gpt-5", "o1", "o3", "o4"))


def _completion_text(response) -> str:
    """Extract text from Chat Completions with a useful empty-output error."""
    body = response.json()
    try:
        choice = body["choices"][0]
        content = choice["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError(
            "Provider returned an unexpected Chat Completions response shape."
        ) from exc
    if not content:
        raise RuntimeError(
            "Provider returned no text content "
            f"(finish_reason={choice.get('finish_reason')!r}). Increase "
            "ALERTMIND_MAX_TOKENS or lower reasoning effort."
        )
    return content


def _completion_meta(response) -> dict:
    """
    Response metadata the experiment's interpretation depends on: which model
    actually served the request, its id/fingerprint, and token usage including
    reasoning tokens (which consume the output budget).
    """
    try:
        body = response.json()
    except Exception:
        return {}
    if not isinstance(body, dict):
        return {}
    usage = body.get("usage") or {}
    details = usage.get("completion_tokens_details") or {}
    choices = body.get("choices") or [{}]
    meta = {
        "response_id": body.get("id"),
        "model_actual": body.get("model"),
        "system_fingerprint": body.get("system_fingerprint"),
        "finish_reason": (choices[0] or {}).get("finish_reason"),
        "usage": {
            "prompt_tokens": usage.get("prompt_tokens"),
            "completion_tokens": usage.get("completion_tokens"),
            "total_tokens": usage.get("total_tokens"),
            "reasoning_tokens": details.get("reasoning_tokens"),
        },
    }
    return {k: v for k, v in meta.items() if v is not None}


def budget_exhausted(meta: dict) -> bool:
    """
    True only when the output budget was actually exhausted: the provider stopped
    because it hit the cap AND completion tokens reached the configured budget.

    Nonzero `reasoning_tokens` alone does NOT mean exhaustion — a reasoning model
    emits them on every successful call. Diagnosing on that signal alone would
    misreport an ordinary response as a budget failure.
    """
    usage = meta.get("usage") or {}
    budget = (meta.get("request_config") or {}).get("token_budget")
    completion = usage.get("completion_tokens")
    return (
        meta.get("finish_reason") == "length"
        and isinstance(completion, int)
        and isinstance(budget, int)
        and completion >= budget
    )


def _anthropic_meta(body: dict) -> dict:
    usage = body.get("usage") or {}
    return {k: v for k, v in {
        "response_id": body.get("id"),
        "model_actual": body.get("model"),
        "finish_reason": body.get("stop_reason"),
        "usage": {
            "prompt_tokens": usage.get("input_tokens"),
            "completion_tokens": usage.get("output_tokens"),
        },
    }.items() if v is not None}


def provider_request_info(provider: str, model: str) -> dict:
    """Resolve the endpoint and request family used by a provider."""
    if provider == "openai":
        base = _api_root(
            os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
            "OPENAI_BASE_URL",
        )
        official = _is_official_openai(base)
        return {
            "url": base + "/chat/completions",
            "base": base,
            "official_openai": official,
            "token_parameter": (
                "max_completion_tokens" if official else "max_tokens"
            ),
            "model": model,
        }
    if provider == "ollama":
        # OPENAI_BASE_URL remains a compatibility fallback for older .env files.
        base = _api_root(
            os.environ.get(
                "OLLAMA_BASE_URL",
                os.environ.get(
                    "OPENAI_BASE_URL", "http://localhost:11434/v1"
                ),
            ),
            "OLLAMA_BASE_URL",
        )
        return {
            "url": base + "/chat/completions",
            "base": base,
            "official_openai": False,
            "token_parameter": "max_tokens",
            "model": model,
        }
    raise ValueError(f"provider request info is unavailable for {provider!r}")


def _openai(system: str, user: str, model: str) -> tuple[str, dict]:
    info = provider_request_info("openai", model)
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        raise RuntimeError("OPENAI_API_KEY not set")

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    reasoning_model = info["official_openai"] and _uses_reasoning_effort(model)
    if info["official_openai"]:
        # Official OpenAI rejects legacy max_tokens.
        payload["max_completion_tokens"] = _MAX_TOKENS
        if reasoning_model:
            # Reasoning models reject temperature; leave it unset (stochastic).
            if _OPENAI_REASONING_EFFORT:
                payload["reasoning_effort"] = _OPENAI_REASONING_EFFORT
        else:
            # Non-reasoning official models (e.g. gpt-4o) DO support temperature —
            # pin it to 0 to align the sampling configuration with the Ollama path.
            payload["temperature"] = 0
    else:
        # Preserve compatibility with NVIDIA and other Chat Completions APIs.
        payload.update({"temperature": 0, "max_tokens": _MAX_TOKENS})

    # Built BEFORE the request so it survives a timeout, a connection failure, or
    # an empty-content response.
    request_config = {
        "provider": "openai",
        "model_requested": model,
        "endpoint": info["url"],
        "official_openai": info["official_openai"],
        "reasoning_model": reasoning_model,
        "token_parameter": info["token_parameter"],
        "token_budget": _MAX_TOKENS,
        "reasoning_effort": (
            payload.get("reasoning_effort", "unset (vendor default)")
            if reasoning_model
            else "n/a (non-reasoning model or third-party endpoint)"
        ),
        "temperature": payload.get(
            "temperature",
            "omitted (unsupported on official OpenAI reasoning models)",
        ),
    }

    try:
        response = _post(
            info["url"],
            {"Authorization": f"Bearer {key}", "content-type": "application/json"},
            payload,
        )
    except Exception as exc:  # timeout / connection / HTTP error
        raise ProviderError(str(exc), meta={"request_config": request_config}) from exc

    # Extract metadata BEFORE validating content, so an empty-content failure
    # still reports usage/reasoning_tokens/finish_reason.
    meta = _completion_meta(response)
    meta["request_config"] = request_config
    try:
        text = _completion_text(response)
    except RuntimeError as exc:
        raise ProviderError(str(exc), meta=meta) from exc
    return text, meta


def _ollama(system: str, user: str, model: str) -> tuple[str, dict]:
    info = provider_request_info("ollama", model)
    key = os.environ.get("OLLAMA_API_KEY", "ollama")  # Ollama ignores it.
    payload = {
        "model": model,
        "temperature": 0,
        "max_tokens": _MAX_TOKENS,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    request_config = {
        "provider": "ollama",
        "model_requested": model,
        "endpoint": info["url"],
        "token_parameter": info["token_parameter"],
        "token_budget": _MAX_TOKENS,
        "temperature": 0,
    }
    try:
        response = _post(
            info["url"],
            {"Authorization": f"Bearer {key}", "content-type": "application/json"},
            payload,
        )
    except Exception as exc:
        raise ProviderError(str(exc), meta={"request_config": request_config}) from exc

    meta = _completion_meta(response)
    meta["request_config"] = request_config
    try:
        text = _completion_text(response)
    except RuntimeError as exc:
        raise ProviderError(str(exc), meta=meta) from exc
    return text, meta


_PROVIDERS = {
    "mock": _mock,
    "anthropic": _anthropic,
    "openai": _openai,
    "ollama": _ollama,
}


def call_llm_meta(provider: str, system: str, user: str, model: str):
    """Return (text, metadata). Metadata carries the effective request config and
    the provider's response metadata (actual model, id, fingerprint, token usage
    including reasoning tokens) — needed to interpret and reproduce a run."""
    if provider not in _PROVIDERS:
        raise ValueError(f"unknown provider {provider}; choose from {list(_PROVIDERS)}")
    if provider != "mock" and requests is None:
        raise RuntimeError("`requests` is required for non-mock providers (pip install requests)")
    result = _PROVIDERS[provider](system, user, model)
    if isinstance(result, tuple):
        return result
    return result, {}


def call_llm(provider: str, system: str, user: str, model: str) -> str:
    """Text-only convenience wrapper (UI, tests, preflight)."""
    return call_llm_meta(provider, system, user, model)[0]


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
