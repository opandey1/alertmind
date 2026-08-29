#!/usr/bin/env python3
"""
preflight.py — diagnose an LLM provider connection BEFORE running the 20-alert batch.

A hosted GPU endpoint answers in seconds; a 300 s timeout means the request never
reached a working endpoint. This prints exactly which URL/key/model are resolved,
then makes one tiny request with a short timeout so you get a real error in ~20 s
instead of a 300 s hang per alert.

Usage:
  python preflight.py --provider openai --model meta/llama-3.3-70b-instruct
  python preflight.py --provider ollama --model llama3.1
"""
import argparse
import json
import os
import sys
import time

import llm  # noqa: F401  (importing loads .env)

try:
    import requests
except ImportError:
    requests = None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", default="openai",
                    choices=["openai", "ollama", "anthropic", "mock"])
    ap.add_argument("--model", required=True)
    ap.add_argument("--timeout", type=int, default=20, help="short, so failures are fast")
    args = ap.parse_args()

    print("=" * 62)
    print("AlertMind preflight")
    print("=" * 62)

    request_info = None
    if args.provider == "anthropic":
        base = "https://api.anthropic.com/v1"
        key = os.environ.get("ANTHROPIC_API_KEY", "")
        key_var = "ANTHROPIC_API_KEY"
    else:
        try:
            request_info = llm.provider_request_info(
                args.provider, args.model
            )
        except Exception as exc:
            print(f"CONFIG ERROR: {exc}")
            return 1
        base = request_info["base"]
        if args.provider == "ollama":
            key = os.environ.get("OLLAMA_API_KEY", "")
            key_var = "OLLAMA_API_KEY"
        else:
            key = os.environ.get("OPENAI_API_KEY", "")
            key_var = "OPENAI_API_KEY"

    print(f"provider     : {args.provider}")
    print(f"model        : {args.model}")
    print(f"base URL     : {base}")
    if args.provider == "ollama" and not key:
        key_status = "not required"
    else:
        key_status = (
            "set (" + key[:6] + "…, len " + str(len(key)) + ")"
            if key else "NOT SET"
        )
    print(f"{key_var:13}: {key_status}")
    if request_info:
        print(f"request URL  : {request_info['url']}")
        print(f"token field  : {request_info['token_parameter']}")
    print()

    # --- sanity checks on the resolved config -------------------------------
    problems = []
    if args.provider == "openai" and "localhost" in base:
        problems.append(
            "base URL points at LOCALHOST but provider is 'openai'. If you ran Ollama\n"
            "     earlier in this shell, OPENAI_BASE_URL is probably still\n"
            "     http://localhost:11434/v1 — a hosted model name sent there will hang\n"
            "     or 404. Set the hosted URL in THIS shell before running.")
    if args.provider == "openai" and "localhost" not in base and not key:
        problems.append(f"{key_var} is not set in this shell — hosted endpoints will reject or hang.")
    if args.provider == "openai" and "nvidia" in base and not base.rstrip("/").endswith("/v1"):
        problems.append("NVIDIA base URL should be exactly https://integrate.api.nvidia.com/v1")
    for p in problems:
        print(f"  [WARN] {p}")
    if problems:
        print()

    if requests is None:
        print("requests not installed — pip install requests"); return 2

    # --- 1. can we list models? (cheap reachability + auth check) -----------
    if args.provider != "anthropic":
        url = base.rstrip("/") + "/models"
        print(f"[1/2] GET {url}  (timeout {args.timeout}s)")
        t0 = time.time()
        try:
            h = {"Authorization": f"Bearer {key}"} if key else {}
            r = requests.get(url, headers=h, timeout=args.timeout)
            dt = time.time() - t0
            print(f"      -> HTTP {r.status_code} in {dt:.1f}s")
            if r.status_code == 200:
                try:
                    ids = [m["id"] for m in r.json().get("data", [])]
                    print(f"      -> {len(ids)} models available")
                    if args.model in ids:
                        print(f"      -> '{args.model}' IS available [OK]")
                    else:
                        print(f"      -> '{args.model}' NOT in the list [FAIL]")
                        for i in ids[:8]:
                            print(f"           {i}")
                except Exception:
                    print("      -> (could not parse model list)")
            elif r.status_code in (401, 403):
                print("      -> AUTH failed: the API key is missing/invalid for this endpoint.")
            else:
                print(f"      -> body: {r.text[:200]}")
        except requests.exceptions.Timeout:
            print(f"      -> TIMEOUT after {args.timeout}s. The endpoint is not answering.")
            print("         Likely: wrong base URL, or egress blocked by a firewall/proxy/VPN.")
            return 1
        except requests.exceptions.ConnectionError as e:
            print(f"      -> CONNECTION ERROR: {str(e)[:160]}")
            print("         Nothing is listening / DNS or network is blocked.")
            return 1
        print()

    # --- 2. one tiny provider completion -----------------------------------
    print(f"[2/2] one 'ping' completion  (timeout {args.timeout}s)")
    t0 = time.time()
    try:
        # P1: --timeout must apply to the completion request as well, not just
        # GET /models. Without this the banner says 20s while the call waits 300s.
        with llm.timeout_override(args.timeout):
            out, meta = llm.call_llm_meta(
                args.provider, "Reply with the single word: pong.", "ping", args.model
            )
        dt = time.time() - t0
        print(f"      -> OK in {dt:.1f}s | response: {out.strip()[:80]!r}")
        cfg = meta.get("request_config", {})
        if cfg:
            print(f"      -> effective: {cfg.get('token_parameter')}={cfg.get('token_budget')}"
                  f" · reasoning_effort={cfg.get('reasoning_effort')}"
                  f" · temperature={cfg.get('temperature')}"
                  f" · top_p={cfg.get('top_p')} · seed={cfg.get('seed')}"
                  f" · response_format={cfg.get('response_format')}")
        if meta.get("model_actual"):
            print(f"      -> served by model: {meta['model_actual']}"
                  f"  (pin this snapshot for the measured run)")
        if meta.get("usage"):
            print(f"      -> usage: {meta['usage']}")
        print()
        per20 = dt * 20
        print(f"Estimated batch of 20 alerts ~ {per20/60:.1f} min "
              f"(responses are longer than 'pong', so treat as a floor).")
        print("Preflight PASSED — safe to run runner.py.")
        return 0
    except Exception as e:
        print(f"      -> FAILED in {time.time()-t0:.1f}s")
        print(f"      -> {str(e)[:800]}")
        meta = getattr(e, "meta", {}) or {}
        cfg = meta.get("request_config", {})
        if cfg:
            print(f"      -> effective request: {cfg.get('token_parameter')}="
                  f"{cfg.get('token_budget')} · reasoning_effort="
                  f"{cfg.get('reasoning_effort')} · temperature={cfg.get('temperature')}"
                  f" · top_p={cfg.get('top_p')} · seed={cfg.get('seed')}"
                  f" · response_format={cfg.get('response_format')}")
        if meta.get("usage"):
            print(f"      -> usage: {meta['usage']}  finish_reason={meta.get('finish_reason')}")
            # Only diagnose exhaustion when the budget was genuinely hit —
            # reasoning tokens are present on every reasoning-model call.
            if llm.budget_exhausted(meta):
                usage = meta["usage"]
                print(f"         Output budget exhausted: finish_reason=length and "
                      f"completion_tokens={usage.get('completion_tokens')} >= budget="
                      f"{cfg.get('token_budget')} "
                      f"(reasoning_tokens={usage.get('reasoning_tokens')}). Raise "
                      "ALERTMIND_MAX_TOKENS or lower ALERTMIND_OPENAI_REASONING_EFFORT.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
