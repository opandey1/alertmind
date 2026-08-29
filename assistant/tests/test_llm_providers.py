#!/usr/bin/env python3
"""Offline regression tests for provider endpoints and request payloads."""

from __future__ import annotations

import os
import sys
from types import SimpleNamespace
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import llm  # noqa: E402


def completion_response(content: str = "pong") -> Mock:
    response = Mock()
    response.json.return_value = {
        "choices": [
            {
                "finish_reason": "stop",
                "message": {"content": content},
            }
        ]
    }
    return response


class ProviderPayloadTests(unittest.TestCase):
    @patch.object(llm, "_post")
    def test_official_openai_uses_gpt55_parameters(self, post: Mock) -> None:
        post.return_value = completion_response()
        with patch.dict(
            os.environ,
            {
                "OPENAI_BASE_URL": "https://api.openai.com/v1",
                "OPENAI_API_KEY": "test-key",
            },
            clear=False,
        ):
            output, meta = llm._openai("system", "user", "gpt-5.5")

        self.assertEqual(output, "pong")
        self.assertEqual(
            meta["request_config"]["reasoning_effort"], "unset (vendor default)"
        )
        url, headers, payload = post.call_args.args
        self.assertEqual(
            url, "https://api.openai.com/v1/chat/completions"
        )
        self.assertEqual(headers["Authorization"], "Bearer test-key")
        self.assertEqual(payload["max_completion_tokens"], llm._MAX_TOKENS)
        self.assertNotIn("max_tokens", payload)
        self.assertNotIn("temperature", payload)
        # Unset by default -> the model's vendor default effort applies.
        self.assertNotIn("reasoning_effort", payload)

    @patch.object(llm, "_post")
    def test_third_party_openai_compatible_keeps_legacy_parameters(
        self, post: Mock
    ) -> None:
        post.return_value = completion_response()
        with patch.dict(
            os.environ,
            {
                "OPENAI_BASE_URL": "https://integrate.api.nvidia.com/v1",
                "OPENAI_API_KEY": "test-key",
            },
            clear=False,
        ):
            llm._openai("system", "user", "vendor/model")

        url, _, payload = post.call_args.args
        self.assertEqual(
            url, "https://integrate.api.nvidia.com/v1/chat/completions"
        )
        self.assertEqual(payload["max_tokens"], llm._MAX_TOKENS)
        self.assertEqual(payload["temperature"], 0)
        self.assertNotIn("max_completion_tokens", payload)
        self.assertNotIn("reasoning_effort", payload)

    @patch.object(llm, "_post")
    def test_ollama_uses_separate_base_url(self, post: Mock) -> None:
        post.return_value = completion_response()
        with patch.dict(
            os.environ,
            {
                "OPENAI_BASE_URL": "https://api.openai.com/v1",
                "OLLAMA_BASE_URL": "http://localhost:11434/v1",
                "ALERTMIND_OLLAMA_TEMPERATURE": "0",
                "ALERTMIND_OLLAMA_TOP_P": "",
                "ALERTMIND_OLLAMA_SEED": "",
                "ALERTMIND_OLLAMA_STRUCTURED_OUTPUTS": "0",
            },
            clear=False,
        ):
            _, meta = llm._ollama("system", "user", "llama3.1:8b")

        url, _, payload = post.call_args.args
        self.assertEqual(
            url, "http://localhost:11434/v1/chat/completions"
        )
        self.assertEqual(payload["max_tokens"], llm._MAX_TOKENS)
        self.assertEqual(payload["temperature"], 0)
        self.assertNotIn("top_p", payload)
        self.assertNotIn("seed", payload)
        self.assertNotIn("response_format", payload)
        self.assertFalse(meta["request_config"]["structured_outputs"])

    @patch.object(llm, "_post")
    def test_ollama_qwen_final_configuration_is_explicit_and_audited(
        self, post: Mock
    ) -> None:
        post.return_value = completion_response()
        with patch.object(llm, "_MAX_TOKENS", 4096), patch.dict(
            os.environ,
            {
                "OLLAMA_BASE_URL": "http://localhost:11434/v1",
                "ALERTMIND_OLLAMA_TEMPERATURE": "0.6",
                "ALERTMIND_OLLAMA_TOP_P": "0.95",
                "ALERTMIND_OLLAMA_SEED": "42",
                "ALERTMIND_OLLAMA_STRUCTURED_OUTPUTS": "1",
            },
            clear=False,
        ):
            _, meta = llm._ollama("system", "user", "qwen3:8b")

        _, _, payload = post.call_args.args
        self.assertEqual(payload["temperature"], 0.6)
        self.assertEqual(payload["top_p"], 0.95)
        self.assertEqual(payload["seed"], 42)
        self.assertEqual(payload["max_tokens"], 4096)
        self.assertNotIn("reasoning_effort", payload)
        response_format = payload["response_format"]
        self.assertEqual(response_format["type"], "json_schema")
        self.assertTrue(response_format["json_schema"]["strict"])
        provider_schema = response_format["json_schema"]["schema"]
        self.assertNotIn(
            "pattern", provider_schema["properties"]["attack_technique_id"]
        )
        self.assertIn(
            "pattern", llm.JSON_SCHEMA["properties"]["attack_technique_id"]
        )

        cfg = meta["request_config"]
        self.assertEqual(cfg["temperature"], 0.6)
        self.assertEqual(cfg["top_p"], 0.95)
        self.assertEqual(cfg["seed"], 42)
        self.assertEqual(cfg["token_budget"], 4096)
        self.assertTrue(cfg["structured_outputs"])
        self.assertEqual(
            cfg["response_format"], "json_schema_ollama_compatible"
        )
        self.assertEqual(
            cfg["provider_schema_omissions"],
            ["attack_technique_id.pattern"],
        )
        self.assertTrue(cfg["runtime_attack_id_validation"])
        self.assertIn("model default", cfg["top_k"])
        self.assertIn("model default", cfg["repeat_penalty"])

    def test_endpoint_suffix_in_base_url_fails_before_request(self) -> None:
        with patch.dict(
            os.environ,
            {
                "OPENAI_BASE_URL": "https://api.openai.com/v1/responses",
                "OPENAI_API_KEY": "test-key",
            },
            clear=False,
        ):
            with self.assertRaisesRegex(
                RuntimeError, "must stop at the API root"
            ):
                llm._openai("system", "user", "gpt-5.5")

    def test_http_error_preserves_provider_message(self) -> None:
        response = Mock()
        response.ok = False
        response.status_code = 400
        response.json.return_value = {
            "error": {
                "message": "Unsupported parameter: max_tokens",
                "param": "max_tokens",
                "code": "unsupported_parameter",
            }
        }
        fake_requests = SimpleNamespace(
            post=Mock(return_value=response),
            exceptions=SimpleNamespace(
                Timeout=TimeoutError,
                ConnectionError=ConnectionError,
            ),
        )
        with patch.object(llm, "requests", fake_requests):
            with self.assertRaisesRegex(
                RuntimeError,
                r"Unsupported parameter: max_tokens.*parameter=max_tokens",
            ):
                llm._post(
                    "https://api.openai.com/v1/chat/completions",
                    {},
                    {"model": "gpt-5.5"},
                )


class ReasoningEffortTests(unittest.TestCase):
    @patch.object(llm, "_post")
    def test_reasoning_effort_sent_only_when_explicitly_configured(
        self, post: Mock
    ) -> None:
        post.return_value = completion_response()
        with patch.dict(
            os.environ,
            {
                "OPENAI_BASE_URL": "https://api.openai.com/v1",
                "OPENAI_API_KEY": "test-key",
            },
            clear=False,
        ), patch.object(llm, "_OPENAI_REASONING_EFFORT", "low"):
            llm._openai("system", "user", "gpt-5.5")
        self.assertEqual(post.call_args.args[2]["reasoning_effort"], "low")

    @patch.object(llm, "_post")
    def test_non_reasoning_model_never_gets_reasoning_effort(
        self, post: Mock
    ) -> None:
        post.return_value = completion_response()
        with patch.dict(
            os.environ,
            {
                "OPENAI_BASE_URL": "https://api.openai.com/v1",
                "OPENAI_API_KEY": "test-key",
            },
            clear=False,
        ), patch.object(llm, "_OPENAI_REASONING_EFFORT", "high"):
            _, meta = llm._openai("system", "user", "gpt-4o")
        payload = post.call_args.args[2]
        self.assertNotIn("reasoning_effort", payload)
        # gpt-4o is NOT a reasoning model: temperature IS supported, so pin it to 0
        # and record it accurately (it used to claim "unsupported ... reasoning models").
        self.assertEqual(payload["temperature"], 0)
        cfg = meta["request_config"]
        self.assertEqual(cfg["temperature"], 0)
        self.assertFalse(cfg["reasoning_model"])
        self.assertNotIn("unsupported", str(cfg["temperature"]))


class EmptyCompletionTests(unittest.TestCase):
    @patch.object(llm, "_post")
    def test_empty_content_raises_actionable_error(self, post: Mock) -> None:
        response = Mock()
        response.json.return_value = {
            "choices": [
                {"finish_reason": "length", "message": {"content": ""}}
            ]
        }
        post.return_value = response
        with patch.dict(
            os.environ,
            {
                "OPENAI_BASE_URL": "https://api.openai.com/v1",
                "OPENAI_API_KEY": "test-key",
            },
            clear=False,
        ):
            with self.assertRaisesRegex(
                RuntimeError, "ALERTMIND_MAX_TOKENS"
            ):
                llm._openai("system", "user", "gpt-5.5")


class TimeoutOverrideTests(unittest.TestCase):
    """P1 regression: preflight's --timeout must govern the completion request,
    not just GET /models. Previously _post always used the global 300s value."""

    def test_timeout_override_is_passed_to_post_and_restored(self) -> None:
        captured = {}

        def fake_post(url, headers=None, json=None, timeout=None):
            captured["timeout"] = timeout
            return completion_response()

        fake_requests = SimpleNamespace(
            post=fake_post,
            exceptions=SimpleNamespace(
                Timeout=TimeoutError, ConnectionError=ConnectionError
            ),
        )
        original = llm._TIMEOUT
        with patch.object(llm, "requests", fake_requests):
            with llm.timeout_override(7):
                llm._post("https://example.test/v1/chat/completions", {}, {"model": "m"})
        self.assertEqual(captured["timeout"], 7)
        self.assertEqual(llm._TIMEOUT, original)  # restored

    def test_timeout_override_restores_on_exception(self) -> None:
        original = llm._TIMEOUT
        with self.assertRaises(ValueError):
            with llm.timeout_override(5):
                raise ValueError("boom")
        self.assertEqual(llm._TIMEOUT, original)


class ResponseMetadataTests(unittest.TestCase):
    @patch.object(llm, "_post")
    def test_openai_metadata_captures_model_usage_and_config(self, post: Mock) -> None:
        response = Mock()
        response.json.return_value = {
            "id": "chatcmpl-abc",
            "model": "gpt-5.5-2026-04-23",
            "system_fingerprint": "fp_test",
            "choices": [{"finish_reason": "stop", "message": {"content": "pong"}}],
            "usage": {
                "prompt_tokens": 11,
                "completion_tokens": 22,
                "total_tokens": 33,
                "completion_tokens_details": {"reasoning_tokens": 9},
            },
        }
        post.return_value = response
        with patch.dict(
            os.environ,
            {
                "OPENAI_BASE_URL": "https://api.openai.com/v1",
                "OPENAI_API_KEY": "test-key",
            },
            clear=False,
        ):
            _, meta = llm._openai("system", "user", "gpt-5.5-2026-04-23")

        self.assertEqual(meta["model_actual"], "gpt-5.5-2026-04-23")
        self.assertEqual(meta["response_id"], "chatcmpl-abc")
        self.assertEqual(meta["system_fingerprint"], "fp_test")
        self.assertEqual(meta["usage"]["reasoning_tokens"], 9)
        cfg = meta["request_config"]
        self.assertEqual(cfg["token_parameter"], "max_completion_tokens")
        self.assertEqual(cfg["token_budget"], llm._MAX_TOKENS)
        self.assertEqual(cfg["reasoning_effort"], "unset (vendor default)")
        self.assertIn("omitted", cfg["temperature"])


class FailurePathMetadataTests(unittest.TestCase):
    """P2: the empty-content failure (reasoning ate the output budget) is exactly
    when usage/reasoning_tokens/finish_reason are needed — they must survive."""

    @patch.object(llm, "_post")
    def test_empty_content_error_carries_usage_and_config(self, post: Mock) -> None:
        response = Mock()
        response.json.return_value = {
            "id": "chatcmpl-empty",
            "model": "gpt-5.5-2026-04-23",
            "choices": [{"finish_reason": "length", "message": {"content": ""}}],
            "usage": {
                "prompt_tokens": 900,
                "completion_tokens": 1024,
                "total_tokens": 1924,
                "completion_tokens_details": {"reasoning_tokens": 1024},
            },
        }
        post.return_value = response
        with patch.dict(
            os.environ,
            {
                "OPENAI_BASE_URL": "https://api.openai.com/v1",
                "OPENAI_API_KEY": "test-key",
            },
            clear=False,
        ):
            with self.assertRaises(llm.ProviderError) as ctx:
                llm._openai("system", "user", "gpt-5.5-2026-04-23")

        meta = ctx.exception.meta
        self.assertEqual(meta["usage"]["reasoning_tokens"], 1024)
        self.assertEqual(meta["finish_reason"], "length")
        self.assertEqual(meta["model_actual"], "gpt-5.5-2026-04-23")
        self.assertEqual(
            meta["request_config"]["token_parameter"], "max_completion_tokens"
        )
        self.assertIn("ALERTMIND_MAX_TOKENS", str(ctx.exception))

    def test_transport_failure_still_reports_request_config(self) -> None:
        fake_requests = SimpleNamespace(
            post=Mock(side_effect=TimeoutError()),
            exceptions=SimpleNamespace(
                Timeout=TimeoutError, ConnectionError=ConnectionError
            ),
        )
        with patch.object(llm, "requests", fake_requests), patch.dict(
            os.environ,
            {
                "OPENAI_BASE_URL": "https://api.openai.com/v1",
                "OPENAI_API_KEY": "test-key",
            },
            clear=False,
        ):
            with self.assertRaises(llm.ProviderError) as ctx:
                llm._openai("system", "user", "gpt-5.5-2026-04-23")
        cfg = ctx.exception.meta["request_config"]
        self.assertEqual(cfg["model_requested"], "gpt-5.5-2026-04-23")
        self.assertEqual(cfg["token_budget"], llm._MAX_TOKENS)


class BudgetExhaustionTests(unittest.TestCase):
    """P3: reasoning tokens alone must not be diagnosed as budget exhaustion."""

    def test_reasoning_tokens_without_exhaustion_is_not_flagged(self) -> None:
        meta = {
            "finish_reason": "stop",
            "usage": {"completion_tokens": 300, "reasoning_tokens": 250},
            "request_config": {"token_budget": 25000},
        }
        self.assertFalse(llm.budget_exhausted(meta))

    def test_length_finish_at_budget_is_flagged(self) -> None:
        meta = {
            "finish_reason": "length",
            "usage": {"completion_tokens": 1024, "reasoning_tokens": 1024},
            "request_config": {"token_budget": 1024},
        }
        self.assertTrue(llm.budget_exhausted(meta))

    def test_length_finish_below_budget_is_not_flagged(self) -> None:
        meta = {
            "finish_reason": "length",
            "usage": {"completion_tokens": 10, "reasoning_tokens": 0},
            "request_config": {"token_budget": 25000},
        }
        self.assertFalse(llm.budget_exhausted(meta))

    def test_missing_metadata_is_not_flagged(self) -> None:
        self.assertFalse(llm.budget_exhausted({}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
