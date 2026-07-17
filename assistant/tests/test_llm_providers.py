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
            output = llm._openai("system", "user", "gpt-5.5")

        self.assertEqual(output, "pong")
        url, headers, payload = post.call_args.args
        self.assertEqual(
            url, "https://api.openai.com/v1/chat/completions"
        )
        self.assertEqual(headers["Authorization"], "Bearer test-key")
        self.assertEqual(payload["max_completion_tokens"], llm._MAX_TOKENS)
        self.assertEqual(payload["reasoning_effort"], "none")
        self.assertNotIn("max_tokens", payload)
        self.assertNotIn("temperature", payload)

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
            },
            clear=False,
        ):
            llm._ollama("system", "user", "llama3.1:8b")

        url, _, payload = post.call_args.args
        self.assertEqual(
            url, "http://localhost:11434/v1/chat/completions"
        )
        self.assertEqual(payload["max_tokens"], llm._MAX_TOKENS)
        self.assertEqual(payload["temperature"], 0)

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
