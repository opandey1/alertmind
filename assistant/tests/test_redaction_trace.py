#!/usr/bin/env python3
"""Redaction trace: covers regex + sensitive-key redactions, never leaks raw
values, keeps the Hashes IOC, and matches redact_alert() exactly."""
import json, sys, unittest
from pathlib import Path
HERE = Path(__file__).resolve().parent
ROOT = HERE if (HERE / "redact.py").exists() else HERE.parent
sys.path.insert(0, str(ROOT))
import redact
import paste_core as pc
from samples import PLANTED_SECRETS_ALERT

RAW = ["Sup3rSecret!", "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEYAB",
       "sk-DEMOabcdEFGH1234567890ijklmnop", "hunter2-not-real",
       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.demopayload.sig"]


class RedactionTraceTests(unittest.TestCase):
    def setUp(self):
        self.red, self.trace = redact.redact_alert_with_trace(PLANTED_SECRETS_ALERT)

    def test_delegation_identical(self):
        self.assertEqual(redact.redact_alert(PLANTED_SECRETS_ALERT), self.red)

    def test_original_not_mutated(self):
        self.assertIn("Sup3rSecret!", PLANTED_SECRETS_ALERT["key_fields"]["CommandLine"])

    def test_trace_covers_regex_and_sensitive_key(self):
        sources = {r["source"] for r in self.trace}
        self.assertIn("regex", sources)
        self.assertIn("sensitive_key", sources)

    def test_no_raw_value_in_trace_or_proof(self):
        blob = json.dumps(self.trace)
        for raw in RAW:
            self.assertNotIn(raw, blob)
        result = pc.run_paste_pipeline(json.dumps(PLANTED_SECRETS_ALERT),
                                       provider="mock", model="mock")
        md = pc.build_proof_markdown(result)
        for raw in RAW:
            self.assertNotIn(raw, md)

    def test_hashes_ioc_preserved(self):
        self.assertIn("1111111111111111111111111111111111111111111111111111111111111111",
                      json.dumps(self.red))

    def test_removed_flag_true(self):
        self.assertTrue(all(r["removed"] for r in self.trace))

    def test_sensitive_keys_redact_every_json_type(self):
        cases = {
            "password": 123456,
            "credentials": ["hunter2"],
            "api_key": True,
            "private_key": {"material": "secret"},
        }
        red, trace = redact.redact_alert_with_trace(cases)
        self.assertTrue(all(v == "[REDACTED:sensitive_field]" for v in red.values()))
        self.assertEqual(len(trace), len(cases))
        blob = json.dumps(red) + json.dumps(trace)
        for raw in ("123456", "hunter2", '"material": "secret"'):
            self.assertNotIn(raw, blob)

    def test_openai_project_key_is_redacted(self):
        key = "sk-proj-abcdefghijklmnopqrstuvwxyz123456"
        red, trace = redact.redact_alert_with_trace({"note": f"token seen: {key}"})
        self.assertNotIn(key, json.dumps(red))
        self.assertTrue(any(row["rule"] == "openai_key" for row in trace))


if __name__ == "__main__":
    unittest.main(verbosity=2)
