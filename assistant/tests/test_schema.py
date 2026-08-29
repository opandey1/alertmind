#!/usr/bin/env python3
"""Regression tests keeping the enforced and documented schemas aligned."""

import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from schema import JSON_SCHEMA, ollama_json_schema, validate_output  # noqa: E402


def valid_output(query_count=2):
    return {
        "summary": ["Scheduled task creation detected."],
        "attack_technique_id": "T1053.003/T1059.001",
        "attack_technique_name": "Scheduled Task/Job and PowerShell",
        "disposition_suggestion": "needs_investigation",
        "confidence": "medium",
        "investigation_queries": [f"query {i}" for i in range(query_count)],
        "draft_user_message": "Please confirm whether this task was expected.",
        "caveats": "Administrative activity can produce similar telemetry.",
    }


class SchemaAlignmentTests(unittest.TestCase):
    def test_formal_schema_rejects_undeclared_fields(self):
        self.assertFalse(JSON_SCHEMA["additionalProperties"])
        output = valid_output()
        output["invented_field"] = "not part of the contract"
        ok, errors, _ = validate_output(output)
        self.assertFalse(ok)
        self.assertIn("additional_property:invented_field", errors)

    def test_documented_pattern_accepts_multi_technique_ids(self):
        pattern = JSON_SCHEMA["properties"]["attack_technique_id"]["pattern"]
        self.assertIsNotNone(re.fullmatch(pattern, "T1136/T1098"))
        self.assertIsNotNone(re.fullmatch(pattern, "T1021.002, T1569.002"))
        provider_schema = ollama_json_schema()
        self.assertNotIn(
            "pattern", provider_schema["properties"]["attack_technique_id"]
        )
        self.assertIn(
            "pattern", JSON_SCHEMA["properties"]["attack_technique_id"]
        )

    def test_strict_provider_schema_requires_nullable_optional_name(self):
        provider_schema = ollama_json_schema()
        self.assertNotIn("attack_technique_name", JSON_SCHEMA["required"])
        self.assertIn("attack_technique_name", provider_schema["required"])
        self.assertEqual(
            provider_schema["properties"]["attack_technique_name"]["type"],
            ["string", "null"],
        )

    def test_provider_schema_copy_is_cached(self):
        self.assertIs(ollama_json_schema(), ollama_json_schema())

    def test_runtime_validator_accepts_multi_technique_ids(self):
        ok, errors, _ = validate_output(valid_output())
        self.assertTrue(ok, errors)

    def test_formal_schema_records_runtime_query_bounds(self):
        queries = JSON_SCHEMA["properties"]["investigation_queries"]
        self.assertEqual(queries["minItems"], 1)
        self.assertEqual(queries["maxItems"], 4)

    def test_runtime_validator_enforces_one_to_four_queries(self):
        for count in (1, 4):
            ok, errors, _ = validate_output(valid_output(count))
            self.assertTrue(ok, errors)
        for count in (0, 5):
            ok, errors, _ = validate_output(valid_output(count))
            self.assertFalse(ok)
            self.assertTrue(any("investigation_queries:count" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
