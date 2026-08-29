#!/usr/bin/env python3
"""Regression tests for non-destructive, explicit corpus sub-selection."""

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from runner import select_alerts, subset_run_suffix  # noqa: E402


ALERTS = [
    {"alert_id": "A01"},
    {"alert_id": "A02"},
    {"alert_id": "A03"},
    {"alert_id": "A04"},
]


class RunnerSelectionTests(unittest.TestCase):
    def test_explicit_ids_preserve_frozen_corpus_order(self):
        selected = select_alerts(ALERTS, "A04,A02")
        self.assertEqual([a["alert_id"] for a in selected], ["A02", "A04"])
        self.assertEqual(len(ALERTS), 4)  # source corpus is not modified

    def test_unknown_alert_id_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "unknown alert ID.*A99"):
            select_alerts(ALERTS, "A01,A99")

    def test_alert_ids_and_limit_are_mutually_exclusive(self):
        with self.assertRaisesRegex(ValueError, "cannot be combined"):
            select_alerts(ALERTS, "A01", limit=1)

    def test_subset_suffix_encodes_identity_not_only_count(self):
        first = subset_run_suffix(select_alerts(ALERTS, "A01,A02"))
        second = subset_run_suffix(select_alerts(ALERTS, "A03,A04"))
        reordered = subset_run_suffix(select_alerts(ALERTS, "A02,A01"))
        self.assertRegex(first, r"^_subset2_[0-9a-f]{8}$")
        self.assertNotEqual(first, second)
        self.assertEqual(first, reordered)


if __name__ == "__main__":
    unittest.main()
