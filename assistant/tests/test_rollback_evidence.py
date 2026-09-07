"""Offline drift guards for the owner-reported rollback evidence, not live tests."""
import hashlib
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
PROOF = ROOT / "evidence/rbac/phase1c-rollback-revocation-proof.md"
OLD = "SHA256:+DDAvCldN5xpP0spEP3ClVsmhnhhQtcvJpD3GRyTaDo"
NEW = "SHA256:RAmkB1Xh5VLXel/ezCNgQRrl54HnnuUoQmlEY/XIb1c"


def section(text, number):
    matches = list(re.finditer(rf"^## {number}\. .*$", text, re.M))
    if len(matches) != 1:
        raise ValueError("missing or duplicate section")
    tail = text[matches[0].end():]
    return re.split(r"^## \d+\. ", tail, maxsplit=1, flags=re.M)[0]


def rows(text, number):
    result = {}
    for line in section(text, number).splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if cells[0] in {"Item", "Check", "Artifact under `siem/rbac/`"}:
            continue
        if all(re.fullmatch(r":?-+:?", cell) for cell in cells):
            continue
        if cells[0] in result:
            raise ValueError("duplicate row")
        result[cells[0]] = cells[1:]
    return result


def validate_review(text):
    expected = {
        "Reviewer": ["Pending — Claude requested through HANDOFF"],
        "Evidence commit": [
            "Identified by the author submission in HANDOFF; execution source is pinned in Section 1"
        ],
        "Verdict": ["Awaiting independent review; not approved"],
        "Required corrections": ["Not yet assessed"],
    }
    if rows(text, 9) != expected:
        raise ValueError("immutable author-submission review state changed")


class RollbackEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = PROOF.read_text(encoding="utf-8")
        cls.normalized = " ".join(cls.text.split())

    def test_all_sections_and_template_are_preserved(self):
        self.assertEqual(re.findall(r"^## (\d+)\. ", self.text, re.M),
                         [str(n) for n in range(1, 10)])
        template = PROOF.with_name("phase1c-rollback-revocation-proof-template.md")
        digest = hashlib.sha256(template.read_text(encoding="utf-8").encode()).hexdigest()
        self.assertEqual(digest, "17358b1dcb3b3a9beb2f66bb61d06def6d5e1d54b0d0a6edc345422e4adc4aec")
        self.assertNotIn("`PENDING`", self.text)
        for n in range(1, 10):
            rows(self.text, n)  # Fail on any duplicate table key, not just first match.

    def test_artifact_bindings_match_committed_content(self):
        for name, values in rows(self.text, 2).items():
            path = ROOT / "siem/rbac" / name.strip("`")
            digest = hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
            self.assertEqual(values[0], f"`{digest}`", name)
        self.assertEqual(len(rows(self.text, 2)), 5)
        self.assertIn("ea37cd89caac8858652317803386df85f01760bb", rows(self.text, 1)["Reviewed execution commit"][0])
        self.assertIn("not these manifest-file digests", self.normalized)

    def test_distinct_key_and_credential_checkpoints(self):
        ssh = rows(self.text, 6)
        self.assertEqual(ssh["Revoked client fingerprint"], [f"`{OLD}`"])
        self.assertEqual(ssh["Replacement client fingerprint"], [f"`{NEW}`"])
        self.assertNotEqual(OLD, NEW)
        self.assertEqual(rows(self.text, 4)["Old credential after deletion"],
                         ["HTTP `401` on fresh readback"])
        credentials = rows(self.text, 5)
        self.assertEqual(credentials["Positive credential recheck"], [
            "Fresh read-only HTTP `200`, exact `assistant-svc`, effective roles `[]`, backend roles `[]`"
        ])
        self.assertIn("Fresh known-OLD test HTTP `401`", credentials["Negative credential recheck"][0])
        self.assertEqual(credentials["Restricted reads"],
                         ["Cluster health `403`; username-index search `403`"])
        self.assertIn("comparison alone does not identify the real old credential", self.normalized)

    def test_tls_and_denials_preserve_scope(self):
        ssh = rows(self.text, 6)
        self.assertEqual(ssh["Final shell/command"], ["Windows wrapper exit `-1`; marker absent"])
        self.assertEqual(ssh["Final PTY/session"], ["Windows wrapper exit `-1`; marker absent"])
        self.assertEqual(ssh["Final remote forward"], ["Exit `255`; denial PASS"])
        self.assertEqual(ssh["Final password-only authentication"], ["Exit `255`; password prompts disabled"])
        self.assertEqual(ssh["Correct-identity read"], [
            "`127.0.0.1` accepted; `failed_shards=0; visible_hits=10000; relation=gte` on replacement and canonical paths"
        ])
        for phrase in (
            "explicit public-key rejection", "same canonical-key positive forward",
            "summaries alone do not establish successful authentication on every fresh connection",
            "lower bound", "no effective certificate-revocation protection",
            "administratively prohibited", "Not forensic erasure",
        ):
            self.assertIn(phrase, self.normalized)

    def test_interruption_and_unknowns_cannot_disappear(self):
        deviations = " ".join(section(self.text, 8).split())
        for phrase in (
            "Exact DELETE codes and the original final tail were not retained",
            "no exact rerun response was captured", "also returned 401",
            "secondary JSON parse traceback", "could not confirm it",
            "Cause remains unknown", "Repeated pasted copies are one checkpoint",
            "Separate read-only rechecks", "Agent usage-limit interruptions",
        ):
            self.assertIn(phrase, deviations)
        self.assertIn("interrupted, checkpoint-reconciled drill", self.normalized)
        self.assertIn("not one uninterrupted passing script", self.normalized)
        self.assertIn("Exact per-command wall-clock timestamps were not captured", self.normalized)

    def test_final_health_does_not_claim_future_features(self):
        final = rows(self.text, 7)
        self.assertEqual(final["Final health order"], [
            "Indexer → Manager → Filebeat → Dashboard: each individually active; final restored-state PASS"
        ])
        self.assertIn("password/hash was neither displayed nor compared for equality", final["`socanalyst`"][0])
        for phrase in (
            "not proof of no transient service change between checkpoints",
            "Not established", "application-profile rollback", "OIDC",
            "Dashboard/Server RBAC", "production readiness",
            "no live analyst/Wazuh profile",
            "or a fresh complete Phase 1B DLS/write-denial matrix",
        ):
            self.assertIn(phrase, self.normalized)

    def test_review_status_is_explicit_and_unique(self):
        validate_review(self.text)
        self.assertEqual(self.text.count("**Status:**"), 1)
        self.assertIn("author consolidation awaiting independent review", self.normalized)

    def test_review_guards_reject_approval_or_duplicate_verdict(self):
        mutations = (
            self.text.replace("Awaiting independent review; not approved", "Approved"),
            self.text.replace("| Verdict | Awaiting independent review; not approved |",
                              "| Verdict | Awaiting independent review; not approved |\n| Verdict | Approved |"),
            self.text.replace("## 9. Independent review", "## 9. Independent review\n\n## 9. Extra review"),
        )
        for changed in mutations:
            with self.subTest(change=changed[-500:]):
                with self.assertRaises(ValueError):
                    validate_review(changed)

    def test_no_embedded_secret_or_raw_alert_material(self):
        for forbidden in ("-----BEGIN", "Authorization: Basic", "Authorization: Bearer", '"_source":'):
            self.assertNotIn(forbidden, self.text)
        self.assertIsNone(re.search(r"ssh-ed25519\s+AAAA", self.text))


if __name__ == "__main__":
    unittest.main()
