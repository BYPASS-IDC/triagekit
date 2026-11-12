"""Tests for the defensive exploit/PoC module (T10).

The contract this module must uphold, in priority order:

1.  It never produces a weaponized payload.  Every PoC is a DETECTION PoC -- a
    marker that proves a defect exists and shows how it is reached.
2.  It never invents a mechanism for a finding it did not recognise.
3.  Every PoC carries a remediation and a VERIFICATION step, so a PoC that
    cannot be falsified (and therefore proves nothing) is not emitted.
4.  It is tied to a real finding: no speculative PoCs for code that was not
    observed to be vulnerable.
"""

from __future__ import annotations

import unittest
from dataclasses import dataclass, field
from typing import Any, Optional

from triagekit.core.analyzers.poc import (
    PoC,
    has_poc,
    poc_for,
    poc_markdown,
    pocs_for_findings,
)


@dataclass
class _Finding:
    """A minimal stand-in for the real scanner finding objects."""

    category: str
    severity: str = "high"
    cwe_ids: list = field(default_factory=list)
    title: str = ""
    endpoint: str = ""
    evidence: str = ""
    language: str = ""


class PoCContractTests(unittest.TestCase):
    """The module-wide rules, applied to every PoC it can produce."""

    CATEGORIES = [
        "template-injection", "sql-injection", "command-injection", "xss-eval",
        "xss-dom", "path-traversal", "ssrf", "weak-hash", "hardcoded-secret",
        "jwt-verify-off", "disclosure", "unsafe-deserialization",
        "injection-surface",
    ]

    def test_every_poc_is_complete(self) -> None:
        for category in self.CATEGORIES:
            with self.subTest(category=category):
                poc = poc_for(category=category, severity="high")
                self.assertIsNotNone(poc, f"no PoC for {category}")
                assert poc is not None
                self.assertTrue(poc.title)
                self.assertTrue(poc.mechanism, f"{category}: no mechanism")
                self.assertTrue(poc.remediation, f"{category}: no remediation")
                self.assertTrue(poc.verification, f"{category}: no verification step")
                self.assertTrue(poc.poc_request, f"{category}: no PoC request")
                self.assertTrue(poc.poc_expected, f"{category}: no expected result")
                self.assertTrue(poc.impact, f"{category}: no impact")

    def test_every_poc_states_a_verification_step(self) -> None:
        # A PoC that cannot be shown to be fixed is theatre, not a test.
        for category in self.CATEGORIES:
            poc = poc_for(category=category, severity="high")
            assert poc is not None
            self.assertTrue(
                poc.verification,
                f"{category} must state how to prove the fix worked",
            )

    def test_no_poc_contains_a_destructive_or_weaponized_instruction(self) -> None:
        # The output goes to third parties helping clients FIX issues.  It must
        # not double as an attack toolkit.
        banned = (
            "rm -rf", "curl | sh", "curl | bash", "nc -e", "/dev/tcp",
            "chmod 777", "mkfifo", "wget -O- | sh",
        )
        for category in self.CATEGORIES:
            poc = poc_for(category=category, severity="critical")
            assert poc is not None
            blob = poc_markdown([poc]).lower()
            for marker in banned:
                self.assertNotIn(
                    marker.lower(), blob,
                    f"{category}: PoC contains a destructive construct ({marker})",
                )

    def test_pocs_are_marked_as_requiring_authorisation(self) -> None:
        for category in self.CATEGORIES:
            poc = poc_for(category=category)
            assert poc is not None
            self.assertTrue(
                poc.requires_authorisation,
                f"{category}: PoC must declare that confirmation needs authorisation",
            )

    def test_the_markdown_section_is_structured(self) -> None:
        poc = poc_for(category="sql-injection", severity="critical")
        assert poc is not None
        md = poc_markdown([poc])
        for heading in (
            "## Proof-of-concept, impact, and remediation",
            "### SQL Injection (sql-injection, CWE-89) - critical",
            "**How it works**",
            "**Safe detection PoC**",
            "**What proves it**",
            "**What an attacker gains**",
            "**Fix**",
            "**How to prove the fix worked**",
        ):
            self.assertIn(heading, md)
        self.assertIn("```", md)

    def test_markdown_with_no_pocs_says_so(self) -> None:
        md = poc_markdown([])
        self.assertIn("No defect class in this scan has a defensive proof-of-concept", md)


class PoCResolutionTests(unittest.TestCase):
    def test_public_risk_aliases_resolve_to_the_same_poc(self) -> None:
        # The heuristic layer emits "-risk" suffixed types; they must not fall
        # through to "no PoC".
        for alias, canonical in (
            ("sql-injection-risk", "sql-injection"),
            ("template-injection-risk", "template-injection"),
            ("path-traversal-risk", "path-traversal"),
            ("ssrf-risk", "ssrf"),
            ("shell-injection-risk", "command-injection"),
        ):
            self.assertEqual(
                poc_for(category=alias).category,
                poc_for(category=canonical).category,
                f"{alias} should resolve like {canonical}",
            )

    def test_cwe_resolves_when_the_category_does_not(self) -> None:
        poc = poc_for(category="something-unmapped", cwe_ids=["CWE-89"])
        self.assertIsNotNone(poc)
        assert poc is not None
        self.assertEqual(poc.category, "sql-injection")

    def test_an_unknown_category_yields_no_poc(self) -> None:
        # Never invent a mechanism for something not in the table.
        self.assertIsNone(poc_for(category="totally-unrecognised", cwe_ids=[]))
        self.assertFalse(has_poc("totally-unrecognised"))

    def test_has_poc_accepts_cwe_only(self) -> None:
        self.assertTrue(has_poc("whatever", ["CWE-79"]))
        self.assertTrue(has_poc("xss-eval"))
        self.assertFalse(has_poc("whatever", ["CWE-9999"]))

    def test_cwe_string_is_accepted_as_a_scalar(self) -> None:
        poc = poc_for(category="", cwe_ids="CWE-22")
        self.assertIsNotNone(poc)
        assert poc is not None
        self.assertEqual(poc.category, "path-traversal")

    def test_severity_is_never_lowered_by_the_finding(self) -> None:
        low = poc_for(category="sql-injection", severity="low")
        assert low is not None
        self.assertEqual(low.severity, "critical", "a class default must not be downgraded")

    def test_a_higher_reported_severity_is_respected(self) -> None:
        poc = poc_for(category="injection-surface", severity="critical")
        assert poc is not None
        self.assertEqual(poc.severity, "critical")

    def test_a_lower_reported_severity_is_recorded_as_a_note(self) -> None:
        poc = poc_for(category="sql-injection", severity="low")
        assert poc is not None
        self.assertTrue(
            any("lower than the class default" in n for n in poc.notes),
            "a downgrade must be flagged, not silent",
        )


class PoCFindingTests(unittest.TestCase):
    def test_findings_are_processed_without_importing_the_scanner(self) -> None:
        pocs = pocs_for_findings([
            _Finding(category="sql-injection", severity="critical",
                     cwe_ids=["CWE-89"], endpoint="/search",
                     evidence="param=q; probe=sqli_quote"),
            _Finding(category="path-traversal", severity="high", cwe_ids=["CWE-22"]),
        ])
        self.assertEqual([p.category for p in pocs], ["sql-injection", "path-traversal"])

    def test_findings_without_a_poc_are_skipped(self) -> None:
        pocs = pocs_for_findings([
            _Finding(category="headers", severity="low"),
            _Finding(category="sql-injection", severity="critical"),
        ])
        self.assertEqual(len(pocs), 1)
        self.assertEqual(pocs[0].category, "sql-injection")

    def test_evidence_and_endpoint_reach_the_poc_notes(self) -> None:
        poc = poc_for(category="sql-injection", endpoint="/search",
                      evidence="param=q   probe=sqli_quote", title="SQLi signal")
        assert poc is not None
        joined = " ".join(poc.notes)
        self.assertIn("Observed at: /search", joined)
        self.assertIn("Scanner evidence: param=q probe=sqli_quote", joined)
        self.assertIn("Reported as: SQLi signal", joined)

    def test_pocs_are_sorted_by_severity(self) -> None:
        # injection-surface is a medium class default, so the reported medium is
        # honoured and the sort order is fully determined by the inputs.
        pocs = pocs_for_findings([
            _Finding(category="disclosure", severity="medium"),
            _Finding(category="sql-injection", severity="critical"),
            _Finding(category="injection-surface", severity="medium"),
        ])
        self.assertEqual(
            [p.severity for p in pocs],
            ["critical", "medium", "medium"],
        )

    def test_a_class_default_is_not_downgraded_by_a_low_finding(self) -> None:
        # The whole point of the guard: a reviewer's severity is a floor, not a
        # ceiling.  weak-hash defaults to high and stays high.
        pocs = pocs_for_findings([_Finding(category="weak-hash", severity="medium")])
        self.assertEqual(pocs[0].severity, "high")

    def test_nothing_is_generated_for_an_empty_input(self) -> None:
        self.assertEqual(pocs_for_findings([]), [])

    def test_the_language_note_is_added_for_template_findings(self) -> None:
        poc = poc_for(category="template-injection", language="python")
        assert poc is not None
        self.assertTrue(any("python" in n for n in poc.notes))


class PoCMechanismTests(unittest.TestCase):
    """The mechanism must describe the defect, not restate its name."""

    def test_mechanisms_are_actionable_prose(self) -> None:
        poc = poc_for(category="sql-injection")
        assert poc is not None
        joined = " ".join(poc.mechanism)
        # The mechanism must explain causation, not merely name the defect.
        self.assertIn("concatenated", joined.lower())
        self.assertGreater(len(poc.mechanism), 2)

    def test_remediation_names_the_concrete_fix(self) -> None:
        poc = poc_for(category="command-injection")
        assert poc is not None
        joined = " ".join(poc.remediation)
        self.assertIn("argument list", joined.lower())

    def test_template_poc_distinguishes_evaluation_from_reflection(self) -> None:
        # Conflating the two is how a reflected marker gets reported as RCE.
        poc = poc_for(category="template-injection")
        assert poc is not None
        joined = " ".join(list(poc.notes) + [poc.poc_expected] + list(poc.verification))
        self.assertIn("reflection", joined.lower())


if __name__ == "__main__":
    unittest.main()
