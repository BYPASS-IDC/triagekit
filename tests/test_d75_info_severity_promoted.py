"""D75 -- an informational finding is promoted to MEDIUM one layer later.

Found by the adversarial review workflow (`wf_153958c2-f7e`), which verified it
by execution rather than by inspection:

* `web_scan.WebFinding(severity="info")` for "TLS chain verified" and for the
  D67 "TLS chain NOT_ASSESSED (local trust store incomplete)" notice;
* `WebScanResult.compute_score` weights `"info"` **0** -- the D67 contract,
  stated in a comment on the weight table itself: "a statement that the scan
  could not assess something is coverage, not a vulnerability (defect D67)";
* `WebScanner._scan` then converted it through
  ``severity_map.get(finding.severity, Severity.MEDIUM)``, and ``severity_map``
  had no `"info"` key -- so every coverage notice became a **MEDIUM**
  UnifiedFinding worth 4 points, in `by_severity`, in `remediation_priority`,
  and in the prioritized findings list.

That is the D67 false positive reintroduced downstream of the fix, on a machine
with no CA bundle: the owner is told a medium-severity problem exists on a server
whose chain is fine, and told to fix it.  `Severity.INFORMATIONAL` exists and
`_calculate_priority` already ranks it last; only the mapping was missing.

Run with the project venv:

    PYTHONPATH=src .venv/Scripts/python.exe -m pytest tests/test_d75_info_severity_promoted.py -q
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

from triagekit.core.analyzers import web_scan as ws  # noqa: E402
from triagekit.core.scanners.base import Severity  # noqa: E402
from triagekit.core.scanners.web_scanner import WebScanner  # noqa: E402


def info_finding(title: str) -> ws.WebFinding:
    return ws.WebFinding(
        "info", "tls", title,
        "detail of a coverage notice", "No server-side change is implied.",
    )


class InformationalIsNotMediumTests(unittest.TestCase):
    """A coverage notice must never acquire a severity that costs points."""

    def _converted(self, title: str):
        scanner = WebScanner({"offline": False})
        # Drive only the conversion, which is the code under test.  Reaching
        # WebScanner._scan would run a live scan.
        web_result = ws.WebScanResult(
            url="https://example.test", final_url="https://example.test")
        web_result.findings = [info_finding(title)]
        severity_map = getattr(scanner, "_severity_map", None)
        self.assertIsNotNone(
            severity_map,
            "WebScanner no longer exposes the severity mapping as its own "
            "attribute, so it cannot be tested without a live scan")
        return severity_map["info"], severity_map.get("informational")

    def test_info_is_not_the_default_medium_fallback(self):
        """The mapping must name "info" explicitly, not fall through to MEDIUM."""
        mapped, _ = self._converted("TLS chain verified")
        self.assertNotEqual(
            mapped, Severity.MEDIUM,
            'an informational coverage notice was converted to MEDIUM; the '
            'default fallback is doing the mapping',
        )

    def test_info_maps_to_informational(self):
        mapped, _ = self._converted("TLS chain verified")
        self.assertEqual(
            mapped, Severity.INFORMATIONAL,
            f"info mapped to {mapped}, not Severity.INFORMATIONAL",
        )

    def test_informational_spelling_maps_the_same_way(self):
        """Both spellings must land in the same bucket."""
        _, mapped = self._converted("TLS chain verified")
        self.assertEqual(
            mapped, Severity.INFORMATIONAL,
            f"the 'informational' spelling mapped to {mapped}",
        )

    def test_the_real_severities_still_map_to_themselves(self):
        """The fix must not remap the real severities while adding one."""
        _, _ = self._converted("x")
        scanner = WebScanner({"offline": False})
        sm = scanner._severity_map
        for name in ("critical", "high", "medium", "low"):
            self.assertEqual(
                sm[name], getattr(Severity, name.upper()),
                f"{name} no longer maps to Severity.{name.upper()}",
            )

    def test_informational_is_ranked_last_in_remediation_priority(self):
        """The downstream consumer must already rank it below every defect."""
        from triagekit.core.scanners.correlation import (
            CorrelatedGroup,
            FindingCorrelator,
        )
        # The priority calculator lives on FindingCorrelator, which
        # CorrelationEngine delegates to -- naming the class that owns the
        # method keeps this test honest about what it exercises.
        weights = (
            Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW,
        )
        g = CorrelatedGroup(
            id="g", primary_finding=None, related_findings=[],
            scan_types=(), combined_severity=Severity.INFORMATIONAL,
        )
        priority = FindingCorrelator()._calculate_priority(g)
        for sev in weights:
            other = CorrelatedGroup(
                id="g", primary_finding=None, related_findings=[],
                scan_types=(), combined_severity=sev,
            )
            self.assertLess(
                FindingCorrelator()._calculate_priority(other), priority,
                f"INFORMATIONAL ranked above {sev} in remediation priority",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
