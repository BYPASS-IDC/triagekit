"""D68 -- the AI agent turns a coverage note into attack surface.

The web scanner now reports a TLS local-trust gap as::

    [info] tls  TLS chain NOT_ASSESSED (local trust store incomplete)
        "No server-side change is implied by this notice."

The AI brief for the same target came back with:

    attack_surface:
      - Potential connection issues due to inability to verify SSL certificates
        (TLS trust issue).

A statement the tool made explicitly about *its own* limitations was promoted
into a list of "realistic attack paths" for the owner.  This is the D67 false
positive surviving into the part of the report the user actually reads first,
and it is worse than the original: it is now phrased as an attack path, in the
imperative voice of a conclusion, with no NOT_ASSESSED marker left.

Two things cause it:
  1. ``_AGENT_SYSTEM_CORE`` tells the model what shape to return and nothing
     about which findings describe a *risk* versus a *coverage limitation*.
  2. The evidence payload puts informational findings in the same
     ``findings_sample`` list as real ones, so the model has one indistinguishable
     bucket to reason over.

The fix separates the two, states the rule in the prompt, and removes from
``attack_surface`` any bullet that is a restatement of a coverage limitation.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parent.parent
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

from triagekit.core.analyzers.repo_scan import Finding, RepoScanResult  # noqa: E402
import triagekit.core.analyzers.security_agent as sa  # noqa: E402


def web_scan_like_result() -> RepoScanResult:
    """The shape the web path builds from a webscan result.

    Mirrors cli.py's webscan adapter: the informational TLS coverage note is
    converted into a Finding like any other, with its severity preserved.
    """
    res = RepoScanResult(root="https://akstreamers.net/")
    res.findings = [
        Finding(
            severity="info",
            category="tls",
            title="TLS chain NOT_ASSESSED (local trust store incomplete)",
            file="akstreamers.net",
            recommendation="Configure a CA bundle for openssl (SSL_CERT_FILE / "
                           "SSL_CERT_DIR) to make this probe able to verify; or "
                           "verify the chain with a client that has a trust "
                           "store.  No server-side change is implied by this notice.",
            snippet="unable to get local issuer certificate",
        ),
        Finding(
            severity="high",
            category="headers",
            title="Missing security header: HSTS",
            file="/",
            recommendation="Send Strict-Transport-Security: max-age=31536000; "
                           "includeSubDomains; preload",
        ),
        Finding(
            severity="high",
            category="headers",
            title="Missing security header: CSP",
            file="/",
            recommendation="Deploy a tight Content-Security-Policy.",
        ),
        Finding(
            severity="low",
            category="disclosure",
            title="Technology disclosure via server",
            file="cloudflare",
            recommendation="Remove or genericize version banners.",
        ),
    ]
    res.score = 81.0
    res.grade = "B"
    res.summary = "Security adviser score 81.0/100 (B)."
    return res


class PromptSeparatesRiskFromCoverageTests(unittest.TestCase):
    """The model must be told which findings are risks."""

    def setUp(self):
        self.prompt = sa._AGENT_SYSTEM_CORE

    def test_the_prompt_defines_an_informational_finding(self):
        low = self.prompt.lower()
        self.assertIn("info", low, "the prompt never names the 'info' severity it will be sent")
        self.assertTrue(
            "not_assessed" in low.replace(" ", "_") or "not assessed" in low
            or "coverage" in low,
            "the prompt has no concept of a coverage limitation",
        )

    def test_the_prompt_forbids_promoting_coverage_into_attack_surface(self):
        low = self.prompt.lower()
        self.assertIn("attack_surface", low, "attack_surface is not in the prompt")
        self.assertIn("coverage", low, "the prompt has no concept of coverage")
        # The rule must be stated as an explicit prohibition, not implied.
        self.assertTrue(
            any(p in low for p in (
                "never place a coverage", "may not be promoted",
                "must never", "never a \"realistic attack path\"",
            )),
            "the prompt mentions coverage but never forbids promoting it into "
            "attack_surface",
        )
        # And it must tell the model where such a statement belongs instead.
        self.assertIn("residual_risk", low,
                      "the prohibition names no correct destination for a "
                      "coverage limitation")


class PayloadSeparatesRiskFromCoverageTests(unittest.TestCase):
    """Findings the tool could not assess must not sit in one bucket with real ones."""

    def test_informational_findings_are_not_in_findings_sample(self):
        built = sa._agent_evidence(web_scan_like_result())
        sample = built.get("findings_sample") or []
        sevs = {f.get("sev") for f in sample}
        self.assertNotIn(
            "info", sevs,
            "informational findings are still being fed to the model as "
            "ordinary findings",
        )

    def test_informational_findings_are_listed_as_coverage_limitations(self):
        built = sa._agent_evidence(web_scan_like_result())
        cov = built.get("coverage_limitations") or []
        self.assertTrue(
            any("tls" in str(c).lower() or "trust" in str(c).lower() for c in cov),
            f"the TLS coverage note is not surfaced as a limitation: {cov}",
        )

    def test_real_findings_are_still_present(self):
        built = sa._agent_evidence(web_scan_like_result())
        sample = built.get("findings_sample") or []
        self.assertEqual(len(sample), 3, f"only {len(sample)} of 3 real findings survived")
        self.assertEqual({f["sev"] for f in sample}, {"high", "low"})


class AttackSurfaceIsStrippedOfCoverageTests(unittest.TestCase):
    """The merged brief must not restate a limitation as an attack path."""

    def test_a_coverage_restatement_is_removed_from_attack_surface(self):
        brief = sa.run_security_agent(web_scan_like_result(), use_llm=False)
        # Simulate what the model returned for the same target.
        brief["attack_surface"] = [
            "Client-side downgrade attacks due to missing HSTS.",
            "Exploitation via XSS or injection if CSP is not properly configured.",
            "Potential connection issues due to inability to verify SSL "
            "certificates (TLS trust issue).",
        ]
        cleaned = sa._strip_coverage_from_attack_surface(brief, web_scan_like_result())
        kept = cleaned["attack_surface"]
        self.assertEqual(
            len(kept), 2,
            f"a coverage limitation was left in attack_surface: {kept}",
        )
        self.assertFalse(
            any("ssl" in k.lower() or "certificate" in k.lower() for k in kept),
            "the certificate coverage note is still presented as an attack path",
        )

    def test_a_genuine_attack_path_survives(self):
        brief = {"attack_surface": [
            "Client-side downgrade attacks due to missing HSTS.",
            "Stored XSS via unsanitised comment body.",
        ]}
        cleaned = sa._strip_coverage_from_attack_surface(brief, web_scan_like_result())
        self.assertEqual(len(cleaned["attack_surface"]), 2)

    def test_an_empty_attack_surface_stays_empty(self):
        cleaned = sa._strip_coverage_from_attack_surface(
            {"attack_surface": []}, web_scan_like_result())
        self.assertEqual(cleaned["attack_surface"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
