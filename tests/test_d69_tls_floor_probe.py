"""D69 -- the TLS probe could not see a legacy protocol floor.

``_recon_host`` shells out to openssl once, at the client's default protocol
preference.  That single handshake negotiates the *highest* version both sides
support, so "Protocol version: TLSv1.3" is reported and the probe moves on.

Measured on the user's own site, three independent clients that were each told
to offer only one version:

    SCHANNEL (.NET)     TLS 1.0 -> ACCEPTED   TLS 1.1 -> ACCEPTED
    Python ssl (1.1.1n) TLS 1.0 -> ACCEPTED   TLS 1.1 -> ACCEPTED
    curl / OpenSSL 3.5  TLS 1.0 -> no protocols available (LOCAL refusal)

TriageKit's own report for the same target, same minute::

    [info] tls  TLS chain verified
    ... protocol TLSv1.3

The floor is a real weakness (CWE-757, negotiable downgrade) and it was
invisible because nothing ever asked the question.  A false NEGATIVE of the
same family as D67 was a false positive: the scan's silence read as "nothing
wrong here".

curl's third line is the reason the probe must be built carefully -- on a host
whose openssl disables TLS 1.0, the *local* library refuses and the tool would
be asserting the target's posture from evidence about itself.  So the floor
probe asserts a finding ONLY when a handshake actually completed at the legacy
version, exactly the discipline D67 established for chain verification.
"""

from __future__ import annotations

import unittest
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parent.parent
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

import triagekit.core.analyzers.web_scan as ws  # noqa: E402


def probe_with(attempt):
    """Drive _recon_host with the TLS floor handshake replaced by `attempt`.

    `attempt(host, name, version)` returns ("completed", negotiated),
    ("unavailable", ...) or ("refused", ...).  The openssl chain probe is also
    fixed to a known-good blob so every run starts from a non-empty result --
    otherwise a host with no ``dig`` and a failing openssl call returns nothing
    at all, and the assertions below would pass for the wrong reason (absence of
    findings rather than correct classification).
    """
    from unittest import mock

    class _Proc:
        stdout = ("Connecting to 203.0.113.10\nCONNECTION ESTABLISHED\n"
                  "Protocol version: TLSv1.3\nPeer certificate: CN=example.test\n"
                  "Verification: OK\nDONE\n")
        stderr = ""

    def fake_run(cmd, *a, **kw):
        if cmd and str(cmd[0]).endswith("openssl"):
            return _Proc()
        raise OSError("no external tool in this test")

    def fake_which(name):
        # ``shutil.which("openssl")`` must stay truthy or _recon_host skips the
        # chain probe entirely and the harness returns nothing.
        if name == "openssl":
            return "/usr/bin/openssl"
        return None

    with mock.patch("shutil.which", fake_which), \
            mock.patch("subprocess.run", fake_run):
        ws._TLS_FLOOR_ATTEMPT = attempt
        try:
            return ws._recon_host("example.test")
        finally:
            ws._TLS_FLOOR_ATTEMPT = None


def completed(*versions):
    """An attempt that succeeds for the named versions and is refused for others."""
    def _attempt(host, name, version):
        if name in versions:
            return "completed", name
        return "refused", "sslv3 alert handshake failure"
    return _attempt


def local_refusal():
    """The real error string a host that cannot offer TLS 1.0 produces.

    Measured here with curl against the local library:
    ``error:0A000042:SSL routines:no protocols available``.  The outcome is
    ``"unavailable"`` -- one of the three `_tls_floor_attempt` actually returns
    -- so the probe's classification, not its generic exception handler, is what
    these tests exercise.
    """
    _MSG = "error:0A000042:SSL routines:no protocols available"

    def _attempt(host, name, version):
        return "unavailable", _MSG
    return _attempt


def baseline_titles():
    """Run the probe with an all-refusing attempt, to confirm it is non-empty."""
    return [f.title for f in probe_with(completed())]


class LegacyFloorIsDetectedTests(unittest.TestCase):
    """A server still speaking TLS 1.0 must be reported."""

    def test_the_probe_produces_a_baseline_to_begin_with(self):
        """Guards the other assertions against passing through silence."""
        titles = baseline_titles()
        self.assertTrue(
            titles,
            "the harness returned no findings at all; every assertion below "
            "would trivially pass",
        )
        self.assertTrue(
            any("chain verified" in t.lower() for t in titles),
            f"the fixed chain probe produced no baseline finding: {titles}",
        )

    def test_tls10_acceptance_is_reported_as_high(self):
        findings = probe_with(completed("TLS 1.0"))
        legacy = [f for f in findings if "legacy" in f.title.lower() or "1.0" in f.title]
        self.assertTrue(
            legacy, "the floor probe produced no finding at all; a server that "
                    "still completes a TLS 1.0 handshake is invisible to the report")
        top = legacy[0]
        self.assertEqual(top.severity, "high")
        self.assertIn("tls", top.category)
        self.assertEqual(top.cwe, "CWE-757",
                         "a negotiable downgrade to a broken protocol is CWE-757, "
                         f"not {top.cwe}")

    def test_tls11_acceptance_is_reported(self):
        findings = probe_with(completed("TLS 1.1"))
        legacy = [f for f in findings if "1.1" in f.title]
        self.assertTrue(legacy, "TLS 1.1 acceptance was not reported")
        self.assertEqual(legacy[0].severity, "medium")

    def test_a_modern_only_server_produces_no_legacy_finding(self):
        findings = probe_with(completed())
        legacy = [f for f in findings
                  if "1.0" in f.title or "1.1" in f.title]
        self.assertEqual(legacy, [],
                         "a server that refuses both legacy versions was still "
                         "reported as speaking them")

    def test_the_finding_tells_the_owner_what_to_do(self):
        findings = probe_with(completed("TLS 1.0"))
        legacy = [f for f in findings if "1.0" in f.title]
        self.assertTrue(legacy)
        rec = legacy[0].recommendation.lower()
        self.assertTrue(
            any(t in rec for t in ("minimum", "disable", "1.2", "floor", "cipher")),
            f"the finding offers no actionable remediation: {legacy[0].recommendation!r}")

    def test_the_finding_names_the_negotiated_version_as_evidence(self):
        findings = probe_with(completed("TLS 1.0"))
        legacy = [f for f in findings if "1.0" in f.title]
        self.assertTrue(legacy)
        self.assertTrue(legacy[0].evidence,
                        "the finding records no evidence of what was negotiated")


class TheProbeCannotAssertTests(unittest.TestCase):
    """An inability on the scanning host is never evidence about the target.

    This is the D67 rule applied to the floor.  On a host whose openssl
    disables TLS 1.0, the local library refuses -- measured here with curl:
    ``error:0A000042:SSL routines:no protocols available`` -- and the target
    must not be credited or blamed for it.
    """

    def test_a_local_refusal_is_not_reported_as_a_target_defect(self):
        findings = probe_with(local_refusal())
        legacy = [f for f in findings if ("1.0" in f.title or "1.1" in f.title)
                  and f.severity in ("high", "medium")]
        self.assertEqual(
            legacy, [],
            "the local openssl library refused to offer the protocol, yet a "
            "target-side severity was asserted")

    def test_a_local_refusal_is_disclosed_as_not_assessed(self):
        findings = probe_with(local_refusal())
        blob = " ".join(str(f.title) + str(f.detail) for f in findings).lower()
        self.assertTrue(
            "not_assessed" in blob or "not assessed" in blob or "could not" in blob,
            "the probe could not determine the floor and said nothing about it")

    def test_an_unclassified_error_is_not_a_finding(self):
        findings = probe_with(lambda host, name, version: (
            "refused", "something entirely new"))
        self.assertEqual(
            [f for f in findings if f.severity in ("high", "medium") and "1.0" in f.title],
            [], "an unrecognised error was promoted to a severity")


class PartialProbeIsDisclosedTests(unittest.TestCase):
    """Half a probe is coverage, not a conclusion."""

    def test_an_unavailable_version_is_named_alongside_a_detected_one(self):
        def attempt(host, name, version):
            if name == "TLS 1.1":
                return "completed", "TLSv1_1"
            return "unavailable", "error:0A000042:SSL routines:no protocols available"

        findings = probe_with(attempt)
        blob = " ".join(f"{f.title} {f.detail}" for f in findings).lower()
        self.assertIn("1.1", blob, "the version that WAS accepted is missing")
        self.assertTrue(
            "not_assessed" in blob or "could not" in blob or "unavailable" in blob,
            "the version the local library refused was not disclosed as unknown")


class GenuineDefectsStaySilentSafeTests(unittest.TestCase):
    """The floor probe must not smear other TLS conclusions."""

    def test_a_completed_legacy_handshake_does_not_assert_a_chain_defect(self):
        findings = probe_with(completed("TLS 1.0"))
        for f in findings:
            if "1.0" in f.title:
                self.assertNotEqual(
                    f.cwe, "CWE-295",
                    "completing a weak handshake says nothing about certificate "
                    "validation; D67's rule applies to this finding too")


class TheHarnessIsActuallyExercisingTheClassifierTests(unittest.TestCase):
    """Why these tests exist at all.

    Every callback in this file used to take two parameters against a
    three-argument contract, so each raised ``TypeError`` on its first call and
    the probe's generic ``except`` handler turned that into the NOT_ASSESSED
    notice the assertions went looking for.  Four tests passed through an
    exception, never through ``_tls_floor_attempt``'s classification -- which is
    what let a defect that silently discarded the ``"unavailable"`` outcome ship
    behind a green suite.  These guards make that failure mode loud.
    """

    def test_the_seam_is_called_with_the_documented_arity(self):
        seen = []

        def spy(host, name, version):
            seen.append((host, name, version))
            return "refused", "no"

        probe_with(spy)
        self.assertEqual(len(seen), 2,
                         f"attempt was called {len(seen)} times, not once per "
                         f"legacy version -- a callback with the wrong arity "
                         f"raises before recording anything")
        for host, name, version in seen:
            self.assertTrue(host, "the seam received no host")
            self.assertTrue(name, "the seam received no version name")
            self.assertIsNotNone(version,
                                 "the seam received no ssl.TLSVersion to pin")

    def test_the_real_attempt_classifier_still_knows_local_unavailability(self):
        """Guard against emptying ``_TLS_LOCAL_UNAVAILABLE``.

        With that tuple empty, a local refusal is indistinguishable from a target
        refusal and the D69 discipline collapses -- yet all 11 tests in this file
        stayed green, because they never reached the classifier.
        """
        self.assertTrue(
            ws._TLS_LOCAL_UNAVAILABLE,
            "_TLS_LOCAL_UNAVAILABLE is empty: a local inability to offer a "
            "protocol would be read as the target refusing it"
        )
        self.assertIn(
            "no protocols available", ws._TLS_LOCAL_UNAVAILABLE,
            "the actual openssl error string is not in the marker tuple"
        )

    def test_the_real_attempt_returns_one_of_the_documented_outcomes(self):
        """The classifier's three outcomes are the whole vocabulary."""
        outcome, evidence = ws._tls_floor_attempt("no-such-host.invalid", "TLS 1.0", None)
        self.assertIn(
            outcome, ("completed", "unavailable", "refused"),
            f"_tls_floor_attempt returned an undocumented outcome {outcome!r}; "
            f"the probe's dispatch only understands these three"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
