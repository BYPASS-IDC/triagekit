"""D67 -- the TLS probe reported the target for the scanner's own environment.

``_recon_host`` shells out to ``openssl s_client -brief`` and decides severity
with::

    ver_fail = "verification error" in blob.lower() or "verify return code" in blob.lower() and "0 (ok)" not in blob.lower()

Two things are wrong, and both were measured against a real site that serves a
valid certificate.

1. ``and`` binds tighter than ``or``, so this parses as
   ``A or (B and C)`` and the A disjunct is entirely unguarded.
2. ``-brief`` never prints ``Verify return code:`` at all -- that line only
   appears in verbose output. So the B disjunct is always False and the whole
   expression collapses to ``"verification error" in blob``.

OpensSL prints ``Verification error: unable to get local issuer certificate``
(error 20) whenever *its own* trust store is incomplete -- a property of the
machine running the scan, not of the server. On a host with no configured CA
bundle that fires for every site, valid chain or not. Measured:

    target chain, validated by the OS trust store : valid
    _recon_host verdict on that same target       : MEDIUM, CWE-295,
                                                   "fix certificate chain/
                                                    hostname mismatches"

The finding is a false positive that sends the site owner to repair a server
that is fine, and it is the inverse of a false negative: the report is *more*
alarming than reality, which erodes trust in the true findings next to it.

The probe must therefore only assert a target-side defect from verification
evidence it can actually attribute, and must state NOT_ASSESSED when it cannot.
"""

from __future__ import annotations

import unittest
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parent.parent
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

import triagekit.core.analyzers.web_scan as ws  # noqa: E402


# openssl -brief output for a VALID chain, emitted on a host with no CA bundle.
BRIEF_LOCAL_TRUST_GAP = """\
Connecting to 203.0.113.10
depth=3 C=US, O=Internet Security Research Group, CN=ISRG Root X2
verify error:num=20:unable to get local issuer certificate
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN=example.test
Hash used: SHA256
Signature type: ECDSA
Verification error: unable to get local issuer certificate
Server Temp Key: X25519, 253 bits
DONE
"""

# openssl -brief output when the local trust store IS complete and the chain is good.
BRIEF_OK = """\
Connecting to 203.0.113.10
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN=example.test
Verification: OK
DONE
"""

# A genuinely broken chain: the certificate has expired. That is the target's fault.
BRIEF_EXPIRED = """\
Connecting to 203.0.113.10
depth=0 CN=example.test
verify error:num=10:certificate has expired
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Peer certificate: CN=example.test
Verification error: certificate has expired
DONE
"""

# A hostname mismatch. Also the target's fault.
BRIEF_HOSTNAME = """\
Connecting to 203.0.113.10
verify error:num=62:hostname mismatch
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Verification error: hostname mismatch
DONE
"""


def run_probe(blob: str) -> list:
    """Drive _recon_host with openssl's output fixed to `blob`.

    ``_recon_host`` imports ``shutil``/``subprocess`` inside the function body,
    so the patch has to be on the modules themselves rather than on the module
    namespace.  Only the openssl invocation is intercepted; ``dig``/``nslookup``
    keep calling through so the probe behaves normally on hosts that have them.
    """
    import shutil
    import subprocess
    from unittest import mock

    real_which = shutil.which
    real_run = subprocess.run

    class _Proc:
        stdout = blob
        stderr = ""

    def fake_which(name):
        if name == "openssl":
            return "/usr/bin/openssl"
        return real_which(name)

    def fake_run(cmd, *a, **kw):
        if cmd and cmd[0] in ("/usr/bin/openssl", "openssl"):
            return _Proc()
        return real_run(cmd, *a, **kw)

    with mock.patch("shutil.which", fake_which), mock.patch("subprocess.run", fake_run):
        return ws._recon_host("example.test")


class LocalTrustGapIsNotATargetDefectTests(unittest.TestCase):
    """Error 20 says the scanner cannot verify, not that the server is broken."""

    def test_a_valid_chain_is_not_reported_as_medium(self):
        findings = run_probe(BRIEF_LOCAL_TRUST_GAP)
        tls = [f for f in findings if f.category == "tls"]
        self.assertEqual(
            len(tls), 1,
            "the probe produced no TLS finding at all; the coverage statement "
            "must still be emitted",
        )
        for f in tls:
            self.assertNotEqual(
                f.severity, "medium",
                "an incomplete local trust store was reported as a medium "
                "target-side defect on a site whose chain is valid",
            )

    def test_no_cwe_295_is_asserted_from_an_environment_failure(self):
        findings = run_probe(BRIEF_LOCAL_TRUST_GAP)
        for f in findings:
            if f.category == "tls":
                self.assertNotEqual(
                    f.cwe, "CWE-295",
                    "CWE-295 (improper certificate validation) describes a "
                    "defect in the CLIENT's verification; the evidence here is "
                    "that the client could not verify at all",
                )

    def test_the_recommendation_is_not_to_fix_the_server(self):
        findings = run_probe(BRIEF_LOCAL_TRUST_GAP)
        for f in findings:
            if f.category == "tls":
                self.assertNotIn(
                    "fix certificate chain", f.recommendation.lower(),
                    "the owner is being told to repair a server that is fine",
                )

    def test_the_finding_states_it_could_not_be_assessed(self):
        findings = run_probe(BRIEF_LOCAL_TRUST_GAP)
        for f in findings:
            if f.category == "tls":
                blob = f"{f.title} {f.detail} {f.recommendation}".lower()
                self.assertTrue(
                    "not_assessed" in blob or "not assessed" in blob
                    or "local trust" in blob or "could not" in blob,
                    "the probe asserts a verdict without saying it could not "
                    "form one",
                )


class TheCollapsedConditionItselfTests(unittest.TestCase):
    """The shipped expression cannot distinguish these cases at all."""

    def test_the_brief_format_never_contains_verify_return_code(self):
        """Why the guard is dead code: -brief does not print that line.

        This used to assert against this file's own string constants, which means
        it could only fail if someone edited the constants -- no production code
        was anywhere on the path, and any mutation of ``_tls_verdict`` left it
        green.  It now drives the real classifier: the D67 expression
        ``A or (B and C)`` looked for a ``Verify return code:`` line that
        ``-brief`` never prints, so C was False for every input and the whole
        expression collapsed to A.  The invariant is that the classifier does not
        *depend* on such a line, which is only observable by feeding it one.
        """
        ws._tls_verdict  # the classifier is the thing under test
        for base in (BRIEF_OK, BRIEF_LOCAL_TRUST_GAP, BRIEF_EXPIRED, BRIEF_HOSTNAME):
            without = ws._tls_verdict(base)
            # openssl's long format does print the line; -brief does not.  If the
            # classifier's answer changes when it is present, it is depending on
            # a line that only one of the two formats produces.
            with_line = ws._tls_verdict(
                base.replace("DONE\n", "Verify return code: 0 (ok)\nDONE\n"))
            self.assertEqual(
                without, with_line,
                f"_tls_verdict classified the same handshake differently "
                f"depending on a 'Verify return code:' line that -brief never "
                f"prints: {without} vs {with_line}",
            )

    def test_the_local_trust_gap_is_classified_cannot_verify_not_peer_defect(self):
        """The consequence the dead guard was hiding, asserted on the classifier."""
        outcome, _ = ws._tls_verdict(BRIEF_LOCAL_TRUST_GAP)
        self.assertEqual(
            outcome, "cannot_verify",
            "a local trust gap is a fact about the scanning host; classifying "
            "it as a peer defect is the D67 false positive",
        )

    def test_a_good_chain_is_not_a_failure(self):
        findings = run_probe(BRIEF_OK)
        for f in findings:
            if f.category == "tls":
                self.assertNotEqual(f.severity, "medium")

    def test_unparseable_verification_is_not_asserted_as_a_defect(self):
        """A blob carrying no numeric code says nothing; the tool must not guess."""
        blob = "CONNECTION ESTABLISHED\nProtocol version: TLSv1.3\nVerification error: something new\nDONE\n"
        findings = run_probe(blob)
        for f in findings:
            if f.category == "tls":
                self.assertNotEqual(
                    f.severity, "medium",
                    "no numeric verification code was present, yet a medium "
                    "target-side defect was asserted",
                )


class RealTargetDefectsStillSurfaceTests(unittest.TestCase):
    """The fix must not silence genuine problems."""

    def test_an_expired_certificate_is_reported(self):
        findings = run_probe(BRIEF_EXPIRED)
        tls = [f for f in findings if f.category == "tls"]
        self.assertEqual(len(tls), 1, "an expired certificate was not reported")
        self.assertEqual(tls[0].severity, "high")
        self.assertIn("expired", f"{tls[0].title}{tls[0].detail}".lower())

    def test_a_hostname_mismatch_is_reported(self):
        findings = run_probe(BRIEF_HOSTNAME)
        tls = [f for f in findings if f.category == "tls"]
        self.assertEqual(len(tls), 1, "a hostname mismatch was not reported")
        self.assertEqual(tls[0].severity, "high")

    def test_a_real_defect_keeps_cwe_295_and_remediation(self):
        findings = run_probe(BRIEF_EXPIRED)
        for f in findings:
            if f.category == "tls":
                self.assertEqual(f.cwe, "CWE-295")
                lowered = f.recommendation.lower()
                self.assertTrue(
                    any(term in lowered for term in
                        ("reissue", "chain", "hostname", "certificate", "protocol")),
                    "a genuine certificate defect was reported with no actionable "
                    "server-side remediation",
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
