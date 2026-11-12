"""D84 -- a web scan that never reached the site reported grade A.

Found while re-verifying the UI end to end (two repo scans and two web scans in
one server process).  Pointing `/api/webscan` at a host nothing was listening on
returned::

    ok=True  score=91.0  grade=A  critical=0  endpoints=0  status_code=0

The scan had assessed nothing.  `WebScanResult` opens with
``score: float = 100.0, grade: str = "A"``, and `compute_score` derives the grade
purely from the finding penalty -- so the single HIGH "Connection failed" (weight
9, confidence 1.0) left 91 points and printed **A**.

That is the worst direction for a false answer.  A pentester who mistypes a host,
or scans a site during an outage, is handed a clean bill of health for a target no
request ever touched -- and a clean bill of health is the one result that gets
filed without a second look.  An overstated F would also be wrong; the truthful
answer is "not assessed", which the project rules already require
(`dev/AUTONOMOUS_TODO.md` §D: missing evidence is reported as NOT_ASSESSED, never
fabricated).

The fix: when nothing was assessed -- no HTTP traces, no endpoints, no status
code -- the grade is ``N``, the score is 0.0, and the summary leads with the
reason.  ``F`` was deliberately not used: the reader must be able to tell "this
site is badly broken" from "we never got an answer", and a letter that means both
means neither.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from triagekit.core.analyzers import web_scan as ws  # noqa: E402


def _unreachable_result() -> ws.WebScanResult:
    """The shape scan_website returns when the root GET never completes."""
    result = ws.WebScanResult(url="http://127.0.0.1:9")
    result.findings = [
        ws.WebFinding(
            "high", "availability", "Connection failed", "[Errno 111] refused",
            "Verify DNS/TLS and allowlisting.", cwe="CWE-754", confidence="high",
        )
    ]
    result.compute_score()
    return result


class UnassessedIsNotHealthyTests(unittest.TestCase):
    """The grade must not claim health for a scan that assessed nothing."""

    def test_an_unreachable_target_is_not_grade_a(self) -> None:
        result = _unreachable_result()
        self.assertEqual(result.grade, "N",
                         f"an unreachable target graded {result.grade}")
        self.assertEqual(result.score, 0.0,
                         "a score was invented for a scan with no evidence")

    def test_the_summary_states_nothing_was_assessed(self) -> None:
        summary = _unreachable_result().summary
        self.assertIn("NOT ASSESSED", summary)
        # ...and it must not read as a health statement anywhere.
        self.assertNotIn("grade A", summary)
        self.assertNotIn("Security adviser score 9", summary)

    def test_the_markdown_does_not_print_a_health_verdict(self) -> None:
        md = _unreachable_result().to_markdown()
        self.assertIn("0.0/100 (N)", md)
        self.assertIn("NOT ASSESSED", md)
        # The old report line said "Score: 91.0/100 (A)".
        self.assertNotIn("91.0/100 (A)", md)

    def test_a_reachable_scan_still_uses_the_a_to_f_bands(self) -> None:
        """The fix must not flatten real results."""
        result = ws.WebScanResult(url="https://example.com", status_code=200)
        result.network = [{"method": "GET", "url": "https://example.com",
                           "status": 200}]
        result.endpoints = [{"path": "/"}]
        result.compute_score()
        self.assertIn(result.grade, ("A", "B", "C", "D", "F"),
                      f"a live scan graded outside the bands: {result.grade}")

    def test_one_trace_alone_is_enough_to_be_an_assessment(self) -> None:
        """A site that answered exactly one request was reached."""
        result = ws.WebScanResult(url="https://example.com", status_code=403)
        result.network = [{"method": "GET", "status": 403}]
        result.compute_score()
        self.assertNotEqual(result.grade, "N")
        self.assertGreater(result.score, 0.0)

    def test_a_clean_scan_is_still_grade_a(self) -> None:
        """No findings on a live site is an A -- the point of the tool."""
        result = ws.WebScanResult(url="https://example.com", status_code=200)
        result.network = [{"method": "GET", "status": 200}]
        result.endpoints = [{"path": "/"}]
        result.findings = []
        result.compute_score()
        self.assertEqual((result.score, result.grade), (100.0, "A"))


if __name__ == "__main__":
    unittest.main()
