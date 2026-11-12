"""D65 -- one advisory is one vulnerability, however many scanners found it.

repository_scanner and dependency_scanner both query OSV and both emit a
finding per advisory.  Deduplication ran inside each ScanResult separately, so
nothing ever compared the two, and a repository with 12 advisories produced 24
findings.  The machine-readable payload then reported::

    "cve_findings": [ ... 24 entries ... ]

where there were 12.  A consumer that counts that list -- a CI gate, a
dashboard, a triage queue -- concludes the codebase carries twice the
vulnerabilities it does, and every remediation ticket is duplicated.

Fixing D64 (distinct advisories collapsing into one) is what made this
visible: before, both scanners emitted 1 and the payload carried 2 entries for
1 advisory, which read as a rounding error rather than a rule.

The fold is corroboration, not a discard.  The surviving finding records which
other scanners found the same advisory, so the report can say the dedicated
SCA scanner and the god-mode repo scanner agree.
"""

from __future__ import annotations

import asyncio
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import sys

REPO = Path(__file__).resolve().parent.parent
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

from triagekit.core.analyzers.repo_scan import RepoScanResult  # noqa: E402
from triagekit.core.scanners import dependency_scanner as dep_mod  # noqa: E402
from triagekit.core.scanners import repo_scanner as rs  # noqa: E402
from triagekit.core.scanners.base import (  # noqa: E402
    ScanContext,
    ScanResult,
    ScanType,
)
from triagekit.core.scanners.correlation import (  # noqa: E402
    CorrelationEngine,
    advisory_id,
)

MANIFEST = "requirements.txt"
FLASK_IDS = ["GHSA-9hjg-9r4m-mvj7", "GHSA-m2qf-hxjv-5gpq", "PYSEC-2023-62", "PYSEC-2026-2151"]
REQUESTS_IDS = [
    "GHSA-68rp-wp8r-4726", "GHSA-9wx4-h78v-vm56", "GHSA-gc5v-m9x4-r6x2",
    "GHSA-j8r2-6x86-q33q", "PYSEC-2023-74", "PYSEC-2026-1872",
    "PYSEC-2026-1873", "PYSEC-2026-2275",
]
ALL_IDS = FLASK_IDS + REQUESTS_IDS


def advisory(aid: str, package: str) -> dict:
    return {
        "id": aid,
        "package": package,
        "version": f"{package}==0.12.2" if package == "flask" else f"{package}==2.19.1",
        "fixed": "1.0" if package == "flask" else "2.20.0",
        "severity": "HIGH",
        "summary": f"{aid} affects {package}.",
        "manifest": MANIFEST,
        "ecosystem": "PyPI",
        "cwes": ["CWE-502"],
        "aliases": [],
    }


def all_advisories() -> list[dict]:
    out = [advisory(i, "flask") for i in FLASK_IDS]
    out += [advisory(i, "requests") for i in REQUESTS_IDS]
    return out


def repo_scan_result() -> ScanResult:
    """The ScanResult RepositoryScanner produces for the same advisories."""
    fake = RepoScanResult(
        root="probe", files_scanned=1, findings=[],
        dependency_files=[MANIFEST], cve_findings=all_advisories(), summary="probe",
    )
    real = rs.scan_repository
    rs.scan_repository = lambda **kw: fake
    try:
        with TemporaryDirectory() as tmp:
            (Path(tmp) / MANIFEST).write_text("flask==0.12.2\n", encoding="utf-8")
            ctx = ScanContext(target=tmp)
            ctx.config["max_files"] = 100
            ctx.config["max_packages"] = 40
            return asyncio.run(rs.RepositoryScanner({})._scan(ctx))
    finally:
        rs.scan_repository = real


def dep_scan_result() -> ScanResult:
    """The ScanResult DependencyScanner produces for the same advisories."""
    real = dep_mod.scan_dependencies
    dep_mod.scan_dependencies = lambda *a, **kw: (all_advisories(), {})
    try:
        with TemporaryDirectory() as tmp:
            (Path(tmp) / MANIFEST).write_text("flask==0.12.2\n", encoding="utf-8")
            ctx = ScanContext(target=tmp)
            ctx.metadata["manifest_files"] = [MANIFEST]
            ctx.config["max_packages"] = 40
            return asyncio.run(dep_mod.DependencyScanner({})._scan(ctx))
    finally:
        dep_mod.scan_dependencies = real


def run_both_scanners() -> list[ScanResult]:
    return [repo_scan_result(), dep_scan_result()]


class OneAdvisoryOneFindingTests(unittest.TestCase):
    """Two scanners, one advisory, one finding."""

    def test_the_same_advisory_is_not_reported_by_two_scanners(self):
        results = run_both_scanners()
        CorrelationEngine().process(results)
        all_dep = [f for r in results for f in r.findings if f.category == "vulnerable-dependency"]
        ids = [advisory_id(f) for f in all_dep]
        distinct = {i for i in ids if i}
        self.assertEqual(
            len(all_dep), len(distinct),
            f"{len(all_dep)} findings carry only {len(distinct)} advisories; "
            "the same vulnerability is being counted once per scanner",
        )

    def test_twelve_advisories_from_two_scanners_become_twelve_findings(self):
        results = run_both_scanners()
        out = CorrelationEngine().process(results)
        self.assertEqual(
            out["summary"]["total_findings"], 12,
            f"two scanners reporting 12 advisories produced "
            f"{out['summary']['total_findings']} findings",
        )

    def test_payload_cve_findings_has_one_entry_per_advisory(self):
        """The list the CLI and --json consumers actually read."""
        results = run_both_scanners()
        CorrelationEngine().process(results)
        # This is cli.py's collection rule verbatim.
        cve_findings = [f for r in results for f in r.findings if f.category == "vulnerable-dependency"]
        ids = {advisory_id(f) for f in cve_findings}
        self.assertEqual(
            len(cve_findings), len(ids),
            f"cve_findings lists {len(cve_findings)} entries for {len(ids)} advisories",
        )

    def test_the_fold_records_the_other_scanner_as_corroboration(self):
        """A fold must not be a silent discard."""
        results = run_both_scanners()
        CorrelationEngine().process(results)
        survivors = [f for r in results for f in r.findings if f.category == "vulnerable-dependency"]
        confirming = [f for f in survivors if f.scanner_metadata.get("corroborated_by")]
        self.assertTrue(
            confirming,
            "advisories were folded across scanners but no surviving finding "
            "records which scanner agreed with it",
        )

    def test_genuinely_distinct_advisories_are_not_folded_by_the_same_rule(self):
        """The cross-scanner fold must not re-introduce the D64 collapse."""
        results = run_both_scanners()
        CorrelationEngine().process(results)
        survivors = [f for r in results for f in r.findings if f.category == "vulnerable-dependency"]
        self.assertEqual(len(survivors), 12, f"only {len(survivors)} of 12 advisories survived")


class AdverseTests(unittest.TestCase):
    """The fold must not fire where it has no business."""

    def test_one_scanner_alone_keeps_every_advisory(self):
        result = repo_scan_result()
        out = CorrelationEngine().process([result])
        self.assertEqual(out["summary"]["total_findings"], 12)

    def test_non_dependency_findings_are_never_folded_by_this_rule(self):
        from triagekit.core.scanners.base import Severity, UnifiedFinding
        findings = [
            UnifiedFinding(
                scanner_name="repository_scanner", scanner_version="2.0.0",
                scan_type=ScanType.REPOSITORY_SCAN, title="SQL injection in app.py",
                description="x", severity=Severity.HIGH, category="sql-injection",
                file_path="app.py", line_number=10, layer="regex",
            ),
            UnifiedFinding(
                scanner_name="heuristic_security", scanner_version="1.0.0",
                scan_type=ScanType.STATIC_ANALYSIS, title="SQL injection in app.py",
                description="x", severity=Severity.HIGH, category="sql-injection",
                file_path="app.py", line_number=10, layer="regex",
            ),
        ]
        result = ScanResult(
            scanner_name="repository_scanner", scanner_version="2.0.0",
            scan_type=ScanType.REPOSITORY_SCAN, target="probe",
        )
        for f in findings:
            result.add_finding(f)
        out = CorrelationEngine().process([result])
        self.assertEqual(
            out["summary"]["total_findings"], 2,
            "the advisory fold reached non-dependency findings",
        )

    def test_an_advisory_without_an_id_is_not_folded_away(self):
        """An unidentifiable advisory cannot be shown to be a duplicate.

        Three generations of this test were wrong, in three different ways, and
        each was found by mutation rather than by inspection:

        1. It asserted ``out["summary"]["total_findings"] == len(dep)`` where
           ``dep`` filtered the same result for the same category.  Every finding
           in that result is a dependency finding, so the two sides are equal by
           construction and the assertion cannot fail.
        2. It then gave the two advisories identical text, so
           ``compute_fingerprint`` gave them the same fingerprint and
           ``FindingDeduplicator`` merged them into one *before*
           ``_fold_duplicate_advisories`` ran.  The fold was never on the path.
        3. The version that fixed both also dropped the ``CorrelationEngine``
           call entirely, so the fold still was not on the path.

        This one runs the real pipeline and asserts on what survives it.  The
        mutation that has to kill it is the reviewer's: delete ``if not aid:
        continue`` in ``_fold_duplicate_advisories`` and coerce the missing id
        to ``""``, so the group key becomes the package name alone.  Then these
        two advisories collapse to one and ``surviving`` is 1, not 2.
        """
        advisories = [
            {"id": None, "package": "flask", "severity": "HIGH",
             "manifest": MANIFEST, "summary": "first unidentifiable advisory"},
            {"id": None, "package": "flask", "severity": "HIGH",
             "manifest": MANIFEST, "summary": "second unidentifiable advisory"},
        ]
        fake = RepoScanResult(
            root="probe", files_scanned=1, findings=[],
            dependency_files=[MANIFEST], summary="probe",
            cve_findings=advisories,
        )
        real = rs.scan_repository
        rs.scan_repository = lambda **kw: fake
        try:
            with TemporaryDirectory() as tmp:
                (Path(tmp) / MANIFEST).write_text("flask\n", encoding="utf-8")
                ctx = ScanContext(target=tmp)
                ctx.config["max_packages"] = 40
                result = asyncio.run(rs.RepositoryScanner({})._scan(ctx))
        finally:
            rs.scan_repository = real

        # Both advisories must be distinguishable before the pipeline is even
        # invoked, or the deduplicator merges them for a reason that has nothing
        # to do with the fold.  Distinct summaries must therefore survive into
        # the title, which is what ``compute_fingerprint`` reads.
        titles = {f.title for f in result.findings}
        self.assertEqual(
            len(titles), len(advisories),
            "two advisories with different summaries produced the same title; "
            "the fingerprint is computed from the title, so the deduplicator "
            "will merge them before the fold is reached",
        )

        CorrelationEngine().process([result])
        surviving = [f for f in result.findings if f.category == "vulnerable-dependency"]
        self.assertEqual(
            len(surviving), len(advisories),
            "two advisories for one package were folded away on the package "
            "name alone -- an advisory with no id cannot be shown to be a "
            "duplicate of anything",
        )

    def test_two_identifiable_advisories_for_one_package_are_both_kept(self):
        """The fold must not become an over-exclusion either.

        Same package, different advisory ids -- the guard is ``not aid``, so both
        must survive.  This is the mirror of the test above: together they pin
        the fold to *identity*, excluding neither "no id" nor "two ids".
        """
        advisories = [
            {"id": "GHSA-aaaa", "package": "flask", "severity": "HIGH",
             "manifest": MANIFEST, "summary": "advisory A"},
            {"id": "GHSA-bbbb", "package": "flask", "severity": "HIGH",
             "manifest": MANIFEST, "summary": "advisory B"},
        ]
        fake = RepoScanResult(
            root="probe", files_scanned=1, findings=[],
            dependency_files=[MANIFEST], summary="probe",
            cve_findings=advisories,
        )
        real = rs.scan_repository
        rs.scan_repository = lambda **kw: fake
        try:
            with TemporaryDirectory() as tmp:
                (Path(tmp) / MANIFEST).write_text("flask\n", encoding="utf-8")
                ctx = ScanContext(target=tmp)
                ctx.config["max_packages"] = 40
                result = asyncio.run(rs.RepositoryScanner({})._scan(ctx))
        finally:
            rs.scan_repository = real
        dep = [f for f in result.findings if f.category == "vulnerable-dependency"]
        self.assertEqual(
            len(dep), len(advisories),
            "two distinct advisories for the same package were folded into one",
        )

    def test_an_advisory_finding_carries_a_rule_id(self):
        """Every advisory row must show a rule, like every other row.

        ``UnifiedFinding`` has no ``rule_id`` field -- Pydantic silently drops
        the kwarg -- so the rule id travels in ``scanner_metadata``, which is
        where cli.py's --json payload and the web-UI both read it from.  The
        CVE branch of ``_convert_findings`` never set it, so every advisory row
        rendered with a null rule while static-analysis rows had one.
        """
        fake = RepoScanResult(
            root="probe", files_scanned=1, findings=[],
            dependency_files=[MANIFEST], summary="probe",
            cve_findings=[
                {"id": "GHSA-aaaa", "package": "flask", "severity": "HIGH",
                 "manifest": MANIFEST, "summary": "advisory A"},
            ],
        )
        real = rs.scan_repository
        rs.scan_repository = lambda **kw: fake
        try:
            with TemporaryDirectory() as tmp:
                (Path(tmp) / MANIFEST).write_text("flask\n", encoding="utf-8")
                ctx = ScanContext(target=tmp)
                ctx.config["max_packages"] = 40
                result = asyncio.run(rs.RepositoryScanner({})._scan(ctx))
        finally:
            rs.scan_repository = real
        rules = [f.scanner_metadata.get("rule_id") for f in result.findings
                 if f.category == "vulnerable-dependency"]
        self.assertTrue(rules, "no dependency findings were produced")
        self.assertTrue(
            all(rules),
            f"an advisory finding carries no rule id: {rules}",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
