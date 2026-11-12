"""D64 -- every distinct advisory is its own vulnerability.

A repository whose requirements.txt pins flask==0.12.2 and requests==2.19.1
produced 12 OSV advisories.  Every layer above the analyzer reported 1.

Two defects compose here:

  * The title of a dependency finding named only the package, so 12 advisories
    for 2 packages produced 2 distinct fingerprints rather than 12.
  * ``_are_similar`` returned True for "same file and line".  A manifest is a
    list, not a line: every entry in requirements.txt shares one file_path, and
    neither dependency scanner sets line_number -- so it was 0 for all of them
    and the condition held for every pair.  Twelve advisories became one.

The reader of a report that says "1 vulnerable dependency" where the scan
found 12 has been told the codebase is eleven vulnerabilities cleaner than it
is.  Under-reporting is the dangerous direction: a maintainer who trusts the
count skips the upgrade that would have removed four of them.

These tests are the specification for the fix.  Offline by construction: the
advisory records are fabricated and the analyzers are stubbed, so the suite
never depends on api.osv.dev answering.
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
    Severity,
    UnifiedFinding,
)
from triagekit.core.scanners.correlation import (  # noqa: E402
    CorrelationEngine,
    FindingDeduplicator,
    advisory_id,
)


# --------------------------------------------------------------------------
# The measured scenario.  Twelve advisories across two packages, one manifest.
# --------------------------------------------------------------------------
FLASK_IDS = [
    "GHSA-9hjg-9r4m-mvj7",
    "GHSA-m2qf-hxjv-5gpq",
    "PYSEC-2019-1",
    "CVE-2019-1010083",
]
REQUESTS_IDS = [
    "GHSA-68rp-wp8r-4726",
    "GHSA-j8r2-6x86-q33q",
    "PYSEC-2018-28",
    "CVE-2018-18074",
    "GHSA-9wx4-h78v-vm56",
    "GHSA-dd4-9fh7-4f2q",
    "CVE-2023-32681",
    "PYSEC-2023-54",
]
ALL_IDS = FLASK_IDS + REQUESTS_IDS
MANIFEST = "requirements.txt"


def advisory(aid: str, package: str) -> dict:
    """One record in the shape scan_dependencies/OSV enrichment produces."""
    return {
        "id": aid,
        "package": package,
        "version": "flask==0.12.2" if package == "flask" else "requests==2.19.1",
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


def run_repo_scanner(advisories: list[dict]) -> list[UnifiedFinding]:
    """Findings exactly as RepositoryScanner builds them.

    The scanner is driven for real against a stubbed ``scan_repository`` so
    the test measures the shape the CLI actually emits, rather than a copy of
    it that can go stale.  The stub is what leaves the network out of it.
    """
    fake = RepoScanResult(
        root="probe",
        files_scanned=1,
        findings=[],
        dependency_files=[MANIFEST],
        cve_findings=advisories,
        summary="probe",
    )
    real = rs.scan_repository
    rs.scan_repository = lambda **kw: fake
    try:
        with TemporaryDirectory() as tmp:
            (Path(tmp) / MANIFEST).write_text("flask==0.12.2\n", encoding="utf-8")
            ctx = ScanContext(target=tmp)
            ctx.config["max_files"] = 100
            ctx.config["max_packages"] = 40
            res = asyncio.run(rs.RepositoryScanner({})._scan(ctx))
    finally:
        rs.scan_repository = real
    return res.findings


def repo_style_findings(advisories: list[dict]) -> list[UnifiedFinding]:
    """Findings exactly as RepositoryScanner emits them."""
    return run_repo_scanner(advisories)


def dep_style_findings(advisories: list[dict]) -> list[UnifiedFinding]:
    """Findings exactly as DependencyScanner builds them."""
    out = []
    for a in advisories:
        out.append(UnifiedFinding(
            scanner_name="dependency_scanner",
            scanner_version="1.0.0",
            scan_type=ScanType.DEPENDENCY_SCAN,
            title=f"{a.get('id', 'CVE')}: {a.get('package', 'unknown')}",
            description=a.get("summary", ""),
            severity=Severity.HIGH,
            category="vulnerable-dependency",
            file_path=a.get("manifest"),
            recommendation=f"Upgrade {a.get('package')} to {a.get('fixed')}",
            scanner_metadata={
                "package": a.get("package"),
                "advisory_id": a.get("id"),
            },
        ))
    return out


class AdvisoryIdentityTests(unittest.TestCase):
    """A distinct advisory is a distinct vulnerability, whatever the manifest."""

    def test_twelve_distinct_advisories_all_survive_dedup(self):
        kept = FindingDeduplicator().deduplicate(repo_style_findings(all_advisories()))
        self.assertEqual(
            len(kept), 12,
            f"12 distinct advisories on one manifest collapsed to {len(kept)}; "
            "each one is a separate vulnerability the reader must be told about",
        )

    def test_eight_advisories_for_one_package_all_survive(self):
        kept = FindingDeduplicator().deduplicate(
            repo_style_findings([advisory(i, "requests") for i in REQUESTS_IDS])
        )
        self.assertEqual(
            len(kept), len(REQUESTS_IDS),
            f"{len(REQUESTS_IDS)} advisories for one package collapsed to {len(kept)}",
        )

    def test_dep_title_format_survives_too(self):
        kept = FindingDeduplicator().deduplicate(dep_style_findings(all_advisories()))
        self.assertEqual(
            len(kept), 12,
            f"the '<id>: <package>' title format also collapsed 12 to {len(kept)}",
        )

    def test_two_findings_on_one_manifest_are_not_similar(self):
        dedup = FindingDeduplicator()
        f1, f2 = dep_style_findings(all_advisories())[:2]
        self.assertFalse(
            dedup._are_similar(f1, f2),
            f"{f1.scanner_metadata['advisory_id']} and "
            f"{f2.scanner_metadata['advisory_id']} are two different advisories "
            "and were treated as the same finding",
        )

    def test_the_same_advisory_twice_is_still_one_finding(self):
        """Genuine duplicates must still collapse -- the fix must not over-correct."""
        a = advisory("GHSA-68rp-wp8r-4726", "requests")
        dup = repo_style_findings([a, a])
        kept = FindingDeduplicator().deduplicate(dup)
        self.assertEqual(
            len(kept), 1,
            "the same advisory reported twice was kept twice, which is now the "
            "opposite failure",
        )

    def test_the_same_advisory_id_across_scanners_is_not_fuzzy_merged(self):
        """Cross-scanner reports of one advisory must not be reported twice.

        ``_are_similar`` already declines when the scanners differ; the
        correlation engine relies on that.  This test exists so the D64 fix
        cannot satisfy the tests above by making every cross-scanner pair
        dissimilar in a way that also breaks this one.
        """
        a = advisory("GHSA-68rp-wp8r-4726", "requests")
        f1 = repo_style_findings([a])[0]
        f2 = dep_style_findings([a])[0]
        self.assertFalse(
            FindingDeduplicator()._are_similar(f1, f2),
            "cross-scanner reports must not be fuzzy-merged into one finding; "
            "correlation needs both",
        )

    def test_a_merge_still_records_what_was_merged(self):
        """When the engine does merge, the merged finding must name the rest.

        A count that fell from 12 to 1 with no record of the other 11 is
        indistinguishable from a scan that only ever found 1.  The case that
        legitimately merges is the same advisory reported twice.
        """
        a = advisory("GHSA-68rp-wp8r-4726", "requests")
        kept = FindingDeduplicator().deduplicate(repo_style_findings([a, a]))
        self.assertEqual(len(kept), 1, "a genuine duplicate was not merged")
        self.assertTrue(
            kept[0].correlated_findings,
            "the merged finding does not record the duplicate it absorbed, so "
            "a reader cannot tell 2 reports of 1 advisory from 1 report",
        )

    def test_every_distinct_advisory_is_a_separate_finding(self):
        """The headline property: 12 advisories produce 12 findings.

        Stated on its own because it is the whole defect -- every other test
        here exists to keep this one from being satisfied by accident.
        """
        kept = FindingDeduplicator().deduplicate(repo_style_findings(all_advisories()))
        shipped = {advisory_id(f) for f in kept}
        self.assertEqual(
            len(shipped), 12,
            f"{12 - len(shipped)} advisories are missing from the report; only "
            f"{sorted(shipped)} survived",
        )


class CorrelationEngineTests(unittest.TestCase):
    """The engine the CLI actually runs must not drop advisories either."""

    def test_engine_keeps_every_advisory(self):
        result = ScanResult(
            scanner_name="repository_scanner",
            scanner_version="2.0.0",
            scan_type=ScanType.REPOSITORY_SCAN,
            target="probe",
        )
        for f in repo_style_findings(all_advisories()):
            result.add_finding(f)
        self.assertEqual(len(result.findings), 12)

        CorrelationEngine().process([result])

        self.assertEqual(
            len(result.findings), 12,
            f"the correlation engine left {len(result.findings)} of 12 advisories",
        )

    def test_engine_summary_matches_the_findings_it_kept(self):
        result = ScanResult(
            scanner_name="repository_scanner",
            scanner_version="2.0.0",
            scan_type=ScanType.REPOSITORY_SCAN,
            target="probe",
        )
        for f in repo_style_findings(all_advisories()):
            result.add_finding(f)
        out = CorrelationEngine().process([result])
        self.assertEqual(
            out["summary"]["total_findings"],
            12,
            "the summary the CLI prints does not describe the findings that exist",
        )


class TitleTests(unittest.TestCase):
    """The finding title must name the advisory, not just the package."""

    def _run_repo_scanner(self, advisories: list[dict]) -> list[UnifiedFinding]:
        return run_repo_scanner(advisories)

    def test_repository_scanner_titles_carry_the_advisory_id(self):
        findings = self._run_repo_scanner(all_advisories())
        dep = [f for f in findings if f.category == "vulnerable-dependency"]
        self.assertEqual(len(dep), 12, f"repository_scanner emitted {len(dep)} findings")
        for f in dep:
            aid = f.scanner_metadata.get("advisory_id")
            self.assertTrue(
                aid and aid in f.title,
                f"finding titled {f.title!r} does not name its advisory {aid!r}; "
                "two advisories for one package then share a fingerprint",
            )

    def test_dependency_scanner_titles_carry_the_advisory_id(self):
        real = dep_mod.scan_dependencies
        dep_mod.scan_dependencies = lambda *a, **kw: (all_advisories(), {})
        try:
            with TemporaryDirectory() as tmp:
                (Path(tmp) / MANIFEST).write_text("flask==0.12.2\n", encoding="utf-8")
                ctx = ScanContext(target=tmp)
                ctx.metadata["manifest_files"] = [MANIFEST]
                ctx.config["max_packages"] = 40
                res = asyncio.run(dep_mod.DependencyScanner({})._scan(ctx))
        finally:
            dep_mod.scan_dependencies = real
        dep = [f for f in res.findings if f.category == "vulnerable-dependency"]
        self.assertEqual(len(dep), 12)
        for f in dep:
            aid = f.scanner_metadata.get("advisory_id")
            self.assertTrue(aid and aid in f.title, f"{f.title!r} omits {aid!r}")

    def test_manifest_is_not_treated_as_a_line(self):
        """A manifest entry has no meaningful line number; it must not be 0-meaning.

        The defect is that line_number == 0 for every entry, which made
        'same file and line' true for all of them.  Either the entry carries
        its real manifest line, or the identity rests on the advisory id.
        """
        findings = self._run_repo_scanner(all_advisories())
        dep = [f for f in findings if f.category == "vulnerable-dependency"]
        ids = [f.scanner_metadata.get("advisory_id") for f in dep]
        self.assertEqual(len(set(ids)), len(ids), "advisories collapsed on the manifest path")


if __name__ == "__main__":
    unittest.main(verbosity=2)
