"""D66 -- a pin in a second manifest is a second place to fix.

Two manifests can declare the same package at the same version:

    requirements.txt          flask==0.12.2
    sub/requirements.txt      flask==0.12.2

``scan_dependencies`` deduplicates packages before querying OSV, which is
right -- the same package at the same version answers with the same
advisories, and spending the package budget and a network call twice buys
nothing.  But the deduplication dropped the *second manifest* with it, and
the coverage section reported nothing about it::

    manifests discovered : ['requirements.txt', 'sub/requirements.txt']
    packages_resolved    : 1
    manifests_unparsed   : []
    packages_skipped_over_cap : 0

The reader is told the scan was complete.  They upgrade the one manifest the
report names, redeploy, and the vulnerable pin is still live in the other.
Every advisory pointed at a location that had been fixed, and the actual
exposure was never stated.

The fix keeps one finding per advisory -- one vulnerability, not two -- and
names every manifest that pins it, so the remediation step is complete.  A
new coverage counter records the replicated packages, because "I found this
in more than one place" is a fact the scan knows and the reader needs.

Offline: the OSV lookup is stubbed.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import sys

REPO = Path(__file__).resolve().parent.parent
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

import triagekit.core.analyzers.cve as cve_mod  # noqa: E402
from triagekit.core.analyzers.repo_scan import scan_repository  # noqa: E402

MANIFESTS = ["requirements.txt", "sub/requirements.txt"]


def two_manifests(root: Path) -> None:
    (root / "requirements.txt").write_text("flask==0.12.2\n", encoding="utf-8")
    (root / "sub").mkdir()
    (root / "sub" / "requirements.txt").write_text("flask==0.12.2\n", encoding="utf-8")


class StubbedOsv:
    """Records what OSV was asked, and answers with fixed advisories."""

    def __init__(self):
        self.queries: list[tuple[str, str, str]] = []
        self._real = cve_mod.query_osv

    def __enter__(self):
        def fake(name, version, ecosystem):
            self.queries.append((name, version, ecosystem))
            return [
                {
                    "id": f"GHSA-0000-0000-{n:04d}",
                    "package": name,
                    "version": version,
                    "ecosystem": ecosystem,
                    "severity": "HIGH",
                    "summary": f"{name} {version} is affected.",
                    "fixed": "2.0.0",
                }
                for n in range(4)
            ]
        cve_mod.query_osv = fake
        return self

    def __exit__(self, *exc):
        cve_mod.query_osv = self._real
        return False


class EveryManifestIsNamedTests(unittest.TestCase):
    """An advisory must name every manifest that pins the package."""

    def test_a_pin_in_two_manifests_is_named_in_both(self):
        with StubbedOsv(), TemporaryDirectory() as tmp:
            root = Path(tmp)
            two_manifests(root)
            findings, stats = cve_mod.scan_dependencies(root, MANIFESTS)
        self.assertEqual(len(findings), 4, "advisories were multiplied per manifest")
        for f in findings:
            named = f.get("manifests") or [f.get("manifest")]
            self.assertEqual(
                sorted(named), sorted(MANIFESTS),
                f"advisory {f.get('id')} names {named}; the maintainer must "
                f"upgrade {MANIFESTS[1]} too and was not told",
            )

    def test_the_second_manifest_is_not_reported_as_clean(self):
        """The coverage section must state what it deduplicated."""
        with StubbedOsv(), TemporaryDirectory() as tmp:
            root = Path(tmp)
            two_manifests(root)
            findings, stats = cve_mod.scan_dependencies(root, MANIFESTS)
        self.assertNotEqual(
            stats.get("packages_duplicated_across_manifests", 0), 0,
            "a package pinned in 2 manifests was deduplicated with no record "
            "of it, so the coverage section reads as complete",
        )

    def test_the_package_budget_is_not_spent_twice(self):
        """The fix must not turn one dedup into two OSV calls."""
        with StubbedOsv() as stub, TemporaryDirectory() as tmp:
            root = Path(tmp)
            two_manifests(root)
            cve_mod.scan_dependencies(root, MANIFESTS)
        self.assertEqual(
            len(stub.queries), 1,
            f"the same package at the same version was queried "
            f"{len(stub.queries)} times",
        )

    def test_two_distinct_versions_are_both_queried(self):
        """Manifest replication is not the same as version replication."""
        with StubbedOsv() as stub, TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text(
                "flask==0.12.2\nflask==1.0\n", encoding="utf-8"
            )
            findings, stats = cve_mod.scan_dependencies(root, ["requirements.txt"])
        self.assertEqual(len(stub.queries), 2, f"queried {stub.queries}")
        self.assertEqual(len(findings), 8, f"{len(findings)} advisories for 2 versions")


class ReportLevelTests(unittest.TestCase):
    """The god-mode report must carry the same fact."""

    def test_scan_repository_names_every_manifest(self):
        with StubbedOsv(), TemporaryDirectory() as tmp:
            root = Path(tmp)
            two_manifests(root)
            result = scan_repository(root)
        self.assertEqual(len(result.cve_findings), 4)
        for f in result.cve_findings:
            named = f.get("manifests") or [f.get("manifest")]
            self.assertEqual(
                sorted(named), sorted(MANIFESTS),
                f"the repo report names {named} for {f.get('id')}",
            )

    def test_the_report_states_the_coverage_fact(self):
        """A reader of the markdown must not be left to assume completeness."""
        with StubbedOsv(), TemporaryDirectory() as tmp:
            root = Path(tmp)
            two_manifests(root)
            result = scan_repository(root)
            md = result.to_markdown()
        self.assertTrue(
            "more than one manifest" in md,
            "the report does not mention that a package was pinned in more "
            "than one manifest",
        )


class AdverseTests(unittest.TestCase):
    """The new attribution must not fire where it has no business."""

    def test_a_single_manifest_names_only_itself(self):
        with StubbedOsv(), TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text("flask==0.12.2\n", encoding="utf-8")
            findings, stats = cve_mod.scan_dependencies(root, ["requirements.txt"])
        for f in findings:
            named = f.get("manifests") or [f.get("manifest")]
            self.assertEqual(named, ["requirements.txt"])

    def test_distinct_packages_in_distinct_manifests_are_separate(self):
        with StubbedOsv() as stub, TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text("flask==0.12.2\n", encoding="utf-8")
            (root / "sub").mkdir()
            (root / "sub" / "requirements.txt").write_text(
                "requests==2.19.1\n", encoding="utf-8"
            )
            findings, stats = cve_mod.scan_dependencies(root, MANIFESTS)
        self.assertEqual(len(stub.queries), 2)
        self.assertEqual(len(findings), 8)
        self.assertEqual(
            stats.get("packages_duplicated_across_manifests", 0), 0,
            "distinct packages were counted as duplicated",
        )
        by_pkg = {}
        for f in findings:
            by_pkg.setdefault(f["package"], f.get("manifests") or [f.get("manifest")])
        self.assertEqual(by_pkg["flask"], ["requirements.txt"])
        self.assertEqual(by_pkg["requests"], ["sub/requirements.txt"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
