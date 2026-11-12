"""Tests for the vulnerability-intelligence layer (T11).

The layer's job: turn a bare "this dependency has a CVE" into a finding a third
party can act on -- the weakness it is (CWE), how severe (CVSS, via the FIRST.org
calculator rather than a number this tool invents), and where public attack
material for it is documented (NVD, ExploitDB, Rapid7).

The contract, in priority order:

1.  An enriched intel is self-consistent on *every* construction path.  Only
    ``enrich_osv_record`` used to fill the derived fields, so an object built
    directly silently lost its exploit references and its CVSS link.
2.  Generated exploit-database searches are terms a reviewer would actually
    type.  They are search URLs, never module content: nothing is fetched or
    executed.
3.  Nothing is claimed that was not measured.  An absent CVSS vector stays
    absent; an unknown weakness class does not get an invented impact.
4.  The scanner puts this on the finding, not in a module nobody imports.
"""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from triagekit.core.analyzers import cve as cve_mod
from triagekit.core.analyzers.cve import query_osv
from triagekit.core.analyzers.vuln_intel import (
    VulnIntel,
    calculator_link,
    cwe_guidance,
    cvss_version,
    enrich_osv_record,
    intel_markdown,
    metasploit_links,
    parse_cvss_vector,
    reference_links,
)
from triagekit.core.scanners import dependency_scanner as dep_mod
from triagekit.core.scanners.base import ScanContext
from triagekit.core.scanners.dependency_scanner import DependencyScanner

VEC4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"


def _record(**overrides) -> dict:
    """A dependency-scan advisory record as query_osv() returns one."""
    base = {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "package": "log4j-core",
        "version": "2.14.1",
        "ecosystem": "Maven",
        "summary": "remote code execution",
        "severity": "critical",
        "fixed": "2.15.0",
        "cvss_vector": VEC4,
        "aliases": ["CVE-2021-44228"],
        "cwes": ["CWE-502"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        "manifest": "pom.xml",
    }
    base.update(overrides)
    return base


class SelfConsistencyTests(unittest.TestCase):
    """The gap that started this work: derived fields on every path."""

    def test_a_directly_constructed_intel_carries_its_exploit_references(self) -> None:
        intel = VulnIntel(package="flask", version="2.0.1", ecosystem="PyPI",
                          aliases=["CVE-2023-0001"], cve_ids=["CVE-2023-0001"],
                          cwe_ids=["CWE-79"])
        self.assertTrue(intel.exploitdb_queries, "no ExploitDB terms when built directly")
        self.assertTrue(intel.metasploit_queries, "no Metasploit terms when built directly")

    def test_a_directly_constructed_intel_carries_its_cvss_link(self) -> None:
        intel = VulnIntel(package="flask", version="2.0.1", ecosystem="PyPI",
                          cvss_vector=VEC4)
        self.assertIsNotNone(intel.cvss_link)
        self.assertIn(VEC4, intel.cvss_link or "")

    def test_a_known_class_gets_a_derived_vector_and_it_is_labelled(self) -> None:
        # A derived vector is useful, but only if the reader is told it was
        # not measured -- otherwise it reads as the advisory's own score.
        intel = VulnIntel(package="x", version=None, ecosystem="PyPI", cwe_ids=["CWE-89"])
        self.assertEqual(intel.cvss_source, "derived")
        self.assertIsNotNone(intel.cvss_vector)
        self.assertIsNotNone(intel.cvss_link)

    def test_no_class_means_no_derived_vector(self) -> None:
        intel = VulnIntel(package="x", version=None, ecosystem="PyPI")
        self.assertIsNone(intel.cvss_vector)
        self.assertIsNone(intel.cvss_link)
        self.assertEqual(intel.cvss_source, "none")


class SearchTermTests(unittest.TestCase):
    """Generated searches must be terms a reviewer would type."""

    def test_terms_are_not_metasploit_module_paths(self) -> None:
        # The table once held "auxiliary/scanner/http/" and an invented
        # "exploits/*/sqlmap_style_param_probes"; as a search query those match
        # nothing, so the capability was reachable but useless.
        intel = enrich_osv_record(_record())
        for term in intel.metasploit_queries + intel.exploitdb_queries:
            self.assertNotIn("*", term, f"{term!r} is a glob, not a search term")
            self.assertNotRegex(term, r"^(auxiliary|exploits|payloads)/",
                                f"{term!r} is a module path, not a search term")

    def test_the_cve_is_the_most_specific_exploitdb_term(self) -> None:
        intel = enrich_osv_record(_record())
        self.assertEqual(intel.exploitdb_queries[0], "CVE-2021-44228")

    def test_the_versioned_product_is_the_exploitdb_fallback(self) -> None:
        intel = enrich_osv_record(_record(aliases=[], cve_ids=None))
        self.assertIn("log4j-core 2.14.1", intel.exploitdb_queries)

    def test_the_class_vocabulary_matches_the_weakness(self) -> None:
        cases = {
            "CWE-89": "SQL injection",
            "CWE-78": "command execution",
            "CWE-79": "cross-site scripting",
            "CWE-502": "deserialization",
            "CWE-22": "path traversal",
            "CWE-918": "server-side request forgery",
        }
        for cwe, needle in cases.items():
            with self.subTest(cwe=cwe):
                intel = VulnIntel(package="libx", version=None, ecosystem="PyPI",
                                  cwe_ids=[cwe])
                self.assertIn(needle.lower(), intel.metasploit_queries[0].lower())

    def test_an_unknown_class_claims_no_impact(self) -> None:
        # Inventing "remote code execution" for an unclassified weakness
        # asserts an impact nobody measured.
        for cwes in ([], ["CWE-9999"]):
            with self.subTest(cwes=cwes):
                intel = VulnIntel(package="libx", version=None, ecosystem="PyPI",
                                  cwe_ids=cwes)
                self.assertEqual(intel.metasploit_queries[0], "libx")

    def test_the_rapid7_search_url_carries_a_real_term(self) -> None:
        intel = enrich_osv_record(_record())
        rapid7 = [l for l in metasploit_links(intel) if l["source"] == "rapid7-db"]
        self.assertTrue(rapid7, "no Rapid7 link at all")
        for link in rapid7:
            self.assertTrue(link["url"].startswith("https://www.rapid7.com/db/?q="))
            self.assertNotIn("%2F", link["url"].upper(), "the query contains a path separator")

    def test_the_report_gets_at_most_two_rapid7_links(self) -> None:
        # One link per stored query is noise in a report.
        intel = enrich_osv_record(_record(aliases=["CVE-1", "CVE-2", "CVE-3"],
                                          cve_ids=["CVE-1", "CVE-2", "CVE-3"]))
        rapid7 = [l for l in metasploit_links(intel) if l["source"] == "rapid7-db"]
        self.assertLessEqual(len(rapid7), 2)


class HonestyTests(unittest.TestCase):
    """Nothing is claimed that was not measured."""

    def test_an_absent_vector_never_becomes_the_string_none(self) -> None:
        # str(None) is "None", which is truthy: a record with no CVSS field
        # came out carrying cvss_vector="None" and a ".../calculator/4.0#None"
        # report link labelled advisory-supplied.
        intel = enrich_osv_record({"id": "X", "package": "p", "ecosystem": "PyPI",
                                   "severity": "low"})
        self.assertIsNone(intel.cvss_vector)
        self.assertIsNone(intel.cvss_link)
        self.assertEqual(intel.cvss_source, "none")

    def test_a_blank_vector_is_never_used_as_a_vector(self) -> None:
        # A whitespace-only field must not reach calculator_link(): that used
        # to be the source of a "#None"-style report URL.
        # With a known CWE the class vector legitimately stands in, and must be
        # labelled derived rather than passed off as the advisory's own.
        intel = enrich_osv_record(_record(cvss_vector="   "))
        self.assertEqual(intel.cvss_source, "derived")
        self.assertNotIn("None", intel.cvss_link or "")
        # With no CWE there is nothing to derive from, so nothing is claimed.
        bare = enrich_osv_record(_record(cvss_vector="   ", cwes=[]))
        self.assertIsNone(bare.cvss_vector)
        self.assertIsNone(bare.cvss_link)
        self.assertEqual(bare.cvss_source, "none")

    def test_a_present_vector_is_attributed_to_the_advisory(self) -> None:
        intel = enrich_osv_record(_record())
        self.assertEqual(intel.cvss_source, "advisory")
        self.assertIn(VEC4, intel.cvss_link or "")

    def test_the_report_states_when_a_vector_was_not_measured(self) -> None:
        derived = VulnIntel(package="x", version=None, ecosystem="PyPI", cwe_ids=["CWE-89"])
        md = intel_markdown([derived])
        self.assertIn("not measured", md)

    def test_the_report_states_it_does_not_execute_exploits(self) -> None:
        intel = enrich_osv_record(_record())
        md = intel_markdown([intel])
        self.assertIn("does not download, weaponise or execute", md)


class RecordShapeTests(unittest.TestCase):
    """Both the flat scanner record and the raw OSV object must enrich."""

    def test_a_flat_record_populates_everything(self) -> None:
        intel = enrich_osv_record(_record())
        self.assertEqual(intel.package, "log4j-core")
        self.assertEqual(intel.version, "2.14.1")
        self.assertEqual(intel.advisory_id, "GHSA-xxxx-yyyy-zzzz")
        self.assertEqual(intel.cve_ids, ["CVE-2021-44228"])
        self.assertEqual(intel.cwe_ids, ["CWE-502"])
        self.assertEqual(intel.fixed, "2.15.0")
        self.assertEqual(intel.severity, "critical")
        self.assertEqual(intel.cvss_source, "advisory")

    def test_a_raw_osv_object_populates_the_same_fields(self) -> None:
        raw = {
            "id": "GHSA-raw",
            "aliases": ["CVE-2020-0001"],
            "summary": "bad",
            "severity": [{"type": "CVSS_V4", "score": VEC4}],
            "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2020-0001"}],
            "affected": [{"ranges": [{"events": [{"introduced": "0"},
                                                 {"fixed": "3.0.0"}]}]}],
            "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-79"]},
        }
        intel = enrich_osv_record(raw)
        self.assertEqual(intel.fixed, "3.0.0")
        self.assertEqual(intel.cwe_ids, ["CWE-79"])
        self.assertEqual(intel.severity, "high")
        self.assertEqual(intel.cvss_vector, VEC4)

    def test_a_ghsa_alias_is_never_promoted_to_a_cve_id(self) -> None:
        intel = enrich_osv_record(_record(aliases=["GHSA-1234"], cve_ids=[]))
        self.assertEqual(intel.cve_ids, [])
        self.assertEqual(intel.aliases, ["GHSA-1234"])

    def test_an_unclassifiable_reference_is_dropped_from_the_finding(self) -> None:
        intel = enrich_osv_record(_record(references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            "https://not-a-classifiable-host.example/x",
        ]))
        self.assertIn("https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                      [l["url"] for l in reference_links(intel)])

    def test_an_empty_record_still_produces_a_honest_intel(self) -> None:
        intel = enrich_osv_record({"package": "left-pad", "ecosystem": "npm"})
        self.assertEqual(intel.exploitdb_queries, ["left-pad"])
        self.assertEqual(intel.metasploit_queries, ["left-pad"])
        self.assertIsNone(intel.advisory_id)
        self.assertIsNone(intel.cvss_vector)


class ReferenceLinkTests(unittest.TestCase):
    def test_references_are_classified_by_host(self) -> None:
        intel = enrich_osv_record(_record(references=[
            "https://github.com/advisories/GHSA-xxxx",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        ]))
        kinds = {l["kind"] for l in reference_links(intel)}
        self.assertIn("ghsa", kinds)
        self.assertIn("nvd", kinds)

    def test_an_nvd_search_link_is_not_added_when_one_is_already_present(self) -> None:
        intel = enrich_osv_record(_record(
            cve_ids=["CVE-2021-44228"],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        ))
        self.assertEqual(len(reference_links(intel)), 1)

    def test_an_nvd_search_link_is_added_when_none_is_present(self) -> None:
        intel = enrich_osv_record(_record(references=[]))
        self.assertIn("nvd-search", [l["kind"] for l in reference_links(intel)])


class CvssParsingTests(unittest.TestCase):
    def test_a_v4_vector_yields_its_base_metrics(self) -> None:
        metrics = parse_cvss_vector(VEC4)
        assert metrics is not None
        self.assertEqual(len(metrics), 11)
        self.assertEqual(metrics["AV"], "N")
        self.assertEqual(metrics["VC"], "H")

    def test_a_v31_vector_is_rejected_rather_than_translated(self) -> None:
        v31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        self.assertIsNone(parse_cvss_vector(v31))

    def test_garbage_is_rejected(self) -> None:
        for bad in ("", "not a vector", "CVSS:4.0/AV:Q", None):
            with self.subTest(bad=bad):
                self.assertIsNone(parse_cvss_vector(bad))

    def test_calculator_link_carries_the_vector_verbatim(self) -> None:
        link = calculator_link(VEC4)
        self.assertEqual(
            link,
            "https://www.first.org/cvss/calculator/4.0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/"
            "UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
        )


class CweGuidanceTests(unittest.TestCase):
    def test_a_known_cwe_gets_a_label_a_meaning_and_a_fix(self) -> None:
        out = cwe_guidance(["CWE-89"])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["cwe"], "CWE-89")
        self.assertTrue(out[0]["label"])
        self.assertTrue(out[0]["what_it_means"])
        self.assertTrue(out[0]["how_to_fix"])
        self.assertIn("cwe.mitre.org", out[0]["url"])

    def test_an_unknown_cwe_degrades_instead_of_vanishing(self) -> None:
        out = cwe_guidance(["CWE-9999"])
        self.assertTrue(out[0]["how_to_fix"])

    def test_duplicates_are_collapsed(self) -> None:
        self.assertEqual(len(cwe_guidance(["CWE-89", "cwe-89", "CWE-89"])), 1)

    def test_an_empty_list_yields_nothing(self) -> None:
        self.assertEqual(cwe_guidance([]), [])


class OsvRecordTests(unittest.TestCase):
    """query_osv() must keep the vector, not only the band derived from it."""

    def test_the_vector_survives_the_flat_record(self) -> None:
        raw = {
            "id": "GHSA-vec",
            "aliases": ["CVE-2021-0001"],
            "summary": "x",
            "severity": [{"type": "CVSS_V4", "score": VEC4}],
            "references": [],
            "affected": [],
            "database_specific": {"severity": "HIGH"},
        }

        class _Resp:
            status_code = 200

            @staticmethod
            def json() -> dict:
                return {"vulns": [raw]}

        original = cve_mod.httpx.post
        cve_mod.httpx.post = lambda url, json=None, timeout=None, **kw: _Resp()
        try:
            records = query_osv("acme", "1.0", "PyPI")
        finally:
            cve_mod.httpx.post = original

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["cvss_vector"], VEC4)

    def test_a_record_with_no_cvss_has_no_vector_string(self) -> None:
        raw = {"id": "GHSA-novec", "summary": "x", "references": [], "affected": [],
               "severity": [], "database_specific": {}}

        class _Resp:
            status_code = 200

            @staticmethod
            def json() -> dict:
                return {"vulns": [raw]}

        original = cve_mod.httpx.post
        cve_mod.httpx.post = lambda url, json=None, timeout=None, **kw: _Resp()
        try:
            records = query_osv("acme", "1.0", "PyPI")
        finally:
            cve_mod.httpx.post = original

        self.assertIsNone(records[0]["cvss_vector"])


class ScannerWiringTests(unittest.TestCase):
    """The layer is only worth anything if a finding carries it."""

    def _scan(self, records: list[dict]) -> object:
        original = dep_mod.scan_dependencies
        dep_mod.scan_dependencies = lambda root, rels, cap=40: (records, {})
        try:
            scanner = DependencyScanner()
            with tempfile.TemporaryDirectory() as tmp:
                return asyncio.run(scanner._scan(ScanContext(
                    target=tmp, metadata={"manifest_files": ["pom.xml"]},
                )))
        finally:
            dep_mod.scan_dependencies = original

    def test_a_finding_carries_the_cwe_ids(self) -> None:
        result = self._scan([_record()])
        self.assertEqual(result.findings[0].cwe_ids, ["CWE-502"])

    def test_a_finding_carries_the_cvss_vector(self) -> None:
        result = self._scan([_record()])
        self.assertEqual(result.findings[0].cvss_vector, VEC4)

    def test_a_finding_carries_classified_references(self) -> None:
        result = self._scan([_record(references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            "https://unclassifiable.example/x",
        ])])
        self.assertEqual(result.findings[0].references,
                         ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"])

    def test_the_exploit_references_reach_the_metadata(self) -> None:
        result = self._scan([_record()])
        md = result.findings[0].scanner_metadata
        self.assertTrue(md["aliases"])
        self.assertTrue(md["cvss_link"])
        self.assertTrue(md["exploitdb_queries"])
        self.assertTrue(md["metasploit_queries"])
        self.assertTrue(md["exploit_reference_links"])

    def test_the_recommendation_carries_the_cwe_fix(self) -> None:
        result = self._scan([_record()])
        rec = result.findings[0].recommendation
        self.assertIn("Upgrade log4j-core to 2.15.0", rec)
        self.assertIn("CWE-502", rec)
        self.assertIn("CWE-502 guidance:", rec)

    def test_the_description_states_the_fixed_version(self) -> None:
        result = self._scan([_record()])
        self.assertIn("2.15.0", result.findings[0].description)

    def test_a_record_with_no_cwe_still_becomes_a_finding(self) -> None:
        # No CWE, no vector: the CVE itself must survive intact.
        result = self._scan([_record(cwes=[], cvss_vector=None)])
        finding = result.findings[0]
        self.assertEqual(finding.title, "GHSA-xxxx-yyyy-zzzz: log4j-core")
        self.assertEqual(finding.cwe_ids, [])
        self.assertIsNone(finding.cvss_vector)
        self.assertIn("Upgrade log4j-core to 2.15.0", finding.recommendation)

    def test_a_broken_record_does_not_lose_the_cve(self) -> None:
        # Enrichment is additive; a failure in it must not cost the reader
        # the vulnerability itself.
        original = dep_mod.enrich_osv_record
        dep_mod.enrich_osv_record = lambda rec: (_ for _ in ()).throw(RuntimeError("boom"))
        try:
            result = self._scan([_record()])
        finally:
            dep_mod.enrich_osv_record = original
        self.assertEqual(len(result.findings), 1)
        self.assertIn("log4j-core", result.findings[0].title)


class CvssVersionTests(unittest.TestCase):
    """A vector is only meaningful next to the version it belongs to.

    v3.1 and v4.0 are different scoring systems: AT and VC/VI/VA/SC/SI/SA do
    not exist in 3.1, and Scope does not exist in 4.0.  The v4.0 calculator
    requires the literal CVSS:4.0 prefix, so a 3.1 vector sent to it is a
    broken link at best and a wrong score at worst.
    """

    V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    V40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"

    def test_the_version_is_recognised(self) -> None:
        self.assertEqual(cvss_version(self.V40), "4.0")
        self.assertEqual(cvss_version(self.V31), "3.1")
        self.assertEqual(cvss_version("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"), "3.0")

    def test_a_non_vector_has_no_version(self) -> None:
        for bad in (None, "", "not a vector", "CVSS:9.9/AV:N"):
            with self.subTest(bad=bad):
                self.assertIsNone(cvss_version(bad))

    def test_a_v31_vector_is_not_stored_as_a_v40_vector(self) -> None:
        intel = enrich_osv_record(_record(cvss_vector=self.V31))
        self.assertIsNone(intel.cvss_vector, "a 3.1 vector was stored as the v4.0 vector")
        self.assertIsNone(intel.cvss_link, "a 3.1 vector produced a v4.0 calculator link")
        self.assertEqual(intel.cvss_other_vector, self.V31)

    def test_a_v31_vector_is_kept_and_linked_on_its_own_terms(self) -> None:
        intel = enrich_osv_record(_record(cvss_vector=self.V31))
        md = intel_markdown([intel])
        self.assertIn("CVSS v3.1 vector (advisory-supplied, not scored by this build)", md)
        self.assertIn(
            "https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/"
            "S:U/C:N/I:N/A:H",
            md,
        )
        self.assertNotIn("CVSS v4.0 vector", md)

    def test_the_v31_vector_never_reaches_the_v40_calculator(self) -> None:
        intel = enrich_osv_record(_record(cvss_vector=self.V31))
        md = intel_markdown([intel])
        self.assertNotIn("calculator/4.0#CVSS:3.1", md)

    def test_a_v40_vector_is_used_as_usual(self) -> None:
        intel = enrich_osv_record(_record(cvss_vector=self.V40))
        self.assertEqual(intel.cvss_vector, self.V40)
        self.assertIsNone(intel.cvss_other_vector)
        self.assertEqual(intel.cvss_source, "advisory")
        self.assertIn(self.V40, intel.cvss_link or "")

    def test_a_v40_vector_from_a_raw_osv_object_is_used(self) -> None:
        raw = {
            "id": "R", "summary": "s", "references": [], "affected": [],
            "aliases": [], "database_specific": {"severity": "HIGH"},
            "severity": [{"type": "CVSS_V4", "score": self.V40}],
        }
        self.assertEqual(enrich_osv_record(raw).cvss_vector, self.V40)

    def test_a_v31_vector_from_a_raw_osv_object_is_separated(self) -> None:
        raw = {
            "id": "R", "summary": "s", "references": [], "affected": [],
            "aliases": [], "database_specific": {"severity": "HIGH"},
            "severity": [{"type": "CVSS_V3", "score": self.V31}],
        }
        intel = enrich_osv_record(raw)
        self.assertIsNone(intel.cvss_vector)
        self.assertEqual(intel.cvss_other_vector, self.V31)

    def test_the_legacy_vector_survives_to_dict(self) -> None:
        intel = enrich_osv_record(_record(cvss_vector=self.V31))
        self.assertEqual(intel.to_dict()["cvss_other_vector"], self.V31)

    def test_the_repo_report_labels_the_version(self) -> None:
        from triagekit.core.analyzers.repo_scan import RepoScanResult

        target = RepoScanResult(root=".", findings=[],
                                cve_findings=[_record(cvss_vector=self.V31)],
                                files_scanned=1)
        target.compute_score()
        md = target.to_markdown()
        self.assertIn("CVSS v3.1 vector (advisory-supplied, not scored by this build)", md)
        self.assertIn("calculator/3.1", md)
        self.assertNotIn("CVSS v4.0 vector", md)


class ScanRepositoryDependencyTests(unittest.TestCase):
    """The repo scan used to name its manifests and then never query OSV.

    ``scan_repository`` recorded ``dependency_files`` and reported
    "0 dependency advisories" for a repository it had just measured -- a silent
    false negative that reads as a clean bill of health.
    """

    def _run(self, **kwargs) -> object:
        from triagekit.core.analyzers.repo_scan import scan_repository

        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "requirements.txt").write_text(
                "flask==0.12.2\n", encoding="utf-8")
            return scan_repository(Path(tmp), **kwargs)

    def test_discovered_manifests_are_queried(self) -> None:
        calls: list[dict] = []

        import triagekit.core.analyzers.cve as cve_mod

        real = cve_mod.scan_dependencies

        def spy(root, rels, cap):
            calls.append({"rels": list(rels), "cap": cap})
            return [{"id": "GHSA-spy", "package": "flask", "severity": "high",
                     "summary": "x", "fixed": "1.0", "manifest": rels[0] if rels else ""}], {}

        # scan_repository imports scan_dependencies inside the function, so the
        # stub has to sit on the cve module, not on repo_scan.
        cve_mod.scan_dependencies = spy
        try:
            result = self._run()
        finally:
            cve_mod.scan_dependencies = real

        self.assertTrue(calls, "scan_dependencies was never called")
        self.assertIn("requirements.txt", calls[0]["rels"])
        self.assertEqual(calls[0]["cap"], 40)
        self.assertEqual(len(result.cve_findings), 1)

    def test_the_package_cap_is_forwarded(self) -> None:
        import triagekit.core.analyzers.cve as cve_mod

        caps: list[int] = []
        real = cve_mod.scan_dependencies

        def spy(root, rels, cap):
            caps.append(cap)
            return [], {}

        cve_mod.scan_dependencies = spy
        try:
            self._run(max_packages=7)
        finally:
            cve_mod.scan_dependencies = real
        self.assertEqual(caps, [7])

    def test_no_deps_means_no_osv_call(self) -> None:
        import triagekit.core.analyzers.cve as cve_mod

        calls: list[int] = []
        real = cve_mod.scan_dependencies

        def spy(root, rels, cap):
            calls.append(1)
            return [], {}

        cve_mod.scan_dependencies = spy
        try:
            result = self._run(no_deps=True)
        finally:
            cve_mod.scan_dependencies = real

        self.assertEqual(calls, [], "OSV was queried despite being disabled")
        self.assertEqual(result.cve_findings, [])
        self.assertIn("disabled", result.coverage.get("dependency_scan", ""))

    def test_a_repo_with_no_manifests_makes_no_call(self) -> None:
        from triagekit.core.analyzers.repo_scan import scan_repository

        import triagekit.core.analyzers.cve as cve_mod

        calls: list[int] = []
        real = cve_mod.scan_dependencies

        def spy(root, rels, cap):
            calls.append(1)
            return [], {}

        cve_mod.scan_dependencies = spy
        try:
            with tempfile.TemporaryDirectory() as tmp:
                result = scan_repository(Path(tmp))
        finally:
            cve_mod.scan_dependencies = real

        self.assertEqual(calls, [])

    def test_a_failed_lookup_is_a_coverage_failure_not_a_clean_repo(self) -> None:
        import triagekit.core.analyzers.cve as cve_mod

        real = cve_mod.scan_dependencies

        def boom(root, rels, cap):
            raise RuntimeError("osv down")

        cve_mod.scan_dependencies = boom
        try:
            result = self._run()
        finally:
            cve_mod.scan_dependencies = real

        self.assertEqual(result.cve_findings, [])
        self.assertIn("advisory lookup failed", result.coverage.get("dependency_scan", ""))
        self.assertIn("osv down", result.coverage.get("dependency_scan", ""))
        # The report must say the advisories are unknown, not clean.
        md = result.to_markdown()
        self.assertIn("Scan coverage limits", md)


class RepoScannerWiringTests(unittest.TestCase):
    """The repo path is a second consumer and had the same gap."""

    def _scan(self, cve_findings: list[dict]) -> object:
        from triagekit.core.analyzers.repo_scan import RepoScanResult
        from triagekit.core.scanners import repo_scanner as rs_mod
        from triagekit.core.scanners.repo_scanner import RepositoryScanner

        target = RepoScanResult(root=".", findings=[], cve_findings=cve_findings,
                                files_scanned=1)
        original = rs_mod.scan_repository
        rs_mod.scan_repository = lambda *a, **kw: target
        try:
            scanner = RepositoryScanner()
            with tempfile.TemporaryDirectory() as tmp:
                marker = Path(tmp) / "requirements.txt"
                marker.write_text("django==3.2.0\n", encoding="utf-8")
                return asyncio.run(scanner._scan(ScanContext(target=tmp)))
        finally:
            rs_mod.scan_repository = original

    def test_the_repo_finding_carries_the_cwe_ids(self) -> None:
        result = self._scan([_record()])
        dep = [f for f in result.findings if f.category == "vulnerable-dependency"]
        self.assertTrue(dep, "no dependency finding produced")
        self.assertEqual(dep[0].cwe_ids, ["CWE-502"])

    def test_the_repo_finding_carries_the_vector(self) -> None:
        result = self._scan([_record()])
        dep = [f for f in result.findings if f.category == "vulnerable-dependency"]
        self.assertEqual(dep[0].cvss_vector, VEC4)

    def test_the_repo_recommendation_carries_the_fix_and_the_cwe(self) -> None:
        result = self._scan([_record()])
        dep = [f for f in result.findings if f.category == "vulnerable-dependency"]
        rec = dep[0].recommendation
        self.assertIn("Upgrade log4j-core to 2.15.0", rec)
        self.assertIn("CWE-502 guidance:", rec)

    def test_the_repo_metadata_carries_the_exploit_references(self) -> None:
        result = self._scan([_record()])
        dep = [f for f in result.findings if f.category == "vulnerable-dependency"]
        md = dep[0].scanner_metadata
        self.assertTrue(md["aliases"])
        self.assertTrue(md["cvss_link"])
        self.assertTrue(md["exploit_reference_links"])

    def test_no_cve_disables_the_repo_path_too(self) -> None:
        # The dependency_scanner key carries 0 for "--no-cve"; this scanner
        # used to ignore it, so an "offline" scan still hit the network.
        from triagekit.core.analyzers.repo_scan import RepoScanResult
        from triagekit.core.scanners import repo_scanner as rs_mod
        from triagekit.core.scanners.repo_scanner import RepositoryScanner

        seen: dict = {}
        target = RepoScanResult(root=".", findings=[], cve_findings=[], files_scanned=1)
        target.coverage["dependency_scan"] = "disabled by configuration"

        def fake_scan(root, max_files=8000, progress_cb=None, max_packages=40,
                      no_deps=False):
            seen["max_packages"] = max_packages
            seen["no_deps"] = no_deps
            return target

        original = rs_mod.scan_repository
        rs_mod.scan_repository = fake_scan
        try:
            scanner = RepositoryScanner()
            with tempfile.TemporaryDirectory() as tmp:
                (Path(tmp) / "requirements.txt").write_text("flask\n", encoding="utf-8")
                asyncio.run(scanner._scan(ScanContext(
                    target=tmp, config={"max_packages": 0},
                )))
        finally:
            rs_mod.scan_repository = original

        self.assertTrue(seen.get("no_deps"), "no_deps was not forwarded")
        self.assertEqual(seen.get("max_packages"), 0)

    def test_the_default_still_queries_osv(self) -> None:
        from triagekit.core.analyzers.repo_scan import RepoScanResult
        from triagekit.core.scanners import repo_scanner as rs_mod
        from triagekit.core.scanners.repo_scanner import RepositoryScanner

        seen: dict = {}
        target = RepoScanResult(root=".", findings=[], cve_findings=[], files_scanned=1)

        def fake_scan(root, max_files=8000, progress_cb=None, max_packages=40,
                      no_deps=False):
            seen.update(max_packages=max_packages, no_deps=no_deps)
            return target

        original = rs_mod.scan_repository
        rs_mod.scan_repository = fake_scan
        try:
            scanner = RepositoryScanner()
            with tempfile.TemporaryDirectory() as tmp:
                (Path(tmp) / "requirements.txt").write_text("flask\n", encoding="utf-8")
                asyncio.run(scanner._scan(ScanContext(target=tmp)))
        finally:
            rs_mod.scan_repository = original

        self.assertFalse(seen.get("no_deps"))
        self.assertEqual(seen.get("max_packages"), 40)

    def test_a_record_with_no_cwe_still_produces_a_finding(self) -> None:
        result = self._scan([_record(cwes=[], cvss_vector=None)])
        dep = [f for f in result.findings if f.category == "vulnerable-dependency"]
        self.assertEqual(dep[0].cwe_ids, [])
        self.assertIsNone(dep[0].cvss_vector)


class RepoReportTests(unittest.TestCase):
    """The rendered repo report must carry the intelligence too."""

    def _render(self, cve_findings: list[dict]) -> str:
        from triagekit.core.analyzers.repo_scan import RepoScanResult

        target = RepoScanResult(root=".", findings=[], cve_findings=cve_findings,
                                files_scanned=1)
        target.compute_score()
        return target.to_markdown()

    def test_the_report_carries_the_advisory_body(self) -> None:
        md = self._render([_record()])
        self.assertIn("GHSA-xxxx-yyyy-zzzz: log4j-core", md)
        self.assertIn("Fixed in: 2.15.0", md)
        self.assertIn("`pom.xml`", md)

    def test_the_report_carries_the_enrichment(self) -> None:
        md = self._render([_record()])
        for needle in ("CVE-2021-44228", "CWE-502", "cwe.mitre.org",
                       "first.org/cvss/calculator", "exploit-db.com/search",
                       "rapid7.com/db"):
            self.assertIn(needle, md)

    def test_a_report_with_no_advisories_renders_no_advisory_section(self) -> None:
        md = self._render([])
        self.assertNotIn("Dependency / CVE findings", md)
        self.assertIn("TriageKit god-mode scan", md)

    def test_a_broken_enrichment_does_not_break_the_report(self) -> None:
        # Enrichment is additive: the advisory's own fields must survive even
        # if the enrichment blows up.  Make it actually blow up, rather than
        # handing it a record that merely looks odd.
        from triagekit.core.analyzers import repo_scan as rs_analyzers

        original = rs_analyzers._intel_lines

        def broken(intel):  # noqa: ANN001, ANN002
            raise RuntimeError("enrichment exploded")

        rs_analyzers._intel_lines = broken
        try:
            md = self._render([_record()])
        finally:
            rs_analyzers._intel_lines = original
        self.assertIn("GHSA-xxxx-yyyy-zzzz: log4j-core", md)
        self.assertIn("Fixed in: 2.15.0", md)
        self.assertNotIn("CWE-502", md)  # only the enrichment that did NOT run


class ReportRenderingTests(unittest.TestCase):
    def test_the_report_carries_every_enriched_field(self) -> None:
        intel = enrich_osv_record(_record())
        md = intel_markdown([intel])
        for needle in (
            "GHSA-xxxx-yyyy-zzzz",
            "CVE-2021-44228",
            "2.15.0",
            "first.org/cvss/calculator",
            "cwe.mitre.org",
            "exploit-db.com/search",
            "rapid7.com/db",
        ):
            self.assertIn(needle, md)

    def test_no_items_renders_nothing_rather_than_an_empty_heading(self) -> None:
        self.assertEqual(intel_markdown([]), "")

    def test_to_dict_round_trips_the_derived_fields(self) -> None:
        intel = enrich_osv_record(_record())
        d = intel.to_dict()
        self.assertTrue(d["exploitdb_queries"])
        self.assertTrue(d["metasploit_queries"])
        self.assertTrue(d["cvss_link"])


if __name__ == "__main__":
    unittest.main()
