"""Repository Scanner - wraps the existing god-mode repo scanner."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ..analyzers.repo_scan import Finding, RepoScanResult, scan_repository
from ..analyzers.vuln_intel import (
    cwe_guidance,
    enrich_osv_record,
    metasploit_links,
    reference_links,
)
from .base import (
    BaseScanner,
    ScanContext,
    ScanResult,
    ScanType,
    ScannerMetadata,
    Severity,
    UnifiedFinding,
)


# The rule-id reported for every dependency advisory this scanner emits.  It is
# a label, not an identifier of a specific advisory: the advisory id already
# lives in ``scanner_metadata["advisory_id"]`` and in the finding title.  What
# was missing was any rule at all, so advisory rows rendered as a null rule
# alongside static-analysis rows that had one.
_DEPENDENCY_RULE_ID = "vulnerable-dependency"


def _advisory_hint(cve_finding: dict[str, Any]) -> str:
    """A short, distinguishing label for an advisory that has no id.

    OSV identifies an advisory by its ``id``.  When that is missing there is
    nothing to name the advisory by, but two advisories for one package are
    still two advisories, and ``compute_fingerprint`` derives identity from the
    title -- so the title has to carry the difference or the deduplicator will
    merge them.  The summary is the only remaining distinguishing field.
    """
    summary = str(cve_finding.get("summary") or "").strip()
    if not summary:
        return "unidentified advisory"
    # Fold whitespace and cut at a word boundary; a fingerprint needs a stable
    # token, not a paragraph.
    collapsed = " ".join(summary.split())
    if len(collapsed) > 80:
        collapsed = collapsed[:80].rsplit(" ", 1)[0].rstrip(",;:") or collapsed[:80]
    return collapsed


class RepositoryScanner(BaseScanner[ScanResult]):
    """Full repository security scanner (god-mode).

    Scans entire repository for:
    - Injection vulnerabilities (SQL, command, XSS, path traversal)
    - Hardcoded secrets and credentials
    - Weak cryptography and authentication
    - Code quality issues
    - Docker/CI configuration issues
    - Language-specific patterns (Python, JS, Go, Rust, Java, C#, C++, Swift)
    - Dependency file analysis
    """

    def _get_metadata(self) -> ScannerMetadata:
        return ScannerMetadata(
            name="repository_scanner",
            version="2.0.0",
            scan_type=ScanType.REPOSITORY_SCAN,
            description="Comprehensive repository security scan with multi-language support",
            supported_languages=[
                "python", "javascript", "typescript", "go", "rust", "java",
                "c#", "c++", "swift", "php", "ruby", "shell", "sql",
            ],
            required_tools=["git"],
            estimated_duration_seconds=120,
            tags=["sast", "repository", "multi-language", "secrets", "dependencies"],
        )

    async def _scan(self, context: ScanContext) -> ScanResult:
        result = ScanResult(
            scanner_name=self.name,
            scanner_version=self.version,
            scan_type=self.scan_type,
            target=context.target,
        )

        # Resolve target path
        target_path = self._resolve_target(context.target)
        if not target_path:
            result.errors.append(f"Could not resolve target path: {context.target}")
            result.complete()
            return result

        # Configuration from context
        max_files = context.config.get("max_files", 8000)
        # --no-cve must switch this path off too.  The dependency_scanner key
        # carries 0 for "disabled", which this scanner used to ignore, so a user
        # asking for an offline scan still got OSV calls on the repo path.
        dep_cap = context.config.get("max_packages", 40)
        no_deps = dep_cap is None or dep_cap <= 0
        dry_run = context.dry_run

        # Progress callback
        def progress_cb(scanned: int, total: int, current: str) -> None:
            if scanned % 100 == 0:
                result.metadata["progress"] = {
                    "scanned": scanned,
                    "total": total,
                    "current": current,
                }

        try:
            if dry_run:
                result.warnings.append("Dry run mode - skipping actual scan")
                result.summary = f"Dry run: would scan {target_path}"
                result.complete()
                return result

            # Run the repository scan
            repo_result: RepoScanResult = scan_repository(
                root=target_path,
                max_files=max_files,
                progress_cb=progress_cb,
                max_packages=dep_cap,
                no_deps=no_deps,
            )

        except Exception as e:
            result.errors.append(f"Repository scan failed: {e}")
            result.complete()
            return result

        # Convert findings to UnifiedFindings
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }

        for finding in repo_result.findings:
            # Use rule_id as category for consistent cross-scanner correlation
            category = finding.rule_id or finding.category
            unified = UnifiedFinding(
                scanner_name=self.name,
                scanner_version=self.version,
                scan_type=self.scan_type,
                title=finding.title,
                description=finding.recommendation or "Security issue detected",
                severity=severity_map.get(finding.severity, Severity.MEDIUM),
                category=category,
                file_path=finding.file,
                line_number=finding.line,
                snippet=finding.snippet,
                recommendation=finding.recommendation,
                cwe_ids=[finding.cwe] if finding.cwe else [],
                rule_id=finding.rule_id,
                scanner_metadata={
                    "original_severity": finding.severity,
                    "rule_id": finding.rule_id,
                },
                layer="regex",
            )
            result.add_finding(unified)

        # Add CVE/dependency findings
        for cve_finding in repo_result.cve_findings:
            cve_severity = (cve_finding.get("severity") or "medium").lower()
            # OSV answers with aliases, CWE ids, a CVSS vector and reference
            # URLs.  Enriching here is what carries them onto the finding; the
            # intel layer was previously imported by nothing, so every value
            # it computed was unreachable from a scan.
            try:
                intel = enrich_osv_record(cve_finding)
            except Exception:
                intel = None

            fix_target = cve_finding.get("fixed") or "a fixed release"
            description = cve_finding.get("summary", "") or (
                f"{cve_finding.get('id', 'Advisory')} affects "
                f"{cve_finding.get('package', 'this package')}."
            )
            if cve_finding.get("fixed"):
                description += f" Fixed in {cve_finding['fixed']}."

            # The title must name the advisory, not just the package.  A
            # package is affected by several at once -- flask==0.12.2 answers
            # with four -- and the fingerprint is computed from the title, so
            # "<id>: <package>" gives each advisory its own identity while
            # "Vulnerable dependency: <package>" gave every advisory for a
            # package the same one, and the report showed one where the scan
            # found twelve (defect D64).  It also tells the reader which
            # vulnerability they are looking at, which a package name cannot.
            advisory_id = cve_finding.get("id")
            package_name = cve_finding.get("package", "unknown")
            if advisory_id:
                title = f"{advisory_id}: {package_name}"
            else:
                # No id to name it by, so the summary has to.  Without this the
                # title is "Vulnerable dependency: <package>" for *every*
                # unidentifiable advisory of that package, the fingerprint is
                # computed from the title, and FindingDeduplicator merges them
                # into one -- so two real advisories are reported as one, which
                # is defect D64's under-report reached by another road.  The
                # summary is truncated because a fingerprint, not a sentence, is
                # what is being distinguished.
                title = f"Vulnerable dependency: {package_name} ({_advisory_hint(cve_finding)})"

            unified = UnifiedFinding(
                scanner_name=self.name,
                scanner_version=self.version,
                scan_type=ScanType.DEPENDENCY_SCAN,
                title=title,
                description=description,
                severity=severity_map.get(cve_severity, Severity.MEDIUM),
                category="vulnerable-dependency",
                file_path=cve_finding.get("manifest"),
                recommendation=f"Upgrade {cve_finding.get('package', 'the package')} to {fix_target}"
                + (
                    f". {intel.cwe_ids[0]} guidance: {cwe_guidance(intel.cwe_ids)[0]['how_to_fix']}"
                    if intel and intel.cwe_ids else ""
                ),
                cwe_ids=(intel.cwe_ids if intel else []),
                cvss_vector=(intel.cvss_vector if intel else None),
                references=([l["url"] for l in reference_links(intel)] if intel else []),
                scanner_metadata={
                    # The rule-id channel.  ``UnifiedFinding`` has no ``rule_id``
                    # field (Pydantic would silently drop the kwarg -- see the
                    # comment in correlation.py), so every consumer reads it from
                    # ``scanner_metadata``: cli.py's --json payload, the web-UI
                    # finding table, and ``_REGEX_TO_SINK_CATEGORY``.  The branch
                    # above sets it for source-pattern findings; this one never
                    # did, so every advisory row showed a null rule while every
                    # static-analysis row showed one.
                    "rule_id": _DEPENDENCY_RULE_ID,
                    "package": cve_finding.get("package"),
                    "version": cve_finding.get("version"),
                    "fixed": cve_finding.get("fixed"),
                    "advisory_id": cve_finding.get("id"),
                    "aliases": (intel.aliases if intel else []),
                    "cvss_link": (intel.cvss_link if intel else None),
                    "cvss_source": (intel.cvss_source if intel else "none"),
                    "exploitdb_queries": (intel.exploitdb_queries if intel else []),
                    "metasploit_queries": (intel.metasploit_queries if intel else []),
                    "exploit_reference_links": (metasploit_links(intel) if intel else []),
                    "intel": (intel.to_dict() if intel else {}),
                },
            )
            result.add_finding(unified)

        # Summary
        result.summary = repo_result.summary
        result.metadata = {
            "files_scanned": repo_result.files_scanned,
            "languages": repo_result.languages,
            "dependency_files": repo_result.dependency_files,
            "grade": repo_result.grade,
            "score": repo_result.score,
            "counts": repo_result.counts(),
        }

        # Add advisories and exploit relevance if present
        if hasattr(repo_result, "advisories") and repo_result.advisories:
            result.metadata["advisories"] = repo_result.advisories
        if hasattr(repo_result, "relevance") and repo_result.relevance:
            result.metadata["exploit_relevance"] = repo_result.relevance

        result.complete()
        return result

    def _resolve_target(self, target: str) -> Path | None:
        """Resolve target to a local path."""
        # Handle GitHub URLs
        if target.startswith("https://github.com/"):
            # This would need github_client to download
            # For now, return None to indicate needs download
            return None

        # Local path
        path = Path(target).expanduser().resolve()
        if path.exists():
            return path

        # Try relative to cwd
        cwd_path = Path.cwd() / target
        if cwd_path.exists():
            return cwd_path.resolve()

        return None

    def validate_config(self) -> list[str]:
        errors = []
        if "max_files" in self.config:
            try:
                max_files = int(self.config["max_files"])
                if max_files < 1 or max_files > 50000:
                    errors.append("max_files must be between 1 and 50000")
            except ValueError:
                errors.append("max_files must be an integer")
        return errors

    def get_supported_targets(self) -> list[str]:
        return ["*", "repo:*", "path:*", "github:*"]


def create_repo_scanner(config: dict[str, Any] | None = None) -> RepositoryScanner:
    """Factory function to create a RepositoryScanner."""
    return RepositoryScanner(config)