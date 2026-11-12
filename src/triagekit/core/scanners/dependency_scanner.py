"""Dependency/CVE Scanner - wraps the existing OSV-based CVE lookup."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..analyzers.cve import query_osv, scan_dependencies
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


class DependencyScanner(BaseScanner[ScanResult]):
    """Dependency vulnerability scanner using OSV (Open Source Vulnerabilities) database.

    Supports:
    - Python (requirements.txt, pyproject.toml)
    - JavaScript/TypeScript (package.json)
    - Go (go.mod)
    - And other ecosystems via OSV
    """

    def _get_metadata(self) -> ScannerMetadata:
        return ScannerMetadata(
            name="dependency_scanner",
            version="1.0.0",
            scan_type=ScanType.DEPENDENCY_SCAN,
            description="Dependency vulnerability scanning via OSV database",
            supported_languages=["python", "javascript", "typescript", "go"],
            requires_network=True,
            estimated_duration_seconds=30,
            tags=["sca", "dependencies", "osv", "cve", "supply-chain"],
        )

    async def _scan(self, context: ScanContext) -> ScanResult:
        result = ScanResult(
            scanner_name=self.name,
            scanner_version=self.version,
            scan_type=self.scan_type,
            target=context.target,
        )

        # Get manifest files from context
        manifest_rels = context.metadata.get("manifest_files", [])
        if not manifest_rels:
            # Try to discover from target path
            target_path = Path(context.target)
            if target_path.is_dir():
                manifest_rels = self._discover_manifests(target_path)
            elif target_path.is_file():
                manifest_rels = [target_path.name]

        if not manifest_rels:
            result.warnings.append("No dependency manifests found")
            result.complete()
            return result

        max_packages = context.config.get("max_packages", 40)
        dry_run = context.dry_run

        try:
            if max_packages is not None and max_packages <= 0:
                # Explicitly disabled (--no-cve), not a misconfiguration.
                result.warnings.append("Dependency scanning disabled by configuration")
                result.summary = f"Disabled: {len(manifest_rels)} manifests not queried"
                result.complete()
                return result

            if dry_run:
                result.warnings.append("Dry run mode - skipping actual scan")
                result.summary = f"Dry run: would scan {len(manifest_rels)} manifests"
                result.complete()
                return result

            # Run dependency scan
            target_path = Path(context.target)
            cve_findings, dep_stats = scan_dependencies(
                target_path, manifest_rels, max_packages
            )

        except Exception as e:
            result.errors.append(f"Dependency scan failed: {e}")
            result.complete()
            return result

        # Convert to UnifiedFindings
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }

        for cve in cve_findings:
            cve_severity = (cve.get("severity") or "medium").lower()
            # The OSV lookup answers with far more than a title and a summary:
            # aliases, CWE ids, a CVSS vector, reference URLs.  Enriching here
            # is what turns a bare "upgrade this" into a finding that carries
            # the weakness it is, the vector to score it with, and where public
            # attack material for it is documented.
            try:
                intel = enrich_osv_record(cve)
            except Exception:
                # A malformed record must not cost the reader the CVE itself.
                intel = None

            description = cve.get("summary", "") or (
                f"{cve.get('id', 'Advisory')} affects {cve.get('package', 'this package')}."
            )
            if intel and intel.fixed:
                description += f" Fixed in {intel.fixed}."

            unified = UnifiedFinding(
                scanner_name=self.name,
                scanner_version=self.version,
                scan_type=self.scan_type,
                title=f"{cve.get('id', 'CVE')}: {cve.get('package', 'unknown')}",
                description=description,
                severity=severity_map.get(cve_severity, Severity.MEDIUM),
                category="vulnerable-dependency",
                file_path=cve.get("manifest"),
                recommendation=(
                    f"Upgrade {cve.get('package')} to {cve.get('fixed') or 'a fixed release'}"
                    + (
                        f". {intel.cwe_ids[0]} guidance: {cwe_guidance(intel.cwe_ids)[0]['how_to_fix']}"
                        if intel and intel.cwe_ids else ""
                    )
                ),
                cwe_ids=(intel.cwe_ids if intel else []),
                cvss_vector=(intel.cvss_vector if intel else None),
                # Classified references only: a URL whose host nobody can
                # classify is noise on a finding, and the classifier already
                # exists for exactly this purpose.
                references=([l["url"] for l in reference_links(intel)] if intel else []),
                scanner_metadata={
                    "package": cve.get("package"),
                    "version": cve.get("version"),
                    "fixed_version": cve.get("fixed"),
                    "advisory_id": cve.get("id"),
                    "ecosystem": cve.get("ecosystem"),
                    "manifest": cve.get("manifest"),
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

        result.summary = (
            f"Dependency scan: {len(manifest_rels)} manifests, "
            f"{len(cve_findings)} vulnerabilities found "
            f"({result.counts['critical']}C, {result.counts['high']}H, "
            f"{result.counts['medium']}M, {result.counts['low']}L)"
        )
        result.metadata = {
            "manifests_scanned": manifest_rels,
            "vulnerabilities": cve_findings,
            "dependency_coverage": dep_stats,
        }

        result.complete()
        return result

    def _discover_manifests(self, root: Path) -> list[str]:
        """Discover dependency manifest files in a directory.

        Matching is case-insensitive: on Windows and macOS the filesystem
        itself is, so a repo authored as ``gemfile.lock`` is findable by name
        but was skipped here because the set listed only ``Gemfile.lock``.
        Directories that are not part of the shipped source (vendored copies of
        a dependency, build output, other checkouts) are skipped to avoid
        querying the same third-party package a second time.
        """
        manifest_names = {
            "requirements.txt", "requirements-dev.txt", "pipfile", "pipfile.lock",
            "pyproject.toml", "package.json", "package-lock.json",
            "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
            "go.mod", "cargo.toml", "cargo.lock",
            "composer.json", "composer.lock", "gemfile.lock",
            "pom.xml", "build.gradle", "build.gradle.kts",
        }
        skip_dirs = {
            "node_modules", ".git", ".venv", "venv", "env", "__pycache__",
            "dist", "build", "out", "target", "vendor", ".tox", ".mypy_cache",
            "site-packages", ".idea", ".vscode", "coverage", ".pytest_cache",
        }

        found = []
        for path in root.rglob("*"):
            lower = path.name.lower()
            # "requirements-anywhere.txt" is a pip requirements file, whatever
            # it is prefixed or suffixed with.
            if lower not in manifest_names and not (
                "requirements" in lower and lower.endswith(".txt")
            ):
                continue
            if any(part.lower() in skip_dirs for part in path.parts):
                continue
            try:
                rel = path.relative_to(root)
                found.append(str(rel))
            except ValueError:
                pass
        return sorted(found)

    def validate_config(self) -> list[str]:
        errors = []
        if "max_packages" in self.config:
            try:
                val = int(self.config["max_packages"])
                # 0 means "disabled" (the CLI's --no-cve), which is valid.
                if val < 0 or val > 500:
                    errors.append("max_packages must be 0 (disabled) or between 1 and 500")
            except ValueError:
                errors.append("max_packages must be an integer")
        return errors

    def get_supported_targets(self) -> list[str]:
        return ["*", "repo:*", "path:*", "manifest:*"]


def create_dependency_scanner(config: dict[str, Any] | None = None) -> DependencyScanner:
    """Factory function to create a DependencyScanner."""
    return DependencyScanner(config)