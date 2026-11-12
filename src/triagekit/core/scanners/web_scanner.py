"""Web Scanner - wraps the existing website security adviser."""

from __future__ import annotations

from typing import Any

from ..analyzers.web_scan import WebScanResult, scan_website
from .base import (
    BaseScanner,
    ScanContext,
    ScanResult,
    ScanType,
    ScannerMetadata,
    Severity,
    UnifiedFinding,
)


class WebScanner(BaseScanner[ScanResult]):
    """Website security adviser scanner.

    Performs 6-layer assessment:
    1. Transport & edge posture (HTTPS, HSTS, cookies, CORS, headers)
    2. Attack surface mapping (crawl, robots, sitemap, JS-extracted APIs)
    3. Leak & exposure hunting (sensitive paths, body secrets, backups)
    4. HTML/JS analysis (forms, CSRF, sinks/sources, hardcoded secrets)
    5. Safe active checks (reflection canaries, method probing, soft-404)
    6. Stack-aware guidance + prioritized remediation playbook
    """

    # How the web layer's severity words become framework severities.  Kept as
    # an attribute so the mapping can be checked without running a live scan --
    # the D75 defect was that ``info`` was missing here and the MEDIUM default
    # quietly covered for it, so a test that cannot read this table cannot catch
    # the next word that goes missing.
    _severity_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        # A statement about the scanner's own coverage, not about the target.
        "info": Severity.INFORMATIONAL,
        "informational": Severity.INFORMATIONAL,
    }

    def _get_metadata(self) -> ScannerMetadata:
        return ScannerMetadata(
            name="web_scanner",
            version="4.0.0",
            scan_type=ScanType.WEB_SCAN,
            description="Multi-layer website security assessment with safe active checks",
            supported_languages=["*"],
            requires_network=True,
            estimated_duration_seconds=60,
            tags=["dast", "web", "active-scanning", "reconnaissance", "remediation"],
        )

    async def _scan(self, context: ScanContext) -> ScanResult:
        result = ScanResult(
            scanner_name=self.name,
            scanner_version=self.version,
            scan_type=self.scan_type,
            target=context.target,
        )

        url = context.target
        if not url:
            result.errors.append("No target URL provided")
            result.complete()
            return result

        # Configuration from context
        timeout = context.config.get("timeout", 30.0)
        check_sensitive_paths = context.config.get("check_sensitive_paths", True)
        max_paths = context.config.get("max_paths", 120)
        crawl = context.config.get("crawl", True)
        max_crawl_pages = context.config.get("max_crawl_pages", 25)
        max_js_files = context.config.get("max_js_files", 20)
        max_js_bytes = context.config.get("max_js_bytes", 1_800_000)
        active = context.config.get("active", True)
        dry_run = context.dry_run

        try:
            if dry_run:
                result.warnings.append("Dry run mode - skipping actual scan")
                result.summary = f"Dry run: would scan {url}"
                result.complete()
                return result

            # Run the web scan
            web_result: WebScanResult = scan_website(
                url=url,
                timeout=timeout,
                check_sensitive_paths=check_sensitive_paths,
                max_paths=max_paths,
                crawl=crawl,
                max_crawl_pages=max_crawl_pages,
                max_js_files=max_js_files,
                max_js_bytes=max_js_bytes,
                active=active,
            )

        except Exception as e:
            result.errors.append(f"Web scan failed: {e}")
            result.complete()
            return result

        # Convert findings to UnifiedFindings.  ``info`` is the web layer's word
        # for a statement about the *scanner's own* coverage -- "TLS chain
        # NOT_ASSESSED (local trust store incomplete)", "TLS chain verified".
        # compute_score weights it 0 for exactly that reason (defect D67), and
        # this map used to have no ``info`` key, so the MEDIUM default silently
        # promoted every coverage notice to a 4-point defect with a row in
        # by_severity and a place in remediation_priority (defect D75).  The
        # D67 contract has to hold on both sides of the boundary.
        severity_map = self._severity_map

        confidence_map = {
            "high": "high",
            "medium": "medium",
            "low": "low",
        }

        for finding in web_result.findings:
            unified = UnifiedFinding(
                scanner_name=self.name,
                scanner_version=self.version,
                scan_type=self.scan_type,
                title=finding.title,
                description=finding.detail,
                severity=severity_map.get(finding.severity, Severity.MEDIUM),
                category=finding.category,
                file_path=None,
                line_number=None,
                url=finding.endpoint,
                evidence=finding.evidence,
                recommendation=finding.recommendation,
                cwe_ids=[finding.cwe] if finding.cwe else [],
                confidence=confidence_map.get(finding.confidence, "medium"),
                scanner_metadata={
                    "original_severity": finding.severity,
                    "original_confidence": finding.confidence,
                    "endpoint": finding.endpoint,
                },
            )
            result.add_finding(unified)

        # Summary
        result.summary = web_result.summary
        result.metadata = {
            "final_url": web_result.final_url,
            "status_code": web_result.status_code,
            "technologies": web_result.technologies,
            "endpoints_count": len(web_result.endpoints),
            "network_traces": len(web_result.network),
            "cookies_count": len(web_result.cookies),
            "forms_count": len(web_result.forms),
            "js_files_count": len(web_result.js_files),
            "api_hints_count": len(web_result.api_hints),
            "score": web_result.score,
            "grade": web_result.grade,
            "playbook": web_result.playbook,
        }

        if hasattr(web_result, "advisories") and web_result.advisories:
            result.metadata["advisories"] = web_result.advisories
        if hasattr(web_result, "relevance") and web_result.relevance:
            result.metadata["exploit_relevance"] = web_result.relevance

        result.complete()
        return result

    def validate_config(self) -> list[str]:
        errors = []
        numeric_fields = {
            "timeout": (1, 300),
            "max_paths": (1, 1000),
            "max_crawl_pages": (1, 500),
            "max_js_files": (1, 100),
            "max_js_bytes": (1000, 50_000_000),
        }
        for field, (min_val, max_val) in numeric_fields.items():
            if field in self.config:
                try:
                    val = int(self.config[field]) if field != "timeout" else float(self.config[field])
                    if not (min_val <= val <= max_val):
                        errors.append(f"{field} must be between {min_val} and {max_val}")
                except ValueError:
                    errors.append(f"{field} must be a number")
        return errors

    def get_supported_targets(self) -> list[str]:
        return ["http://*", "https://*", "web:*", "url:*"]


def create_web_scanner(config: dict[str, Any] | None = None) -> WebScanner:
    """Factory function to create a WebScanner."""
    return WebScanner(config)