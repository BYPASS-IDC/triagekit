"""Heuristic Security Scanner - wraps the existing heuristic security analyzer."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..analyzers.files_data import synthesize_files_data
from ..analyzers.security import (
    canonical_rule_ids,
    cwe_for,
    scan_diff_for_security,
    security_signals_text,
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


class HeuristicSecurityScanner(BaseScanner[ScanResult]):
    """Scanner for heuristic security signal extraction from diffs.

    Detects patterns for:
    - Command injection risks
    - SQL injection risks
    - XSS/eval risks
    - Unsafe deserialization
    - Hardcoded secrets
    - Weak cryptography
    - TLS verification disabled
    - Dependency file changes
    """

    def _get_metadata(self) -> ScannerMetadata:
        return ScannerMetadata(
            name="heuristic_security",
            version="1.0.0",
            scan_type=ScanType.HEURISTIC_SECURITY,
            description="Heuristic security pattern detection in code diffs",
            supported_languages=["*"],
            estimated_duration_seconds=10,
            tags=["heuristic", "pattern-matching", "security", "diff-analysis"],
        )

    async def _scan(self, context: ScanContext) -> ScanResult:
        result = ScanResult(
            scanner_name=self.name,
            scanner_version=self.version,
            scan_type=self.scan_type,
            target=context.target,
        )

        files_data = context.metadata.get("files_data", [])
        synth_stats: dict[str, Any] | None = None
        if not files_data:
            # D3: a local directory scan has no diff, so the payload is
            # synthesized.  It is labelled as such at every layer -- a fabricated
            # diff must never read like a real pull request.
            synthesized = synthesize_files_data(
                context.target,
                max_files=int(context.config.get("max_files", 1000)),
            )
            files_data = synthesized.files_data
            if not files_data:
                result.warnings.append(
                    "No files_data provided in context and no local directory to "
                    "synthesize one from; heuristic analysis needs a diff"
                )
                result.complete()
                return result
            synth_stats = synthesized.stats
            result.warnings.append(
                f"No PR diff supplied; analyzed {synth_stats['files_included']} "
                "in-scope local file(s) as a synthesized payload (status=synthesized, "
                "zero diff churn). This is a full-source scan, not a pull-request review."
            )

        # Run heuristic scan
        try:
            raw_findings = scan_diff_for_security(files_data)
        except Exception as e:
            result.errors.append(f"Heuristic scan failed: {e}")
            result.complete()
            return result

        # Convert to UnifiedFindings
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }

        for raw in raw_findings:
            finding = UnifiedFinding(
                scanner_name=self.name,
                scanner_version=self.version,
                scan_type=self.scan_type,
                title=raw["type"].replace("-", " ").title(),
                description=raw["message"],
                severity=severity_map.get(raw["severity"], Severity.MEDIUM),
                category=raw["type"],
                file_path=raw["file"],
                evidence=raw.get("message", ""),
                recommendation=self._get_recommendation(raw["type"]),
                cwe_ids=self._get_cwe_ids(raw["type"]),
                line_number=raw.get("line"),
                scanner_metadata={
                    "original_severity": raw["severity"],
                    "file": raw["file"],
                },
                layer="regex",
            )
            result.add_finding(finding)

        # Add summary signals
        signals = security_signals_text(raw_findings)
        result.metadata["signals"] = signals
        if synth_stats is not None:
            result.metadata["synthesized_files"] = synth_stats
        result.summary = (
            f"Heuristic security scan: {len(raw_findings)} findings "
            f"({result.counts['critical']}C, {result.counts['high']}H, "
            f"{result.counts['medium']}M, {result.counts['low']}L)"
            + (" [synthesized from local files, not a PR diff]" if synth_stats else "")
        )

        result.complete()
        return result

    def _get_recommendation(self, finding_type: str) -> str:
        """Remediation text for a finding type.

        The diff layer used to carry its own hand-written copy of this table, so
        a rule that existed in the canonical table had no recommendation here and
        fell through to "Review and harden this pattern".  The canonical
        mechanism/impact/fix/verify text is now the source of truth; the local
        map only covers the two diff-specific signals that have no canonical
        rule (a path was touched, a manifest changed).
        """
        from ..analyzers.repo_scan import RECS

        local = {
            "dependency-change": "Review dependency changes for known vulnerabilities; run dependency scanner",
            "sensitive-path": "Review authn/authz, crypto, and secret handling carefully",
        }
        if finding_type in local:
            return local[finding_type]

        for rule_id in canonical_rule_ids(finding_type):
            text = (RECS.get(rule_id) or "").strip()
            if text:
                return text
        return "Review and harden this pattern"

    def _get_cwe_ids(self, finding_type: str) -> list[str]:
        """CWE ids from the canonical rule table (see _get_recommendation)."""
        if finding_type == "dependency-change":
            return ["CWE-1104"]
        if finding_type == "sensitive-path":
            return []
        return cwe_for(finding_type)

    def validate_config(self) -> list[str]:
        return []

    def get_supported_targets(self) -> list[str]:
        return ["pr:*", "github:*", "diff:*", "path:*", "*"]


def create_heuristic_scanner(config: dict[str, Any] | None = None) -> HeuristicSecurityScanner:
    """Factory function to create a HeuristicSecurityScanner."""
    return HeuristicSecurityScanner(config)