"""Static Analysis Scanner - wraps the existing static analyzer."""

from __future__ import annotations

from typing import Any

from ..analyzers.files_data import SYNTHESIZED_STATUS, synthesize_files_data
from ..analyzers.static import analyze_files, compute_static_risk, content_flags, summarize_files
from ..models import FileInsight
from .base import (
    BaseScanner,
    ScanContext,
    ScanResult,
    ScanType,
    ScannerMetadata,
    Severity,
    UnifiedFinding,
)


class StaticAnalysisScanner(BaseScanner[ScanResult]):
    """Scanner for static risk analysis of PR file changes.

    Computes risk score based on:
    - Security-sensitive files touched
    - Critical path files
    - API surface files
    - Change churn (lines added/deleted)
    - Number of changed files
    - Test file presence (positive signal)
    """

    def _get_metadata(self) -> ScannerMetadata:
        return ScannerMetadata(
            name="static_analysis",
            version="1.0.0",
            scan_type=ScanType.STATIC_ANALYSIS,
            description="Static risk scoring based on file change patterns",
            supported_languages=["*"],
            estimated_duration_seconds=5,
            tags=["static", "risk-scoring", "pr-analysis"],
        )

    async def _scan(self, context: ScanContext) -> ScanResult:
        result = ScanResult(
            scanner_name=self.name,
            scanner_version=self.version,
            scan_type=self.scan_type,
            target=context.target,
        )

        # Get files data from context
        files_data = context.metadata.get("files_data", [])
        synth_stats: dict[str, Any] | None = None
        if not files_data:
            # D3: a local directory scan has no diff, so the payload is
            # synthesized and labelled as such.  ``compute_static_risk`` is
            # calibrated on diffs, so a synthesized payload reports only its
            # COMPOSITION signals -- the synthesized entries carry zero diff
            # churn by construction (see analyzers/files_data.py), which keeps a
            # 6 000-line repository from scoring as a "very large diff".
            synthesized = synthesize_files_data(
                context.target,
                max_files=int(context.config.get("max_files", 1000)),
            )
            files_data = synthesized.files_data
            if not files_data:
                result.warnings.append("No files_data provided in context")
                result.complete()
                return result
            synth_stats = synthesized.stats
            result.warnings.append(
                f"No PR diff supplied; risk computed over {synth_stats['files_included']} "
                "in-scope local file(s) as a synthesized payload. Composition signals only "
                "(security-sensitive / critical-path / api-surface) -- not comparable to a "
                "pull-request risk score, because a directory scan has no diff."
            )

        # On a synthesized (directory) payload there is no changed-file list to
        # score, so the path heuristic in analyze_files has almost nothing to
        # classify: app/server.py matches no security/critical/api path fragment.
        # Judge those files by their content as well, and say which basis each
        # flag came from -- a reviewer must be able to tell "named auth/" from
        # "calls subprocess".
        content_by_path: dict[str, set[str]] = {}
        if synth_stats is not None:
            for entry in files_data:
                flags = content_flags(entry.get("patch") or "")
                if flags:
                    content_by_path[entry.get("filename") or entry.get("path") or ""] = flags

        # Analyze files
        try:
            insights = analyze_files(files_data, content_by_path or None)
        except Exception as e:
            result.errors.append(f"File analysis failed: {e}")
            result.complete()
            return result

        # Compute static risk
        additions = sum(int(f.get("additions", 0)) for f in files_data)
        deletions = sum(int(f.get("deletions", 0)) for f in files_data)
        changed_files = len(files_data)

        try:
            static_score, signals = compute_static_risk(insights, additions, deletions, changed_files)
        except Exception as e:
            result.errors.append(f"Risk computation failed: {e}")
            result.complete()
            return result

        # Convert insights to UnifiedFindings
        for insight in insights:
            # Only create findings for notable files
            flags = []
            if insight.is_security_sensitive:
                flags.append("security-sensitive")
            if insight.is_critical:
                flags.append("critical-path")
            if insight.is_api_surface:
                flags.append("api-surface")
            if insight.is_test:
                flags.append("test")
            if insight.additions + insight.deletions > 400:
                flags.append("large-change")

            derived = content_by_path.get(insight.path, set())
            content_flags_found = sorted(
                f for f in derived
                if f not in flags and f != "test"
            )
            flags.extend(content_flags_found)

            if flags:
                if insight.status == SYNTHESIZED_STATUS:
                    # Do not describe an in-scope local file as "modified in a PR".
                    desc = (
                        f"File in scan scope: {insight.path} "
                        f"(synthesized from local tree, not a PR diff)"
                    )
                else:
                    desc = (
                        f"File modified in PR: {insight.path} ({insight.status}) "
                        f"+{insight.additions}/-{insight.deletions}"
                    )
                finding = UnifiedFinding(
                    scanner_name=self.name,
                    scanner_version=self.version,
                    scan_type=self.scan_type,
                    title=f"File in scope: {insight.path}",
                    description=desc,
                    severity=Severity.LOW,
                    category="file-change",
                    file_path=insight.path,
                    line_number=None,
                    evidence=f"Status: {insight.status}, Flags: {', '.join(flags)}"
                             + (f", of which from content: {', '.join(content_flags_found)}"
                                if content_flags_found else ""),
                    recommendation="Review changes in this file for security implications",
                    tags=flags,
                    scanner_metadata={
                        "status": insight.status,
                        "additions": insight.additions,
                        "deletions": insight.deletions,
                        "is_security_sensitive": insight.is_security_sensitive,
                        "is_critical": insight.is_critical,
                        "is_api_surface": insight.is_api_surface,
                        "is_test": insight.is_test,
                    },
                    layer="risk",
                )
                result.add_finding(finding)

        # Add overall static risk finding
        risk_finding = UnifiedFinding(
            scanner_name=self.name,
            scanner_version=self.version,
            scan_type=self.scan_type,
            title="Static Risk Score",
            description=f"Computed static risk score: {static_score}/10.0 based on {len(signals)} signals",
            severity=self._score_to_severity(static_score),
            category="risk-score",
            evidence="\n".join(signals),
            recommendation="Review high-risk file changes; consider additional security review",
            scanner_metadata={
                "static_score": static_score,
                "signals": signals,
                "additions": additions,
                "deletions": deletions,
                "changed_files": changed_files,
                "basis": "synthesized-from-local-tree" if synth_stats else "pr-diff",
            },
            layer="risk",
        )
        result.add_finding(risk_finding)

        # Summary
        result.summary = (
            f"Static analysis: {len(insights)} files analyzed, "
            f"risk score {static_score}/10, {len(signals)} risk signals"
            + (" [composition only -- synthesized from local tree, no diff]" if synth_stats else "")
        )
        # merge, do not replace: `progress` written by progress_cb above is still
        # useful, and dropping it made the progress bar vanish on completion.
        result.metadata.update({
            "static_score": static_score,
            "signals": signals,
            "file_summary": summarize_files(insights),
            "basis": "synthesized-from-local-tree" if synth_stats else "pr-diff",
        })
        if synth_stats is not None:
            result.metadata["synthesized_files"] = synth_stats

        result.complete()
        return result

    def _score_to_severity(self, score: float) -> Severity:
        if score >= 8.0:
            return Severity.CRITICAL
        elif score >= 5.5:
            return Severity.HIGH
        elif score >= 2.5:
            return Severity.MEDIUM
        elif score > 0:
            return Severity.LOW
        return Severity.INFORMATIONAL

    def validate_config(self) -> list[str]:
        return []

    def get_supported_targets(self) -> list[str]:
        return ["pr:*", "github:*", "path:*", "*"]


def create_static_scanner(config: dict[str, Any] | None = None) -> StaticAnalysisScanner:
    """Factory function to create a StaticAnalysisScanner."""
    return StaticAnalysisScanner(config)