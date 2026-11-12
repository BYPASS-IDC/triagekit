"""One implementation of "scan a repository target", shared by CLI and API.

``api/app.py`` used to call ``scan_target`` from ``analyzers/repo_scan`` -- a
function that has never existed there -- so both repo-scan endpoints in the UI
answered every request with::

    cannot import name 'scan_target' from 'triagekit.core.analyzers.repo_scan'

The CLI had a working implementation, written inline inside the ``scan`` command,
with no test covering it because nothing imported it.  That is how the two
drifted: the UI pointed at a name that only ever existed in a comment.

The conversion below is the part worth sharing.  ``ScannerOrchestrator`` returns
``UnifiedFinding`` models; the security agent, the report renderer and the skill
selector all read the legacy ``Finding`` record.  Converting in two places is how
the ``cwe`` and ``rule_id`` fields get dropped from one of them -- which is the
same defect class as the web-to-agent crossing, where a CRITICAL CWE-89 arrived
at the skill selector with nothing to match on.

Usage::

    path, cleanup, legacy, orchestration = run_repo_scan("owner/repo", no_cve=True)
    try:
        ... use legacy (RepoScanResult) and orchestration (for SARIF/raw) ...
    finally:
        if cleanup:
            cleanup()
"""

from __future__ import annotations

import asyncio
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Optional

from .analyzers.repo_scan import Finding, RepoScanResult
from .repo_fetch import resolve_scan_target


@dataclass
class ScanRun:
    """A completed repository scan, in both shapes the callers need."""

    path: Any
    legacy: RepoScanResult
    orchestration: Any = None
    cleanup: Optional[Any] = None
    languages: list = field(default_factory=list)

    def dispose(self) -> None:
        """Remove a temporary clone.  Safe to call when there is nothing to do."""
        if self.cleanup:
            try:
                self.cleanup()
            except Exception:
                pass
            self.cleanup = None


def _to_legacy_findings(orchestration_result: Any) -> tuple:
    """Convert orchestrator findings into the legacy ``Finding`` record.

    ``cwe`` and ``rule_id`` are carried across deliberately: the rule id is how
    the report groups findings and how the skill selector recognises a class,
    and the first CWE is the primary class signal.  Dropping either one is what
    makes an otherwise-correct brief read as generic procedure.
    """
    out: list[Finding] = []
    for scan_result in getattr(orchestration_result, "scan_results", []) or []:
        for f in getattr(scan_result, "findings", []) or []:
            out.append(Finding(
                severity=str(getattr(f.severity, "value", f.severity) or ""),
                category=str(getattr(f, "category", "") or ""),
                title=str(getattr(f, "title", "") or ""),
                file=str(getattr(f, "file_path", "") or ""),
                line=int(getattr(f, "line_number", 0) or 0),
                snippet=str(getattr(f, "snippet", "") or "")[:160],
                recommendation=str(getattr(f, "recommendation", "") or ""),
                cwe=(f.cwe_ids[0] if getattr(f, "cwe_ids", None) else None),
                rule_id=str((getattr(f, "scanner_metadata", None) or {}).get("rule_id") or ""),
            ))
    return out, orchestration_result


def _aggregate(legacy_findings: list, orchestration_result: Any) -> tuple:
    """Score, grade and file count for a whole run, from the findings that exist.

    The old UI returned a hardcoded ``grade: "A"`` next to an averaged
    per-scanner score, so a scan of a clean repo and a scan of a badly broken
    one produced the same letter.  The weights are the ones ``cli.py`` and
    ``web_scan.compute_score`` already use, so one repo cannot read as a
    different severity depending on which surface scanned it.
    """
    penalty = sum(
        {"critical": 18, "high": 8, "medium": 3, "low": 1}.get(
            str(f.severity or "").lower(), 2)
        for f in legacy_findings
    )
    score = max(0.0, round(100.0 - min(penalty, 100.0), 1))
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 \
        else "D" if score >= 40 else "F"
    files = sum(
        int(getattr(r, "metadata", {}).get("files_scanned", 0) or 0)
        for r in getattr(orchestration_result, "scan_results", []) or []
    )
    # RepoScanResult.languages is a dict of name -> count, which is what
    # repo_scan populates and what the report renders.
    langs: Counter = Counter()
    for r in getattr(orchestration_result, "scan_results", []) or []:
        for name in getattr(r, "metadata", {}).get("languages", []) or []:
            langs[name] += 1
    return score, grade, files, dict(langs)


def run_repo_scan(
    target: str,
    *,
    branch: str = "",
    github_token: Optional[str] = None,
    no_cve: bool = False,
    max_files: int = 8000,
) -> ScanRun:
    """Resolve a target, run every scanner, and hand back both result shapes.

    Raises on an unresolvable target -- the caller decides whether that is a
    400 or a 500, and neither one is a silent empty scan.
    """
    from .scanners import OrchestratorConfig, ScanContext, ScannerOrchestrator

    path, cleanup = resolve_scan_target(
        target.strip(), github_token=github_token, branch=branch or None
    )
    path_str = str(path)
    config = OrchestratorConfig(
        scanner_configs={
            "repository_scanner": {
                "max_files": max_files,
                "max_packages": 0 if no_cve else 40,
            },
            "dependency_scanner": {"max_packages": 0 if no_cve else 40},
            "taint_analysis": {"max_files": max_files},
            "static_analysis": {},
            "heuristic_security": {},
        }
    )
    orchestrator = ScannerOrchestrator(config)
    orchestrator.initialize()
    context = ScanContext(target=path_str)
    orchestration_result = asyncio.run(orchestrator.run_scan(path_str, context))

    legacy_findings, _ = _to_legacy_findings(orchestration_result)
    score, grade, files, langs = _aggregate(legacy_findings, orchestration_result)

    legacy = RepoScanResult(root=path_str)
    legacy.findings = legacy_findings
    legacy.files_scanned = files
    legacy.languages = langs
    legacy.dependency_files = []
    legacy.cve_findings = []
    legacy.score = score
    legacy.grade = grade
    legacy.summary = (
        f"{len(legacy_findings)} finding(s) across {files} file(s) in "
        f"{len(langs)} language(s); score {score}/100 ({grade})."
    )
    return ScanRun(path=path, legacy=legacy, orchestration=orchestration_result,
                   cleanup=cleanup, languages=langs)
