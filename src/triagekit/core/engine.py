"""Multi-stage triage engine with security analysis."""

from __future__ import annotations
from .skills import skill_system_prefix
from typing import Any, Optional
from .analyzers.static import analyze_files, compute_static_risk, summarize_files
from .analyzers.security import cwe_for, scan_diff_for_security, security_signals_text
from .github_client import GitHubClient
from .llm import LLMClient
from .models import (
    ChangeType, CodeSuggestion, ImpactArea, ImpactAssessment,
    LabelSuggestion, RecommendedAction, RiskFactor, RiskLevel,
    SecurityFinding, SuggestionCategory, TriageResult,
)
from .prompts import SYSTEM, build_user


def _risk(v: str, default: str = "medium") -> RiskLevel:
    try:
        return RiskLevel(v)
    except Exception:
        return RiskLevel(default)


def _findings_for_skills(sec_findings_raw: list[dict[str, str]]) -> list[dict[str, Any]]:
    """Shape stage-1 heuristic findings for skill selection.

    ``scan_diff_for_security`` records ``type``/``severity``/``file``/``message``
    and no CWE; :func:`cwe_for` supplies the class identifiers, without which
    the finding-driven skill map has nothing to match on and the caller falls
    back to the static list -- which for pr_triage is the very thing that left
    the injection classes out.
    """
    out: list[dict[str, Any]] = []
    for f in sec_findings_raw or []:
        ftype = str(f.get("type") or "")
        out.append({
            "severity": f.get("severity") or "medium",
            "type": ftype,
            "file": f.get("file") or "",
            "message": f.get("message") or "",
            "cwe_ids": cwe_for(ftype),
        })
    return out


class TriageEngine:
    def __init__(self, github: Optional[GitHubClient] = None, llm: Optional[LLMClient] = None):
        self.github = github or GitHubClient()
        self.llm = llm or LLMClient()

    def full_triage(self, repo: str, number: int) -> TriageResult:
        pr = self.github.get_pull(repo, number)
        ctx = self.github.pr_context(pr)

        # Stage 1 — static + security heuristics
        insights = analyze_files(ctx["files"])
        static_score, static_signals = compute_static_risk(
            insights, ctx["additions"], ctx["deletions"], ctx["changed_files"]
        )
        file_summary = summarize_files(insights)

        sec_findings_raw = scan_diff_for_security(ctx["files"])
        sec_signals = security_signals_text(sec_findings_raw)

        if sec_findings_raw:
            critical_sec = sum(1 for f in sec_findings_raw if f.get("severity") == "critical")
            high_sec = sum(1 for f in sec_findings_raw if f.get("severity") == "high")
            static_score = min(10.0, static_score + critical_sec * 1.5 + high_sec * 0.8)
            static_signals = static_signals + [f"{len(sec_findings_raw)} heuristic security finding(s)"]

        # Stage 2 — deep structured reasoning (security-aware)
        try:
            # The skills the model receives follow what the diff FOUND.  Stage 1
            # already ran, so its heuristic findings are available here; a diff
            # touching authentication with a hardcoded-credential signal needs
            # the authn/authz and secrets skills in its prompt, and the static
            # pr_triage list mentions neither.
            _sys = skill_system_prefix("pr_triage", _findings_for_skills(sec_findings_raw)) + "\n\n" + SYSTEM
            data = self.llm.complete_json(
                _sys, build_user(ctx, static_signals, file_summary, sec_signals)
            )
        except Exception as llm_err:
            # Fallback: static/heuristic-only so CLI/UI still return a report
            data = {
                "summary": (
                    f"LLM triage unavailable ({type(llm_err).__name__}: {str(llm_err)[:240]}). "
                    f"Showing static/heuristic analysis only for PR #{number}."
                ),
                "one_line_verdict": "Partial result — configure a working LLM and re-run for full AI triage.",
                "primary_change_type": "security" if sec_findings_raw else "unknown",
                "risk_level": "high" if static_score >= 6.5 else ("medium" if static_score >= 3.5 else "low"),
                "risk_score": static_score,
                "risk_factors": [
                    {"name": s, "severity": "medium", "explanation": s}
                    for s in (static_signals or ["static analysis only"])[:8]
                ],
                "key_changes": [],
                "has_breaking_changes": False,
                "suggested_labels": [{"name": "needs-review", "confidence": 0.5, "reason": "LLM failed"}],
                "recommended_actions": [
                    {
                        "action": "Fix LLM (.env model/base_url) and re-run triage",
                        "priority": "high",
                        "rationale": str(llm_err)[:300],
                        "owner_hint": "maintainer",
                    }
                ],
                "suggestions": [],
                "security_findings": [],
                "test_coverage_impression": "unknown",
                "needs_human_review": True,
                "confidence": 0.3,
                "review_focus": ["Verify LLM configuration", "Review heuristic security findings"],
            }

        # Stage 3 — blend + normalize
        llm_score = float(data.get("risk_score", 5.0))
        blended = round(min(10.0, max(0.0, static_score * 0.30 + llm_score * 0.70)), 1)

        if blended >= 8.0:
            risk_level = RiskLevel.CRITICAL
        elif blended >= 5.5:
            risk_level = RiskLevel.HIGH
        elif blended >= 2.5:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW

        try:
            change_type = ChangeType(data.get("primary_change_type", "unknown"))
        except ValueError:
            change_type = ChangeType.UNKNOWN

        impact_raw = data.get("impact") or {}
        areas = []
        for a in impact_raw.get("areas", []):
            try:
                areas.append(ImpactArea(a))
            except ValueError:
                pass

        impact = ImpactAssessment(
            areas=areas,
            user_facing=bool(impact_raw.get("user_facing", False)),
            requires_migration=bool(impact_raw.get("requires_migration", False)),
            migration_notes=impact_raw.get("migration_notes"),
            rollback_difficulty=impact_raw.get("rollback_difficulty", "easy"),
        )

        risk_factors = [
            RiskFactor(
                name=r.get("name", "Unknown"),
                severity=_risk(r.get("severity")),
                explanation=r.get("explanation", ""),
                evidence=r.get("evidence"),
                mitigable=bool(r.get("mitigable", True)),
            )
            for r in data.get("risk_factors", [])
        ]

        labels = [
            LabelSuggestion(
                name=l["name"],
                confidence=float(l.get("confidence", 0.75)),
                reason=l.get("reason", ""),
            )
            for l in data.get("suggested_labels", []) if l.get("name")
        ]

        actions = [
            RecommendedAction(
                action=a["action"],
                priority=a.get("priority", "normal"),
                rationale=a.get("rationale", ""),
                owner_hint=a.get("owner_hint"),
            )
            for a in data.get("recommended_actions", []) if a.get("action")
        ]

        suggestions = []
        for s in data.get("suggestions", []):
            try:
                cat = SuggestionCategory(s.get("category", "cleanup"))
            except ValueError:
                cat = SuggestionCategory.CLEANUP
            suggestions.append(CodeSuggestion(
                category=cat,
                title=s.get("title", "Suggestion"),
                description=s.get("description", ""),
                severity=_risk(s.get("severity"), "medium"),
                file=s.get("file"),
                line_hint=s.get("line_hint"),
                suggested_change=s.get("suggested_change"),
                effort=s.get("effort", "medium"),
                impact=s.get("impact"),
            ))

        security_findings = []
        for sf in data.get("security_findings", []):
            security_findings.append(SecurityFinding(
                title=sf.get("title", "Security note"),
                severity=_risk(sf.get("severity"), "medium"),
                category=sf.get("category", "other"),
                file=sf.get("file"),
                description=sf.get("description", ""),
                recommendation=sf.get("recommendation", ""),
                cwe_hint=sf.get("cwe_hint"),
            ))

        existing = {(sf.file or "") + sf.title for sf in security_findings}
        for h in sec_findings_raw:
            key = (h.get("file") or "") + h.get("type", "")
            if key not in existing:
                security_findings.append(SecurityFinding(
                    title=h.get("type", "heuristic-finding").replace("-", " ").title(),
                    severity=_risk(h.get("severity", "medium")),
                    category="other",
                    file=h.get("file"),
                    description=h.get("message", ""),
                    recommendation="Review this finding and apply a safer pattern or confirm it is intentional.",
                ))

        critical = data.get("critical_files_touched") or [
            i.path for i in insights if i.is_critical or i.is_security_sensitive
        ]

        return TriageResult(
            repo=repo,
            number=number,
            title=ctx["title"],
            author=ctx["user"],
            url=ctx.get("html_url"),
            summary=data.get("summary", ""),
            one_line_verdict=data.get("one_line_verdict", ""),
            primary_change_type=change_type,
            risk_level=risk_level,
            risk_score=blended,
            risk_factors=risk_factors,
            has_breaking_changes=bool(data.get("has_breaking_changes")),
            breaking_notes=data.get("breaking_notes"),
            key_changes=data.get("key_changes", []),
            file_insights=insights,
            critical_files_touched=critical[:20],
            impact=impact,
            suggested_labels=labels,
            recommended_actions=actions,
            suggestions=suggestions,
            security_findings=security_findings,
            test_coverage_impression=data.get("test_coverage_impression", "unknown"),
            needs_human_review=bool(data.get("needs_human_review", True)),
            confidence=float(data.get("confidence", 0.75)),
            review_focus=data.get("review_focus", []),
        )

    def triage_markdown(self, repo: str, number: int) -> str:
        return self.full_triage(repo, number).to_markdown()
