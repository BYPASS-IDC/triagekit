"""Structured result models — risk, findings, suggestions, and review focus."""

from __future__ import annotations
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ChangeType(str, Enum):
    FEATURE = "feature"
    BUGFIX = "bugfix"
    REFACTOR = "refactor"
    DOCS = "docs"
    TEST = "test"
    CHORE = "chore"
    SECURITY = "security"
    BREAKING = "breaking"
    PERFORMANCE = "performance"
    DEPENDENCY = "dependency"
    UNKNOWN = "unknown"


class SuggestionCategory(str, Enum):
    FIX = "fix"
    CLEANUP = "cleanup"
    REFACTOR = "refactor"
    TEST = "test"
    SECURITY = "security"
    PERFORMANCE = "performance"
    DOCS = "docs"
    DX = "dx"
    API = "api"
    MIGRATION = "migration"


class ImpactArea(str, Enum):
    RUNTIME = "runtime"
    API = "api"
    DATA = "data"
    SECURITY = "security"
    BUILD = "build"
    DX = "dx"
    DOCS = "docs"


class RiskFactor(BaseModel):
    name: str
    severity: RiskLevel
    explanation: str
    evidence: Optional[str] = None
    mitigable: bool = True


class FileInsight(BaseModel):
    path: str
    status: str
    additions: int = 0
    deletions: int = 0
    is_critical: bool = False
    is_security_sensitive: bool = False
    is_api_surface: bool = False
    is_test: bool = False
    reason: Optional[str] = None


class LabelSuggestion(BaseModel):
    name: str
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str


class RecommendedAction(BaseModel):
    action: str
    priority: str = "normal"
    rationale: str
    owner_hint: Optional[str] = None


class CodeSuggestion(BaseModel):
    category: SuggestionCategory
    title: str
    description: str
    severity: RiskLevel = RiskLevel.MEDIUM
    file: Optional[str] = None
    line_hint: Optional[str] = None
    suggested_change: Optional[str] = None
    effort: str = "medium"
    impact: Optional[str] = None


class SecurityFinding(BaseModel):
    title: str
    severity: RiskLevel
    category: str
    file: Optional[str] = None
    description: str
    recommendation: str
    cwe_hint: Optional[str] = None


class ImpactAssessment(BaseModel):
    areas: list[ImpactArea] = Field(default_factory=list)
    user_facing: bool = False
    requires_migration: bool = False
    migration_notes: Optional[str] = None
    rollback_difficulty: str = "easy"


class TriageResult(BaseModel):
    repo: str
    number: int
    title: str
    author: str
    url: Optional[str] = None

    summary: str
    one_line_verdict: str
    primary_change_type: ChangeType = ChangeType.UNKNOWN

    risk_level: RiskLevel
    risk_score: float = Field(ge=0.0, le=10.0)
    risk_factors: list[RiskFactor] = Field(default_factory=list)
    has_breaking_changes: bool = False
    breaking_notes: Optional[str] = None

    key_changes: list[str] = Field(default_factory=list)
    file_insights: list[FileInsight] = Field(default_factory=list)
    critical_files_touched: list[str] = Field(default_factory=list)
    impact: ImpactAssessment = Field(default_factory=ImpactAssessment)

    suggested_labels: list[LabelSuggestion] = Field(default_factory=list)
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    suggestions: list[CodeSuggestion] = Field(default_factory=list)
    security_findings: list[SecurityFinding] = Field(default_factory=list)

    test_coverage_impression: str = "unknown"
    needs_human_review: bool = True
    confidence: float = Field(ge=0.0, le=1.0, default=0.75)
    review_focus: list[str] = Field(default_factory=list)

    def to_markdown(self) -> str:
        lines = [
            f"# Deep Triage — PR #{self.number}: {self.title}",
            "",
            f"**Author:** @{self.author}  ",
            f"**Risk:** `{self.risk_level.value.upper()}` ({self.risk_score:.1f}/10)  ",
            f"**Type:** {self.primary_change_type.value}  ",
            f"**Breaking:** {'YES — ' + (self.breaking_notes or 'see notes') if self.has_breaking_changes else 'No'}  ",
            f"**Confidence:** {self.confidence:.0%}  ",
            f"**Needs human review:** {'Yes' if self.needs_human_review else 'No'}",
            "",
            "## Summary",
            self.summary,
            "",
            "## Verdict",
            f"> {self.one_line_verdict}",
        ]

        if self.key_changes:
            lines += ["", "## Key Changes"]
            lines += [f"- {c}" for c in self.key_changes]

        if self.security_findings:
            lines += ["", "## Security Findings"]
            for sf in self.security_findings:
                lines.append(f"### [{sf.severity.value.upper()}] {sf.title}")
                lines.append(f"- Category: {sf.category}")
                if sf.file:
                    lines.append(f"- File: `{sf.file}`")
                lines.append(f"- {sf.description}")
                lines.append(f"- **Recommendation:** {sf.recommendation}")
                if sf.cwe_hint:
                    lines.append(f"- Hint: {sf.cwe_hint}")
                lines.append("")

        if self.impact.areas or self.impact.requires_migration:
            lines += ["", "## Impact"]
            if self.impact.areas:
                lines.append(f"- Areas: {', '.join(a.value for a in self.impact.areas)}")
            lines.append(f"- User-facing: {'Yes' if self.impact.user_facing else 'No'}")
            lines.append(f"- Requires migration: {'Yes' if self.impact.requires_migration else 'No'}")
            if self.impact.migration_notes:
                lines.append(f"- Migration: {self.impact.migration_notes}")
            lines.append(f"- Rollback difficulty: {self.impact.rollback_difficulty}")

        if self.risk_factors:
            lines += ["", "## Risk Factors"]
            for rf in self.risk_factors:
                lines.append(f"- **{rf.name}** ({rf.severity.value}): {rf.explanation}")

        # A finding that says WHAT is wrong without saying how an attacker gets
        # in, and how to prove the fix worked, leaves the reader to guess at
        # both -- so the defensive PoC section is part of the report, not an
        # optional extra.
        try:
            from ..analyzers.poc import pocs_for_findings, poc_markdown

            pocs = pocs_for_findings(self.security_findings)
            if pocs:
                lines += ["", poc_markdown(pocs).rstrip("\n")]
        except Exception:
            # The PoC section is additive: a failure here must not cost the
            # reader the rest of the report.
            pass

        if self.review_focus:
            lines += ["", "## Review Focus (look here first)"]
            lines += [f"- {x}" for x in self.review_focus]

        if self.suggestions:
            lines += ["", "## Suggestions & Fixes"]
            for s in self.suggestions:
                lines.append(f"### [{s.category.value.upper()}] {s.title}")
                lines.append(f"- Severity: {s.severity.value} · Effort: {s.effort}")
                lines.append(f"- {s.description}")
                if s.file:
                    lines.append(f"- File: `{s.file}`" + (f" ({s.line_hint})" if s.line_hint else ""))
                if s.suggested_change:
                    lines.append(f"- Suggestion: `{s.suggested_change}`")
                if s.impact:
                    lines.append(f"- Impact: {s.impact}")
                lines.append("")

        if self.critical_files_touched:
            lines += ["## Critical Files"]
            lines += [f"- `{f}`" for f in self.critical_files_touched]

        if self.suggested_labels:
            labels = ", ".join(f"`{l.name}` ({l.confidence:.0%})" for l in self.suggested_labels)
            lines += ["", "## Suggested Labels", labels]

        if self.recommended_actions:
            lines += ["", "## Recommended Actions"]
            for a in self.recommended_actions:
                who = f" [{a.owner_hint}]" if a.owner_hint else ""
                lines.append(f"- **{a.action}** ({a.priority}){who} — {a.rationale}")

        lines += [
            "",
            "---",
            "*Security review is heuristic + LLM-assisted. It does not replace dedicated SAST, dependency scanning, or a full security audit.*",
        ]
        return "\n".join(lines).strip() + "\n"
