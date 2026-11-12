"""Professional security-agent layer: prioritizes findings and builds a remediation plan.

Uses the configured LLM when available; otherwise produces a strong heuristic brief.
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional

from .repo_scan import RepoScanResult
from triagekit.core.skills import skill_system_prefix

_AGENT_SYSTEM_CORE = """You are an elite application security engineer performing a professional code security assessment.
Given static findings and dependency advisories, produce a concise executive security brief.

Return ONLY valid JSON with this shape:
{
  "executive_summary": "2-4 sentences for a maintainer or CISO",
  "overall_risk": "critical|high|medium|low",
  "attack_surface": ["short bullets of realistic attack paths"],
  "priority_fixes": [
    {"priority": 1, "title": "...", "why": "...", "how": "concrete remediation", "effort": "low|medium|high"}
  ],
  "quick_wins": ["easy high-value fixes"],
  "residual_risk": "what remains after fixes",
  "recommended_next_tools": ["CodeQL", "Semgrep", "Dependabot", "..."]
}
Be specific. Reference real file paths from the input when possible.
No markdown fences. Valid JSON only. Escape backslashes in strings.

CRITICAL -- risk versus coverage. Findings arrive in two distinct buckets and
you must never confuse them:
  * "findings_sample" holds findings the tool ASSESSED. Only these may drive
    overall_risk, attack_surface and priority_fixes.
  * "coverage_limitations" holds findings the tool could NOT assess. Their
    severity is "info" and they say so. They are statements about the limits of
    this scan, not about the target.

  attack_surface therefore takes ONLY entries derivable from findings_sample.
  Never place a coverage limitation in attack_surface: an unverified
  certificate chain, an unparsed manifest, an unreachable tool is a gap in what
  was measured, never a "realistic attack path". If a bullet is about something
  the scan could not check, it belongs in residual_risk, phrased as an open
  question. An "info" finding may not be promoted to any risk level."""


def _web_rule_id(category: str) -> str:
    return f"web_{category}" if category else ""


def web_findings_as_repo(
    web_findings: Any,
    *,
    url: str,
    final_url: str = "",
    score: float = 0.0,
    grade: str = "",
    summary: str = "",
) -> RepoScanResult:
    """Adapt a web scan's findings into the shape the agent consumes.

    One implementation for the CLI and both API paths.  This used to be three
    inline copies, and all three dropped ``cwe`` and ``rule_id`` on the floor --
    which is the second, independent reason a web scan's narrative came back
    generic: the skill selector matches the class from the CWE, so a CRITICAL
    CWE-89 finding that arrived with no CWE selected no SQL-injection skill, and
    the model was asked to explain an injection it had been told nothing about.
    ``web_scan.py``'s probe layer folds to ``WebFinding`` records that carry
    ``cwe``; it has to survive the crossing.
    """
    from .repo_scan import Finding, RepoScanResult

    adapted = RepoScanResult(root=url)
    adapted.findings = [
        Finding(
            severity=str(f.severity or ""),
            category=str(f.category or ""),
            title=str(f.title or ""),
            file=final_url or url,
            recommendation=getattr(f, "recommendation", "") or "",
            snippet=(getattr(f, "evidence", None) or getattr(f, "detail", "") or "")[:160],
            cwe=getattr(f, "cwe", None),
            rule_id=_web_rule_id(str(getattr(f, "category", "") or "")),
        )
        for f in (web_findings or [])
    ]
    adapted.score = score
    adapted.grade = grade
    adapted.summary = summary
    return adapted


def _heuristic_agent(result: RepoScanResult) -> dict[str, Any]:
    counts = result.counts()
    if counts["critical"]:
        overall = "critical"
    elif counts["high"]:
        overall = "high"
    elif counts["medium"]:
        overall = "medium"
    else:
        overall = "low"

    # group by rule
    by_rule: dict[str, list] = {}
    for f in result.findings:
        by_rule.setdefault(f.rule_id or f.title, []).append(f)

    priority_fixes = []
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    ranked = sorted(result.findings, key=lambda x: (order.get(x.severity, 9), x.file))
    seen = set()
    p = 1
    for f in ranked:
        key = f.rule_id or f.title
        if key in seen:
            continue
        seen.add(key)
        priority_fixes.append({
            "priority": p,
            "title": f"{f.title} ({f.severity})",
            "why": f"Found in {f.file}" + (f":{f.line}" if f.line else ""),
            "how": f.recommendation or "Review and harden.",
            "effort": "low" if f.severity in ("low", "medium") else "medium",
        })
        p += 1
        if p > 8:
            break

    for cf in result.cve_findings[:5]:
        priority_fixes.append({
            "priority": p,
            "title": f"Dependency advisory {cf.get('id')} — {cf.get('package')}",
            "why": (cf.get("summary") or "")[:160],
            "how": f"Upgrade {cf.get('package')}" + (f" to {cf['fixed']}" if cf.get("fixed") else " to a patched release"),
            "effort": "low",
        })
        p += 1
        if p > 12:
            break

    attack = []
    if any(f.rule_id and "sql" in f.rule_id for f in result.findings):
        attack.append("SQL injection could allow data theft or auth bypass via tainted queries.")
    if any(f.rule_id and "command" in (f.rule_id or "") for f in result.findings):
        attack.append("Command injection could yield remote code execution on the host.")
    if any(f.category == "secret" or (f.rule_id and "secret" in f.rule_id) for f in result.findings):
        attack.append("Leaked secrets in source enable account takeover and lateral movement.")
    if any("xss" in (f.rule_id or "") for f in result.findings):
        attack.append("XSS can steal sessions or perform actions as the victim user.")
    if result.cve_findings:
        attack.append("Known vulnerable dependencies expand exploitability without custom payloads.")
    if not attack:
        attack.append("No high-confidence attack path from heuristics; residual risk remains for logic bugs.")

    quick = []
    for f in ranked:
        if f.severity in ("critical", "high") and f.recommendation:
            quick.append(f"{f.file}: {f.recommendation}")
        if len(quick) >= 5:
            break

    return {
        "executive_summary": result.summary,
        "overall_risk": overall,
        "attack_surface": attack,
        "priority_fixes": priority_fixes,
        "quick_wins": quick or ["Keep dependencies updated", "Enable branch protection and CI SAST"],
        "residual_risk": "Heuristic scan cannot prove absence of vulnerabilities. AuthZ logic, business rules, and novel bugs need human or SAST review.",
        "recommended_next_tools": ["Semgrep or CodeQL", "Dependabot/OSV-Scanner", "Secret scanning (gitleaks)", "Penetration test for critical apps"],
    }


# Words that mark a finding as a statement about what the scan could not
# establish.  ``_strip_coverage_from_attack_surface`` uses them to recognise an
# attack-surface bullet that is really a restatement of a coverage limitation.
_COVERAGE_MARKERS = (
    "not_assessed", "not assessed", "unable to verify", "inability to verify",
    "cannot verify", "could not verify", "failed to verify", "not verified",
    "unable to complete", "could not complete", "local trust", "trust store",
    "not parsed", "unparsed", "unclassified", "not known", "issuer",
)

# Words that carry no signal about *which* finding a bullet describes.  Left in,
# they inflate the apparent overlap between any two security statements -- which
# is exactly how a coverage limitation slipping past this filter looks like a
# genuine attack path.
_OVERLAP_STOPWORDS = frozenset("""
the and for with this that due when from into via are was were has have had
issue issues problem problems potential attack attacks surface findings finding
risk risks scanning scan scanner tool target should would could will can may
also not but all any its their there here what which while such more most
""".split())


def _distinctive_words(text: str) -> set[str]:
    """Content words of a string, lowercased, naively de-pluralised.

    ``certificates`` and ``certificate`` are the same subject; ``tls`` and
    ``trust`` are strong evidence of the TLS coverage note while ``potential``
    and ``issues`` are present in nearly every security sentence.
    """
    raw = re.split(r"[^a-z0-9]+", str(text).lower())
    words = set()
    for w in raw:
        if len(w) < 3 or w in _OVERLAP_STOPWORDS:
            continue
        if len(w) > 4 and w.endswith("s") and not w.endswith("ss"):
            w = w[:-1]
        words.add(w)
    return words


def _is_coverage_finding(f) -> bool:
    """True when a finding records a limit of the scan rather than a risk.

    Severity ``info`` is the contract the scanners use for this (see the TLS
    probe in web_scan.py and the dependency coverage sections).  A finding is
    also treated as coverage when its own text says the tool could not assess
    it, so a caller that drops the severity cannot smuggle a limitation back in.
    """
    severity = str(getattr(f, "severity", "") or "").lower()
    if severity in ("info", "informational"):
        return True
    blob = " ".join(str(x or "") for x in (
        getattr(f, "title", ""), getattr(f, "recommendation", ""),
        getattr(f, "snippet", ""))).lower()
    return any(marker in blob for marker in _COVERAGE_MARKERS)


def _agent_evidence(result: RepoScanResult) -> dict[str, Any]:
    """Shape the scan into the evidence payload for the model.

    Findings the tool assessed and limitations it could not assess go in
    SEPARATE buckets.  Putting them in one list is what let an informational
    "[info] TLS chain NOT_ASSESSED (local trust store incomplete)" finding come
    back out of the model as a bullet in attack_surface (defect D68).
    """
    assessed: list[dict[str, Any]] = []
    coverage: list[dict[str, Any]] = []
    for f in result.findings[:40]:
        item = {
            "sev": f.severity,
            "rule": getattr(f, "rule_id", None),
            "file": f.file,
            "line": f.line,
            "snip": (f.snippet or "")[:100],
        }
        if _is_coverage_finding(f):
            item["reason"] = str(f.recommendation or "")[:160]
            coverage.append(item)
        else:
            assessed.append(item)
    return {
        "score": result.score,
        "grade": result.grade,
        "summary": result.summary,
        "languages": result.languages,
        "findings_sample": assessed,
        "coverage_limitations": coverage,
        "cves_sample": result.cve_findings[:20],
        "counts": result.counts(),
    }


def _strip_coverage_from_attack_surface(brief: dict[str, Any], result: RepoScanResult) -> dict[str, Any]:
    """Remove attack-surface bullets that restate a coverage limitation.

    The model is instructed not to do this; the instruction is not a guarantee,
    so the merged brief is checked too.  A bullet is dropped only when it
    overlaps the text of a finding the tool could not assess -- a genuine attack
    path never shares that vocabulary.
    """
    surface = brief.get("attack_surface")
    if not isinstance(surface, list) or not surface:
        return brief
    coverage_texts = [
        f for f in result.findings if _is_coverage_finding(f)
    ]
    if not coverage_texts:
        return brief

    def _words(text: str) -> set[str]:
        return _distinctive_words(text)

    vocab = [_words(" ".join(str(x or "") for x in (
        f.title, f.recommendation, f.snippet, getattr(f, "rule_id", "") or "")))
        for f in coverage_texts]

    kept: list[Any] = []
    for bullet in surface:
        words = _words(bullet)
        if not words:
            kept.append(bullet)
            continue
        # A bullet is a restatement of a limitation when it shares most of its
        # content vocabulary with one, or when it is dominated by coverage
        # markers.  Stopwords are removed and plurals folded first: "Potential
        # connection issues due to inability to verify SSL certificates" shares
        # tls/ssl/certificate/trust/verify with the TLS coverage note and
        # nothing else, and without that normalisation the boilerplate words
        # ("potential", "issues", "due") dilute the ratio below any useful
        # threshold -- which is how this bullet survived the first version.
        marker_hits = sum(1 for m in _COVERAGE_MARKERS if m.replace("_", " ") in str(bullet).lower())
        overlap = max(
            len(words & v) / max(1, len(words)) for v in vocab
        ) if vocab else 0.0
        if overlap >= 0.5 or marker_hits >= 2:
            continue
        kept.append(bullet)
    brief["attack_surface"] = kept
    return brief


def run_security_agent(result: RepoScanResult, use_llm: bool = True, operation: str = "agent") -> dict[str, Any]:
    brief = _heuristic_agent(result)
    # The skills the model receives are chosen by what the scan FOUND, not by the
    # operation it ran under.  A web scan reporting a CRITICAL SQL injection
    # needs 09-sql-injection.md in its prompt; the static list for web_scan never
    # mentioned it, and then dropped five more skills to the 60 KB budget, so the
    # model wrote generic procedure about a specific defect.
    AGENT_SYSTEM = (
        skill_system_prefix(operation, result.findings) + "\n\n" + _AGENT_SYSTEM_CORE
    )
    if not use_llm:
        return brief

    try:
        from ..llm import LLMClient
        client = LLMClient()
    except Exception:
        return brief

    # Compact evidence for the model, with assessed findings and coverage
    # limitations in separate buckets.
    user = json.dumps(_agent_evidence(result), ensure_ascii=False)

    try:
        data = client.complete_json(AGENT_SYSTEM, user)
        # merge: prefer LLM narrative, keep structure
        for k in ("executive_summary", "overall_risk", "attack_surface", "priority_fixes",
                  "quick_wins", "residual_risk", "recommended_next_tools"):
            if k in data and data[k]:
                brief[k] = data[k]
    except Exception:
        pass
    # An informational finding may never reach attack_surface, whatever the
    # model returned (defect D68).
    _strip_coverage_from_attack_surface(brief, result)
    return brief
