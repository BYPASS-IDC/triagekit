"""Maximum static signal extraction — no LLM."""

from __future__ import annotations
import re
from typing import Any, Optional
from ..config import get_settings
from ..models import FileInsight

TEST_IND = ("test_", "_test.", "/tests/", "tests/", "spec.", ".spec.", "__tests__", "/test/", "testing/")
API_IND = ("api/", "routes/", "endpoints/", "handlers/", "controllers/", "public/")

# ---------------------------------------------------------------------------
# Content-derived composition flags
# ---------------------------------------------------------------------------
# ``analyze_files`` classifies a file by its PATH: a file called
# ``auth/session.py`` is security-sensitive and a file called ``app/server.py``
# is not, no matter that it hardcodes a secret, shells out, and unpickles request
# bodies.  On a directory scan (where the payload is synthesized from the local
# tree and there is no changed-file list to score) the path heuristic alone
# therefore reports nothing for most real projects.
#
# These flags are judged by what the file DOES.  They deliberately overlap the
# repository scanner's rules -- this is a triage signal ("start here"), not a
# finding, and it must never be counted as one.

_CONTENT_SIGNALS: tuple[tuple[str, "re.Pattern[str]"], ...] = (
    ("security-sensitive", re.compile(
        r"(?i)\b(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key"
        r"|bearer|credential|oauth|jwt|session[_-]?id|set[_-]?cookie)\b")),
    ("security-sensitive", re.compile(
        r"(?i)\b(?:hashlib\.(?:md5|sha1|sha256)|bcrypt|scrypt|argon2|pbkdf2|hmac|crypto\.|"
        r"createHash|createHmac|MessageDigest|Cipher\.getInstance|SSLContext|ssl\.)_?")),
    ("critical-path", re.compile(
        r"(?i)\b(?:os\.system|subprocess\.|os\.popen|shell\s*=\s*True|child_process|execSync"
        r"|Runtime\.exec|ProcessBuilder|popen\s*\()")),
    ("critical-path", re.compile(
        r"(?i)\b(?:pickle\.loads|yaml\.load|unserialize|ObjectInputStream|BinaryFormatter"
        r"|Marshal\.load|readObject\s*\()")),
    ("critical-path", re.compile(
        r"(?i)(?:\.execute\s*\(|\.query\s*\(|SELECT\s+\w+\s+.*\bFROM\b|prepareStatement"
        r"|createQuery|executemany\s*\()")),
    ("api-surface", re.compile(
        r"(?i)(?:@app\.(?:get|post|put|delete|patch|route)|@router\.|app\.(?:get|post|put|delete)\s*\(|"
        r"@(?:Get|Post|Put|Delete|Request)Mapping|@RestController|@Controller|@path\s*\()")),
)


def content_flags(text: str) -> set[str]:
    """Composition flags derived from a file's own content.

    Returns a subset of ``{"security-sensitive", "critical-path", "api-surface"}``.
    Classification only: this is where a reviewer should start, never evidence
    that a defect exists.
    """
    if not text:
        return set()
    found: set[str] = set()
    for flag, pattern in _CONTENT_SIGNALS:
        if flag not in found and pattern.search(text):
            found.add(flag)
    return found

def analyze_files(
    files_data: list[dict[str, Any]],
    content_flags_by_path: Optional[dict[str, set[str]]] = None,
) -> list[FileInsight]:
    """Classify each file by path, optionally augmented by content-derived flags.

    ``content_flags_by_path`` maps a filename to the flags returned by
    :func:`content_flags`.  It exists because the path heuristic alone classifies
    almost nothing in a real project: ``app/server.py`` matches no security,
    critical, or api path fragment even when it hardcodes a secret and shells
    out.  Content flags are unioned in, never substituted, so a path signal is
    still reported when the content is silent.
    """
    s = get_settings()
    out: list[FileInsight] = []
    for f in files_data:
        path = f.get("filename") or f.get("path") or ""
        status = f.get("status", "modified")
        adds = int(f.get("additions") or 0)
        dels = int(f.get("deletions") or 0)
        lower = path.lower()

        is_test = any(t in lower for t in TEST_IND)
        is_sec = any(p in lower for p in s.security_paths)
        is_crit = any(p in lower for p in s.critical_paths) or is_sec
        is_api = any(p in lower for p in s.api_surface_paths) or any(p in lower for p in API_IND)

        if content_flags_by_path:
            derived = content_flags_by_path.get(path) or set()
            is_sec = is_sec or "security-sensitive" in derived
            is_crit = is_crit or "critical-path" in derived
            is_api = is_api or "api-surface" in derived

        if "migration" in lower or "schema" in lower:
            is_crit = True
        if any(x in lower for x in ("auth", "security", "crypto", "password", "jwt", "oauth")):
            is_sec = is_crit = True

        reasons = []
        if is_sec: reasons.append("security-sensitive")
        if is_crit and not is_sec: reasons.append("critical path")
        if is_api: reasons.append("api-surface")
        if is_test: reasons.append("test")
        if adds + dels > 400: reasons.append("large-change")

        out.append(FileInsight(
            path=path, status=status, additions=adds, deletions=dels,
            is_critical=is_crit, is_security_sensitive=is_sec,
            is_api_surface=is_api, is_test=is_test,
            reason="; ".join(reasons) or None,
        ))
    return out


def compute_static_risk(insights: list[FileInsight], additions: int, deletions: int, changed_files: int):
    score = 0.0
    signals: list[str] = []

    sec = sum(1 for i in insights if i.is_security_sensitive)
    crit = sum(1 for i in insights if i.is_critical)
    api = sum(1 for i in insights if i.is_api_surface)
    tests = sum(1 for i in insights if i.is_test)
    churn = additions + deletions

    if sec:
        score += 2.8 * min(sec, 3)
        signals.append(f"{sec} security-sensitive file(s)")
    if crit:
        score += 1.3 * min(crit, 5)
        signals.append(f"{crit} critical-path file(s)")
    if api:
        score += 1.1 * min(api, 3)
        signals.append(f"{api} API-surface file(s)")
    if churn > 1000:
        score += 2.2; signals.append(f"very large diff ({churn} lines)")
    elif churn > 400:
        score += 1.1; signals.append(f"large diff ({churn} lines)")
    if changed_files > 30:
        score += 1.5; signals.append(f"very wide change ({changed_files} files)")
    elif changed_files > 15:
        score += 0.7; signals.append(f"wide change ({changed_files} files)")

    # Positive signal
    if tests and churn > 30:
        score = max(0.0, score - 1.15)
        signals.append(f"includes {tests} test file(s) (positive)")

    return min(10.0, round(score, 2)), signals


def summarize_files(insights: list[FileInsight], limit: int = 50) -> str:
    lines = []
    for i in insights[:limit]:
        flags = []
        if i.is_security_sensitive: flags.append("SECURITY")
        if i.is_critical: flags.append("CRITICAL")
        if i.is_api_surface: flags.append("API")
        if i.is_test: flags.append("TEST")
        flag = f" [{', '.join(flags)}]" if flags else ""
        lines.append(f"- {i.path} ({i.status}) +{i.additions}/-{i.deletions}{flag}")
    return "\n".join(lines) or "No files"