"""Automatic skill assignment — no manual selection required.

Maps each operation (pr_triage, repo_scan, web_scan) to the SKILLS/*.md
guides and injects them into agent/LLM context.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Iterable

# package root → repo root skills/
_PKG = Path(__file__).resolve().parent.parent  # triagekit/
_CANDIDATES = [
    # The real directory is lowercase ``skills`` at the repo root.  Only the
    # uppercase spelling was listed here, so nothing matched on a case-sensitive
    # filesystem and load_skills_text() silently returned its fallback text --
    # every skill was ignored on Linux/macOS while appearing to work on Windows.
    _PKG.parent.parent / "skills",           # <repo>/skills
    _PKG.parent.parent / "SKILLS",           # alternate capitalisation
    _PKG.parent.parent.parent / "skills",
    _PKG.parent.parent.parent / "SKILLS",
    Path.cwd() / "skills",
    Path.cwd() / "SKILLS",
    _PKG / "skills",                         # packaged copy
    Path(__file__).resolve().parent.parent / "skills",
]

# A rich operational skill needs more than one screen to be useful; the old
# 3 500-char ceiling cut every one of them off mid-sentence, which is worse than
# short: the model reads a truncated instruction as a complete one.
_MAX_SKILL_CHARS = 12_000

# A single skill can be rich; the ASSEMBLED set is what goes into a prompt, and
# it has to fit in one.  Before this budget existed, `repo_scan` concatenated
# 21 full skills into a ~180,000-character prompt: the model either hit its
# context ceiling or spent its whole window reading procedure instead of doing
# the task.  Ordering is deliberate -- the first entries are the gates and the
# procedures that every finding depends on, and the per-class detail degrades
# gracefully behind them.
_MAX_SKILLS_TOTAL_CHARS = 60_000

# The authorization gate is never dropped: it is the one skill whose absence
# turns a defensive scan into an unauthorized one.
_ALWAYS_INCLUDE = {"01-authorized-use.md"}

SKILL_MAP: dict[str, list[str]] = {
    "pr_triage": [
        "01-authorized-use.md", "02-pr-triage.md", "06-injection-surface.md",
        "07-remediation-playbook.md", "26-finding-narrative.md",
        "27-false-positive-control.md", "28-report-quality.md",
        "09-sql-injection.md", "11-command-injection.md", "12-path-traversal.md",
        "13-secrets-and-tokens.md", "15-authn-authz.md", "10-xss.md",
    ],
    "repo_scan": [
        "01-authorized-use.md", "03-repo-scan.md", "26-finding-narrative.md",
        "27-false-positive-control.md", "06-injection-surface.md",
        "07-remediation-playbook.md", "28-report-quality.md",
        "29-general-lang-scanner.md", "13-secrets-and-tokens.md",
        "18-dependency-cve.md", "05-exploitdb-intel.md",
        "09-sql-injection.md", "11-command-injection.md", "12-path-traversal.md",
        "17-deserialization.md", "15-authn-authz.md", "14-crypto-and-tls.md",
        "22-rust-security.md", "23-php-security.md", "24-javascript-security.md",
        "25-docker-and-supply-chain.md", "21-branch-scanning.md",
    ],
    "web_scan": [
        "01-authorized-use.md", "04-web-adviser.md", "26-finding-narrative.md",
        "27-false-positive-control.md", "28-report-quality.md",
        "19-headers-and-cookies.md", "20-api-and-graphql.md",
        "16-ssrf-and-redirects.md", "15-authn-authz.md",
        "06-injection-surface.md", "07-remediation-playbook.md",
        "13-secrets-and-tokens.md", "05-exploitdb-intel.md",
    ],
    "agent": [
        "01-authorized-use.md", "26-finding-narrative.md",
        "27-false-positive-control.md", "28-report-quality.md",
        "07-remediation-playbook.md", "05-exploitdb-intel.md",
    ],
}


# ---------------------------------------------------------------------------
# Finding-driven skill assignment
# ---------------------------------------------------------------------------

# What a vulnerability CLASS means, keyed by CWE number.  The operation an
# analysis runs under says almost nothing about which classes it found: a web
# scan of a JSON API can report a CRITICAL SQL injection, and until this map
# existed it was fed headers-and-cookies.md and told nothing about SQL
# injection at all -- so its narrative was generic procedure rather than an
# account of the defect the scan actually reported.
_CWE_SKILLS: dict[str, tuple[str, ...]] = {
    "79": ("10-xss.md",),
    "80": ("10-xss.md",),
    "89": ("09-sql-injection.md",),
    "564": ("09-sql-injection.md",),
    "78": ("11-command-injection.md",),
    "77": ("11-command-injection.md",),
    "22": ("12-path-traversal.md",),
    "23": ("12-path-traversal.md",),
    "36": ("12-path-traversal.md",),
    "601": ("16-ssrf-and-redirects.md",),
    "918": ("16-ssrf-and-redirects.md",),
    "502": ("17-deserialization.md",),
    "798": ("13-secrets-and-tokens.md",),
    "259": ("13-secrets-and-tokens.md",),
    "321": ("13-secrets-and-tokens.md",),
    "295": ("14-crypto-and-tls.md",),
    "319": ("14-crypto-and-tls.md",),
    "327": ("14-crypto-and-tls.md", "13-secrets-and-tokens.md"),
    "326": ("14-crypto-and-tls.md",),
    "287": ("15-authn-authz.md",),
    "284": ("15-authn-authz.md",),
    "862": ("15-authn-authz.md",),
    "306": ("15-authn-authz.md",),
    "1004": ("19-headers-and-cookies.md",),
    "1275": ("19-headers-and-cookies.md",),
    "614": ("19-headers-and-cookies.md",),
    "942": ("20-api-and-graphql.md",),
    "346": ("20-api-and-graphql.md",),
    "1104": ("18-dependency-cve.md",),
    "1395": ("18-dependency-cve.md",),
    "1035": ("18-dependency-cve.md",),
}

# The same, keyed by the category strings the scanners emit.  Substring match,
# because categories are namespaced by the layer that produced them:
# ``probe-sqli``, ``js-domxss``, ``probe-cmd_sep``.
_CATEGORY_SKILLS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("sqli", ("09-sql-injection.md",)),
    ("xss", ("10-xss.md",)),
    ("domxss", ("10-xss.md",)),
    ("js-sink", ("10-xss.md",)),
    ("js-source", ("10-xss.md",)),
    ("cmd", ("11-command-injection.md",)),
    ("command", ("11-command-injection.md",)),
    ("sep", ("11-command-injection.md",)),
    ("traversal", ("12-path-traversal.md",)),
    ("path", ("12-path-traversal.md",)),
    ("redirect", ("16-ssrf-and-redirects.md",)),
    ("ssrf", ("16-ssrf-and-redirects.md",)),
    ("open_redirect", ("16-ssrf-and-redirects.md",)),
    ("secret", ("13-secrets-and-tokens.md",)),
    ("token", ("13-secrets-and-tokens.md",)),
    ("credential", ("13-secrets-and-tokens.md",)),
    ("tls", ("14-crypto-and-tls.md",)),
    ("crypto", ("14-crypto-and-tls.md",)),
    ("certificate", ("14-crypto-and-tls.md",)),
    ("auth", ("15-authn-authz.md",)),
    ("session", ("15-authn-authz.md",)),
    ("access_control", ("15-authn-authz.md",)),
    ("cookie", ("19-headers-and-cookies.md",)),
    ("header", ("19-headers-and-cookies.md",)),
    ("cors", ("20-api-and-graphql.md",)),
    ("api", ("20-api-and-graphql.md",)),
    ("graphql", ("20-api-and-graphql.md",)),
    ("dependency", ("18-dependency-cve.md",)),
    ("cve", ("18-dependency-cve.md",)),
    ("advisory", ("18-dependency-cve.md",)),
)

# The procedures every finding depends on, whatever the class.  These are the
# reason a finding reads as an assessment rather than a ticket: one says how to
# write it up, one says how to decide whether it is real, one says what the
# report owes the reader.
_PROCEDURE_SKILLS: tuple[str, ...] = (
    "27-false-positive-control.md",
    "26-finding-narrative.md",
    "28-report-quality.md",
)


def _get(f: Any, name: str, default: Any = None) -> Any:
    """Read a field off a finding whether it is an object or a plain dict.

    Every caller here passes findings from a *different* layer: the web scanner
    emits ``WebFinding`` dataclasses, the repo scanner emits ``UnifiedFinding``
    models, the PR path emits ``dict`` records from ``scan_diff_for_security``.
    Reading with ``getattr`` alone silently yields ``None`` for the dict ones --
    which is how a caller "supports findings" while passing none of the signal.
    """
    if isinstance(f, dict):
        return f.get(name, default)
    return getattr(f, name, default)


def _finding_cwes(f: Any) -> list[str]:
    """CWE identifiers a finding carries, as bare numbers.

    Total by construction.  ``cwe_ids`` arrives as a list, as a single string,
    as a bare number, and -- from a JSON body that was not validated -- as a
    scalar in the wrong place.  Raising here is not an option: this runs inside
    the prompt assembly, so a ``TypeError`` from one malformed finding would
    take the whole AI request down and surface as a generic fallback narrative
    with no indication that the cause was a field shape.
    """
    raw = _get(f, "cwe_ids")
    if raw is None:
        single = _get(f, "cwe")
        raw = [single] if single else []
    if isinstance(raw, (str, bytes, int, float)):
        raw = [raw]
    if not isinstance(raw, (list, tuple, set, frozenset)):
        return []
    out: list[str] = []
    for value in raw:
        text = str(value if value is not None else "").strip().upper()
        if not text:
            continue
        text = text.replace("CWE-", "").replace("CWE", "")
        if text.isdigit():
            out.append(text)
    return out


def skills_for_findings(findings: Iterable[Any]) -> list[str]:
    """Ordered skill filenames for the classes this scan actually FOUND.

    Order is severity-driven, not discovery-driven: a CRITICAL SQL injection
    pulls 09-sql-injection.md ahead of a LOW missing header, because the prompt
    budget is finite and the class that decides the risk is the one the model
    must understand.  Returns [] for an empty finding list, which callers use to
    fall back to the plain operation mapping.
    """
    # Highest severity first, so the classes that matter claim budget first.
    ranked: list[tuple[int, Any]] = []
    for index, f in enumerate(findings or []):
        sev = str(_get(f, "severity", "") or "").lower()
        ranked.append((_SEV_ORDER.get(sev, 9), index, f))
    ranked.sort(key=lambda item: (item[0], item[1]))

    chosen: list[str] = []

    def _add(names) -> None:
        for name in names:
            if name not in chosen:
                chosen.append(name)

    for _order, _idx, f in ranked:
        for cwe in _finding_cwes(f):
            _add(_CWE_SKILLS.get(cwe, ()))
        # The category is the primary class signal, but not every layer sets one:
        # the PR scanner's records carry ``type`` and ``message`` instead.  Fall
        # back to that text so a diff finding about authn still pulls the
        # authn/authz skill rather than nothing.
        haystack = " ".join(
            str(_get(f, key, "") or "").lower()
            for key in ("category", "type", "title", "rule_id", "name")
        )
        for needle, names in _CATEGORY_SKILLS:
            if needle in haystack:
                _add(names)
    return chosen


def assign_skills_for(
    operation: str,
    findings: Iterable[Any] | None = None,
    extra: Iterable[str] | None = None,
) -> list[str]:
    """Skill list for an operation, re-pointed at what the scan found.

    Assembly order is deliberate and load-bearing:

      1. the authorization gate -- never moves, never dropped;
      2. the skills for the classes actually reported -- these are what make
         the output mean something rather than restate the finding;
      3. the procedures every finding depends on;
      4. whatever is left of the operation defaults.

    ``load_skills_text`` consumes the budget from the front, so this ordering is
    how a CRITICAL SQL injection keeps 09-sql-injection.md in the prompt while a
    LOW header note can be truncated.  The old static lists put the injection
    classes nowhere in the web_scan list at all, and then dropped five more to
    the 60 KB budget -- measured: 102,667 characters assigned, 8 of 13 present,
    no SQL-injection skill in any of them.
    """
    base = list(SKILL_MAP.get(operation, SKILL_MAP["agent"]))
    ordered: list[str] = ["01-authorized-use.md"]
    for name in skills_for_findings(findings or []):
        if name not in ordered:
            ordered.append(name)
    for name in _PROCEDURE_SKILLS:
        if name not in ordered:
            ordered.append(name)
    for name in base:
        if name not in ordered:
            ordered.append(name)
    for name in extra or []:
        if name not in ordered:
            ordered.append(name)
    return ordered


def _skills_dir() -> Path | None:
    for d in _CANDIDATES:
        if d.is_dir() and (d / "README.md").exists():
            return d
    # last chance: walk up from cwd
    cur = Path.cwd()
    for _ in range(5):
        cand = cur / "SKILLS"
        if cand.is_dir():
            return cand
        cur = cur.parent
    return None


@lru_cache(maxsize=32)
def _read_skill(name: str) -> str:
    root = _skills_dir()
    if not root:
        return ""
    path = root / name
    if not path.is_file():
        return ""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        # Keep skills compact for LLM context, but truncate on a SECTION
        # BOUNDARY rather than mid-sentence: a partial instruction reads as a
        # complete one and silently misleads the model.
        if len(text) <= _MAX_SKILL_CHARS:
            return text.strip()
        return _truncate_at_section(text, _MAX_SKILL_CHARS)
    except Exception:
        return ""


def _truncate_at_section(text: str, limit: int) -> str:
    """Cut ``text`` at the last heading that fits, never mid-paragraph."""
    if len(text) <= limit:
        return text.strip()
    head, sep, _ = text.partition("\n")
    # Only honour headings from line 2 onward; line 1 is the skill title.
    cut_points = [0]
    for index, line in enumerate(text.splitlines()[1:], start=1):
        if line.startswith("#"):
            cut_points.append(index)
    best = 0
    lines = text.splitlines()
    offset = 0
    for point in cut_points:
        offset = sum(len(lines[i]) + 1 for i in range(point))
        if offset > limit:
            break
        best = offset
    body = text[:best].rstrip() if best else head
    return (body + "\n\n<!-- skill truncated at a section boundary; "
            "full text in skills/ -->").strip()


def assign_skills(operation: str, extra: Iterable[str] | None = None) -> list[str]:
    """Return ordered skill filenames for an operation (auto)."""
    names = list(SKILL_MAP.get(operation, SKILL_MAP["agent"]))
    for e in extra or []:
        if e not in names:
            names.append(e)
    return names


# Severity ranking used only to decide which class claims prompt budget first.
_SEV_ORDER = {
    "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
    "informational": 4,
}


def load_skills_text(
    operation: str,
    extra: Iterable[str] | None = None,
    findings: Iterable[Any] | None = None,
) -> str:
    """Load and concatenate skill bodies for injection into prompts.

    The assembled text is bounded by ``_MAX_SKILLS_TOTAL_CHARS`` because it is
    going into a prompt: an unbounded concatenation of rich skills produced a
    ~180 KB prompt for ``repo_scan``, which either exceeds the model's context
    or spends all of it on procedure.

    Ordering is the priority.  When ``findings`` is supplied the list is built by
    :func:`assign_skills_for`, so the budget is spent on the classes the scan
    reported rather than on a static list that may not mention them at all.
    A skill that cannot fit whole is cut at a section boundary, and one that
    cannot fit at all is named in the trailing note.  Nothing is dropped
    silently -- a hidden coverage gap reads as "the skill said nothing about
    this", which is worse than an explicit one.
    """
    names = (
        assign_skills_for(operation, findings, extra)
        if findings is not None
        else assign_skills(operation, extra)
    )
    parts: list[str] = []
    dropped: list[str] = []
    remaining = _MAX_SKILLS_TOTAL_CHARS
    for name in names:
        body = _read_skill(name)
        if not body:
            continue
        header = f"### SKILL {name}\n"
        cost = len(header) + len(body) + 2
        if cost <= remaining or name in _ALWAYS_INCLUDE:
            if cost > remaining:
                # Keep this one regardless of the budget, but do not let it
                # grow past the per-skill ceiling on the way in.
                body = body[:_MAX_SKILL_CHARS]
                cost = len(header) + len(body) + 2
            parts.append(header + body)
            remaining = max(0, remaining - cost)
            continue
        if remaining > 400:
            body = _truncate_at_section(body, remaining - len(header) - 400)
            if body:
                parts.append(header + body)
                remaining = 0
                break
        dropped.append(name)
    if not parts:
        dropped_or_none = ", ".join(dropped) if dropped else "none found"
        return (
            "### SKILL default\n"
            "Authorized defensive analysis only. Prefer high-confidence findings, "
            "concrete remediations, and CWE references. Do not invent exploits.\n\n"
            f"<!-- no skill file loaded (attempted: {dropped_or_none}); see skills/ -->"
        )
    if dropped:
        parts.append(
            "<!-- Skills omitted to stay within the prompt budget: "
            + ", ".join(dropped)
            + ". Full text in skills/. Treat an unlisted class as NOT_ASSESSED "
            "unless you read the file directly. -->"
        )
    return "\n\n".join(parts)


def skill_system_prefix(
    operation: str,
    findings: Iterable[Any] | None = None,
) -> str:
    """System prefix listing the auto-assigned skills and their content.

    ``findings`` re-points the skill set at what the scan reported (see
    :func:`assign_skills_for`).  Pass it whenever the caller has findings: the
    difference between a generic paragraph and a meaningful one is whether the
    model was given the skill for the class it is being asked about.
    """
    names = (
        assign_skills_for(operation, findings)
        if findings is not None
        else assign_skills(operation)
    )
    return (
        f"[AUTO-SKILLS for {operation}: {', '.join(names)}]\n"
        "Follow these operating skills strictly. Defensive analysis only.\n\n"
        + load_skills_text(operation, findings=findings)
    )
