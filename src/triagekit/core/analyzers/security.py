"""Heuristic security signal extraction from diffs and paths."""

from __future__ import annotations
import re
from typing import Any

# ---------------------------------------------------------------------------
# The rules are NOT written here.
# ---------------------------------------------------------------------------
# This file used to keep its own hand-written copies of the injection, secret,
# and crypto patterns.  That copy drifted: while the repository scanner's rules
# were being narrowed, this one kept matching ``cur.execute(...)`` as command
# injection, ``subprocess.run(cmd_list)`` as command injection, and
# ``password = "hunter2"`` (6 characters) as nothing at all.  The two regex
# layers then disagreed about the same line -- one reported it, the other did
# not -- which is precisely what a reviewer cannot use.
#
# The patterns are therefore derived from the single authoritative table in
# repo_scan.py.  The two layers remain independent code paths over the same
# rules (one walks the tree, one reads a diff), so agreement between them is
# still real corroboration and disagreement is now impossible by construction.
#
# The *type names* below are public API: heuristic_scanner's recommendation and
# CWE tables and correlation.py's cross-layer map are keyed on them, so they are
# preserved verbatim while the regexes come from the canonical table.

from . import repo_scan as _rs

# One representative filename per language is enough to reach a pack: the pack
# is chosen by extension alone, so "probe.py" yields the same RULES list that
# any .py file does.
_LANG_EXTENSIONS = (".py", ".rs", ".swift", ".cs", ".java", ".cpp", ".cc", ".c", ".h", ".hpp")

# canonical repo_scan label -> heuristic finding type
_HEURISTIC_TYPE = {
    "sql-injection": "sql-injection-risk",
    "command-injection": "command-injection-risk",
    "shell-injection": "shell-injection-risk",
    "xss-eval": "xss-eval-risk",
    "xss-framework": "xss-framework-risk",
    "unsafe-deserialization": "unsafe-deserialization",
    "path-traversal": "path-traversal-risk",
    "open-redirect": "open-redirect-risk",
    "ssrf": "ssrf-risk",
    "template-injection": "template-injection-risk",
    "php-sqli": "php-sqli-risk",
    "php-xss": "php-xss-risk",
    "hardcoded-secret": "hardcoded-secret",
    "private-key": "private-key-in-diff",
    "aws-access-key": "aws-access-key-pattern",
    "aws-session-key": "aws-session-key-pattern",
    "github-token": "github-token-pattern",
    "openai-style-key": "openai-key-pattern",
    "slack-token": "slack-token-pattern",
    "google-api-key": "google-api-key-pattern",
    "jwt-in-source": "jwt-in-source",
    "nvidia-api-key": "nvidia-api-key-pattern",
    "bearer-token-literal": "bearer-token-literal",
    "weak-hash-md5": "weak-hash",
    "weak-hash-sha1": "weak-hash",
    "tls-verify-off": "tls-verification-disabled",
    "jwt-verify-off": "jwt-verify-disabled",
    "plaintext-password-compare": "plaintext-password-compare",
    "weak-rng": "weak-rng",
    "weak-cipher": "weak-cipher",
}


def _risk_type(canonical_label: str) -> str:
    """Public finding-type name for a canonical repo_scan rule label."""
    return _HEURISTIC_TYPE.get(canonical_label, canonical_label + "-risk")


def _rules(table) -> list[tuple[str, str]]:
    """``(regex, canonical_label)`` from a repo_scan rule table."""
    return [(pattern, label) for pattern, label, *_ in table]


INJECTION_PATTERNS = _rules(_rs.INJECTION)
SECRET_PATTERNS = _rules(_rs.SECRETS)
AUTH_CRYPTO_PATTERNS = _rules(_rs.CRYPTO_AUTH)


def _all_lang_labels() -> list[str]:
    """Every canonical rule id the per-language packs define."""
    labels: list[str] = []
    for ext in _LANG_EXTENSIONS:
        for entry in _rs._lang_rules_for(f"probe{ext}") or []:
            if len(entry) >= 2 and entry[1] not in labels:
                labels.append(entry[1])
    return labels


# A language-pack rule has no bespoke public name, so its alias is the default
# "<canonical>-risk".  Registering them here is what lets the diff layer report
# them with the canonical rule's CWE and remediation text instead of neither.
for _lang_label in _all_lang_labels():
    _HEURISTIC_TYPE.setdefault(_lang_label, _lang_label + "-risk")

# Reverse lookup: public heuristic type -> the canonical rule ids it stands for.
# ``weak-hash`` stands for two canonical rules, so this is one-to-many and the
# order is preserved (md5 first) for callers that need a single representative.
_CANONICAL_LOOKUP: dict[str, list[str]] = {}
for _canonical, _public in _HEURISTIC_TYPE.items():
    _CANONICAL_LOOKUP.setdefault(_public, []).append(_canonical)


def canonical_rule_ids(finding_type: str) -> list[str]:
    """Canonical repo_scan rule ids behind a heuristic finding type.

    Used to look up the authoritative CWE and remediation text for a finding, so
    a rule added to the canonical table is immediately described correctly here
    instead of falling back to "Review and harden this pattern".
    """
    if finding_type in _CANONICAL_LOOKUP:
        return list(_CANONICAL_LOOKUP[finding_type])
    # Already a canonical id (a caller that bypassed the alias): it maps to
    # itself, so the CWE and remediation lookups still resolve.
    return [finding_type] if finding_type in _CWE_BY_LABEL else []


def language_rules(path: str) -> list[tuple[str, str]]:
    """``(pattern, label)`` for a path's language pack.

    The repository scanner applies the per-language packs (Java, C#, Rust, Swift,
    C/C++, Python); the diff layer previously did not, so a Java pull request got
    no java-sqli or java-exec signal at all while the same file scanned locally
    did.  Returns an empty list when the extension has no pack, which keeps a
    diff-only scan cheap.
    """
    return [(pattern, label) for pattern, label, *_ in _rs._lang_rules_for(path) or []]


def cwe_for(finding_type: str) -> list[str]:
    """CWE ids for a heuristic finding type, taken from the canonical rules."""
    out: list[str] = []
    for label in canonical_rule_ids(finding_type):
        cwe = _CWE_BY_LABEL.get(label)
        if cwe and cwe not in out:
            out.append(cwe)
    return out


_LANG_EXTENSIONS = (".py", ".rs", ".swift", ".cs", ".java", ".cpp", ".cc", ".c", ".h", ".hpp")


def _cwe_table() -> dict[str, str]:
    """Canonical rule id -> CWE id, from every rule table the scanner owns."""
    table: dict[str, str] = {}
    for rule_table in (_rs.INJECTION, _rs.SECRETS, _rs.CRYPTO_AUTH, _rs.QUALITY):
        for entry in rule_table:
            if len(entry) >= 4 and entry[3]:
                table.setdefault(entry[1], entry[3])
    # One representative filename per language is enough: the pack is chosen by
    # extension alone, so ".py" reaches the same RULES list any .py file does.
    for ext in _LANG_EXTENSIONS:
        for entry in _rs._lang_rules_for(f"probe{ext}") or []:
            if len(entry) >= 4 and entry[3]:
                table.setdefault(entry[1], entry[3])
    return table


_CWE_BY_LABEL = _cwe_table()


DEPENDENCY_FILES = {
    "requirements.txt", "pyproject.toml", "package.json", "package-lock.json",
    "yarn.lock", "pnpm-lock.yaml", "go.mod", "go.sum", "Cargo.toml", "Cargo.lock",
    "composer.json", "composer.lock", "Gemfile", "Gemfile.lock", "pom.xml",
    "build.gradle", "build.gradle.kts", "Pipfile", "poetry.lock",
}


HUNK_HEADER = re.compile(r"^@@\s*-\d+(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s*@@")


def _added_lines_with_numbers(patch: str) -> list[tuple[int, str]]:
    """Return ``(line_number, text)`` for every added line in a unified diff.

    A hunk header carries the 1-based file line where the hunk's first new line
    lands, so the number is real for a genuine pull-request patch and for a
    synthesized whole-file patch alike.  Without it, every finding from this
    scanner is location-less, which makes it impossible to deduplicate against
    the repository scanner or the taint layer -- the same flaw then appears three
    times in one report with three different shapes (defect D39).
    """
    out: list[tuple[int, str]] = []
    # A patch with no hunk header (a synthesized whole-file payload) starts at
    # file line 1.  Starting at 0 would report every finding one line early,
    # which then fails to deduplicate against the other layers' line numbers.
    line_no = 1
    for raw in patch.splitlines():
        header = HUNK_HEADER.match(raw)
        if header:
            line_no = int(header.group(1))
            continue
        if raw.startswith("+++") or raw.startswith("---"):
            continue
        if raw.startswith("+"):
            out.append((line_no, raw[1:]))
            line_no += 1
        elif raw.startswith("-"):
            continue
        elif raw.startswith("\\"):
            # "\ No newline at end of file" -- context marker, not a line.
            continue
        else:
            # A context line (leading space) or the bare content of a patch with
            # no +/- prefixes.  It still occupies a file line.
            line_no += 1
    return out


def scan_diff_for_security(files_data: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Return list of heuristic security findings from file paths + patches.

    Every finding carries a real line number, and the same suppression guards the
    repository scanner uses are applied here so the two regex layers cannot
    disagree about whether a line is clean.
    """
    from .guards import docstring_line_numbers, is_pattern_definition, suppressed

    findings: list[dict[str, str]] = []

    for f in files_data:
        path = f.get("filename") or f.get("path") or ""
        patch = f.get("patch") or ""
        lower = path.lower()
        base = path.split("/")[-1].lower()

        # Dependency / version surface
        if base in DEPENDENCY_FILES or "lock" in base:
            findings.append({
                "type": "dependency-change",
                "severity": "medium",
                "file": path,
                "message": "Dependency or lockfile changed -- check for known vulnerable versions and major upgrades.",
            })

        # Path-based
        if any(x in lower for x in ("auth", "login", "session", "jwt", "oauth", "password", "crypto", "secret")):
            findings.append({
                "type": "sensitive-path",
                "severity": "high",
                "file": path,
                "message": "Security-sensitive path touched -- review authn/authz, crypto, and secret handling carefully.",
            })

        if not patch:
            continue

        # The per-language packs, resolved once per file rather than once per
        # line: the repository scanner applies them, so a diff that omits them
        # reports less than a directory scan of the same file.
        lang_patterns = language_rules(path)

        added = _added_lines_with_numbers(patch)
        # On a synthesized whole-file patch the added lines ARE the file, so a
        # docstring span that opens and closes inside them is real documentation.
        # On a genuine PR patch the delivered lines are a subset and an
        # unterminated span is truncation, so nothing is suppressed -- the helper
        # is conservative by design.
        prose_indices = docstring_line_numbers([text for _lineno, text in added])

        for idx, (lineno, text) in enumerate(added):
            stripped = text.strip()
            if not stripped or stripped.startswith(("#", "//", "*")):
                continue
            if idx in prose_indices:
                continue
            if is_pattern_definition(stripped):
                continue

            # ``label`` is the canonical repo_scan rule id: the guard table in
            # guards.py is keyed on it, so guarding by the public "-risk" alias
            # would silently skip every guard for that rule.  Only the emitted
            # ``type`` uses the public name.
            for pattern, label in INJECTION_PATTERNS:
                if re.search(pattern, text, re.I) and not suppressed(label, text):
                    ftype = _risk_type(label)
                    findings.append({
                        "type": ftype,
                        "severity": "high",
                        "file": path,
                        "line": lineno,
                        "message": f"Possible {ftype.replace('-', ' ')} pattern in added code.",
                    })
                    break

            for pattern, label in lang_patterns:
                if re.search(pattern, text, re.I) and not suppressed(label, text):
                    ftype = _risk_type(label)
                    findings.append({
                        "type": ftype,
                        "severity": "high",
                        "file": path,
                        "line": lineno,
                        "message": f"Possible {ftype.replace('-', ' ')} pattern in added code.",
                    })
                    break

            for pattern, label in SECRET_PATTERNS:
                if re.search(pattern, text, re.I) and not suppressed(label, text):
                    ftype = _risk_type(label)
                    findings.append({
                        "type": ftype,
                        "severity": "critical",
                        "file": path,
                        "line": lineno,
                        "message": f"Possible {ftype.replace('-', ' ')} detected in added lines.",
                    })
                    break

            for pattern, label in AUTH_CRYPTO_PATTERNS:
                if re.search(pattern, text, re.I) and not suppressed(label, text):
                    ftype = _risk_type(label)
                    findings.append({
                        "type": ftype,
                        "severity": "high",
                        "file": path,
                        "line": lineno,
                        "message": f"Possible {ftype.replace('-', ' ')} pattern.",
                    })
                    break

    # Deduplicate by type + file + LINE, not type + file: one finding per defect,
    # not one per file.  Keying on the file alone collapsed five distinct SQL
    # injections in one module into a single report line.
    seen = set()
    unique = []
    for fnd in findings:
        key = (fnd["type"], fnd["file"], fnd.get("line"))
        if key not in seen:
            seen.add(key)
            unique.append(fnd)
    return unique


def security_signals_text(findings: list[dict[str, str]]) -> list[str]:
    if not findings:
        return []
    lines = []
    for f in findings[:20]:
        loc = f"{f['file']}:{f['line']}" if f.get("line") else f["file"]
        lines.append(f"[security:{f['severity']}] {f['type']} in {loc}: {f['message']}")
    return lines