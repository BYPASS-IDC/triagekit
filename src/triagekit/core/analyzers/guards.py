"""Named, line-scoped suppression guards shared by every regex pattern layer.

WHY THIS MODULE EXISTS
----------------------
A regex rule matches a *shape*.  ``el.innerHTML = x`` and
``el.innerHTML = DOMPurify.sanitize(x)`` are the same shape and different
programs: one is the vulnerability, the other is its fix.  Without a guard, the
pattern layer reports the fix (defect D37), and a report that reports the fix is
worse than no report, because the reader cannot tell which lines are real.

Both regex layers in this codebase consult this module -- ``repo_scan`` (the
repository scanner) and ``security`` (the heuristic diff scanner) -- so they can
no longer disagree about whether a line is clean.  A guard added here fixes both
at once; a guard added in one place only is how the layers drifted apart.

WHAT A GUARD IS NOT
-------------------
Every guard is **line-scoped**.  It answers one question: "does this line contain
a call that neutralises the pattern on this line?"  It does not model data flow.
A sanitizer applied on line 12 and stored in a variable used on line 40 is
invisible here, so the guard under-reports in exactly the cases where the taint
layer is precise.  That is the intended trade: the guard's job is to stop the
*safe idiom on one line* from being reported, and the taint layer's job is to
prove flow.  Neither substitutes for the other, and the report must not imply
that it does (see ``core/scanners/correlation.py``, cross-layer precedence).

A guard failure mode is a FALSE NEGATIVE on that line, never a false positive:
if a guard's pattern appears anywhere on a matching line, the whole rule is
suppressed for that line.  ``el.innerHTML = raw; other.innerHTML = escape(x);``
suppresses both.  These are rare in real code and the taint layer still sees the
first one, so the trade is accepted and recorded rather than hidden.
"""

from __future__ import annotations

import re

__all__ = [
    "ARGV_LIST_CALL",
    "CREDENTIAL_TOKEN",
    "HTML_SANITIZER_CALL",
    "LOCKFILE_INTEGRITY",
    "PATH_BASENAME_CALL",
    "SHELL_QUOTE_CALL",
    "GUARDS",
    "is_pattern_definition",
    "is_prose_mention",
    "suppressed",
    "guard_names",
]

# ---------------------------------------------------------------------------
# Individual guards
# ---------------------------------------------------------------------------

# A shell command invoked as an argv list with no interpreter.  This is the fix
# for command injection, not an instance of it.
ARGV_LIST_CALL = re.compile(
    r"\bsubprocess\.(run|call|Popen|check_output|check_call)\s*\(\s*\["
    r"|\bexecFile\w*\s*\(\s*[\"'][^\"']*[\"']\s*,\s*\["
    r"|\bspawn\w*\s*\(\s*[\"'][^\"']*['\"]\s*,\s*\[",
    re.I,
)

# ``shlex.quote`` / ``pipes.quote``: the shell-quoting fix.  Mirrors the shlex
# sanitizer the Python taint analyzer models (D27), so the two layers agree.
SHELL_QUOTE_CALL = re.compile(r"\b(?:shlex|pipes)\s*\.\s*quote\s*\(", re.I)

# A well-known HTML sanitizer / encoder call.  ``sanitize`` and ``escape`` are
# matched generically (not only as ``DOMPurify.sanitize``) because the same
# one-line shape is written with a dozen different libraries, and under-matching
# here re-creates D37.
HTML_SANITIZER_CALL = re.compile(
    r"(?:dompurify|purify|sanitiz\w*|escape\w*|encode\w*)\s*\.\s*(?:sanitize|escape|encode)\s*\("
    r"|(?<![\w$.])(?:sanitize\w*|escapeHtml|escapeHTML|htmlEscape|htmlEncode|he\s*\.\s*escape"
    r"|_\s*\.\s*escape|encodeHTML|secure)\s*\(",
    re.I,
)

# ``path.basename`` / werkzeug's ``secure_filename``: the only one-line shapes
# that actually remove directory components from a user-supplied path.  A bare
# ``.name`` attribute is deliberately NOT a guard -- ``Path(x).name`` on a
# relative path does not stop ``../`` and would under-report.
PATH_BASENAME_CALL = re.compile(r"\bbasename\s*\(|\bsecure_filename\s*\(", re.I)

# A credential-shaped token.  Used to decide whether a log call is a secret leak
# (a finding) or an ordinary log line (not a finding) -- see D38.
CREDENTIAL_TOKEN = re.compile(
    r"(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key"
    r"|private[_-]?key|authorization|auth[_-]?header|bearer|credential"
    r"|session[_-]?id|ssn|credit[_-]?card|card[_-]?number|cvv)\b"
)

# Subresource-integrity and lockfile checksums.  ``"integrity":
# "sha512-Aup7aUOfpbAUg2ROOJN6Iw5f9DMBlzu0..."`` is a hash the package manager
# generated; every entry in every package-lock.json on earth matches the
# high-entropy rule, so an unguarded rule reports ~100 fake secrets in a normal
# JavaScript repository.
LOCKFILE_INTEGRITY = re.compile(
    r"(?i)[\"']?(?:integrity|resolved|checksum|digest|contenthash|revision|etag)[\"']?\s*[:=]"
    r"|\bsha(?:256|384|512)-[A-Za-z0-9+/=]{16,}"
)

# A line that DEFINES a regular expression.  Point a pattern scanner at any
# linter, WAF, validator, or other scanner -- including this one -- and every
# rule-table row is a hit: ``(r"innerHTML\s*=|eval\s*\(", "xss-eval", ...)``
# matches the xss-eval rule.  Those rows are data about patterns, not program
# behaviour, and reporting them destroys the signal-to-noise ratio of the entire
# class of repositories that most need a scanner.
#
# The signal is deliberately narrow: the line must contain regex *syntax*
# (``\s``, ``\b``, ``(?:``, a negated class, ...) inside a quoted string.
# ``os.system("ping " + host)`` contains none of them, so a real call site is
# never guarded away.
REGEX_SYNTAX_IN_STRING = re.compile(
    r"[\"'][^\"']*(?:\\[sSbBwWdD]|\(\?:|\[\^|\\\.|\\\(|\\\)|\\\+|\|)[^\"']*[\"']"
)

# Character classes such as ``[A-Za-z0-9]{16}`` and ``[A-Z]`` also mark a line as
# a pattern definition (secret and protocol patterns are written this way).
REGEX_CLASS = re.compile(r"\[\^?[A-Za-z0-9\\\-_]{2,}\]\{|\[\^?[A-Za-z]\-[A-Za-z]\]")

# ---------------------------------------------------------------------------
# Prose guard: documentation text that mentions a pattern is not an instance
# ---------------------------------------------------------------------------

# A match that lives inside a quoted string, on a line whose remaining text is
# not code.  ``"py-shell-true": "Never use shell=True with untrusted input...",``
# is documentation about a vulnerability; ``subprocess.run(cmd, shell=True)`` is
# one.  Real code leaves ``(``, ``[``, ``{`` or an operator behind when its string
# literals are removed; documentation does not.
CODE_PUNCT = re.compile(r"[()\[\]{}]|=>|->|\+\+|\bfor\b|\bif\b|\breturn\b")
QUOTED_SPAN = re.compile(r"\"[^\"]*\"|'[^']*'|`[^`]*`")

# Only the rules where a prose mention is the dominant false positive.  The
# secret rules (CWE-798) are deliberately EXCLUDED: ``DB_PASSWORD = "hunter2"``
# leaves no code punctuation either, and suppressing it would hide a real leak.
PROSE_GUARDED_RULES = frozenset({
    "shell-injection",
    "weak-cipher",
    "plaintext-password-compare",
    "unsafe-deserialization",
    "xss-framework",
    "weak-hash-md5",
    "weak-hash-sha1",
    # ``xss-eval`` is deliberately NOT here.  Every explanation of an XSS sink
    # writes the sink down, so the prose guard looks like the right answer -- but
    # `el.innerHTML = location.hash` is real code that carries no parentheses,
    # brackets, or keywords, so the guard reads it as prose and loses a true
    # positive.  The documentation case is handled precisely instead, by
    # docstring_line_numbers, which knows where the string actually is.
    "tls-verify-off",
    "assert-security",
    "debug-enabled",
    "sensitive-log",
    "command-injection",
    "path-traversal",
    "template-injection",
})


def is_prose_mention(line: str) -> bool:
    """True when the matching pattern occurs in documentation text, not code."""
    if not line:
        return False
    # A docstring line is documentation whatever else it contains.
    if '"""' in line or "'''" in line:
        return True
    return not CODE_PUNCT.search(QUOTED_SPAN.sub("", line))


_DOCSTRING_DELIM = re.compile(r'"""|' + "'''")


def multiline_string_line_numbers(text: str) -> frozenset[int]:
    """0-based indices of lines occupied by multi-line string literals.

    Python's own parser answers this exactly, so it is preferred wherever the
    whole file is available: every ``ast.Constant`` string node carries the line
    it starts and ends on, and a line of code that merely names a delimiter --
    ``is_prose_mention`` in this module tests for the delimiter character in a
    line -- is code, not a span.  A line-based scanner cannot tell those apart,
    which is why the token-free fallback below is only used where no parser is
    available.
    """
    import ast
    import warnings

    try:
        # Parsing a module compiles it, and Python 3.9 warns on any invalid
        # escape sequence it finds anywhere in the file -- a property of the
        # *target* being scanned, not of this lookup.  Scoped to this call so
        # no other code loses its warnings.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return frozenset()

    inside: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        start, end = getattr(node, "lineno", None), getattr(node, "end_lineno", None)
        if start is None or end is None or end <= start:
            # A single-line literal: covered by is_prose_mention, which sees
            # the delimiters on that line.
            continue
        inside.update(range(start - 1, end))
    return frozenset(inside)


def docstring_line_numbers(lines: list[str]) -> frozenset[int]:
    """0-based indices of lines that sit inside a triple-quoted string.

    ``is_prose_mention`` sees one line at a time, so it catches a docstring's
    opening and closing lines (they carry the delimiter) and misses everything
    between them.  That gap is not cosmetic: this project's own
    ``taint/analyzer.py`` documents ``shell=True`` as a dangerous case in prose
    and was reported for it, and the rule table that explains
    ``el.innerHTML = raw`` reports itself.  A reviewer cannot use a tool that
    flags its own documentation.

    Deliberately conservative: a span that is not *closed* within ``lines`` is
    not treated as a docstring at all.  On a real pull-request patch, where the
    delivered lines are a subset of the file, an unterminated span is far more
    likely to be truncation than a genuine open block -- and suppressing would
    then hide real code.
    """
    inside: set[int] = set()
    delim: str | None = None
    span_open = -1
    for idx, line in enumerate(lines):
        pos = 0
        while True:
            if delim is None:
                match = _DOCSTRING_DELIM.search(line, pos)
                if not match:
                    break
                delim = match.group(0)
                span_open = idx
                pos = match.end()
                if line.find(delim, pos) >= 0:
                    # Opened and closed on this same line: a complete one-line
                    # literal.  ``is_prose_mention`` already covers that line
                    # because it carries the delimiters, so mark nothing and
                    # keep scanning the rest of the line for further spans.
                    close_at = line.find(delim, pos)
                    width = len(delim)
                    delim = None
                    span_open = -1
                    pos = close_at + width
                    continue
                # The span continues onto later lines.
                inside.add(idx)
            else:
                # Search from ``pos``, not from 0: searching from 0 finds the
                # delimiter that OPENED the span and closes it on its own first
                # line, which suppresses nothing.
                close_at = line.find(delim, pos)
                if close_at < 0:
                    inside.add(idx)
                    break
                inside.add(idx)
                pos = close_at + len(delim)
                delim = None
                span_open = -1
    if delim is not None:
        # Unterminated span -- see the docstring.  Suppress nothing, and undo
        # what was marked on the way in so a truncated patch cannot hide code.
        inside -= set(range(span_open, len(lines)))
    return frozenset(inside)


# rule id -> guards.  A rule id absent from this table has no guard: its pattern
# is already narrow enough, or its false positives are handled elsewhere.
GUARDS: dict[str, tuple[re.Pattern, ...]] = {
    # D37: the sanitized-XSS idiom must not be reported as XSS.
    "xss-eval": (HTML_SANITIZER_CALL,),
    "xss-framework": (HTML_SANITIZER_CALL,),
    "xss-eval-risk": (HTML_SANITIZER_CALL,),
    # Mirrors the taint layer's ``path-basename`` sanitizer.
    "path-traversal": (PATH_BASENAME_CALL,),
    # D32 parity for the Python layer: an argv list is not a shell, and a quoted
    # argument is not an injection.
    "command-injection": (ARGV_LIST_CALL, SHELL_QUOTE_CALL),
    "shell-injection": (ARGV_LIST_CALL, SHELL_QUOTE_CALL),
    "command-injection-risk": (ARGV_LIST_CALL, SHELL_QUOTE_CALL),
    # npm/pip/cargo integrity hashes are not secrets.
    "high-entropy-string": (LOCKFILE_INTEGRITY,),
    "hardcoded-secret": (LOCKFILE_INTEGRITY,),
}


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def is_pattern_definition(line: str) -> bool:
    """True when ``line`` defines a regex/pattern table row rather than calling one."""
    if not line:
        return False
    return bool(REGEX_SYNTAX_IN_STRING.search(line) or REGEX_CLASS.search(line))


def suppressed(rule_id: str, line: str) -> bool:
    """True when a guard neutralises ``rule_id`` on ``line``.

    Returns False for an unknown rule id -- an unguarded rule keeps its current
    behaviour rather than silently acquiring a new false-negative channel.
    """
    if not rule_id or not line:
        return False
    for guard in GUARDS.get(rule_id, ()):
        if guard.search(line):
            return True
    if rule_id in PROSE_GUARDED_RULES and is_prose_mention(line):
        return True
    return False


def guard_names(rule_id: str) -> list[str]:
    """Names of the guards attached to ``rule_id`` (for tests and reports)."""
    return [g.pattern[:48] for g in GUARDS.get(rule_id, ())]
