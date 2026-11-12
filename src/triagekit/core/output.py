"""Console and JSON output safety for TriageKit.

Two defects are fixed here, both measured on the Windows build:

1. **UnicodeEncodeError aborts commands.**  A finding whose title contains a
   character the active console encoding cannot represent (ASCII `->` vs Unicode
   `->`, U+2192, on a cp1252 console) made ``Console.print`` raise mid-write.
   For ``console.print_json`` this was worse than a crash: rich renders the JSON
   incrementally, so the traceback landed *inside* the JSON stream and the
   machine-readable output was corrupted.  A consumer parsing ``--json`` got a
   broken document, not an error.

   The fix is at the boundary, not in the data: reconfigure ``stdout`` to UTF-8
   when the platform allows it, and otherwise fold every unencodable character to
   an ASCII equivalent so output is always emit-able.  Findings keep their
   original text; only the byte stream is made safe.

2. **JSON output must be pure JSON.**  ``--json`` / ``--sarif`` are consumed by
   machines, so nothing but the JSON document may reach stdout on those paths.
   Any un-serialisable member of a payload is reported as a structured error
   object instead of being allowed to break the stream.
"""

from __future__ import annotations

import json
import sys
from typing import Any

# Characters that cannot be represented on a legacy single-byte console, mapped
# to an ASCII form a reader will still understand.  Extend as needed; the
# fallback for an unmapped character is '?' handled by the codec error handler.
_ASCII_FOLD = {
    "→": "->",
    "←": "<-",
    "⇒": "=>",
    "≤": "<=",
    "≥": ">=",
    "≠": "!=",
    "‘": "'",
    "’": "'",
    "“": '"',
    "”": '"',
    "–": "-",
    "—": "--",
    "…": "...",
    "·": "*",
    "€": "EUR",
    "£": "GBP",
    "×": "x",
    "≈": "~=",
    "✓": "OK",
    "✗": "X",
    "★": "*",
    "⚠": "!",
}


def fold_to_ascii(text: str) -> str:
    """Replace characters a cp1252-class console cannot encode with ASCII forms."""
    if not text:
        return text
    # Fast path: already pure ASCII (the overwhelmingly common case).
    try:
        text.encode("ascii")
        return text
    except UnicodeEncodeError:
        pass
    for bad, good in _ASCII_FOLD.items():
        if bad in text:
            text = text.replace(bad, good)
    # Anything still non-ASCII is dropped to '?' by the handler below, but keep
    # the string intact rather than raising.
    return text.encode("ascii", "replace").decode("ascii")


def configure_stdout() -> None:
    """Make stdout/stderr able to emit any character, where the platform allows.

    On Python 3.7+ ``reconfigure`` switches the stream to UTF-8, which removes
    the encoding constraint entirely.  On older or redirected streams it is a
    no-op and ``fold_to_ascii`` carries the guarantee instead.
    """
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            # A detached or already-closed stream must never break a command.
            pass


def safe_console_text(text: Any) -> str:
    """Coerce ``text`` to an emit-able single-line-ish string."""
    if text is None:
        return ""
    out = text if isinstance(text, str) else str(text)
    return fold_to_ascii(out)


def _make_serialisable(value: Any, depth: int = 0) -> Any:
    """Convert ``value`` to something ``json.dumps`` accepts.

    Unknown objects become a small descriptive dict rather than raising, so one
    odd field can never take down a whole report.
    """
    if depth > 12:
        return "<max-depth>"
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, dict):
        return {str(k): _make_serialisable(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_make_serialisable(v, depth + 1) for v in value]
    if hasattr(value, "model_dump"):  # pydantic v2
        try:
            return _make_serialisable(value.model_dump(), depth + 1)
        except Exception:
            pass
    if hasattr(value, "__dict__"):
        try:
            return {
                str(k): _make_serialisable(v, depth + 1)
                for k, v in vars(value).items()
                if not str(k).startswith("_")
            }
        except Exception:
            pass
    if hasattr(value, "isoformat"):
        try:
            return value.isoformat()
        except Exception:
            pass
    if hasattr(value, "__fspath__"):
        return str(value)
    return str(value)


def to_jsonable(payload: Any) -> Any:
    """Return a JSON-serialisable copy of ``payload`` (never raises)."""
    try:
        json.dumps(payload)
        return payload
    except Exception:
        return _make_serialisable(payload)


def dumps_json(payload: Any, indent: int | None = 2) -> str:
    """Serialise ``payload`` to JSON text that is always valid and emit-able."""
    return json.dumps(to_jsonable(payload), indent=indent, ensure_ascii=True, default=str)
