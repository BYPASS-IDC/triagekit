"""Synthesize a PR-shaped ``files_data`` payload from a local target.

WHY THIS MODULE EXISTS (defect D3)
----------------------------------
``StaticAnalysisScanner`` and ``HeuristicSecurityScanner`` were written against
GitHub's pull-request object.  Both consume a list of
``{"filename", "status", "additions", "deletions", "patch"}`` dictionaries, and
nothing anywhere in this repository ever produced that payload for a local scan.
Both scanners were therefore *registered, enabled and target-compatible* while
being structurally unable to emit a single finding: they read
``context.metadata["files_data"]``, found it empty, appended "No files_data
provided in context", and returned.  A local scan ran them and silently got
nothing -- which reads in the report as "these checks passed".

WHAT IS SYNTHESIZED, AND WHAT IS NOT
------------------------------------
A directory scan has no diff.  This module therefore builds a payload that is
shaped like a diff payload and is *explicitly labelled as synthesized*:

* ``status`` is ``"synthesized"``, never ``"modified"`` -- the file is in scope,
  not changed.
* ``additions`` and ``deletions`` are **0**.  Fabricating a line count as "diff
  churn" would drive ``compute_static_risk`` into its "very large diff" branch on
  every repository over 1000 lines and turn a CRITICAL risk score into a constant.
  The risk scorer is calibrated on diffs and keeps only its *composition*
  signals (security-sensitive / critical-path / api-surface counts) here.
* ``patch`` holds the whole file with every line prefixed ``+``, which is what
  ``scan_diff_for_security`` extracts as "added lines".

Callers must surface ``SynthesizedFiles.is_synthesized`` in their result
metadata so no downstream consumer can mistake this for a real pull request.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .repo_scan import (
    CODE_EXTS,
    DEP_FILES,
    LOCKFILE_NAMES,
    SPECIAL_NAMES,
    SKIP_DIRS,
    SKIP_PATH_PARTS,
    is_scannable_source,
)

__all__ = ["SYNTHESIZED_STATUS", "SynthesizedFiles", "synthesize_files_data"]

SYNTHESIZED_STATUS = "synthesized"

# Default scope.  A file cap is applied in priority order (see ``_priority``), and
# what the cap drops is reported -- a silent cap reads as full coverage.
DEFAULT_MAX_FILES = 1000
DEFAULT_MAX_BYTES = 200_000

# Path fragments that make a file worth reading first when a cap applies.
_PRIORITY_FRAGMENTS = (
    "auth", "login", "session", "jwt", "oauth", "password", "crypto", "secret",
    "token", "api/", "route", "endpoint", "handler", "controller", "model",
    "db", "database", "query", "payment", "billing", "admin", "middleware",
    "config", "setting", "permission", "upload", "download", "exec",
)

_TEST_FRAGMENTS = ("/test/", "/tests/", "test_", "_test.", ".spec.", "spec/", "/fixtures/")


def _priority(rel: str) -> int:
    """Lower sorts first.  Security-relevant source, then source, then manifests."""
    lower = rel.lower()
    name = lower.rsplit("/", 1)[-1]
    if any(f in lower for f in _TEST_FRAGMENTS):
        return 3
    if name in DEP_FILES or name in LOCKFILE_NAMES or name.endswith(".lock"):
        return 2
    if any(f in lower for f in _PRIORITY_FRAGMENTS):
        return 0
    if Path(name).suffix.lower() in CODE_EXTS or name in SPECIAL_NAMES:
        return 1
    return 4


def iter_candidates(root: Path) -> Iterable[Path]:
    """Yield every in-scope file under ``root``, sharing repo_scan's skip rules.

    The source filter is ``repo_scan.is_scannable_source`` -- the same predicate
    ``repo_scan``'s own walk uses -- so the two paths can no longer disagree
    about whether a file is code.  Before this, prose reached the heuristic
    scanner here and reported ``[critical] Hardcoded Secret setup.rst:34`` and
    three more high findings from shipped ``.rst`` documentation on a real
    repository (defect D70).  A file excluded here is a statement about what
    kind of file it is, never a claim that it is clean, so the caller reports
    the exclusion in ``SynthesizedFiles`` rather than dropping it silently.
    """
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in sorted(filenames):
            path = Path(dirpath) / name
            rel = str(path).replace("\\", "/").lower()
            if any(part in rel for part in SKIP_PATH_PARTS):
                continue
            if name.endswith(".min.js") or name.endswith(".min.css"):
                continue
            if not is_scannable_source(name, path.suffix, rel):
                continue
            yield path


@dataclass
class SynthesizedFiles:
    """A PR-shaped payload built from a local target, plus what it cost to build."""

    target: str
    files_data: list[dict[str, Any]] = field(default_factory=list)
    is_synthesized: bool = True
    files_included: int = 0
    skipped_cap: list[str] = field(default_factory=list)
    skipped_binary: list[str] = field(default_factory=list)
    skipped_too_large: list[str] = field(default_factory=list)
    skipped_not_source: list[str] = field(default_factory=list)
    bytes_read: int = 0

    @property
    def stats(self) -> dict[str, Any]:
        """Coverage facts.  A scan must be able to say what it did not read."""
        return {
            "synthesized": self.is_synthesized,
            "files_included": self.files_included,
            "bytes_read": self.bytes_read,
            "files_dropped_by_cap": len(self.skipped_cap),
            "files_dropped_binary": len(self.skipped_binary),
            "files_dropped_too_large": len(self.skipped_too_large),
            "files_dropped_not_source": len(self.skipped_not_source),
        }


def synthesize_files_data(
    target: str | Path,
    max_files: int = DEFAULT_MAX_FILES,
    max_bytes: int = DEFAULT_MAX_BYTES,
    include_patches: bool = True,
) -> SynthesizedFiles:
    """Build a PR-shaped ``files_data`` list from a local directory.

    Returns an empty payload (with ``is_synthesized`` still True) when ``target``
    is not a local directory -- a URL, a single file, or a missing path has no
    diff to synthesize and the caller must keep its "no diff supplied" warning
    rather than invent one.
    """
    root = Path(target).expanduser()
    if not root.is_dir():
        return SynthesizedFiles(target=str(target))

    out = SynthesizedFiles(target=str(root.resolve()))

    # Deterministic order: security-relevant source first, then source, then
    # manifests, then tests -- so a file cap drops the least interesting files
    # and the same directory produces the same payload twice.
    ranked: list[tuple[int, str, Path]] = []
    for path in iter_candidates(root):
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            continue
        ranked.append((_priority(rel), rel, path))
    ranked.sort(key=lambda item: (item[0], item[1]))

    for _, rel, path in ranked:
        if out.files_included >= max_files:
            out.skipped_cap.append(rel)
            continue
        try:
            raw = path.read_bytes()
        except OSError:
            out.skipped_binary.append(rel)
            continue
        if b"\x00" in raw[:8192]:
            out.skipped_binary.append(rel)
            continue
        if len(raw) > max_bytes:
            out.skipped_too_large.append(rel)
            continue

        out.bytes_read += len(raw)
        entry: dict[str, Any] = {
            "filename": rel,
            "status": SYNTHESIZED_STATUS,
            # 0 on purpose: see the module docstring.  A synthesized file is in
            # scope, not changed, and must not drive the diff-churn signals.
            "additions": 0,
            "deletions": 0,
        }
        if include_patches:
            text = raw.decode("utf-8", errors="replace")
            entry["patch"] = "".join("+" + ln + "\n" for ln in text.splitlines())
        out.files_data.append(entry)
        out.files_included += 1

    return out
