"""Resolve a scan target: local path, GitHub repo, optional branch/ref."""

from __future__ import annotations

import re
import shutil
import tempfile
from pathlib import Path
from typing import Optional, Tuple


def _parse_github_target(raw: str) -> tuple[str, Optional[str]] | None:
    """Return (owner/repo, ref) or None if not a github target.

    Accepts:
      owner/repo
      owner/repo@branch
      owner/repo#branch
      https://github.com/owner/repo
      https://github.com/owner/repo/tree/branch
    """
    s = raw.strip().rstrip("/")
    m = re.match(r"https?://github\.com/([^/]+)/([^/#?]+)(?:/tree/([^/#?]+))?", s, re.I)
    if m:
        name = m.group(2)
        if name.endswith('.git'):
            name = name[:-4]
        slug = f"{m.group(1)}/{name}"
        return slug, m.group(3)
    if re.match(r"^[\w.-]+/[\w.-]+$", s):
        return s, None
    m = re.match(r"^([\w.-]+/[\w.-]+)[@#]([\w./-]+)$", s)
    if m:
        return m.group(1), m.group(2)
    return None


def resolve_scan_target(
    target: str,
    github_token: Optional[str] = None,
    branch: Optional[str] = None,
) -> Tuple[Path, Optional[Path]]:
    """
    Accepts:
      - Local directory/file
      - GitHub slug: owner/repo or owner/repo@branch
      - GitHub URL with optional /tree/branch
      - branch= overrides ref when provided

    Returns (scan_path, cleanup_path).
    """
    raw = (target or "").strip().strip('"').strip("'")
    if not raw:
        raise ValueError("Empty scan target")

    # Local paths first
    candidates = []
    p = Path(raw).expanduser()
    candidates.append(p)
    try:
        candidates.append(p.resolve())
    except Exception:
        pass
    candidates.append(Path.cwd() / raw)
    for cand in candidates:
        try:
            if not cand.exists():
                continue
        except Exception:
            continue
        if cand.is_dir():
            return cand.resolve(), None
        if cand.is_file():
            tmp = Path(tempfile.mkdtemp(prefix="triagekit-file-"))
            shutil.copy2(cand, tmp / cand.name)
            return tmp, tmp
        raise ValueError(f"Path exists but is not a file or directory: {cand}")

    parsed = _parse_github_target(raw)
    if not parsed:
        raise ValueError(
            f"Target not found locally and not a GitHub slug/URL: {raw!r}. "
            "Use a path, owner/repo, owner/repo@branch, or github.com URL."
        )
    slug, ref = parsed
    ref = branch or ref or "HEAD"

    tmp = Path(tempfile.mkdtemp(prefix="triagekit-scan-"))
    try:
        from .github_client import GitHubClient
        gh = GitHubClient()
        root = gh.download_repo_archive(slug, ref, tmp)
        return Path(root), tmp
    except Exception as e:
        shutil.rmtree(tmp, ignore_errors=True)
        raise ValueError(f"Failed to fetch GitHub {slug}@{ref}: {e}") from e
