from __future__ import annotations
from typing import Any, Optional
import os
from github import Auth, Github
from github.PullRequest import PullRequest
from .config import get_settings

class GitHubClient:
    def __init__(self, token: Optional[str] = None):
        token = token or get_settings().github_token
        if not token:
            raise ValueError("GITHUB_TOKEN is required")
        self._gh = Github(auth=Auth.Token(token))

    def get_pull(self, repo: str, number: int) -> PullRequest:
        return self._gh.get_repo(repo).get_pull(number)

    def get_pr_files(self, pr: PullRequest) -> list[dict[str, Any]]:
        return [{
            "filename": f.filename, "status": f.status,
            "additions": f.additions, "deletions": f.deletions,
            "changes": f.changes, "patch": (f.patch or "")[:8000],
        } for f in pr.get_files()]

    def get_pr_diff_text(self, pr: PullRequest, max_chars: int = 20000) -> str:
        parts, total = [], 0
        for f in pr.get_files():
            header = f"### {f.filename} ({f.status}) +{f.additions}/-{f.deletions}\n"
            chunk = header + (f.patch or "")
            if total + len(chunk) > max_chars:
                if max_chars - total > 500:
                    parts.append(chunk[: max_chars - total] + "\n… [truncated]")
                break
            parts.append(chunk)
            total += len(chunk)
        return "\n\n".join(parts) or "(no textual diff)"

    def pr_context(self, pr: PullRequest) -> dict[str, Any]:
        files = self.get_pr_files(pr)
        return {
            "number": pr.number, "title": pr.title, "body": pr.body or "",
            "user": pr.user.login if pr.user else "unknown",
            "state": pr.state, "draft": bool(pr.draft),
            "base": pr.base.ref, "head": pr.head.ref,
            "additions": pr.additions, "deletions": pr.deletions,
            "changed_files": pr.changed_files, "commits": pr.commits,
            "labels": [l.name for l in pr.labels], "mergeable": pr.mergeable,
            "html_url": pr.html_url, "files": files,
            "diff": self.get_pr_diff_text(pr),
        }

    def download_repo_archive(self, repo: str, ref: str, dest_dir) -> str:
        """Download repo archive for branch/tag/sha into dest_dir; return extract root."""
        import io
        import tarfile
        from pathlib import Path
        dest = Path(dest_dir)
        dest.mkdir(parents=True, exist_ok=True)
        # PyGithub: get_archive is not always present; use requester
        owner, name = repo.split("/", 1)
        url = f"https://api.github.com/repos/{owner}/{name}/tarball/{ref}"
        headers = {"Accept": "application/vnd.github+json"}
        token = getattr(self, "_token", None) or getattr(self, "token", None)
        try:
            from .config import get_settings
            token = token or get_settings().github_token
        except Exception:
            pass
        if token:
            headers["Authorization"] = f"Bearer {token}"
        import httpx
        with httpx.Client(follow_redirects=True, timeout=120.0) as client:
            resp = client.get(url, headers=headers)
            resp.raise_for_status()
            bio = io.BytesIO(resp.content)
            with tarfile.open(fileobj=bio, mode="r:gz") as tar:
                # Secure extraction: validate paths to prevent directory traversal
                for member in tar.getmembers():
                    # Skip absolute paths and paths with directory traversal
                    if os.path.isabs(member.name) or ".." in member.name:
                        continue
                    # Resolve full path and ensure it's within dest
                    member_path = (dest / member.name).resolve()
                    if not str(member_path).startswith(str(dest.resolve())):
                        continue
                # All members validated, safe to extract
                tar.extractall(dest)
        # single top-level directory
        kids = [p for p in dest.iterdir() if p.is_dir()]
        return str(kids[0] if len(kids) == 1 else dest)
