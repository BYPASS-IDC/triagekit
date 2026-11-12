"""Build ASCII / structured directory trees from scan findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class TreeNode:
    name: str
    children: dict[str, "TreeNode"] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        c = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            s = (f.get("severity") or "low").lower()
            if s in c:
                c[s] += 1
        for ch in self.children.values():
            cc = ch.counts
            for k in c:
                c[k] += cc[k]
        return c

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def _insert(root: TreeNode, parts: list[str], finding: dict[str, Any]) -> None:
    node = root
    for part in parts:
        if part not in node.children:
            node.children[part] = TreeNode(name=part)
        node = node.children[part]
    node.findings.append(finding)


def build_finding_tree(
    findings: Iterable[Any],
    *,
    file_attr: str = "file",
    severity_attr: str = "severity",
    title_attr: str = "title",
    line_attr: str = "line",
    rule_attr: str = "rule_id",
) -> TreeNode:
    root = TreeNode(name=".")
    for f in findings:
        if isinstance(f, dict):
            path = f.get(file_attr) or f.get("file") or ""
            sev = f.get(severity_attr) or f.get("severity") or "low"
            title = f.get(title_attr) or f.get("title") or f.get("id") or "issue"
            line = f.get(line_attr) or f.get("line")
            rule = f.get(rule_attr) or f.get("rule_id") or ""
        else:
            path = getattr(f, file_attr, None) or getattr(f, "file", "") or ""
            sev = getattr(f, severity_attr, None) or getattr(f, "severity", "low")
            title = getattr(f, title_attr, None) or getattr(f, "title", "issue")
            line = getattr(f, line_attr, None) or getattr(f, "line", None)
            rule = getattr(f, rule_attr, None) or getattr(f, "rule_id", "") or ""
        path = str(path).replace("\\", "/").strip("/")
        if not path:
            path = "(unknown)"
        parts = [p for p in path.split("/") if p]
        _insert(
            root,
            parts,
            {
                "severity": str(sev).lower(),
                "title": str(title),
                "line": line,
                "rule": str(rule),
                "file": path,
            },
        )
    return root


def _badge(counts: dict[str, int]) -> str:
    parts = []
    for k, label in (("critical", "C"), ("high", "H"), ("medium", "M"), ("low", "L")):
        if counts.get(k):
            parts.append(f"{label}:{counts[k]}")
    return " ".join(parts)


def render_ascii_tree(
    root: TreeNode,
    *,
    max_depth: int = 12,
    show_findings: bool = True,
    max_findings_per_file: int = 4,
) -> str:
    """
    Clean tree:

    project/                        C:2 H:5
    ├── src/                        H:3
    │   ├── api/
    │   │   └── routes.py           H:2
    │   │       ├── [high] SQLi:42
    │   │       └── [high] XSS:18
    │   └── main.py                 C:1
    └── README.md
    """
    lines: list[str] = []
    top = _badge(root.counts)
    lines.append(f"{'project/':<42} {top}".rstrip() if top else "project/")

    def walk(node: TreeNode, prefix: str, depth: int) -> None:
        if depth > max_depth:
            return
        items = sorted(node.children.items(), key=lambda x: (len(x[1].children) == 0, x[0].lower()))
        for i, (name, child) in enumerate(items):
            last = i == len(items) - 1
            elbow = "└── " if last else "├── "
            cont = "    " if last else "│   "
            is_dir = bool(child.children)
            display = f"{name}/" if is_dir else name
            badge = _badge(child.counts)
            # pad name column for badge alignment (approx)
            pad = max(1, 40 - len(prefix) - len(elbow) - len(display))
            line = f"{prefix}{elbow}{display}" + (" " * pad) + (badge if badge else "")
            lines.append(line.rstrip())

            if show_findings and child.findings and not child.children:
                shown = sorted(
                    child.findings,
                    key=lambda x: SEV_ORDER.get(x.get("severity", "low"), 9),
                )[:max_findings_per_file]
                for j, f in enumerate(shown):
                    last_f = j == len(shown) - 1 and len(child.findings) <= max_findings_per_file
                    # if more remain, not last visual
                    if j == len(shown) - 1 and len(child.findings) > max_findings_per_file:
                        last_f = False
                    felbow = "└── " if last_f else "├── "
                    loc = f":{f['line']}" if f.get("line") else ""
                    lines.append(
                        f"{prefix}{cont}{felbow}[{f.get('severity', '?')}] {f.get('title', 'issue')}{loc}"
                    )
                more = len(child.findings) - len(shown)
                if more > 0:
                    lines.append(f"{prefix}{cont}└── … +{more} more")

            walk(child, prefix + cont, depth + 1)

    walk(root, "", 0)
    return "\n".join(lines)


def tree_to_json(root: TreeNode) -> dict[str, Any]:
    def ser(n: TreeNode) -> dict[str, Any]:
        return {
            "name": n.name,
            "counts": n.counts,
            "total": n.total,
            "findings": n.findings,
            "children": [
                ser(c) for c in sorted(n.children.values(), key=lambda x: (len(x.children) == 0, x.name.lower()))
            ],
        }

    return ser(root)


def build_rich_tree(root: TreeNode):
    """Build a rich.tree.Tree for CLI display."""
    from rich.tree import Tree
    from rich.text import Text

    def badge_text(counts: dict) -> Text:
        t = Text()
        mapping = [
            ("critical", "bold red", "C"),
            ("high", "red", "H"),
            ("medium", "yellow", "M"),
            ("low", "green", "L"),
        ]
        parts = []
        for key, style, label in mapping:
            n = counts.get(key) or 0
            if n:
                parts.append((f"{label}:{n}", style))
        out = Text()
        for i, (label, style) in enumerate(parts):
            if i:
                out.append(" ")
            out.append(label, style=style)
        return out

    def add(node: TreeNode, tree: Tree, is_root: bool = False) -> None:
        items = sorted(node.children.items(), key=lambda x: (len(x[1].children) == 0, x[0].lower()))
        for name, child in items:
            is_dir = bool(child.children)
            label = Text()
            label.append("[DIR] " if is_dir else "[FILE] ")
            label.append(f"{name}/" if is_dir else name, style="bold cyan" if is_dir else "white")
            if child.total:
                label.append("  ")
                label.append_text(badge_text(child.counts))
            branch = tree.add(label)
            if child.findings and not child.children:
                shown = sorted(child.findings, key=lambda x: SEV_ORDER.get(x.get("severity", "low"), 9))[:6]
                for f in shown:
                    sev = f.get("severity", "low")
                    style = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "green"}.get(sev, "white")
                    loc = f" · L{f['line']}" if f.get("line") else ""
                    fl = Text()
                    fl.append(f"[{sev.upper()}]", style=style)
                    fl.append(f" {f.get('title', 'issue')}{loc}", style="dim")
                    branch.add(fl)
                more = len(child.findings) - len(shown)
                if more > 0:
                    branch.add(Text(f"... +{more} more", style="dim"))
            add(child, branch)

    title = Text()
    title.append("[ROOT] project", style="bold")
    if root.total:
        title.append("  ")
        title.append_text(badge_text(root.counts))
    tree = Tree(title)
    add(root, tree, True)
    return tree
