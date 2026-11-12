#!/usr/bin/env python3
from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console
from triagekit.core.skills import assign_skills, assign_skills_for
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

from .core.config import get_settings
from .core.engine import TriageEngine
from .core.github_client import GitHubClient
from .core.llm import LLMClient
from .core.output import configure_stdout, dumps_json, safe_console_text

app = typer.Typer(
    name="triagekit",
    help="Deep triage and security scanning for open-source maintainers.",
    no_args_is_help=True,
)
console = Console()

# Output must never abort a command: reconfigure the streams so any character in
# a finding title can be emitted, then fold the ones a legacy console still
# refuses.  Without this, a title containing an arrow character raises
# UnicodeEncodeError mid-write and corrupts `--json` output.
configure_stdout()


def _engine(token: Optional[str] = None) -> TriageEngine:
    return TriageEngine(github=GitHubClient(token=token), llm=LLMClient())


@app.command()
def triage(
    number: int = typer.Argument(..., help="Pull request number"),
    repo: str = typer.Option(..., "--repo", "-r", help="owner/repo"),
    token: Optional[str] = typer.Option(None, "--token", "-t"),
    json_out: bool = typer.Option(False, "--json"),
):
    """Run maximum-depth multi-stage PR triage."""
    engine = _engine(token)
    with console.status("[bold magenta]Auto-skills: "
                        + ", ".join(assign_skills_for("pr_triage"))
                        + " · elite multi-stage triage…"):
        result = engine.full_triage(repo, number)
    if json_out:
        # `model_dump_json` can embed characters a cp1252 console refuses; route
        # through the ASCII-safe emitter so `--json` is always pure JSON.
        print(dumps_json(result.model_dump()))
        return
    color = {
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "bold red",
    }.get(result.risk_level.value, "white")
    t = Table(show_header=False, box=None, padding=(0, 1))
    t.add_column(style="bold")
    t.add_column()
    t.add_row(
        "Risk",
        f"[{color}]{result.risk_level.value.upper()}[/{color}] ({result.risk_score:.1f}/10)",
    )
    t.add_row("Type", result.primary_change_type.value)
    t.add_row("Suggestions", str(len(result.suggestions)))
    t.add_row("Actions", str(len(result.recommended_actions)))
    t.add_row("Confidence", f"{result.confidence:.0%}")
    t.add_row("Human review", "Yes" if result.needs_human_review else "No")
    console.print(Panel(t, title=f"PR #{result.number} · {result.title}", border_style="magenta"))
    console.print(Markdown(result.to_markdown()))


@app.command()
def scan(
    target: str = typer.Argument(
        ..., help="Local folder/file, owner/repo, owner/repo@branch, or GitHub URL"
    ),
    branch: Optional[str] = typer.Option(
        None, "--branch", "-b", help="Git branch/tag/ref (overrides @branch in target)"
    ),
    token: Optional[str] = typer.Option(None, "--token", "-t"),
    no_cve: bool = typer.Option(False, "--no-cve", help="Skip OSV lookup"),
    json_out: bool = typer.Option(False, "--json"),
    max_files: int = typer.Option(8000, "--max-files"),
    sarif: bool = typer.Option(False, "--sarif", help="Emit SARIF JSON"),
    agent: bool = typer.Option(
        True, "--agent/--no-agent", help="Security-agent prioritization"
    ),
):
    """Scan a local path or GitHub repo (no PR required) using the scanner framework."""
    import shutil

    from .core.analyzers.security_agent import run_security_agent
    from .core.scan_runner import run_repo_scan

    settings = get_settings()
    gh_token = token or settings.github_token
    cleanup = None
    run = None
    try:
        # One shared runner, the same one the UI calls (defect D82: the UI used
        # to import a function that never existed, because this logic lived
        # inline here where nothing could import it and test it).  Keeping the
        # conversion in one place is also what keeps the agent's input identical
        # across both surfaces -- it has to carry cwe/rule_id for the skill
        # selector to recognise the class (D79).
        with console.status("[bold magenta]Resolving target…"):
            run = run_repo_scan(
                target,
                branch=branch or "",
                github_token=gh_token,
                no_cve=no_cve,
                max_files=max_files,
            )
        path = run.path
        cleanup = run.cleanup
        result = run.orchestration
        # One score for the whole run, derived from the findings that exist.  The
        # old inline penalty was a second copy of the formula in scan_runner, so
        # the CLI and the UI could grade the same repo differently.
        score = run.legacy.score
        grade = run.legacy.grade

        # Run security agent analysis
        agent_brief = None
        if agent:
            with console.status("[bold magenta]Security agent analysis…"):
                agent_brief = run_security_agent(
                    run.legacy, use_llm=True, operation="repo_scan"
                )

        if sarif:
            # Use first scanner's SARIF or aggregate.  Machine consumers require
            # a document that is pure JSON from the first byte to the last.
            print(dumps_json({"results": [r.to_dict() for r in result.scan_results]}))
            return
        def serialize_finding(f):
            """Serialize a UnifiedFinding to JSON-serializable dict."""
            d = f.__dict__.copy()
            # Convert Path objects to strings
            if d.get("file_path") and hasattr(d["file_path"], "__fspath__"):
                d["file_path"] = str(d["file_path"])
            # Convert datetime objects to ISO format strings
            for key, value in d.items():
                if hasattr(value, "isoformat"):  # datetime objects
                    d[key] = value.isoformat()
            return d

        if json_out:
            all_findings = [f for r in result.scan_results for f in r.findings]
            counts = result.summary["by_severity"]
            dep_results = [
                r for r in result.scan_results
                if r.scan_type.value == "dependency_scan"
            ]
            dep_coverage = {}
            dependency_files: list[str] = []
            for r in dep_results:
                dependency_files.extend(r.metadata.get("manifests_scanned", []) or [])
                dep_coverage.update(r.metadata.get("dependency_coverage", {}) or {})
            payload = {
                "root": str(path),
                "files_scanned": sum(r.metadata.get("files_scanned", 0) for r in result.scan_results),
                "findings": [serialize_finding(f) for f in all_findings],
                "cve_findings": [serialize_finding(f) for f in all_findings if f.category == "vulnerable-dependency"],
                "dependency_files": sorted(set(dependency_files)),
                "counts": counts,
                "score": score,
                "grade": grade,
                "dependency_coverage": dep_coverage,
                "summary": (
                    f"{result.summary['total_findings']} findings across "
                    f"{result.summary['scanners_completed']} scanners "
                    f"({result.summary['scanners_failed']} failed). "
                    f"Score {score}/100 (grade {grade})."
                ),
                "agent": agent_brief,
            }
            print(dumps_json(payload))
            return

        counts = result.summary["by_severity"]
        all_findings = [f for r in result.scan_results for f in r.findings]
        t = Table(show_header=False, box=None, padding=(0, 1))
        t.add_column(style="bold")
        t.add_column()
        t.add_row("Score", f"{score:.1f}/100 (grade {grade})")
        t.add_row("Files", str(sum(r.metadata.get("files_scanned", 0) for r in result.scan_results)))
        t.add_row("Findings", str(result.summary["total_findings"]))
        t.add_row("CVEs", str(sum(len(r.findings) for r in result.scan_results if r.scan_type.value == "dependency_scan")))
        t.add_row("Critical", str(counts.get("critical", 0)))
        t.add_row("High", str(counts.get("high", 0)))
        t.add_row("Medium", str(counts.get("medium", 0)))
        t.add_row("Low", str(counts.get("low", 0)))
        console.print(Panel(t, title=f"Repo scan · {target}", border_style="magenta"))

        # Print findings
        from rich.markdown import Markdown
        lines = [f"## Security Scan Results for {path}", ""]
        for r in result.scan_results:
            if r.findings:
                lines.append(f"### {r.scanner_name} ({len(r.findings)} findings)")
                for f in r.findings:
                    lines.append(f"- **{f.title}** ({f.severity.value}) - {f.description[:100]}...")
                    if f.file_path:
                        lines.append(f"  File: {f.file_path}:{f.line_number or '?'}")
                lines.append("")
        console.print(Markdown("\n".join(lines)))

        try:
            from .core.tree_view import build_finding_tree, build_rich_tree
            all_findings = [f for r in result.scan_results for f in r.findings]
            tree = build_finding_tree(all_findings)
            console.print()
            console.rule("[bold]Directory tree (findings)")
            console.print(build_rich_tree(tree))
        except Exception:
            pass

        if agent_brief:
            lines = [
                "## Security agent brief",
                "",
                agent_brief.get("executive_summary") or "",
                "",
                "### Attack surface",
            ]
            for a in agent_brief.get("attack_surface") or []:
                lines.append(f"- {a}")
            lines += ["", "### Priority fixes"]
            for pf in agent_brief.get("priority_fixes") or []:
                lines.append(
                    f"{pf.get('priority', '')}. **{pf.get('title', '')}** — {pf.get('how', '')}"
                )
            console.print(Markdown("\n".join(lines)))
    finally:
        if cleanup is not None:
            shutil.rmtree(cleanup, ignore_errors=True)




@app.command("webscan")
def webscan(
    url: str = typer.Argument(..., help="Website URL (https://example.com)"),
    no_paths: bool = typer.Option(False, "--no-paths", help="Skip sensitive path checks"),
    agent: bool = typer.Option(True, "--agent/--no-agent", help="AI security brief if LLM configured"),
    json_out: bool = typer.Option(False, "--json"),
):
    """Scan a website security posture (headers, HTTPS, cookies, exposures). Authorized targets only."""
    from .core.analyzers.web_scan import scan_website

    # The status line used to print the static skill list, then build the prompt
    # from a different, finding-driven one. It now prints what will actually be
    # attempted for the skill part of the budget; the class-specific skills are
    # added once stage one has findings to choose them from.
    with console.status("[bold magenta]Auto-skills: "
                        + ", ".join(assign_skills_for("web_scan"))
                        + " · website posture…"):
        result = scan_website(url, check_sensitive_paths=not no_paths)

    agent_brief = None
    if agent:
        try:
            with console.status("[bold magenta]Security agent…"):
                from .core.analyzers.security_agent import run_security_agent, web_findings_as_repo
                # One shared adaptation: it carries the CWE across, which is how
                # the agent's skill selector knows this is a SQL injection.
                fake = web_findings_as_repo(
                    result.findings, url=result.url, final_url=result.final_url,
                    score=result.score, grade=result.grade, summary=result.summary,
                )
                agent_brief = run_security_agent(fake, use_llm=True, operation="web_scan")
        except Exception:
            agent_brief = None

    if json_out:
        payload = {
            "url": result.url,
            "final_url": result.final_url,
            "status_code": result.status_code,
            "score": result.score,
            "grade": result.grade,
            "findings": [f.__dict__ for f in result.findings],
            "technologies": result.technologies,
            "endpoints": result.endpoints,
            "network": result.network,
            "cookies": result.cookies,
            "forms": result.forms,
            "js_files": result.js_files,
            "api_hints": result.api_hints,
            "fixes": result.fixes,
            "playbook": result.playbook,
            "agent": agent_brief,
        }
        print(dumps_json(payload))
        return

    from rich.table import Table
    from rich.panel import Panel
    from rich.markdown import Markdown
    counts = result.counts()
    t = Table(show_header=False, box=None, padding=(0, 1))
    t.add_column(style="bold"); t.add_column()
    t.add_row("Score", f"{result.score}/100 ({result.grade})")
    t.add_row("Status", str(result.status_code))
    t.add_row("Final URL", result.final_url or result.url)
    t.add_row("Findings", str(len(result.findings)))
    t.add_row("Critical", str(counts["critical"]))
    t.add_row("High", str(counts["high"]))
    console.print(Panel(t, title=f"Web scan · {url}", border_style="magenta"))
    console.print(Markdown(result.to_markdown()))
    if agent_brief:
        lines = ["## Security agent brief", "", agent_brief.get("executive_summary") or ""]
        for a in agent_brief.get("attack_surface") or []:
            lines.append(f"- {a}")
        console.print(Markdown("\n".join(lines)))


@app.command()
def serve(
    host: Optional[str] = None,
    port: Optional[int] = None,
):
    """Start the web dashboard (PR triage + local/GitHub scan)."""
    import uvicorn

    s = get_settings()
    h, p = host or s.host, port or s.port
    console.print(f"[bold]TriageKit[/bold] → http://{h}:{p}")
    uvicorn.run("triagekit.api.app:app", host=h, port=p, log_level="info")


if __name__ == "__main__":
    app()
