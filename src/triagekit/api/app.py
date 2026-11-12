from pathlib import Path
import shutil
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from triagekit import __version__
from triagekit.core.engine import TriageEngine
from triagekit.core.config import get_settings
from triagekit.core.analyzers.repo_scan import scan_repository
from triagekit.core.analyzers.cve import scan_dependencies
from triagekit.core.analyzers.security_agent import run_security_agent
from triagekit.core.repo_fetch import resolve_scan_target
from triagekit.core.scan_runner import run_repo_scan

BASE = Path(__file__).resolve().parent.parent
from fastapi.staticfiles import StaticFiles
from pathlib import Path as _Path

app = FastAPI(title="TriageKit", version=__version__)
app.mount("/static", StaticFiles(directory=str(BASE / "web" / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE / "web" / "templates"))


_APP_DIR = _Path(__file__).resolve().parent.parent / "web" / "static" / "app"
if _APP_DIR.is_dir():
    app.mount("/app", StaticFiles(directory=str(_APP_DIR), html=True), name="react-app")

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "version": __version__})


@app.post("/triage", response_class=HTMLResponse)
async def run_triage(request: Request, repo: str = Form(...), number: int = Form(...)):
    error = result = markdown = None
    files = []
    try:
        result = TriageEngine().full_triage(repo.strip(), number)
        markdown = result.to_markdown()
        try:
            from triagekit.core.github_client import GitHubClient
            gh = GitHubClient()
            pr = gh.get_pull(repo.strip(), int(number))
            files = gh.get_pr_files(pr)
        except Exception:
            files = []
    except Exception as e:
        error = str(e)
    return templates.TemplateResponse(
        "result.html",
        {
            "request": request,
            "version": __version__,
            "repo": repo,
            "number": number,
            "result": result,
            "markdown": markdown,
            "files": files,
            "error": error,
        },
    )


@app.post("/scan", response_class=HTMLResponse)
async def run_scan(
    request: Request,
    target: str = Form(...),
    branch: str = Form(""),
    no_cve: str = Form(""),
    no_agent: str = Form(""),
):
    error = None
    result = None
    markdown = None
    counts = None
    agent = None
    finding_tree = None
    skip_cve = no_cve in ("1", "on", "true", "yes")
    skip_agent = no_agent in ("1", "on", "true", "yes")
    path = None
    cleanup = None
    try:
        # The shared runner: every scanner the CLI runs (repository, dependency,
        # taint, static, heuristic), converted once into the record the agent and
        # the report read.  This route used to call scan_repository directly,
        # which omitted the taint/static/heuristic layers entirely -- so the HTML
        # UI and the CLI disagreed about the same repo.
        # Off the event loop: run_repo_scan calls asyncio.run internally, and
        # calling that inside an async route raises "cannot be called from a
        # running event loop" -- the same class of bug as the dead import above,
        # and just as invisible until a request is made.
        run = await run_in_threadpool(
            run_repo_scan,
            target.strip(),
            branch=branch.strip(),
            github_token=get_settings().github_token,
            no_cve=skip_cve,
        )
        path = run.path
        cleanup = run.cleanup
        result = run.legacy
        result.advisories = run.advisories if hasattr(run, "advisories") else []
        if not skip_agent:
            # The skills follow the findings, exactly as the CLI does.
            agent = run_security_agent(result, use_llm=True, operation="repo_scan")
        markdown = result.to_markdown()
        counts = result.counts()
        finding_tree = None
        try:
            from triagekit.core.tree_view import build_finding_tree, tree_to_json
            finding_tree = tree_to_json(build_finding_tree(result.findings))
        except Exception:
            finding_tree = None
    except Exception as e:
        error = str(e)
    finally:
        if cleanup is not None:
            shutil.rmtree(cleanup, ignore_errors=True)

    return templates.TemplateResponse(
        "scan_result.html",
        {
            "request": request,
            "version": __version__,
            "target": target,
            "result": result,
            "markdown": markdown,
            "counts": counts,
            "agent": agent,
            "error": error,
            "no_cve": skip_cve,
            "no_agent": skip_agent,
            "finding_tree": finding_tree,
        },
    )




@app.post("/webscan", response_class=HTMLResponse)
async def run_webscan(
    request: Request,
    url: str = Form(...),
    no_paths: str = Form(""),
    no_agent: str = Form(""),
):
    from triagekit.core.analyzers.web_scan import scan_website
    from triagekit.core.analyzers.security_agent import run_security_agent, web_findings_as_repo
    from triagekit.core.analyzers.repo_scan import RepoScanResult, Finding

    error = None
    result = None
    markdown = None
    counts = None
    agent = None
    skip_paths = no_paths in ("1", "on", "true", "yes")
    skip_agent = no_agent in ("1", "on", "true", "yes")
    try:
        result = scan_website(url.strip(), check_sensitive_paths=not skip_paths)
        markdown = result.to_markdown()
        counts = result.counts()
        if not skip_agent:
            # One shared adaptation: it carries the CWE across, which is how the
            # agent's skill selector knows this is a SQL injection.
            fake = web_findings_as_repo(
                result.findings, url=result.url, final_url=result.final_url,
                score=result.score, grade=result.grade, summary=result.summary,
            )
            agent = run_security_agent(fake, use_llm=True, operation="web_scan")
    except Exception as e:
        error = str(e)

    return templates.TemplateResponse(
        "web_result.html",
        {
            "request": request,
            "version": __version__,
            "url": url,
            "result": result,
            "markdown": markdown,
            "counts": counts,
            "agent": agent,
            "error": error,
        },
    )




# ── JSON API for React / Vite UI (same engines, no detection changes) ──
from fastapi.responses import JSONResponse

def _finding_dict(f):
    if hasattr(f, "__dict__"):
        d = dict(f.__dict__)
        return d
    if isinstance(f, dict):
        return f
    return {"title": str(f)}

@app.get("/api/health")
def api_health():
    return {"ok": True, "version": __version__}

@app.post("/api/triage")
async def api_triage(repo: str = Form(...), number: int = Form(...)):
    try:
        from triagekit.core.engine import TriageEngine
        result = TriageEngine().full_triage(repo.strip(), int(number))
        return JSONResponse({
            "ok": True,
            "markdown": result.to_markdown(),
            "result": result.model_dump(mode="json"),
        })
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)

@app.post("/api/scan")
async def api_scan(
    target: str = Form(...),
    branch: str = Form(""),
    no_cve: str = Form(""),
    no_agent: str = Form(""),
):
    try:
        from triagekit.core.analyzers.security_agent import run_security_agent
        skip_cve = no_cve in ("1", "on", "true", "yes")
        skip_agent = no_agent in ("1", "on", "true", "yes")
        # This route called scan_target, a name that has never existed in
        # repo_scan, so every request answered with an ImportError.  The shared
        # runner is the same implementation the CLI uses, and it runs in the
        # threadpool because it calls asyncio.run internally.
        run = await run_in_threadpool(
            run_repo_scan,
            target.strip(),
            branch=branch.strip(),
            github_token=get_settings().github_token,
            no_cve=skip_cve,
        )
        try:
            result = run.legacy
            agent = None
            if not skip_agent:
                try:
                    agent = run_security_agent(result, use_llm=True, operation="repo_scan")
                except Exception:
                    agent = None
            return JSONResponse({
                "ok": True,
                "markdown": result.to_markdown(),
                "counts": result.counts(),
                "score": result.score,
                "grade": result.grade,
                "summary": result.summary,
                "findings": [_finding_dict(f) for f in result.findings],
                "cve_findings": [_finding_dict(f) for f in getattr(result, "cve_findings", []) or []],
                "languages": result.languages,
                "files_scanned": result.files_scanned,
                "agent": agent,
                "target": target,
            })
        finally:
            run.dispose()
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)


@app.post("/api/webscan")
async def api_webscan(
    url: str = Form(...),
    no_paths: str = Form(""),
    no_agent: str = Form(""),
):
    try:
        from triagekit.core.analyzers.web_scan import scan_website
        from triagekit.core.analyzers.security_agent import run_security_agent, web_findings_as_repo
        from triagekit.core.analyzers.repo_scan import RepoScanResult, Finding
        skip_paths = no_paths in ("1", "on", "true", "yes")
        skip_agent = no_agent in ("1", "on", "true", "yes")
        result = scan_website(url.strip(), check_sensitive_paths=not skip_paths)
        agent = None
        if not skip_agent:
            try:
                fake = web_findings_as_repo(
                    result.findings, url=result.url, final_url=result.final_url,
                    score=result.score, grade=result.grade, summary=result.summary,
                )
                agent = run_security_agent(fake, use_llm=True, operation="web_scan")
            except Exception:
                agent = None
        return JSONResponse({
            "ok": True,
            "markdown": result.to_markdown(),
            "counts": result.counts(),
            "score": result.score,
            "grade": result.grade,
            "summary": result.summary,
            "status_code": result.status_code,
            "final_url": result.final_url,
            "url": result.url,
            "findings": [_finding_dict(f) for f in result.findings],
            "endpoints": result.endpoints,
            "network": result.network,
            "cookies": result.cookies,
            "forms": result.forms,
            "js_files": result.js_files,
            "api_hints": result.api_hints,
            "playbook": result.playbook,
            "technologies": result.technologies,
            "agent": agent,
        })
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)


@app.get("/health")
async def health():
    return {"status": "ok", "version": __version__}
