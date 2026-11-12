# TriageKit Security Architecture

**Version:** 1.0  
**Date:** 2026-11-09  
**Status:** Baseline Architecture Document

---

## 1. Architectural Principles

### 1.1 Core Design Principles (from README.md)

1. **Static First** — Never pay for an LLM call without cheap, deterministic signal
2. **Structured Everything** — No free-form-only output; the model must fill a schema
3. **Blend, Don't Trust One Source** — Static score and LLM score are combined
4. **Security Is Visible** — Findings get their own list, risk boost, and UI section
5. **Actionable Over Vague** — Suggestions should name a file and a concrete change when possible
6. **Honest Scope** — The product must not claim "no vulnerabilities" or full audit completeness
7. **Maintainer UX** — Hierarchy, counters, and "what do I look at first?" beat long walls of text

### 1.2 Security-Specific Principles

8. **Defense in Depth** — Multiple analysis layers (static, heuristic, LLM, taint, external scanners)
9. **Evidence Integrity** — Every finding preserves source location, detection method, trace evidence
10. **Confidence Transparency** — Distinguish CONFIRMED/HIGH/MEDIUM/LOW/NOT_ASSESSED/NOT_APPLICABLE
11. **Missing Evidence ≠ Low Risk** — Unavailable scanners, missing diffs, unsupported languages report as NOT ASSESSED
12. **Least Privilege** — Agent operations default to read-only; destructive actions require explicit approval
13. **Auditability** — All security-relevant operations logged with tamper-resistant trails
14. **Recovery by Default** — Every automated action supports rollback and interruption recovery

---

## 2. System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              TRIAGEKIT SECURITY PLATFORM                              │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │
│  │    CLI       │  │  Classic UI  │  │  React UI    │  │  REST API    │             │
│  │  (Typer)     │  │  (Jinja2)    │  │  (Vite/React)│  │  (FastAPI)   │             │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘             │
│         │                 │                 │                 │                      │
│         └─────────────────┼─────────────────┼─────────────────┘                      │
│                           ▼                                                     │
│              ┌────────────────────────┐                                        │
│              │   Orchestration Layer  │                                        │
│              │  (TriageEngine +       │                                        │
│              │   ScannerOrchestrator) │                                        │
│              └───────────┬────────────┘                                        │
│                          │                                                      │
│         ┌───────────────┼───────────────┐                                      │
│         ▼               ▼               ▼                                      │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐                               │
│  │   Static    │ │  Heuristic  │ │  Taint      │  ──► Scanner Framework       │
│  │  Analysis   │ │  Security   │ │  Analysis   │     (BaseScanner, Registry,  │
│  │  (static.py)│ │  (security) │ │  (taint/*)  │      Orchestrator, Correlation)│
│  └──────┬──────┘ └──────┬──────┘ └──────┬──────┘                               │
│         │               │               │                                        │
│         └───────────────┼───────────────┘                                        │
│                         ▼                                                      │
│              ┌────────────────────────┐                                        │
│              │   LLM Reasoning Layer  │                                        │
│              │  (prompts.py + llm.py) │                                        │
│              └───────────┬────────────┘                                        │
│                          │                                                      │
│         ┌───────────────┼───────────────┐                                      │
│         ▼               ▼               ▼                                      │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐                               │
│  │  Blend &    │ │  Correlation│ │  Recovery   │  ──► Future Phases            │
│  │  Normalize  │ │  Engine     │ │  & Rollback │                               │
│  └─────────────┘ └─────────────┘ └─────────────┘                               │
│                                                                                       │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Architecture

### 3.1 Entry Points

| Component | File | Responsibility |
|-----------|------|----------------|
| **CLI** | `cli.py` | Typer commands: `triage`, `scan`, `webscan`, `serve` |
| **FastAPI App** | `api/app.py` | Routes for Classic UI (HTML) + React API (JSON) |
| **MCP Server** | *Planned* | Model Context Protocol for agent integration |

### 3.2 Orchestration Layer

#### 3.2.1 TriageEngine (Legacy - PR Triage)
```
Location: core/engine.py
Stages:
  1. GitHubClient.pr_context() → PR metadata + files + diff
  2. static.analyze_files() → FileInsight[]
  3. static.compute_static_risk() → (score 0-10, signals[])
  4. security.scan_diff_for_security() → findings[]
  5. security.security_signals_text() → signals for LLM
  6. Critical/High findings BOOST static_score
  7. LLMClient.complete_json(SYSTEM + skills, user_message) → structured JSON
  8. parse_llm_json() → 8-pass repair pipeline
  9. Blend: 0.30 × static + 0.70 × llm → risk_score (0-10)
 10. Risk level thresholds: ≥8=CRITICAL, ≥5.5=HIGH, ≥2.5=MEDIUM, <2.5=LOW
 11. Merge heuristic findings if LLM omitted them
 12. Construct TriageResult (Pydantic validation)
```

#### 3.2.2 ScannerOrchestrator (New - Modular Framework)
```
Location: core/scanners/orchestrator.py
Capabilities:
  - ScannerRegistry: discovery, registration, type-based lookup
  - Concurrent execution with semaphore (default max 3)
  - Timeout handling per scanner
  - CorrelationEngine: deduplication + cross-scanner correlation
  - Attack path identification
  - Prioritized finding list
  - OrchestrationResult with summary metadata
```

### 3.3 Analyzer Layer (Legacy - Direct Imports)

| Analyzer | File | Type | Key Features |
|----------|------|------|--------------|
| **Static** | `core/analyzers/static.py` | Deterministic | Path classification, churn scoring, test detection |
| **Security (Diff)** | `core/analyzers/security.py` | Heuristic | 5 pattern families, added-lines only, severity mapping |
| **Repo Scan** | `core/analyzers/repo_scan.py` | God-mode | 60+ patterns, 5 languages, FP filtering, entropy, OSV, ExploitDB |
| **CVE/OSV** | `core/analyzers/cve.py` | Dependency | 8 manifest formats, CVSS severity, batch queries |
| **Web Scan** | `core/analyzers/web_scan.py` | Active/Passive | 6-layer: transport, crawl, exposure, HTML/JS, probes, intel |
| **Security Agent** | `core/analyzers/security_agent.py` | LLM-assisted | Executive brief, attack surface, priority fixes |
| **ExploitDB** | `core/analyzers/exploitdb.py` | Intelligence | Curated catalog + searchsploit CLI |
| **Exploit Relevance** | `core/analyzers/exploit_relevance.py` | Scoring | Heuristic + LLM refinement |

### 3.4 Scanner Framework Layer (New - Pluggable Architecture)

```
core/scanners/
├── base.py              # BaseScanner ABC, UnifiedFinding, ScanResult, ScannerRegistry
├── orchestrator.py      # ScannerOrchestrator, concurrent execution, correlation
├── correlation.py       # FindingDeduplicator, FindingCorrelator, CorrelationEngine
├── registry_init.py     # register_all_scanners(), default configs
├── static_scanner.py    # Wraps static.py
├── heuristic_scanner.py # Wraps security.py
├── repo_scanner.py      # Wraps repo_scan.py
├── web_scanner.py       # Wraps web_scan.py
├── dependency_scanner.py # Wraps cve.py
└── taint_scanner.py     # Wraps taint/analyzer.py + taint/js_analyzer.py
```

#### 3.4.1 UnifiedFinding Model (Cross-Scanner Standard)
```python
UnifiedFinding:
  - id, scanner_name, scanner_version, scan_type
  - title, description, severity, confidence, category
  - file_path, line_number, column_number, function_name, url, parameter
  - evidence, snippet, raw_data
  - recommendation, fix_example, effort_estimate, references
  - cwe_ids, cvss_vector, cvss_score, owasp_categories, mitre_attack_ids
  - fingerprint, correlated_findings, is_duplicate, duplicate_of, suppressed
  - first_seen, last_seen, status, tags, scanner_metadata
```

#### 3.4.2 Correlation Rules (Pre-Defined)
1. **injection_chain** — SQLi, command injection, XSS across static/heuristic/web/active
2. **secret_exposure_chain** — Hardcoded secrets ↔ leaked in web responses
3. **crypto_weakness_chain** — Weak crypto in code ↔ TLS issues in web scan
4. **auth_bypass_chain** — Auth issues in code ↔ exposed endpoints in web scan
5. **dependency_vuln_chain** — Vulnerable deps ↔ exploitable code patterns
6. **path_traversal_chain** — Path traversal in code ↔ accessible sensitive paths
6. **CWE-based cross-type** — Auto-correlation by shared CWE IDs

### 3.5 Taint Analysis Subsystem

```
core/taint/
├── models.py      # Source, Sink, Sanitizer, TaintTrace, TaintPath, FunctionSummary, CallGraph
├── registry.py    # 27 Python sources, 16 JS sources, 29 Python sinks, 14 JS sinks, 13+6 sanitizers
├── analyzer.py    # Python AST-based: interprocedural, call graph, parameter/return tracking
└── js_analyzer.py # JS/TS regex-based: function extraction, template literals, member expressions
```

#### 3.5.1 Source Categories (Python)
- `http-request` (Flask, Django, FastAPI): GET, POST, cookies, headers, files
- `user-input`: `input()`, `sys.argv`
- `environment`: `os.environ`, `os.getenv()`
- `file`: `open()`, `read()`, `readline()`
- `database`: SQLite, psycopg2, SQLAlchemy, Redis fetch
- `http-response`: `requests` `.json()`, `.text`, `.content`
- `process-output`: `subprocess` stdout/stderr
- `deserialization`: `yaml.load`, `pickle.load`, `json.loads`
- `code-execution`: `eval()`, `exec()`

#### 3.5.2 Sink Categories (Python)
- `sql-execution`: `cursor.execute`, `sqlite3`, `psycopg2`, SQLAlchemy, Django raw
- `command-execution`: `os.system`, `subprocess.*`, `shell=True`
- `code-execution`: `eval`, `exec`, `compile`
- `deserialization`: `pickle.load`, `yaml.load`
- `template-injection`: `render_template`, `jinja2`, `Template()`
- `path-traversal`: `open`, `os.path.join`, `pathlib.Path`, `send_file`
- `open-redirect`: `redirect`, `HttpResponseRedirect`
- `xss`: `HttpResponse`, `Response`, `make_response`
- `log-injection`: `logger.*`, `logging.*`, `print()`
- `ldap-injection`, `xpath-injection`, `regex-dos`

#### 3.5.3 Sanitizer Actions
- `REMOVE` — Complete taint removal (parameterized queries, safe_load)
- `TRANSFORM` — Data transformation (path normalization)
- `ESCAPE` — Character escaping (HTML escape, shlex.quote, re.escape)
- `VALIDATE` — Validation without modification (URL validation)

### 3.6 Data Model Layer

```
core/models/results.py
├── Enums: RiskLevel, ChangeType, SuggestionCategory, ImpactArea
├── RiskFactor, FileInsight, LabelSuggestion, RecommendedAction
├── CodeSuggestion, SecurityFinding, ImpactAssessment
└── TriageResult (primary output)
    - to_markdown() → complete report
    - model_dump_json() → machine-readable
```

### 3.7 Presentation Layer

| UI Stack | Templates/Components | Key Features |
|----------|---------------------|--------------|
| **Classic (Jinja2)** | `web/templates/*.html`, `web/static/style.css` | Analysis Chain tree, accordion panels, diff viewer, syntax highlighting |
| **React (Vite)** | `webui/src/pages/*.jsx`, `webui/src/components/*.jsx` | SessionStorage state, SideNav scroll-spy, FindingList accordions, SeverityBar |
| **CLI** | `cli.py` + Rich | Tables, panels, markdown rendering, JSON output |

---

## 4. Data Flow Architecture

### 4.1 PR Triage Flow (Current)

```
GitHub PR (owner/repo#number)
         │
         ▼
GitHubClient.pr_context()
         │
         ├──► files[] ──► static.analyze_files() ──► FileInsight[]
         │                │
         │                └─► compute_static_risk() ──► static_score (0-10), static_signals[]
         │
         ├──► files[] ──► security.scan_diff_for_security() ──► heuristic_findings[]
         │                │
         │                └─► security_signals_text() ──► sec_signals[]
         │
         ▼
static_score += critical*1.5 + high*0.8 (boost)
         │
         ▼
SYSTEM prompt + skills + build_user(ctx, static_signals, file_summary, sec_signals)
         │
         ▼
LLMClient.complete_json() ──► raw JSON
         │
         ▼
parse_llm_json() (8-pass repair) ──► structured dict
         │
         ▼
blended = 0.30*static + 0.70*llm
risk_level = threshold(blended)
         │
         ▼
Merge heuristic findings not in LLM output
         │
         ▼
TriageResult (Pydantic)
         │
         ├──► CLI: Rich panel + Markdown
         ├──► --json: model_dump_json()
         └──► Web: result.html (Classic) / /api/triage (React)
```

### 4.2 Repo Scan Flow (Current)

```
Target (local path / GitHub URL / owner/repo[@branch])
         │
         ▼
resolve_scan_target() ──► local path (with cleanup for GitHub)
         │
         ▼
scan_repository(path, max_files=8000)
         │
         ├──► Walk files (skip .git, node_modules, venv, etc.)
         ├──► Load .triagekitignore / .gitignore
         ├──► _scan_text() against 6 pattern libraries + lang rules
         ├──► High-entropy string detection (Shannon ≥4.2)
         ├──► _dedupe_and_filter() (FP rules)
         ├──► Dependency manifest detection
         │
         ▼
RepoScanResult(findings[], dependency_files[])
         │
         ├──► scan_dependencies() ──► OSV queries ──► cve_findings[]
         ├──► compute_score() ──► 100 - penalty
         ├──► run_security_agent() ──► executive brief
         │
         ▼
Output: Markdown + tree view + optional SARIF
```

### 4.3 Scanner Framework Flow (New - Target Architecture)

```
Target
    │
    ▼
ScannerOrchestrator.run_scan(target)
    │
    ├──► ScannerRegistry.get_for_target(target)
    │
    ├──► For each scanner (concurrent, max 3):
    │       Scanner.scan(ScanContext)
    │       ├──► BaseScanner.scan() lifecycle
    │       │       ├──► _result = ScanResult(RUNNING)
    │       │       ├──► await _scan(context)
    │       │       ├──► complete(COMPLETED/FAILED)
    │       │       └──► return ScanResult
    │       └──► Timeout / exception handling
    │
    ▼
List[ScanResult]
    │
    ▼
CorrelationEngine.process(results)
    │
    ├──► FindingDeduplicator.deduplicate() per result
    ├──► FindingCorrelator.correlate() across results
    │       ├──► Rule-based correlation (6 rules)
    │       └──► CWE-based cross-type correlation
    │
    ▼
OrchestrationResult
    ├──► scan_results (deduplicated)
    ├──► correlated_groups (CorrelatedGroup[])
    ├──► attack_paths (prioritized)
    ├──► prioritized_findings
    └──► summary metadata
```

---

## 5. Security Control Architecture

### 5.1 Finding Classification Pipeline

```
Raw Detection (pattern match / AST node / LLM output)
         │
         ▼
Severity Assignment
    ├─ Heuristic: secrets=CRITICAL, injection/crypto=HIGH, deps=MEDIUM
    ├─ Taint: inherits from sink.severity (critical/high/medium/low)
    ├─ CVE: CVSS → CRITICAL(≥9)/HIGH(≥7)/MEDIUM(≥4)/LOW(<4)
    └─ Web: confidence-weighted (high=1.0, medium=0.75, low=0.45)
         │
         ▼
Confidence Assessment
    ├─ Pattern confidence (registry: 0.6-0.95)
    ├─ Trace confidence (taint: step average - sanitizer penalty)
    ├─ Correlation boost (multiple scanners +0.1 each, max +0.3)
    └─ LLM confidence (explicit in output)
         │
         ▼
UnifiedFinding (standardized)
         │
         ▼
Deduplication (fingerprint + fuzzy)
         │
         ▼
Correlation (cross-scanner attack paths)
         │
         ▼
Prioritization (severity + correlation count + confidence)
```

### 5.2 Risk Scoring Algorithms

#### 5.2.1 Static Risk Score (0-10) — `static.compute_static_risk`
```python
score = 0
sec = count(is_security_sensitive)     # max 3 → +8.4
crit = count(is_critical)              # max 5 → +6.5
api = count(is_api_surface)            # max 3 → +3.3
churn = additions + deletions          # >1000: +2.2, >400: +1.1
changed = changed_files                # >30: +1.5, >15: +0.7
tests = count(is_test)                 # churn>30: -1.15 (positive signal)
return min(10, round(score, 2))
```

#### 5.2.2 Heuristic Security Boost (Engine)
```python
static_score = min(10, static_score + critical_findings*1.5 + high_findings*0.8)
```

#### 5.2.3 Blended Risk Score (0-10) — Engine
```python
blended = round(clamp(0, 10, static_score * 0.30 + llm_score * 0.70), 1)
```

#### 5.2.4 Repo Scan Score (0-100) — `RepoScanResult.compute_score`
```python
weights = {"critical": 18, "high": 8, "medium": 3, "low": 1}
penalty = sum(weights[f.severity] for f in findings + cve_findings)
score = max(0, round(100 - min(penalty, 100), 1))
Grade: A≥90, B≥75, C≥60, D≥40, F<40
```

#### 5.2.5 Website Scan Score (0-100) — `WebScanResult.compute_score`
```python
weights = {"critical": 20, "high": 9, "medium": 4, "low": 1}
conf_weight = {"high": 1.0, "medium": 0.75, "low": 0.45}
penalty = sum(weights[f.severity] * conf_weight[f.confidence] for f in findings)
score = max(0, round(100 - min(penalty, 100), 1))
```

### 5.3 Confidence Levels (Standardized)

| Level | Value | Meaning |
|-------|-------|---------|
| **HIGH** | 0.9 | Multiple independent confirmations, direct evidence |
| **MEDIUM** | 0.6 | Single strong signal, heuristic with context |
| **LOW** | 0.3 | Weak signal, pattern match without context |
| **NOT ASSESSED** | N/A | Scanner unavailable, language unsupported, diff missing |

**Critical Rule:** Missing evidence (unavailable scanner, missing PR diff, unsupported language) **MUST** be reported as `NOT ASSESSED`, never silently downgraded to LOW or PASS.

---

## 6. Integration Architecture

### 6.1 External Tool Integration Pattern (Target)

Each external tool integrates via a **Scanner Adapter** implementing `BaseScanner`:

```python
class SemgrepScanner(BaseScanner):
    metadata = ScannerMetadata(
        name="semgrep",
        version="1.0",
        scan_type=ScanType.STATIC_ANALYSIS,
        required_tools=["semgrep"],
        supported_languages=["python", "javascript", "typescript", "java", "go", "rust", ...],
        estimated_duration_seconds=120,
    )
    
    async def _scan(self, context: ScanContext) -> ScanResult:
        # 1. Validate semgrep installation
        # 2. Run: semgrep scan --json --config=auto <target>
        # 3. Parse SARIF/JSON output
        # 4. Map to UnifiedFinding[]
        # 5. Return ScanResult
```

### 6.2 Supported Integration Targets

| Category | Tools | Integration Status |
|----------|-------|-------------------|
| **SAST** | Semgrep, CodeQL, Bandit, Ruff, ESLint-security | ❌ Planned (scanner wrappers needed) |
| **SCA** | OSV (✅), Trivy, Grype, Syft, pip-audit, npm audit | ⚠️ Partial (OSV only) |
| **Secrets** | Gitleaks, TruffleHog, detect-secrets | ❌ Planned |
| **Container** | Trivy, Grype, Syft, Dockerfile scanners | ❌ Planned |
| **IaC** | Checkov, KICS, Trivy config | ❌ Planned |
| **DAST** | OWASP ZAP, Nuclei | ❌ Planned |
| **API Security** | OpenAPI analysis, GraphQL introspection | ❌ Planned |

### 6.3 GitHub Integration

| Feature | Status | Location |
|---------|--------|----------|
| PR fetch (files, diff, metadata) | ✅ | `github_client.py` |
| Archive download (shallow clone) | ✅ | `github_client.py:download_repo_archive` |
| PR annotation (SARIF) | ❌ | Planned |
| Status checks | ❌ | Planned |
| Workflow examples | ❌ | Planned (`.github/workflows/` empty) |

---

## 7. Deployment Architecture

### 7.1 Runtime Requirements

| Component | Requirement |
|-----------|-------------|
| **Python** | 3.9+ (tested on 3.9.13) |
| **Node.js** | 18+ (for React UI build) |
| **GitHub Token** | `repo` scope (or public repo read) |
| **LLM API Key** | OpenAI-compatible (OpenAI, NVIDIA NIM, Ollama, LM Studio) |
| **Optional: searchsploit** | For ExploitDB integration |

### 7.2 Service Topology

```
┌─────────────────────────────────────────────────────────────┐
│                      DEPLOYMENT                               │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐   │
│  │  TriageKit  │     │   GitHub    │     │  LLM Provider│   │
│  │  Service    │────►│   API       │     │  (OpenAI/    │   │
│  │  (FastAPI)  │     │             │     │   NIM/Ollama)│   │
│  └─────────────┘     └─────────────┘     └─────────────┘   │
│        │                                           ▲        │
│        │                                           │        │
│        ▼                                           │        │
│  ┌─────────────┐                          ┌─────────────┐   │
│  │  OSV API    │                          │  ExploitDB  │   │
│  │ (osv.dev)   │                          │ (searchsploit)│   │
│  └─────────────┘                          └─────────────┘   │
│        │                                           ▲        │
│        │                                           │        │
│        ▼                                           │        │
│  ┌─────────────────────────────────────────────┐   │        │
│  │            Scanner Subprocesses             │   │        │
│  │  (semgrep, codeql, gitleaks, trivy, etc.)   │   │        │
│  └─────────────────────────────────────────────┘   │        │
│                                                    │        │
└────────────────────────────────────────────────────┼────────┘
                                                     │
                                              (Optional)
                                              External
                                              Scanners
```

### 7.3 Security Boundaries

| Boundary | Controls |
|----------|----------|
| **Network egress** | LLM API, GitHub API, OSV API, ExploitDB (searchsploit CLI) |
| **File system** | Read-only for scans; write-only for reports/artifacts in configured output dir |
| **Subprocess execution** | Controlled via scanner adapters; no shell=True unless explicitly required |
| **Secrets management** | Environment variables only (`.env`); never logged or printed |
| **Web UI** | No authentication (local dev); production requires auth proxy |

---

## 8. Extension Points

### 8.1 Adding a New Static Signal
1. Extend `analyzers/static.py` or `analyzers/security.py`
2. Append to `static_signals` / `security_signals`
3. Optionally boost `static_score`
4. Add test case to testbench

### 8.2 Adding a New Result Field
1. Update `models/results.py` (Pydantic model)
2. Update `prompts.py` (SYSTEM schema + `build_user`)
3. Update normalization in `engine.py`
4. Update UI templates (`web/templates/result.html`, React components)

### 8.3 Adding a New Scanner (Framework)
1. Create `core/scanners/<name>_scanner.py` extending `BaseScanner`
2. Implement `_get_metadata()` and `_scan()`
3. Map tool output to `UnifiedFinding[]`
4. Register in `registry_init.py:register_all_scanners()`
5. Add default config in `get_default_scanner_config()`
6. Add correlation rules if cross-scanner correlation needed

### 8.4 Adding a New Language to Taint Analysis
1. Add sources/sinks/sanitizers to `registry.py` with `languages=["<lang>"]`
2. Create `<lang>_analyzer.py` or extend existing analyzer
3. Add file extension handling in `taint_scanner.py:_detect_languages()`
4. Add test fixtures in `testbench/fixtures/<lang>/`

### 8.5 Swapping LLM Provider
- Set `OPENAI_BASE_URL` and `OPENAI_API_KEY` to any OpenAI-compatible endpoint
- Keep model name in `OPENAI_MODEL`
- No code changes required (handled in `core/llm.py`)

---

## 9. Threat Model (Platform Self-Protection)

### 9.1 Identified Vulnerabilities (Bandit Baseline)

| Severity | Location | Issue | Mitigation |
|----------|----------|-------|------------|
| **HIGH** | `github_client.py:76` | `tarfile.extractall()` without path validation | Validate member paths before extract |
| **MEDIUM** | Multiple | Broad `except Exception:` | Use specific exception types |
| **MEDIUM** | `api/app.py` | No authentication on web UI | Add auth middleware for production |
| **MEDIUM** | `api/app.py` | No rate limiting on scan endpoints | Add rate limiter middleware |
| **LOW** | Multiple | `try/except/pass` patterns | Add logging or handle explicitly |

### 9.2 Security Controls Implemented

| Control | Implementation |
|---------|----------------|
| **Input validation** | Pydantic models on all API endpoints |
| **Path traversal prevention** | `resolve_scan_target()` validates paths; tar extraction needs fix |
| **Secret handling** | Environment variables only; redacted in logs |
| **SSRF prevention** | Web scanner only targets user-supplied URLs; no internal network access |
| **Command injection prevention** | No shell=True in scanner framework; subprocess args as list |
| **XSS prevention** | Jinja2 autoescape; React auto-escapes by default |

### 9.3 Required Hardening (Pre-Production)

1. Fix `tarfile.extractall()` vulnerability
2. Add authentication/authorization to web UI
3. Add rate limiting to `/api/*` endpoints
4. Add request size limits
5. Implement audit logging for all scan operations
6. Add CSP headers to web responses
7. Secure cookie settings (HttpOnly, Secure, SameSite)

---

## 10. Performance Characteristics

| Operation | Typical Duration | Scaling Factor |
|-----------|------------------|----------------|
| PR Triage (small PR) | 10-30s | LLM latency dominant |
| PR Triage (large PR) | 30-120s | Diff truncation at 20KB |
| Repo Scan (1K files) | 15-60s | Linear with file count |
| Repo Scan (8K files) | 60-300s | Max files capped at 8000 |
| Web Scan | 15-60s | Network + crawl dependent |
| Taint Analysis (1K files) | 30-120s | AST parsing + interprocedural |

### 10.1 Resource Limits (Default)

| Limit | Value | Configurable |
|-------|-------|--------------|
| Max repo scan files | 8000 | `--max-files` |
| Max taint analysis files | 1000 | `taint_analysis.max_files` |
| Max OSV packages | 40 | `dependency_scanner.max_packages` |
| Web crawl pages | 25 | `web_scanner.max_crawl_pages` |
| Web JS files | 20 | `web_scanner.max_js_files` |
| Scanner timeout | 300s | `ScanContext.timeout_seconds` |
| Max concurrent scanners | 3 | `OrchestratorConfig.max_concurrent_scans` |

---

## 11. Migration Path: Legacy → Framework

### 11.1 Phase 1: Fix Circular Import & Activate Framework
- Fix `taint_scanner.py` ↔ `registry_init.py` circular import
- Run `ScannerOrchestrator` in parallel with `TriageEngine`
- Verify parity on testbench

### 11.2 Phase 2: Wrap Legacy Analyzers as Scanners
| Legacy | Scanner Wrapper | Status |
|--------|----------------|--------|
| `static.py` | `StaticAnalysisScanner` | ✅ Exists |
| `security.py` | `HeuristicSecurityScanner` | ✅ Exists |
| `repo_scan.py` | `RepositoryScanner` | ✅ Exists |
| `web_scan.py` | `WebScanner` | ✅ Exists |
| `cve.py` | `DependencyScanner` | ✅ Exists |
| `taint/` | `TaintAnalysisScanner` | ⚠️ Blocked by import |

### 11.3 Phase 3: Migrate Engine to Orchestrator
- Replace direct analyzer calls in `TriageEngine.full_triage()` with `ScannerOrchestrator.run_scan()`
- Preserve exact risk formulas and thresholds
- Maintain LLM blending logic
- Keep skill injection

### 11.4 Phase 4: External Scanner Integration
- Add Semgrep, CodeQL, Gitleaks, Trivy, Checkov wrappers
- Implement correlation rules for new scanners
- Add SARIF export for all scan types

---

## 12. Appendix: Key Files Reference

### 12.1 Critical Behavior Invariants (Must Preserve)

| Invariant | Location | Protection |
|-----------|----------|------------|
| Static risk formula (exact weights) | `static.py:121-150` | Regression test |
| Risk blending: 0.30×static + 0.70×LLM | `engine.py:92` | Unit test |
| Risk level thresholds (≥8/5.5/2.5) | `engine.py:94-101` | Unit test |
| Security boost (+1.5 crit, +0.8 high) | `engine.py:44-48` | Unit test |
| Heuristic severity mapping | `security.py:79-95` | Testbench |
| Test file positive signal (-1.15) | `static.py:146` | Testbench |
| Repo scan grading (A≥90/B≥75/C≥60/D≥40/F<40) | `repo_scan.py:580-590` | Testbench |
| FP filtering rules (test-path demotion, shell=True) | `repo_scan.py:384-390` | Testbench |
| LLM JSON repair pipeline (8-pass) | `llm.py:180-280` | Unit test |
| Missing evidence = NOT ASSESSED | `engine.py:56-88` (fallback) | Design principle |

### 12.2 Test Benchmarks

```bash
# Run testbench (validates repo_scan detection)
python testbench/scripts/run_testbench.py

# Run unit tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=src/triagekit --cov-report=term-missing
```

---

*Document generated from read-only repository inspection — 2026-11-09*