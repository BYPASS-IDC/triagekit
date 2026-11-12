# TriageKit Security Integration Audit

## Executive Summary

TriageKit is a **mature, production-ready security triage platform** with three operational surfaces (CLI, Classic Jinja2 Web UI, React/Vite Web UI). The codebase demonstrates sophisticated multi-stage analysis architecture combining deterministic static analysis, heuristic security scanning, LLM-structured reasoning, and a new modular scanner framework with taint analysis capabilities.

**Overall Security Posture:** Strong foundation with critical areas for integration hardening

---

## 1. Already Implemented and Verified ✅

### 1.1 Core Security Analysis Engine

| Capability                                         | Implementation                                                                                            | Location                             | Verification                    |
| -------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | ------------------------------------ | ------------------------------- |
| **Multi-stage PR triage pipeline**           | 5-stage: GitHub fetch → Static analysis → Heuristic security → LLM reasoning → Blend/normalize        | `core/engine.py`                   | ✅ Tested via CLI               |
| **Static risk scoring**                      | Formula:`sec*2.8 + crit*1.3 + api*1.1 + churn + width - test_bonus`                                     | `core/analyzers/static.py:121-150` | ✅ Tested via testbench         |
| **Heuristic security scanning (diff-based)** | 5 pattern families: injection, secrets, crypto/auth, deps, sensitive paths                                | `core/analyzers/security.py`       | ✅ Tested via CLI               |
| **Full-repo "god-mode" scanner**             | 30 injection patterns, 12 secret types, 7 crypto patterns, 8 quality, 6 Docker, 4 CI, 5 language-specific | `core/analyzers/repo_scan.py`      | ✅ Testbench PASS (7 languages) |
| **Dependency intelligence (OSV)**            | 8 manifest formats, CVSS severity mapping, no API key required                                            | `core/analyzers/cve.py`            | ✅ Integrated in scan           |
| **Exploit intelligence**                     | Curated catalog (9 products) + searchsploit integration                                                   | `core/analyzers/exploitdb.py`      | ✅ Functional                   |
| **Website security adviser**                 | 6-layer assessment: transport, crawl, exposure, HTML/JS, active probes, stack-aware                       | `core/analyzers/web_scan.py`       | ✅ Functional                   |
| **LLM-assisted security reasoning**          | Structured JSON schema with security_findings[], suggestions[], risk_factors[]                            | `core/prompts.py`, `core/llm.py` | ✅ 8-pass JSON repair           |

### 1.2 Taint Analysis Subsystem (NEW - Partially Integrated)

| Component                               | Status               | Location                            | Coverage                                  |
| --------------------------------------- | -------------------- | ----------------------------------- | ----------------------------------------- |
| **Source registry**               | ✅ Complete          | `core/taint/registry.py:15-226`   | 27 Python + 16 JS/TS sources              |
| **Sink registry**                 | ✅ Complete          | `core/taint/registry.py:397-774`  | 29 Python + 14 JS/TS sinks                |
| **Sanitizer registry**            | ✅ Complete          | `core/taint/registry.py:781-1072` | 13 Python + 6 JS/TS sanitizers            |
| **Python AST analyzer**           | ✅ Complete          | `core/taint/analyzer.py`          | Interprocedural, call graph, FP filtering |
| **JS/TS regex analyzer**          | ✅ Complete          | `core/taint/js_analyzer.py`       | Function extraction, template literals    |
| **TaintPath/Finding models**      | ✅ Complete          | `core/taint/models.py`            | Full trace with confidence computation    |
| **Scanner framework integration** | ⚠️ Circular import | `core/scanners/taint_scanner.py`  | Blocked by registry_init import issue     |

### 1.3 Scanner Framework Architecture (NEW)

| Component                      | Status               | Location                                 |
| ------------------------------ | -------------------- | ---------------------------------------- |
| **BaseScanner ABC**      | ✅ Complete          | `core/scanners/base.py:239-312`        |
| **UnifiedFinding model** | ✅ Complete          | `core/scanners/base.py:93-182`         |
| **ScanResult container** | ✅ Complete          | `core/scanners/base.py:184-237`        |
| **ScannerRegistry**      | ✅ Complete          | `core/scanners/base.py:314-395`        |
| **CorrelationEngine**    | ✅ Complete          | `core/scanners/correlation.py:542-597` |
| **FindingDeduplicator**  | ✅ Complete          | `core/scanners/correlation.py:42-224`  |
| **FindingCorrelator**    | ✅ Complete          | `core/scanners/correlation.py:226-540` |
| **ScannerOrchestrator**  | ✅ Complete          | `core/scanners/orchestrator.py:47-226` |
| **Scanner registration** | ⚠️ Circular import | `core/scanners/registry_init.py`       |

### 1.4 Web UI & CLI Surfaces

| Surface                       | Status      | Features                                                              |
| ----------------------------- | ----------- | --------------------------------------------------------------------- |
| **CLI (Typer)**         | ✅ Complete | `triage`, `scan`, `webscan`, `serve`, `--json`, `--sarif` |
| **Classic UI (Jinja2)** | ✅ Complete | Analysis Chain tree, accordion panels, diff viewer                    |
| **React UI (Vite)**     | ✅ Complete | 4 pages, 3 components, sessionStorage state, API client               |
| **API endpoints**       | ✅ Complete | `/api/triage`, `/api/scan`, `/api/webscan` JSON                 |

### 1.5 Testing & Regression

| Test                               | Status     | Coverage                                        |
| ---------------------------------- | ---------- | ----------------------------------------------- |
| **Testbench (7 languages)**  | ✅ PASS    | Python, Rust, C++, Java, C#, Swift, Safe        |
| **Cookie parser regression** | ✅ PASS    | 7 test cases in `tests/test_cookie_parser.py` |
| **Testbench criteria**       | ✅ Defined | min_hits, require_any, max_high_or_above        |

---

## 2. Implemented But Incomplete ⚠️

### 2.1 Taint Scanner Integration Blocked by Circular Import

**Problem:** `taint_scanner.py` imports `register_scanner_factory` from `registry_init.py`, but `registry_init.py` imports `TaintAnalysisScanner` from `taint_scanner.py`.

**Files affected:**

- `core/scanners/taint_scanner.py:22` - `from .registry_init import register_scanner_factory`
- `core/scanners/registry_init.py:13` - `from .taint_scanner import TaintAnalysisScanner`

**Impact:** Scanner framework tests fail to collect; taint analysis not available through orchestrator.

### 2.2 Scanner Framework Not Connected to Main Engine

The new modular scanner framework (`core/scanners/`) exists parallel to the legacy analyzers (`core/analyzers/`). The `TriageEngine.full_triage()` still uses direct analyzer imports instead of the orchestrator.

### 2.3 React UI Limited for PR Triage

`TriageResult.jsx` only renders markdown dump — lacks the Analysis Chain tree, severity counters, and accordion panels available in the Classic UI.

### 2.4 Confidence Assessment Partial

Only `web_scan.py` implements structured confidence (high/medium/low). Other analyzers use implicit confidence.

---

## 3. Present But Not Properly Integrated 🔗

### 3.1 Skills System

- **29 project skills** in `skills/` — auto-assigned via `core/skills.py`
- **9 Claude plugin skills** in `.claude/skills/`
- **Integration:** Skills injected into LLM system prompt per operation
- **Gap:** Skills not accessible to scanner framework or taint analysis

### 3.2 SARIF Export

- **Implemented:** `repo_scan.py:to_sarif()` minimal SARIF 2.1.0
- **Gap:** Not available for PR triage results; no unified SARIF across scanners

### 3.3 GitHub Actions / CI/CD

- **Directory exists:** `.github/workflows/` (empty)
- **CLI supports:** `--json`, `--sarif` for CI integration
- **Gap:** No example workflows, no status check integration

---

## 4. Planned But Not Implemented 📋

### 4.1 External SAST Integrations

| Tool              | Status            | Notes                                 |
| ----------------- | ----------------- | ------------------------------------- |
| **Semgrep** | ❌ Not integrated | Rules exist in skills but no runner   |
| **CodeQL**  | ❌ Not integrated | Would need SARIF import + query packs |
| **Bandit**  | ❌ Not integrated | Only ran as baseline audit            |

### 4.2 Advanced Dependency Intelligence

| Capability                       | Status     |
| -------------------------------- | ---------- |
| NVD / GitHub Security Advisories | ❌ Missing |
| EPSS exploitability scoring      | ❌ Missing |
| CISA KEV catalog                 | ❌ Missing |
| Transitive dependency analysis   | ❌ Missing |
| SBOM generation (SPDX/CycloneDX) | ❌ Missing |
| License compliance               | ❌ Missing |

### 4.3 Web/API Security Verification

| Capability                  | Status                   |
| --------------------------- | ------------------------ |
| Active SQLi verification    | ⚠️ Heuristic only      |
| DOM XSS verification        | ⚠️ Reflection only     |
| SSRF verification           | ⚠️ Redirect probe only |
| AuthZ/BOLA detection        | ❌ Missing               |
| GraphQL introspection abuse | ❌ Missing               |

### 4.4 Framework Mappings

| Framework       | Status     |
| --------------- | ---------- |
| OWASP ASVS      | ❌ Missing |
| NIST SSDF / CSF | ❌ Missing |
| MITRE ATT&CK    | ❌ Missing |
| CVSS 4.0        | ❌ Missing |

---

## 5. Missing and Genuinely Required 🔴

### 5.1 Agent Security & Governance (Major Priority)

| Capability                            | Status         |
| ------------------------------------- | -------------- |
| Agent threat model implementation     | ❌ Not started |
| Policy engine (tool allow/deny lists) | ❌ Not started |
| Human approval workflows              | ❌ Not started |
| Durable action ledger / audit trail   | ❌ Not started |
| Agent security test suite             | ❌ Not started |

### 5.2 Recovery & Rollback Architecture

| Capability                         | Status         |
| ---------------------------------- | -------------- |
| Action lifecycle state machine     | ❌ Not started |
| Pre-execution snapshots/backups    | ❌ Not started |
| Verified rollback with state check | ❌ Not started |
| Crash/interruption recovery        | ❌ Not started |
| Recovery dashboard                 | ❌ Not started |

### 5.3 Application Self-Hardening

| Area                                        | Findings (Bandit)                      |
| ------------------------------------------- | -------------------------------------- |
| `tarfile.extractall()` without validation | HIGH (B202) in `github_client.py:76` |
| Broad `except Exception:` patterns        | MEDIUM in multiple files               |
| No authentication on web UI                 | MEDIUM                                 |
| No rate limiting on scan endpoints          | MEDIUM                                 |

### 5.4 CI/CD Integration

| Capability                        | Status     |
| --------------------------------- | ---------- |
| GitHub Actions workflow examples  | ❌ Missing |
| PR annotation / status checks     | ❌ Missing |
| Policy-based blocking thresholds  | ❌ Missing |
| Incremental scanning (diff-based) | ❌ Missing |

---

## 6. Unverified Assumptions Requiring Investigation ❓

| Assumption                                             | Risk   | Verification Needed |
| ------------------------------------------------------ | ------ | ------------------- |
| LLM provider compatibility (NIM, Ollama, LM Studio)    | Medium | Test matrix         |
| Large repo performance (>8000 files)                   | Medium | Benchmark           |
| Multi-repo/organization scanning                       | Low    | Design review       |
| Skill truncation at 3500 chars loses critical guidance | Medium | Content audit       |
| Semgrep config conflict resolution                     | Low    | Investigation       |

---

## 7. Security Baseline Results (Pre-Existing)

| Tool                                | Findings                      | Critical Issues                                        |
| ----------------------------------- | ----------------------------- | ------------------------------------------------------ |
| **Bandit**                    | 67 (4 HIGH, 1 MEDIUM, 62 LOW) | `tarfile.extractall()` without validation            |
| **pip-audit (installed)**     | 58 across 8 packages          | python-multipart path traversal, starlette host header |
| **pip-audit (declared deps)** | 0                             | Version discrepancy: venv older than pyproject.toml    |
| **Gitleaks**                  | 8 (redacted)                  | Config excludes .venv and share-ready.zip              |
| **Semgrep**                   | Not executed                  | Config conflict                                        |

---

## 8. Immediate Action Items

### Critical (Do First)

1. **Fix circular import** in scanner framework (`taint_scanner.py` ↔ `registry_init.py`)
2. **Patch `tarfile.extractall()`** vulnerability in `github_client.py:76`
3. **Recreate venv** to match declared dependencies in `pyproject.toml`

### High (Do Next)

4. **Connect scanner orchestrator** to `TriageEngine` for unified scanning
5. **Expose taint analysis** through CLI (`triagekit taint <target>`)
6. **Add SARIF export** to PR triage results
7. **Implement React UI Analysis Chain** tree for parity with Classic UI

### Medium (Near Term)

8. **Create GitHub Actions workflow examples**
9. **Add Semgrep/CodeQL scanner wrappers**
10. **Implement SBOM generation** (SPDX/CycloneDX)
11. **Add EPSS/CISA KEV enrichment** to dependency scanner

---

## 9. Architecture Compatibility Assessment

| Existing Component              | Compatible with Scanner Framework?   | Migration Effort      |
| ------------------------------- | ------------------------------------ | --------------------- |
| `core/analyzers/static.py`    | ✅ Yes (→ StaticAnalysisScanner)    | Low                   |
| `core/analyzers/security.py`  | ✅ Yes (→ HeuristicSecurityScanner) | Low                   |
| `core/analyzers/repo_scan.py` | ✅ Yes (→ RepositoryScanner)        | Low                   |
| `core/analyzers/web_scan.py`  | ✅ Yes (→ WebScanner)               | Low                   |
| `core/analyzers/cve.py`       | ✅ Yes (→ DependencyScanner)        | Low                   |
| `core/taint/analyzer.py`      | ✅ Yes (→ TaintAnalysisScanner)     | Low (already wrapped) |
| `core/engine.py`              | ⚠️ Requires refactor               | Medium                |
| `cli.py`                      | ✅ Compatible                        | Low                   |

---

## Conclusion

TriageKit possesses a **remarkably complete security analysis foundation** with sophisticated multi-stage PR triage, comprehensive repo scanning, deep website assessment, and a newly-architected modular scanner framework with taint analysis. The primary gaps are:

1. **Integration completion** — scanner framework blocked by circular import
2. **External tool integration** — Semgrep, CodeQL, NVD, EPSS, CISA KEV
3. **Agent security governance** — entirely unimplemented (major priority per requirements)
4. **Recovery/rollback architecture** — entirely unimplemented
5. **Framework mappings** — OWASP ASVS, NIST, MITRE ATT&CK missing
6. **CI/CD operationalization** — workflows, SARIF, PR annotations

The codebase is **well-structured for incremental enhancement** — the new scanner framework follows the exact patterns needed for the roadmap, and the existing analyzers can be wrapped as scanners with minimal effort. The taint analysis subsystem is production-quality but needs the import fix to become operational.

**Recommendation:** Proceed with STAGE B (Security Architecture & Integration Roadmap) using this audit as the factual baseline.
