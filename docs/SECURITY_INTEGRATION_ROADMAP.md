# TriageKit Security Integration Roadmap

**Version:** 1.0  
**Date:** 2026-11-09  
**Based on:** SECURITY_INTEGRATION_AUDIT.md + SECURITY_ARCHITECTURE.md  
**Status:** Prioritized Implementation Plan

---

## Executive Summary

This roadmap translates the audit findings into a phased implementation plan. The strategy follows **STAGE A → STAGE I** from the mission requirements, with emphasis on:

1. **Preserving existing verified functionality** — Zero regression on testbench
2. **Completing the scanner framework** — Fix circular import, activate orchestrator
3. **Integrating external tools** — SAST, SCA, secrets, container, IaC, DAST
4. **Implementing agent security & governance** — Major priority per requirements
5. **Building recovery & rollback architecture** — For automated action safety

---

## Phase Prioritization Matrix

| Phase | Security Impact | Implementation Complexity | Reliability | Testability | Resource Req | Maintenance | Compatibility | Priority Score |
|-------|-----------------|---------------------------|-------------|-------------|--------------|-------------|---------------|----------------|
| **A: Baseline & Critical Fixes** | Critical | Low | High | High | Low | Low | High | **100** |
| **B: Scanner Framework Activation** | High | Medium | High | High | Medium | Low | High | **90** |
| **C: Core Engine Improvements** | High | Medium | High | High | Medium | Medium | High | **85** |
| **D: External Tool Integrations** | High | High | Medium | Medium | High | High | Medium | **75** |
| **E: Agent Security & Governance** | Critical | High | Medium | Medium | High | High | Medium | **80** |
| **F: Recovery & Rollback** | Critical | High | Medium | Medium | High | High | Medium | **78** |
| **G: Framework Mappings & CI/CD** | Medium | Medium | High | High | Medium | Medium | High | **70** |
| **H: Dashboard & UX** | Medium | Medium | High | High | Medium | Medium | High | **65** |
| **I: Comprehensive Verification** | High | Medium | High | High | Medium | Low | High | **80** |

---

## STAGE A — Repository Recovery & Baseline Audit (Week 1) ✅ COMPLETE

### Completed
- [x] Full repository inventory (all directories inspected)
- [x] Architecture report analysis (ARCHITECTURE_REPORT.md)
- [x] Core taint analysis files reviewed (models.py, registry.py, analyzer.py, js_analyzer.py)
- [x] All production modules read (27 Python files in src/triagekit/)
- [x] Diagnostic rules traced (static, heuristic, repo scan, CVE, web scan, exploit relevance)
- [x] Risk calculations understood (4 scoring algorithms)
- [x] Frontend components inspected (Classic + React UI)
- [x] Tests inspected (testbench 7 fixtures, cookie parser 7 cases)
- [x] Security integrations inspected (OSV, ExploitDB, Bandit baseline, pip-audit)
- [x] Baseline reports reviewed (Bandit 67, pip-audit 58/0, Gitleaks 8)
- [x] Skills reviewed (29 project + 9 Claude plugin)
- [x] **Created:** `docs/SECURITY_INTEGRATION_AUDIT.md`
- [x] **Created:** `docs/SECURITY_ARCHITECTURE.md`

### Immediate Critical Fixes (Do Before Phase B)
- [ ] **Fix circular import** in `core/scanners/` (taint_scanner.py ↔ registry_init.py)
- [ ] **Patch tarfile.extractall()** vulnerability in `github_client.py:76` (Bandit B202 HIGH)
- [ ] **Recreate venv** to match pyproject.toml declared dependencies
- [ ] **Run full test suite** and verify testbench still PASS

---

## STAGE B — Security Architecture & Integration Roadmap (Week 1-2)

### B.1 Scanner Framework Activation

| Task | Description | Files | Effort | Dependencies |
|------|-------------|-------|--------|--------------|
| B.1.1 | Fix circular import: move `register_scanner_factory` to `base.py` or new `factories.py` | `taint_scanner.py`, `registry_init.py`, `base.py` | 2h | None |
| B.1.2 | Verify all 6 built-in scanners register correctly | `registry_init.py` | 1h | B.1.1 |
| B.1.3 | Add unit tests for ScannerRegistry, BaseScanner lifecycle | `tests/test_scanner_framework.py` | 4h | B.1.2 |
| B.1.4 | Integration test: ScannerOrchestrator.run_scan() on testbench fixtures | `tests/test_orchestrator.py` | 4h | B.1.2 |
| B.1.5 | Verify correlation engine produces attack paths | `tests/test_correlation.py` | 3h | B.1.2 |

### B.2 Architecture Decision Records (ADRs)

| ADR | Topic | Status |
|-----|-------|--------|
| ADR-001 | Scanner framework as primary orchestration layer | Proposed |
| ADR-002 | UnifiedFinding as canonical finding model | Proposed |
| ADR-003 | Correlation rules as configurable YAML | Proposed |
| ADR-004 | Taint analysis as first-class scanner | Proposed |
| ADR-005 | External scanner adapters via BaseScanner | Proposed |

### B.3 Integration Roadmap Document
- [ ] **Create:** `docs/SECURITY_TOOL_CATALOG.md` — inventory of target external tools
- [ ] **Create:** `docs/INTEGRATION_SPEC.md` — adapter interface specification
- [ ] **Update:** `docs/SECURITY_INTEGRATION_ROADMAP.md` with detailed task breakdown

---

## STAGE C — Core Security Engine Improvements (Week 2-4)

### C.1 Taint Analysis Integration

| Task | Description | Files | Effort | Verification |
|------|-------------|-------|--------|--------------|
| C.1.1 | Expose taint analysis via CLI: `triagekit taint <target>` | `cli.py`, `taint_scanner.py` | 4h | Testbench fixtures |
| C.1.2 | Add taint findings to PR triage (correlate with heuristic findings) | `engine.py`, `taint_scanner.py` | 8h | Testbench + manual PR |
| C.1.3 | Add source-to-sink trace evidence to UnifiedFinding | `taint_scanner.py:_taint_path_to_finding` | 4h | Visual inspection |
| C.1.4 | Implement interprocedural confidence calibration | `analyzer.py:compute_confidence` | 6h | Known vuln samples |
| C.1.5 | Add language-specific taint rules for Java, C#, C++, Rust, Swift | `registry.py`, new analyzers | 16h | Testbench per language |
| C.1.6 | Cross-file taint tracking (module-level) | `analyzer.py`, `js_analyzer.py` | 12h | Multi-file fixtures |

### C.2 Vulnerability Detection Enhancement

| Task | Description | Files | Effort | Verification |
|------|-------------|-------|--------|--------------|
| C.2.1 | Expand injection patterns (NoSQL, LDAP, XPath, ReDoS, prototype pollution) | `repo_scan.py`, `registry.py` | 8h | Testbench expansion |
| C.2.2 | Add authentication/authorization flaw detection (IDOR, BOLA, session issues) | `repo_scan.py`, new rules | 12h | Custom fixtures |
| C.2.3 | Add cryptographic weakness detection (insecure RNG, weak ciphers, cert validation) | `repo_scan.py`, `registry.py` | 8h | Testbench expansion |
| C.2.4 | Add supply chain weakness detection (dependency confusion, typo-squatting) | `cve.py`, new scanner | 8h | Mock registry tests |
| C.2.5 | Implement confidence levels: CONFIRMED/HIGH/MEDIUM/LOW/NOT_ASSESSED/NOT_APPLICABLE | `base.py`, all scanners | 6h | Unit tests |

### C.3 Evidence Integrity & Reporting

| Task | Description | Files | Effort | Verification |
|------|-------------|-------|--------|--------------|
| C.3.1 | Ensure every finding has: location, detection method, code evidence, trace, severity, confidence, rationale, CWE, remediation, scanner provenance, limitations | `UnifiedFinding`, all scanners | 8h | Audit checklist |
| C.3.2 | Implement NOT_ASSESSED for missing diffs, unavailable scanners, unsupported languages | `engine.py`, `orchestrator.py` | 4h | Negative tests |
| C.3.3 | Add SARIF 2.1.0 export for all scan types (not just repo_scan) | `base.py`, all scanners | 6h | SARIF validator |
| C.3.4 | Add CycloneDX SBOM generation | `dependency_scanner.py` | 8h | CycloneDX validator |

---

## STAGE D — External Security Tool Integrations (Week 4-10)

### D.1 SAST Integrations

| Tool | Wrapper | Config | Effort | Priority |
|------|---------|--------|--------|----------|
| **Semgrep** | `SemgrepScanner` | Ruleset management, auto-config | 16h | **Critical** |
| **CodeQL** | `CodeQLScanner` | DB creation, query packs, SARIF import | 24h | **High** |
| **Bandit** | `BanditScanner` | Python-only, config profiles | 8h | Medium |
| **Ruff (security)** | `RuffScanner` | Fast Python linting, security rules | 6h | Medium |
| **ESLint Security** | `ESLintScanner` | JS/TS, plugin management | 12h | Medium |

**Integration Requirements per Tool:**
- [ ] Version detection & installation validation
- [ ] Configuration validation (rulesets, profiles)
- [ ] Supported file types & scan modes
- [ ] Timeout handling & cancellation
- [ ] Resource limits (memory, CPU)
- [ ] Output parsing → UnifiedFinding[]
- [ ] Error reporting & health status
- [ ] Provenance tracking (tool, version, config)

### D.2 SCA (Software Composition Analysis)

| Tool | Wrapper | Capability | Effort | Priority |
|------|---------|------------|--------|----------|
| **OSV** | ✅ Existing | Direct + transitive, 8 ecosystems | — | Done |
| **GitHub Advisories** | `GHSAScanner` | GHSA IDs, CVSS, severities | 12h | **High** |
| **NVD** | `NVDScanner` | CVE details, CVSS 4.0 | 16h | Medium |
| **EPSS** | `EPSSClient` | Exploit probability scoring | 8h | **High** |
| **CISA KEV** | `KEVScanner` | Known exploited vulns | 8h | **High** |
| **Trivy/Grye/Syft** | `ContainerScanner` | Container image vulns + SBOM | 24h | Medium |
| **pip-audit / npm audit** | `PackageAuditScanner` | Lockfile validation | 8h | Medium |

**Advanced SCA Features:**
- [ ] Transitive dependency resolution (deptry/pipdeptree/npm ls)
- [ ] Reachability analysis (call graph + vuln function matching)
- [ ] SBOM generation (SPDX 2.3 + CycloneDX 1.6)
- [ ] License compliance scanning
- [ ] Supply chain risk scoring (SLSA, Sigstore verification)

### D.3 Secret Detection

| Tool | Wrapper | Effort | Priority |
|------|---------|--------|----------|
| **Gitleaks** | `GitleaksScanner` | 12h | **High** |
| **TruffleHog** | `TruffleHogScanner` | 12h | Medium |
| **detect-secrets** | `DetectSecretsScanner` | 8h | Medium |

**Secret Handling Requirements:**
- [ ] Redaction in all logs, reports, telemetry
- [ ] Never store discovered secrets unprotected
- [ ] Entropy-based detection + pattern matching
- [ ] Verification (active/inactive key checking)

### D.4 Container & Image Security

| Tool | Wrapper | Effort | Priority |
|------|---------|--------|----------|
| **Trivy** | `TrivyScanner` | 16h | **High** |
| **Grype** | `GrypeScanner` | 12h | Medium |
| **Syft** | `SyftScanner` (SBOM) | 8h | Medium |
| **Dockerfile scanner** | `DockerfileScanner` | 8h | Medium |

**Analysis Coverage:**
- [ ] Base image vulnerabilities
- [ ] OS package vulnerabilities
- [ ] Application dependencies in container
- [ ] Dangerous configurations (privileged, root, capabilities, mounts)
- [ ] Exposed secrets in layers
- [ ] Image provenance & signing verification

### D.5 IaC Security

| Tool | Wrapper | Effort | Priority |
|------|---------|--------|----------|
| **Checkov** | `CheckovScanner` | 16h | **High** |
| **KICS** | `KICSScanner` | 12h | Medium |
| **Trivy Config** | `TrivyConfigScanner` | 8h | Medium |

**Coverage:**
- [ ] Terraform, Kubernetes, Docker Compose, Helm
- [ ] Cloud configuration (AWS, GCP, Azure)
- [ ] CI/CD infrastructure (GitHub Actions, GitLab CI)
- [ ] Insecure defaults, excessive permissions, public exposure

### D.6 DAST (Dynamic Application Security Testing)

| Tool | Wrapper | Effort | Priority |
|------|---------|--------|----------|
| **OWASP ZAP** | `ZAPScanner` | 24h | Medium |
| **Nuclei** | `NucleiScanner` | 16h | **High** |

**Safety Requirements (MANDATORY):**
- [ ] Only scan explicitly authorized targets
- [ ] Require explicit authorization before intrusive testing
- [ ] Clear scan scope configuration
- [ ] Rate limits and timeouts
- [ ] No destructive payloads by default
- [ ] Safe passive mode (default)
- [ ] Clear distinction: passive vs active exploitation

### D.7 API Security

| Capability | Implementation | Effort | Priority |
|------------|----------------|--------|----------|
| OpenAPI/Swagger analysis | `APISpecScanner` | 16h | **High** |
| Endpoint inventory & mapping | Part of above | — | — |
| AuthN/AuthZ boundary analysis | Part of above | — | — |
| Rate limiting detection | Part of above | — | — |
| Mass assignment / excessive data exposure | Part of above | — | — |
| OWASP API Top 10 mapping | Correlation rules | 8h | **High** |
| GraphQL introspection abuse | `GraphQLScanner` | 12h | Medium |
| Authorized dynamic testing | Integration with DAST | — | — |

---

## STAGE E — AI Agent Security & Governance (Week 6-14) **MAJOR PRIORITY**

### E.1 Agent Threat Model Implementation

| Threat | Mitigation | Implementation | Effort |
|--------|------------|----------------|--------|
| Prompt injection | Input sanitization, instruction hierarchy | `agent_security.py` | 16h |
| Indirect prompt injection | Context isolation, untrusted data marking | `agent_security.py` | 12h |
| Malicious repo instructions | .triagekitignore, instruction allowlist | `agent_security.py` | 8h |
| Untrusted tool output | Output validation, type checking | `agent_security.py` | 8h |
| Secret exfiltration | Redaction, secret scanning in agent context | `agent_security.py` | 8h |
| Context leakage | Session boundaries, data classification | `agent_security.py` | 12h |
| Unauthorized tool execution | Policy engine, tool allowlist | `agent_policy.py` | 16h |
| Privilege escalation | Capability-based permissions | `agent_policy.py` | 12h |
| Tool-chain abuse | Tool composition restrictions | `agent_policy.py` | 8h |
| Filesystem manipulation | Path allowlist/denylist, sandbox | `agent_policy.py` | 12h |
| Unsafe shell execution | Shell command denylist, argv validation | `agent_policy.py` | 8h |
| Network access abuse | Egress allowlist, DNS filtering | `agent_policy.py` | 8h |
| Destructive actions | Approval required, dry-run mode | `agent_approval.py` | 16h |
| Excessive autonomy | Step limits, human-in-the-loop | `agent_approval.py` | 12h |
| Untrusted dependencies | Dependency allowlist, hash pinning | `agent_policy.py` | 8h |
| Agent-generated insecure code | Post-generation security scan | `agent_security.py` | 12h |
| Compromised integrations | Integration health checks, mTLS | `agent_policy.py` | 8h |
| Unsafe MCP server behavior | MCP server allowlist, capability limits | `agent_policy.py` | 8h |

### E.2 Agent Policy Engine

| Component | Description | Files | Effort |
|-----------|-------------|-------|--------|
| **Policy DSL** | YAML/JSON policy definition (allow/deny, scopes, conditions) | `agent_policy.py` | 16h |
| **Permission Scopes** | Read-only, Reversible, Sensitive, Destructive, External-impact | `agent_policy.py` | 8h |
| **Tool Allowlist/Denylist** | Per-tool permissions with parameter constraints | `agent_policy.py` | 12h |
| **Filesystem Boundaries** | Path patterns with read/write/execute controls | `agent_policy.py` | 8h |
| **Network Restrictions** | Egress allowlist, port/protocol limits | `agent_policy.py` | 8h |
| **Environment Protection** | Secret env var access control | `agent_policy.py` | 4h |
| **Approval Requirements** | Risk-based approval thresholds | `agent_approval.py` | 12h |
| **Policy Evaluation Engine** | Fast decision cache, audit trail | `agent_policy.py` | 12h |

### E.3 Human Approval & Execution Safety

| Feature | Description | Files | Effort |
|---------|-------------|-------|--------|
| **Approval Workflow** | CLI/API/UI for reviewing pending high-impact actions | `agent_approval.py`, `api/app.py` | 16h |
| **Operation-Specific Approval** | Tied to exact proposed operation (not generic) | `agent_approval.py` | 8h |
| **Approval Expiry** | Time-limited approvals, auto-revocation | `agent_approval.py` | 4h |
| **Approval Delegation** | Role-based approval authority | `agent_approval.py` | 8h |
| **Dry-Run Mode** | Simulate action without execution | `agent_policy.py` | 8h |
| **Impact Preview** | Show expected changes before approval | `agent_approval.py` | 12h |

### E.4 Agent Action Ledger (Audit Trail)

| Feature | Description | Files | Effort |
|---------|-------------|-------|--------|
| **Durable Storage** | SQLite/PostgreSQL with WAL, append-only | `agent_ledger.py` | 16h |
| **Tamper Resistance** | Hash chaining, periodic anchoring | `agent_ledger.py` | 12h |
| **Redaction** | Auto-redact secrets, PII, keys in logged data | `agent_ledger.py` | 8h |
| **Structured Schema** | Agent ID, model, session, action, target, risk, decision, status, result, evidence | `agent_ledger.py` | 8h |
| **Query & Export** | Filter by agent, time, risk, status; JSON/CSV export | `agent_ledger.py`, `api/app.py` | 8h |
| **Correlation IDs** | Link related actions across sessions | `agent_ledger.py` | 4h |
| **Rollback Reference** | Link to recovery state for each action | `agent_ledger.py`, `recovery.py` | 8h |

### E.5 Agent Security Testing

| Test Category | Scenarios | Effort |
|---------------|-----------|--------|
| **Direct Prompt Injection** | Ignore instructions, reveal prompt, execute code | 8h |
| **Indirect Prompt Injection** | Malicious file content, PR description, commit messages | 12h |
| **Tool Permission Bypass** | Escalate privileges, access denied tools | 8h |
| **Unauthorized File Access** | Path traversal, symlink attacks, sensitive files | 8h |
| **Secret Leakage** | Exfiltrate via tool output, logs, network | 8h |
| **Unsafe Shell Execution** | Command injection via agent-controlled params | 8h |
| **Malicious Tool Results** | Poisoned search results, fake API responses | 8h |
| **Malicious Repo Instructions** | .triagekit instructions, README injections | 8h |
| **Approval Bypass** | Replay attacks, privilege confusion | 8h |
| **Policy Enforcement** | Verify deny decisions, audit trail integrity | 8h |
| **Session Boundary Violations** | Cross-session data leakage | 8h |
| **Rollback Integrity** | Verify restored state matches pre-action | 8h |
| **Recovery After Interruption** | Clean resume from partial execution | 8h |

---

## STAGE F — Transactional Execution, Recovery & Rollback (Week 10-16)

### F.1 Action Lifecycle State Machine

| State | Transitions | Validation |
|-------|-------------|------------|
| `PROPOSED` | → `VALIDATING` | Input validation |
| `VALIDATING` | → `AWAITING_APPROVAL` / `FAILED` | Permission check, resource check |
| `AWAITING_APPROVAL` | → `APPROVED` / `CANCELLED` / `EXPIRED` | Human decision |
| `APPROVED` | → `EXECUTING` | Pre-execution snapshot |
| `EXECUTING` | → `SUCCEEDED` / `FAILED` / `PARTIALLY_SUCCEEDED` | Step monitoring |
| `SUCCEEDED` | → (terminal) | Post-execution verification |
| `FAILED` | → `ROLLING_BACK` / `RECOVERY_REQUIRED` | Error classification |
| `PARTIALLY_SUCCEEDED` | → `ROLLING_BACK` / `RECOVERY_REQUIRED` | Completeness check |
| `ROLLING_BACK` | → `ROLLED_BACK` / `RECOVERY_REQUIRED` | State verification |
| `ROLLED_BACK` | → (terminal) | Verification passed |
| `RECOVERY_REQUIRED` | → `PROPOSED` (manual) / `CANCELLED` | Operator intervention |
| `CANCELLED` | → (terminal) | Cleanup |

**Implementation:** `core/recovery/action_lifecycle.py`

### F.2 Pre-Execution Protection

| Check | Implementation | Effort |
|-------|----------------|--------|
| Target inspection | Existence, permissions, current state | 4h |
| Permission verification | Policy engine evaluation | 4h |
| Precondition recording | State snapshot (files, DB, config) | 8h |
| Backup/snapshot creation | File copy, DB transaction, config export | 12h |
| Impact calculation | Affected resources, blast radius | 8h |
| Rollback feasibility | Reversibility assessment | 4h |
| Resource validation | Disk space, memory, network | 4h |
| Approval validation | Required approvals obtained | 4h |

### F.3 Rollback Architecture

| Method | Applicability | Implementation | Effort |
|--------|---------------|----------------|--------|
| **File snapshots** | File create/modify/delete | Copy-on-write, restore on rollback | 16h |
| **Database transactions** | DB operations | Savepoints, compensating transactions | 12h |
| **Configuration rollback** | Config file changes | Git-backed config, version restore | 8h |
| **Deployment rollback** | Deploy actions | Reference previous deployment, redeploy | 12h |
| **Compensation operations** | External API calls | Inverse API calls, idempotency keys | 16h |
| **Rollback verification** | All methods | Post-rollback state comparison | 8h |

### F.4 Crash & Interruption Recovery

| Scenario | Recovery Strategy | Implementation | Effort |
|----------|-------------------|----------------|--------|
| Agent process crash | Persist action state to ledger; resume from last checkpoint | `recovery.py` | 12h |
| Application restart | Scan ledger for incomplete actions; enter RECOVERY_REQUIRED | `recovery.py` | 8h |
| Action timeout | Mark PARTIALLY_SUCCEEDED; trigger rollback | `recovery.py` | 8h |
| API connection drop | Idempotency keys; retry with same key | `recovery.py` | 8h |
| System power loss | WAL durability; replay from last commit | `recovery.py` (SQLite WAL) | 4h |
| Multi-step partial completion | Step-level checkpoints; resume from failed step | `recovery.py` | 16h |
| Interrupted rollback | Idempotent rollback ops; retry until verified | `recovery.py` | 8h |

### F.5 Recovery Dashboard

| Feature | Description | Files | Effort |
|---------|-------------|-------|--------|
| **Recent Actions** | List last N actions with status | `recovery_dashboard.py`, UI | 8h |
| **Failed Actions** | Filter by failure, show error, retry/rollback | `recovery_dashboard.py`, UI | 8h |
| **Pending Approvals** | Show awaiting approval, expiry, approve/deny | `recovery_dashboard.py`, UI | 8h |
| **Partial Execution** | Show completed/remaining steps, resume | `recovery_dashboard.py`, UI | 8h |
| **Rollback Availability** | Show which actions can be rolled back | `recovery_dashboard.py`, UI | 4h |
| **Recovery Required** | Highlight actions needing operator intervention | `recovery_dashboard.py`, UI | 4h |
| **Backup Status** | Show backup age, size, verification status | `recovery_dashboard.py`, UI | 4h |
| **Execution History** | Full audit trail with filters, export | `recovery_dashboard.py`, UI | 8h |

---

## STAGE G — Framework Mappings & CI/CD (Week 12-18)

### G.1 Security Framework Mappings

| Framework | Mapping Approach | Implementation | Effort |
|-----------|------------------|----------------|--------|
| **OWASP Top 10** | Rule → category mapping | `framework_mapping.py` | 16h |
| **OWASP API Top 10** | API scanner findings → categories | `framework_mapping.py` | 12h |
| **OWASP ASVS** | Requirement → control → evidence | `framework_mapping.py` | 24h |
| **OWASP SAMM** | Maturity level assessment | `framework_mapping.py` | 16h |
| **OWASP LLM Top 10** | Agent security findings → categories | `framework_mapping.py` | 12h |
| **NIST CSF** | Function → category → subcategory | `framework_mapping.py` | 16h |
| **NIST SSDF** | Practice → task → implementation | `framework_mapping.py` | 16h |
| **NIST AI RMF** | Map → measure → manage → govern | `framework_mapping.py` | 12h |
| **CWE** | Finding → CWE (already partially done) | Enhance coverage | 12h |
| **CVSS 4.0** | Calculator + vector generation | `cvss_calculator.py` | 16h |
| **EPSS** | Score enrichment for CVEs | `dependency_scanner.py` | 8h |
| **CISA KEV** | Flag known exploited | `dependency_scanner.py` | 8h |

### G.2 Control Coverage Dashboard

| Feature | Description | Files | Effort |
|---------|-------------|-------|--------|
| **Framework Selector** | Choose framework (OWASP, NIST, etc.) | UI + `framework_mapping.py` | 8h |
| **Control Matrix** | Controls × Implementation Status (Implemented/Partial/Missing) | UI + `framework_mapping.py` | 16h |
| **Evidence Viewer** | Click control → show findings, scans, gaps | UI + `framework_mapping.py` | 12h |
| **Gap Analysis** | Missing evidence, assessment limitations | UI + `framework_mapping.py` | 8h |
| **Export Assessment** | PDF/HTML/JSON compliance report | UI + `framework_mapping.py` | 12h |

### G.3 GitHub Integration

| Feature | Implementation | Effort |
|---------|----------------|--------|
| **PR Analysis Workflow** | `.github/workflows/triagekit-pr.yml` | 8h |
| **Commit/Push Scanning** | Scheduled or webhook-triggered | 8h |
| **Changed-File Analysis** | Diff-aware scanning (incremental) | 16h |
| **Dependency Scanning** | On lockfile change | 8h |
| **SARIF Upload** | GitHub Code Scanning API | 8h |
| **PR Annotations** | Inline finding annotations | 8h |
| **Security Report Artifacts** | Upload markdown/JSON reports | 4h |
| **Status Checks** | Required check with policy thresholds | 8h |
| **Policy-Based Blocking** | Configurable fail thresholds | 8h |
| **Workflow Summary** | Job summary with risk score, findings | 4h |

### G.4 GitHub Actions Reusable Workflows

| Workflow | Stages | Effort |
|----------|--------|--------|
| **triagekit-sast.yml** | Static → Taint → Correlation → SARIF | 8h |
| **triagekit-sca.yml** | Deps → OSV/GHSA/NVD → EPSS/KEV → SBOM | 8h |
| **triagekit-secrets.yml** | Gitleaks → TruffleHog → Redaction | 4h |
| **triagekit-iac.yml** | Checkov/KICS → SARIF | 8h |
| **triagekit-container.yml** | Trivy → Grype → SBOM | 8h |
| **triagekit-dast.yml** | ZAP/Nuclei (authorized only) | 8h |
| **triagekit-api.yml** | Spec analysis → Dynamic (authorized) | 8h |
| **triagekit-full.yml** | All stages with policy gates | 16h |

### G.5 Output Formats

| Format | Implementation | Effort |
|--------|----------------|--------|
| **SARIF 2.1.0** | All scanners → unified SARIF | 12h |
| **JSON** | UnifiedFinding[] + metadata | 4h |
| **HTML** | Dashboard + findings (existing) | — |
| **Markdown** | TriageResult.to_markdown() (existing) | — |
| **CycloneDX SBOM** | DependencyScanner output | 8h |
| **SPDX SBOM** | DependencyScanner output | 8h |

---

## STAGE H — Dashboard & UX (Week 14-20)

### H.1 React UI Parity with Classic UI

| Feature | Classic UI | React UI | Effort |
|---------|------------|----------|--------|
| **Analysis Chain Tree** | ✅ | ❌ | 16h |
| **Severity Counters** | ✅ | ✅ (SeverityBar) | — |
| **Accordion Panels** | ✅ | ✅ (FindingList) | — |
| **Diff Viewer** | ✅ | ❌ | 12h |
| **Suggestion Filters** | ✅ | ❌ | 8h |
| **Copy/Export** | ✅ | ✅ | — |
| **Tree Navigation** | ✅ | ✅ (SideNav) | — |

### H.2 Security Operations Dashboard

| Panel | Description | Data Source | Effort |
|-------|-------------|-------------|--------|
| **Project Security Overview** | Aggregate risk, trends, coverage | OrchestrationResult.summary | 12h |
| **SAST + Taint Findings** | Unified view with trace evidence | TaintAnalysisScanner + StaticScanner | 12h |
| **Dependency & Supply Chain** | CVE, EPSS, KEV, reachability, SBOM | DependencyScanner | 12h |
| **Secret Detection** | Redacted findings, verification status | SecretScanner | 8h |
| **Container & IaC Security** | Image vulns, config issues | ContainerScanner + IaCScanner | 8h |
| **API Security** | Spec findings, dynamic results | APIScanner + DASTScanner | 8h |
| **DAST Results** | Active/passive findings, verification | DASTScanner | 8h |
| **Standards Coverage** | Framework control matrix | FrameworkMapping | 12h |
| **Agent Security** | Policy violations, approvals, ledger | AgentLedger + PolicyEngine | 16h |
| **Agent Action History** | Timeline, search, replay | AgentLedger | 12h |
| **Approvals & Policies** | Pending, history, policy editor | AgentApproval + PolicyEngine | 12h |
| **Recovery & Rollback** | Dashboard from F.5 | RecoveryDashboard | 12h |
| **Scanner Health** | Version, status, last run, errors | ScannerRegistry + OrchestrationResult | 8h |
| **Security Reports** | Generate, schedule, download | All scanners | 8h |

### H.3 Data Visualization Requirements

| Visualization | Type | Implementation |
|---------------|------|----------------|
| Severity distribution | Stacked bar / donut | Recharts |
| Confidence distribution | Heatmap | Recharts |
| Vulnerability trends | Line chart (time series) | Recharts |
| Scan completion status | Progress rings | Recharts |
| NOT ASSESSED visibility | Warning badges, separate panel | Custom |
| Framework coverage | Radar chart / matrix | Recharts |
| Critical findings | Priority table | Custom |
| Remediation status | Kanban board | Custom |
| Integration health | Status grid | Custom |
| Recovery status | Timeline + state badges | Custom |

---

## STAGE I — Comprehensive Verification (Week 18-24)

### I.1 Regression Test Suite

| Test Suite | Coverage | Target |
|------------|----------|--------|
| **Existing testbench** | 7 languages, repo_scan detection | PASS (baseline) |
| **Cookie parser** | 7 cases | PASS |
| **Scanner framework** | Registry, lifecycle, correlation | NEW: 90% coverage |
| **Taint analysis** | Python AST, JS regex, interprocedural | NEW: 80% coverage |
| **Engine blending** | Static/LLM blend, thresholds, fallback | NEW: 100% coverage |
| **Correlation engine** | Deduplication, rules, attack paths | NEW: 90% coverage |
| **Recovery/rollback** | State machine, snapshots, verification | NEW: 80% coverage |
| **Agent security** | Policy enforcement, approval, ledger | NEW: 80% coverage |
| **External scanners** | Adapter parsing, error handling | NEW: 70% coverage (fixture-based) |

### I.2 New Test Categories

| Category | Description | Implementation |
|----------|-------------|----------------|
| **Scanner Discovery** | Tool detection, version parsing, config validation | Unit tests per scanner |
| **Invalid Configurations** | Missing tools, bad config, invalid targets | Negative tests |
| **Missing Executables** | Graceful degradation, NOT_ASSESSED status | Integration tests |
| **Timeout Handling** | Scanner timeout, partial results | Integration tests |
| **Malformed Output** | Parser robustness, error recovery | Unit tests with fixtures |
| **Partial Scan Completion** | Some scanners fail, others succeed | Integration tests |
| **Result Normalization** | Schema compliance, field mapping | Unit tests |
| **Finding Correlation** | Cross-scanner matching, severity boost | Unit tests |
| **Severity/Confidence Mapping** | Consistent across scanners | Unit tests |
| **Source-to-Sink Traces** | Taint path completeness, evidence | Integration tests |
| **Secret Redaction** | No secrets in logs/reports/output | Security tests |
| **SARIF Generation** | Schema validation, round-trip | Unit tests |
| **SBOM Generation** | CycloneDX/SPDX schema validation | Unit tests |
| **AuthZ Boundaries** | API endpoint permissions | Integration tests |
| **Approval Enforcement** | High-impact actions require approval | Integration tests |
| **Action State Transitions** | Valid/invalid transitions | Unit tests |
| **Backup Creation** | Snapshot integrity, restoration | Integration tests |
| **Rollback Verification** | State match after rollback | Integration tests |
| **Interrupted Recovery** | Resume from checkpoints | Integration tests |
| **Malicious Agent Inputs** | Prompt injection, tool bypass | Security tests |
| **Policy Enforcement** | Deny decisions, audit trail | Security tests |

### I.3 Testbench Expansion

| Language | Current | Target | New Fixtures Needed |
|----------|---------|--------|---------------------|
| Python | ✅ vuln + safe | +5 variants | SQLi, XSS, path traversal, deserialization, crypto |
| JavaScript/TypeScript | ❌ | New | 10 fixtures (React, Node, Express, Next.js) |
| Java | ✅ vuln | +3 variants | Spring, deserialization, XXE |
| C# | ✅ vuln | +3 variants | ASP.NET, deserialization, crypto |
| Rust | ✅ vuln | +2 variants | Unsafe, command injection |
| C++ | ✅ vuln | +2 variants | Buffer overflow, format string |
| Swift | ✅ vuln | +2 variants | Keychain, WebView |
| Go | ❌ | New | 5 fixtures |
| PHP | ❌ | New | 5 fixtures |

| Scenario Type | Target Count |
|---------------|--------------|
| Vulnerable examples | 50+ |
| Secure equivalents | 20+ |
| False-positive cases | 15+ |
| Sanitizer cases | 10+ |
| Interprocedural examples | 10+ |
| Dependency vulnerabilities | 10+ |
| Malicious agent scenarios | 10+ |
| Policy enforcement scenarios | 10+ |
| Recovery/rollback scenarios | 10+ |

### I.4 Integration Availability Testing

| Tool | Unit Adapter | Fixture Parser | Local Execution | E2E Verified |
|------|--------------|----------------|-----------------|--------------|
| Semgrep | ✅ | ✅ | ⏳ | ❌ |
| CodeQL | ⏳ | ⏳ | ❌ | ❌ |
| Gitleaks | ⏳ | ✅ | ⏳ | ❌ |
| TruffleHog | ⏳ | ⏳ | ❌ | ❌ |
| Trivy | ⏳ | ⏳ | ⏳ | ❌ |
| Checkov | ⏳ | ⏳ | ⏳ | ❌ |
| Nuclei | ⏳ | ✅ | ⏳ | ❌ |
| OWASP ZAP | ⏳ | ⏳ | ❌ | ❌ |

**Legend:** ✅ Done, ⏳ In Progress, ❌ Not Started

### I.5 Final Verification Report

| Section | Content |
|---------|---------|
| **Completed Integrations** | Scanner name, version, test status, coverage |
| **Partially Completed** | Scanner name, missing features, blockers |
| **Requiring External Install** | Tool name, install instructions, verification steps |
| **E2E Tested** | Tool name, test scenario, result |
| **Fixture-Tested Only** | Tool name, fixture coverage |
| **Unavailable** | Tool name, reason, alternative |
| **Remaining Security Gaps** | Capability, risk, mitigation |
| **Test Results** | Suite, passed, failed, skipped, coverage % |
| **Failed Tests** | Test name, failure reason, fix plan |
| **Performance** | Scan times, memory, CPU per scanner |
| **Migration Requirements** | Breaking changes, upgrade steps |
| **Recommended Next Steps** | Priority, effort, dependencies |

---

## Resource Estimation Summary

| Phase | Engineering Weeks | Parallel Tracks | Key Dependencies |
|-------|-------------------|-----------------|------------------|
| A: Baseline & Fixes | 1 | 1 | None |
| B: Framework Activation | 1-2 | 1 | A complete |
| C: Core Engine | 2-4 | 2 (taint + vuln detection) | B complete |
| D: External Tools | 6 | 3 (SAST, SCA, Secrets/Container/IaC/DAST/API) | C.1-C.2 |
| E: Agent Security | 8 | 2 (policy + approval/ledger + testing) | B, C |
| F: Recovery/Rollback | 6 | 2 (lifecycle + dashboard) | E |
| G: Frameworks + CI/CD | 6 | 2 (mappings + workflows) | C, D |
| H: Dashboard | 6 | 2 (parity + security ops) | G |
| I: Verification | 6 | 2 (tests + testbench + integration) | All |

**Total: ~42 engineering weeks (10.5 months) with 2-3 parallel tracks → ~5-6 calendar months with 3 engineers**

---

## Risk Mitigation

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Circular import delays framework | High | High | Fix in Stage A (2h) |
| External tool API changes | Medium | Medium | Adapter pattern, version pinning |
| LLM provider compatibility | Low | Medium | Test matrix, fallback to static |
| Testbench regression | Medium | High | Run on every PR, gate merges |
| Agent security scope creep | High | High | Fixed threat model, timeboxed phases |
| Recovery complexity | Medium | High | Incremental: file → DB → config → external |
| Dashboard performance | Medium | Medium | Virtualization, pagination, caching |
| Maintenance burden | High | High | Shared scanner framework, config-driven |

---

## Success Criteria by Phase

| Phase | Gate Criteria |
|-------|---------------|
| **A** | Testbench PASS, Bandit HIGH=0, venv matches pyproject.toml |
| **B** | ScannerOrchestrator runs all 6 scanners, correlation produces attack paths |
| **C** | Taint analysis via CLI, 5 new vuln classes detected, NOT_ASSESSED enforced |
| **D** | 5+ external scanners integrated, SARIF export works, secret redaction verified |
| **E** | All 18 threat vectors tested, policy engine blocks unauthorized actions, ledger tamper-resistant |
| **F** | Action lifecycle enforced, rollback verified for 5 action types, recovery dashboard operational |
| **G** | 3 frameworks mapped, 8 GitHub workflows working, 6 output formats validated |
| **H** | React UI parity with Classic, 10 security ops panels functional |
| **I** | 90% test coverage, testbench 50+ fixtures, all integrations verified, final report complete |

---

## Next Immediate Actions (This Week)

1. **Fix circular import** in `core/scanners/` — unblock framework
2. **Patch `github_client.py:76`** — resolve Bandit HIGH finding
3. **Recreate venv** — align with pyproject.toml
4. **Run full test suite** — verify no regressions
5. **Begin Stage B.1** — activate scanner framework

---

*Roadmap generated from factual audit baseline — 2026-11-09*