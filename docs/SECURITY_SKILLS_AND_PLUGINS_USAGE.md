# Security Skills and Plugins Usage

Evidence record for the security skills, plugin capabilities and external tools
available in this environment, what was actually loaded and invoked, and what
was unavailable.  A skill or plugin appearing in a list below is **not** treated
as evidence of use — only entries marked **LOADED AND USED** were invoked.

Last verified: 2026-11-09.

---

## 1. Skills discovered

Eight project-local security skills are installed under `.claude/skills/`.
Verified by listing the directory:

| Skill | Path | Status |
|---|---|---|
| `threat-modeling` | `.claude/skills/threat-modeling/SKILL.md` | Present, not yet loaded |
| `secure-code-review` | `.claude/skills/secure-code-review/SKILL.md` | **LOADED AND USED** |
| `api-security` | `.claude/skills/api-security/SKILL.md` | Present, not yet loaded |
| `cve-triage` | `.claude/skills/cve-triage/SKILL.md` | Present, not yet loaded |
| `patch-prioritization` | `.claude/skills/patch-prioritization/SKILL.md` | Present, not yet loaded |
| `scanner-tuning` | `.claude/skills/scanner-tuning/SKILL.md` | Present, not yet loaded |
| `prompt-injection` | `.claude/skills/prompt-injection/SKILL.md` | Present, not yet loaded |
| `agent-security` | `.claude/skills/agent-security/SKILL.md` | Present, not yet loaded |

Supporting reference files also installed: `api-security/api-top10-checklist.md`,
`api-security/csharp-dotnet.md`, `secure-code-review/csharp-dotnet.md`,
`threat-modeling/csharp-dotnet.md`, `threat-modeling/threat-actor-profiles.md`.

### 1.1 `secure-code-review` — loaded and used

Loaded with the argument "Review the Python taint analyzer in
`src/triagekit/core/taint/analyzer.py` for the source/sink/sanitizer matching
defects, interprocedural propagation gaps and state-isolation bugs before
repairing them."

Steps of the skill's process that were actually executed:

- **Step 1 — Scope and language identification.** Language: Python. Module
  under review: `src/triagekit/core/taint/analyzer.py`. Trust boundaries
  identified: external input entering the analysis target through HTTP request
  objects, `sys.argv`, environment variables and stdin. Applicable ASVS
  sections selected: V5 (validation/sanitization/injection), V12 (files and
  resources), V7 (error handling).
- **Step 2 — Input validation and injection review**, mapped to CWE-89 (SQL
  injection), CWE-78 (OS command injection), CWE-22 (path traversal) and
  CWE-20 (improper input validation). Applied directly to the analyzer's sink
  handling: confirmed the `open()` call is both a `file-read` source and a
  `path-traversal` sink, and that the source check returned early and hid the
  sink.

Findings produced by that review, and their disposition:

| Finding | Disposition |
|---|---|
| Source check returned before the sink check, hiding `open()` as a path-traversal sink (CWE-22) | **Fixed** — sink evaluation moved ahead of source return |
| `sys.argv[`, `os.environ[`, `request.args[` patterns matched against bare call names (CWE-20) | **Fixed** — AST-aware candidate matching added |
| `open(` / `os.path.join(` sink patterns never matched the bare name (CWE-22) | **Fixed** — call-site candidates including the opening paren |
| SQL execution sink matched regardless of what the sink actually consumes (CWE-89) | **Partially fixed** — unsafe dynamic SQL now always reported; parameterized-query false positive still open (see §4) |
| Taint discarded at a non-sanitizing wrapper call | **Open** — blocked, see §4 |

The remaining skills were not loaded because their corresponding milestones
(AI-agent threat model, CVE/CWE intelligence, scanner tuning, API coverage) had
not been reached when this record was produced.

---

## 2. Plugin integrations and tools discovered

**No plugin integrations are configured in this project.** Verified:

- No `.mcp.json` at the repository root.
- No `.claude/plugins/` directory.
- `.claude/settings.local.json` contains only `{"spinnerTipsEnabled": true}`.

Plugin-supplied skills are surfaced by the harness listing (for example
`static-analysis:codeql`, `static-analysis:semgrep`, `variant-analysis`,
`differential-review`, `supply-chain-risk-auditor`), but no plugin is installed
or configured locally, so no plugin functionality could be invoked. Per the
mandate, no plugins were installed and no permissions were requested.

---

## 3. External tools invoked

**None.** No external static-analysis or dependency tooling is installed in this
environment. Verified by probing both `PATH` and importability:

| Tool | On PATH | Python module |
|---|---|---|
| semgrep | not installed | not importable |
| bandit | not installed | not importable |
| codeql | not installed | n/a |
| safety | not installed | n/a |
| pip-audit | not installed | not importable |
| osv-scanner | not installed | n/a |
| cyclonedx-bom | not installed | `cyclonedx` not importable |
| syft | not installed | n/a |
| defusedxml | n/a | not importable |

Consequence for the mandate: **Milestone F (external tool integrations) cannot
be executed here without downloading third-party binaries**, which the mandate
prohibits without approval. What was executed locally instead:

| Command | Result |
|---|---|
| `python -m pytest --no-header -p no:cacheprovider -q` | 49 passed, 7 failed (was 43 passed, 13 failed) |
| `python -m pytest tests/test_taint_analysis.py -v` | 20 passed, 7 failed (was 14 passed, 13 failed) |
| `python tests/test_taint_analysis.py` (standalone ASCII runner) | 14 passed, 13 failed → rerun after fixes |
| `python testbench/scripts/run_testbench.py` | PASS — all 7 fixtures |

---

## 4. Skills and plugins that were unavailable, and why

| Capability | Status | Reason |
|---|---|---|
| `secure-code-review` | Available and used | — |
| 7 other project skills | Available, unused | Corresponding milestones not yet reached |
| Plugin ecosystem skills | Not usable | No plugin configured in this project |
| Semgrep / CodeQL / Bandit | Not usable | Not installed; mandate prohibits downloading without approval |
| Dependency audit (pip-audit, safety, osv-scanner) | Not usable | Not installed |
| SBOM tooling (cyclonedx-bom, syft) | Not usable | Not installed |

---

## 5. Blocker on analyzer source edits

Milestone A's remaining work requires editing
`src/triagekit/core/taint/analyzer.py`. Seven consecutive `Edit` calls against
that file were denied by the auto-mode permission classifier, which is applying
the earlier task's constraint (`Do NOT modify production analyzer code` /
`Do NOT modify taint detection rules, source patterns, propagation logic`)
rather than the current mandate's explicit authorization (`You are now
authorized to fix the production analyzer`).

Edits that purely added detection capability were permitted and landed; edits
touching call-boundary bookkeeping or the parameterized-query decision were
denied. The specific remaining work is:

1. Call-site-sensitive propagation across function boundaries (positional index,
   keyword arguments, wrapper calls, multiple levels) with a depth bound and a
   visited set to prevent infinite recursion.
2. Applying the "only interpolated SQL text is vulnerable" rule inside the
   interprocedural pass, where the current false positive originates.
3. Sequential `step_number` assignment for trace steps.

The user has confirmed authorization for analyzer edits, subject to not
downgrading detection. A permission rule for the `Edit` tool is needed for the
classifier to stop denying these calls.
