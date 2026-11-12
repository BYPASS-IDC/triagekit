# TriageKit skills

Operating guides injected into the agent's context automatically. Which skills
load for which operation is defined by `SKILL_MAP` in
`src/triagekit/core/skills.py` -- you do not select them by hand.

## Index

### Policy and procedure

| File | Use it when |
| --- | --- |
| `01-authorized-use.md` | Before any scan. The authorization gate; passive vs active; the escalation checklist. |
| `02-pr-triage.md` | Reading a pull request diff as an attacker. |
| `03-repo-scan.md` | Running a whole-tree scan and reading its coverage limits. |
| `04-web-adviser.md` | Interpreting a web scan's fingerprints, headers, and endpoints. |
| `05-exploitdb-intel.md` | Correlating an OSV record with ExploitDB/Metasploit entries, honestly. |
| `06-injection-surface.md` | The source/sink/sanitizer map. The core taint reference. |
| `07-remediation-playbook.md` | Turning a finding into a mergeable fix, in priority order. |
| `08-progress-and-ci.md` | Emitting progress and wiring the scanner into CI. |
| `21-branch-scanning.md` | Scanning a non-default ref and diffing against the base branch. |
| `26-finding-narrative.md` | Writing one finding: the seven required parts. |
| `27-false-positive-control.md` | Proving a finding before reporting it. |
| `28-report-quality.md` | What makes a report usable, and what must never appear in one. |

### Vulnerability classes

| File | Class |
| --- | --- |
| `09-sql-injection.md` | SQL injection (CWE-89) |
| `10-xss.md` | Cross-site scripting (CWE-79) |
| `11-command-injection.md` | OS command injection (CWE-78) |
| `12-path-traversal.md` | Path traversal (CWE-22) |
| `13-secrets-and-tokens.md` | Hardcoded credentials (CWE-798) |
| `14-crypto-and-tls.md` | Weak cryptography and TLS (CWE-327/295) |
| `15-authn-authz.md` | Authentication and access control (CWE-287/284) |
| `16-ssrf-and-redirects.md` | SSRF and open redirect (CWE-918/601) |
| `17-deserialization.md` | Unsafe deserialization (CWE-502) |
| `18-dependency-cve.md` | Dependency vulnerabilities via OSV (CWE-1395) |
| `19-headers-and-cookies.md` | Security headers and cookie flags (CWE-693) |
| `20-api-and-graphql.md` | API and GraphQL exposure (CWE-1059) |
| `25-docker-and-supply-chain.md` | Container and supply-chain configuration |
| `29-general-lang-scanner.md` | Fallback for languages with no dedicated skill |

### Languages

| File | Language |
| --- | --- |
| `22-rust-security.md` | Rust |
| `23-php-security.md` | PHP |
| `24-javascript-security.md` | JavaScript / TypeScript (regex-based analyzer; read its limits) |

## The contract

Every file follows `STYLE-GUIDE.md`:

1. **ASCII only.** The platform console is cp1252; a non-ASCII byte can abort a
   run mid-report and produce a silently truncated file.
2. **No numeric CVSS.** v4.0 is a lookup table. Emit a vector and the
   FIRST.org calculator link, never a computed number.
3. **Named, testable claims.** "Prefer X" is banned; say what to run.
4. **A mandatory false-positive section.** This is what keeps the report usable.
5. **No attack on a real target.** Payloads are shapes against a local fixture.
6. **Cross-reference by filename** so a reader can follow the thread.
7. **120-350 lines.** Dense and complete beats exhaustive.

## How a skill is loaded

`load_skills_text(operation)` concatenates the assigned skills into the agent
prompt, and `skill_system_prefix(operation)` prefixes the system prompt with the
list. Skills longer than the configured character limit are truncated **at a
section boundary**, never mid-sentence -- a truncated instruction that reads as
a complete one is worse than a short one, so the loader appends a marker noting
that the full text is in `skills/`.

If a skill you expected is missing from a run, check `SKILL_MAP` first: the
loader resolves the directory case-insensitively and falls back to a default
brief when no skill file is found.

## Adding a skill

1. Read `STYLE-GUIDE.md` and one existing class skill for the shape.
2. Write the file into this directory with the next free number.
3. Add it to the relevant `SKILL_MAP` entry in `src/triagekit/core/skills.py`.
4. Verify it is ASCII-clean and that all eight required sections are present.
5. Cross-reference it from at least one other skill and from this index.
