# General language scanner (the fallback when no dedicated skill applies)

## What it is

TriageKit has deep skills for Python, JavaScript/TypeScript, Rust, and PHP, and
a taint analyzer for Python and JS. For everything else -- Go, Kotlin, Ruby,
Scala, Elixir, Objective-C, and any language with no dedicated skill -- this file
is the operating procedure.

The purpose of a fallback skill is to be *useful without being wrong*. Most of the
damage a scanner does to its own credibility comes from fallback paths that
produce confident findings about languages whose grammar the tool does not model.
The rule here is therefore stricter than elsewhere: **a generic pattern is a lead,
never a finding, unless you have read the line.**

The trust boundary crossed is the same one as everywhere else: attacker-controlled
data reaching a construct that interprets input as instructions. What differs is
how much of that you can infer without an analyzer.

## What the general scanner actually is

Two layers, and it matters which one produced a finding.

### Layer 1: the language rule packs

`src/triagekit/core/analyzers/lang/__init__.py` defines `rules_for_path(path)`,
which returns the pack for a file by extension or language name. Packs exist for:

| Pack | Language | Extensions |
| --- | --- | --- |
| `python_rules` | Python | `.py` |
| `rust_rules` | Rust | `.rs` |
| `swift_rules` | Swift | `.swift` |
| `csharp_rules` | C# | `.cs` |
| `cpp_rules` | C, C++ | `.cpp`, `.cc`, `.cxx`, `.h`, `.hpp`, `.c` |
| `java_rules` | Java | `.java` |

Every rule is a `(regex, rule_id, severity, cwe)` tuple. **There is no Go, Ruby,
Kotlin, Scala, Elixir, PHP, or Objective-C pack.** For those languages only
Layer 2 applies.

### Layer 2: the generic pattern lists

`src/triagekit/core/analyzers/repo_scan.py` defines `INJECTION`, `SECRETS`,
`CRYPTO_AUTH`, `QUALITY`, `CONFIG_DOCKER`, and `CI_PATTERNS`. These are matched
against every scanned file. They are sink-oriented regexes and secret shapes:
`exec(`, `system(`, `Runtime.exec`, `cursor.execute(... + ...)`,
`innerHTML=`, `eval(`, `pickle.loads`, `unserialize(`, `ObjectInputStream`,
`BinaryFormatter`, `child_process.exec(`, `$_GET[...]` into a query, `../../`,
`md5(`, `sha1(`, `verify=False`, `jwt.decode(... verify=False)`, `DES`, `RC4`,
`Blowfish`, `USER root`, `:latest`, `curl | sh`, `permissions: write-all`.

Secret rules carry provider-specific shapes: `AKIA[0-9A-Z]{16}`,
`ghp_`/`gho_`/`github_pat_`, `sk-`/`sk-proj-`, `xox[baprs]-`, `AIza...`,
`nvapi-`, `eyJ...` (a JWT), `-----BEGIN ... PRIVATE KEY-----`, and
`Bearer <20+ chars>`.

**These apply to any file regardless of language**, because a secret is a secret
in Go and a shell pipeline is a shell pipeline in Ruby.

## The decision procedure

For every finding in a language with no dedicated skill, in this order:

### 1. Classify which layer produced it

- **A secret rule (`SECRETS`).** Highest-confidence class in the whole tool. The
  value shape is language-independent. Verify liveness, then report. See
  `skills/13-secrets-and-tokens.md`.
- **A config/CI rule.** A `Dockerfile` or workflow line. Read the stage and the
  context. See `skills/25-docker-and-supply-chain.md`.
- **A generic injection sink pattern.** **A lead.** The regex matched a function
  *name*, and names collide across languages. Confirm by reading.
- **A weak-crypto or TLS pattern.** Language-independent in most cases
  (`verify=False` is a Python/requests spelling; `rejectUnauthorized: false` is
  Node; `--insecure` is curl; `-k` is curl). Read the line.

### 2. Read the line before reporting

The whole point. Open the file at the line. Then ask:

- **Is the regex matching a call, or a string, comment, or declaration?** A
  TypeScript `type Exec = ...`, a docstring containing `system(`, and a test
  asserting on a payload are not sinks.
- **Is the matched function the one the rule means?** A user-defined
  `def system(x)` or a Ruby method named `exec` is not `os.system`. This is the
  dominant false positive in a fallback path.
- **Is the interpolated value attacker-controlled?** In the fallback case there is
  no taint graph, so this question must be answered by reading the enclosing
  function and its callers. If you cannot answer it, the finding is a note.

### 3. Apply the same four checks as everywhere else

From `skills/27-false-positive-control.md`: the source evaluates, every path step
carries the data, no sanitizer breaks the flow, and the attacker can reach it.
The fallback path gives you no help with any of the four, which is exactly why
step 2 is mandatory.

### 4. State the analyzer's limits in the finding

Every fallback finding carries a line like:

    Analyzer: generic sink pattern (no <language> taint analysis).
    Reachability: confirmed by reading foo.go:118-131; the request value is
    passed unchanged into exec.Command.

and every fallback *absence* carries a line like:

    NOT ASSESSED: <language> has no dedicated rule pack or taint analyzer in
    this build. Cross-file and closure flows were not analyzed.

That second line is not boilerplate. It is the difference between an honest
report and a misleading one, and it belongs in the coverage section too.

## How it works (attack mechanics)

The mechanics do not vary by language, which is the one thing that makes a
fallback skill viable. For every language:

| Class | The grammar crossed | The payload shape |
| --- | --- | --- |
| SQL | SQL | `' OR '1'='1` |
| Command | the shell | `;`, `\|`, `` ` ``, `$( )` |
| Template | the template engine | `{{ }}`, `${ }` |
| Path | the filesystem | `../`, an absolute path |
| XSS | HTML | `<img src=x onerror=...>` |
| Deserialization | the object loader | a crafted serialized blob |
| Regex | the regex engine | catastrophic backtracking |
| LDAP / XPath | the query language | `*)(...)`, `' or '1'='1` |

So the fallback skill's real contribution is: name the grammar, name the sink, and
refuse to claim a flow you have not read.

## Is it actually exploitable?

1. **Does the sink in this language actually interpret its argument?** A Go
   `exec.Command("sh", "-c", s)` does; a Go `exec.Command("ls", s)` does not. The
   distinction is the finding.
2. **Is the function name the standard library's, or a local definition?** Grep
   for `func <name>` in the same file before reporting.
3. **Does the language's framework escape by default?** Go templates
   (`html/template`) auto-escape; Ruby on Rails ERB auto-escapes; `text/template`
   does not. The framework decides, not the language.
4. **Is there an interprocedural flow?** With no analyzer, a flow that crosses
   three files will not be found by any regex. If you found it by reading, report
   it; if you did not look, say `NOT ASSESSED`.
5. **Is the pattern in a generated file?** Generated and vendored code is not the
   team's. Check the skip list first.

## False positives (do NOT report)

- **A user-defined function that happens to share a sink's name.** `exec`,
  `system`, `eval`, `query`, `render` are all common local names.
- **A matched function in a comment, a string literal, a docstring, or a log
  format string.**
- **A test fixture containing the payload shape.** The test for the fix, not the
  bug.
- **Generated, vendored, or minified files.** Check the directory skip list.
- **A constant-composed query or command.** No source reaches it.
- **A weak-hash match in a non-security context** -- a checksum, a cache key, a
  deduplication hash.
- **A `DES`/`RC4` match inside an identifier** (`DESCRIBE`, an `ARC4S` constant).
  The rule uses word boundaries for `DES`/`RC4`; other patterns do not.
- **A secret-shaped string in documentation**, an example, or a `.env.example`
  placeholder.
- **A finding in a file whose extension is not in any rule pack** -- confirm the
  file was scanned at all before reporting its absence.

The single most important rule in this skill: **when you cannot read the line,
report a note.** A fallback scanner that guesses produces a report nobody can
trust, and the maintainer will delete the tool rather than argue with it.

## Severity

Score the class, not the fallback. A generic command-execution sink confirmed by
reading, unauthenticated:

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
https://www.first.org/cvss/calculator/4.0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N
```

If reachability was inferred rather than read, the honest severity is lower --
`AT:P` because the flow depends on a deployment precondition you did not verify.
Never inflate a fallback finding to compensate for weak analysis; downgrade it and
say why. Never hand-compute the number.

## Remediation

The remediation is the class's remediation, expressed in the target language's
idiom. Never hand a Python `subprocess.run` snippet to a Go codebase -- name the
idiom instead:

| Class | Idiom, language-neutral |
| --- | --- |
| SQL | the language's parameterized/prepared API |
| Command | spawn the process with an argument array and no shell interpreter |
| Path | resolve, then verify the result is inside an allowlisted base |
| XSS | the template engine's autoescaping, or an allowlist-based sanitizer |
| Template | pass untrusted data as *data* to a compiled template, never as template text |
| Deserialization | a data-only format with schema validation |
| Secret | environment or secret manager; rotate the exposed value |

Exact code belongs in the per-class skill
(`skills/07-remediation-playbook.md` is the starting point).

## Verify the fix

- The finding's own verification step, from its class skill.
- `grep -rn '<sink name>' --include='*.<ext>' .` returns nothing, or every hit is
  a confirmed-safe shape.
- A regression test asserting the payload shape is treated as data.
- For the report: every fallback finding names which layer produced it and states
  whether reachability was read or inferred. If any finding in an unanalyzed
  language does not, the report is not ready.
