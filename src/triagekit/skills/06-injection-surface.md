# Injection surface (sources, sinks, and the flows between)

## What it is

An injection is not a code pattern. It is a flow: data that an attacker controls
reaches a construct that interprets part of its input as instructions. This
skill is the map of both ends -- the sources TriageKit recognizes, the sinks it
recognizes, and the sanitizers that break the flow in between.

The trust boundary crossed is between "data" and "code". A string passed through
a query parser, a shell, a template compiler, an XML parser, or a regex engine
stops being a string and becomes instructions. That crossing is the whole
vulnerability class.

## The two ends

A finding requires BOTH. A source with no sink is a note. A sink with no source
is not reportable. TriageKit's registry names them by pattern, so a finding can
be traced by name.

### Sources (attacker-controlled input)

| Registry name | Category | What it matches |
| --- | --- | --- |
| `http-request-get` | http-request | `request.(GET\|args\|query_params\|query)[` |
| `http-request-post` | http-request | `request.(POST\|form\|data\|json\|body)[` |
| `http-request-cookies` | http-request | `request.cookies[` |
| `http-request-headers` | http-request | `request.headers[` |
| `django-request` | http-request | `request.(GET\|POST\|REQUEST\|FILES)[` |
| `flask-request` | http-request | `request.(values\|args\|form\|json\|files\|data)` |
| `flask-request-methods` | http-request | `request.(get_data\|get_json\|read\|stream)(` |
| `fastapi-request` | http-request | `(query_params\|path_params\|form_data\|body\|cookies\|headers)[` |
| `stdlib-input` | user-input | `input(` |
| `sys-argv` | user-input | `sys.argv[` |
| `os-environ` | environment | `os.environ[` or `os.getenv(` |
| `file-read` | file | `open(` / `read(` / `readline(` / `readlines(` |
| `sqlite-fetch`, `psycopg2-fetch`, `sqlalchemy-result` | database | cursor/result fetch calls |
| `redis-get` | database | `redis.(get\|mget\|hget\|hgetall\|lrange)(` |
| `requests-response` | http-response | `.json(`, `.text`, `.content` |
| `subprocess-output` | process-output | captured process output |

Environment and file sources are attacker-controlled in a different way than
HTTP ones, and the difference changes the vector: `os.environ` requires the
attacker to already influence the process environment, which usually means a
prerequisite (AT:P), not an open network path (AV:N).

### Sinks (constructs that interpret input)

| Registry name | Category |
| --- | --- |
| `sql-execute`, `sql-format`, `sql-concat`, `sql-template`, `sqlite3-execute`, `psycopg2-execute`, `sqlalchemy-execute`, `django-raw-sql`, `mongoose-query` | sql-execution |
| `command-execution`, `shell-command`, `os-popen`, `child-process` | command-execution |
| `eval-function`, `eval-exec-sink`, `eval-sink` | code-execution |
| `html-response`, `response-send`, `innerHTML-sink`, `react-dangerously`, `vue-v-html`, `angular-bypass` | xss |
| `template-render` | template-injection |
| `path-traversal`, `path-traversal-fs`, `archive-extract` | path-traversal |
| `redirect`, `redirect-express` | open-redirect |
| `ssrf-http-request`, `ssrf-request-object` | ssrf |
| `xxe-parse` | xxe |
| `pickle-load-sink`, `yaml-load-sink` | deserialization |
| `weak-hash` | weak-cryptography |
| `log-injection` | log-injection |
| `ldap-query` | ldap-injection |
| `xpath-query` | xpath-injection |
| `regex-dos` | regex-dos |

The Python analyzer is AST-based (`src/triagekit/core/taint/analyzer.py`); it
follows assignments, calls, and returns through the tree. The JS/TS analyzer is
regex-based (`src/triagekit/core/taint/js_analyzer.py`); it extracts function
shapes and reasons line-by-line, so it is weaker on cross-line flows. Treat a JS
finding as a lead to confirm, and an absence of JS findings as absence of
evidence, not evidence of absence -- see `skills/24-javascript-security.md`.

## How it works (attack mechanics)

Take SQL as the shape. The attacker controls `email` because
`request.args.get("email")` reads it. The sink is
`cursor.execute("... WHERE email = '" + email + "'")`. The concatenation puts
attacker bytes inside the SQL grammar, so a single quote ends the literal and
the rest is parsed as SQL. The payload shape is
`' OR '1'='1` -- one line that proves the grammar boundary was crossed.

The same shape repeats per sink type: the payload is whatever the sink's grammar
treats as syntax. Shell: `;`, `|`, `` ` ``, `$( )`. Template: `{{ }}`. Path:
`../`. Regex: a catastrophic backtrack. The specific payload never matters as
much as whether the attacker's byte can reach the grammar at all.

## Is it actually exploitable?

1. **Does the source expression really evaluate?** A pattern hit inside a
   comment, a docstring used as documentation, or dead code is not a source.
2. **Does every step of the path carry the data?** An assignment the path names
   must be on the executed route. The AST analyzer's path is usually right; the
   regex analyzer's is a hint.
3. **Is there a sanitizer in the chain?** See below -- the chain, not the last
   call, decides.
4. **What is the attacker's position?** Unauthenticated network access is
   AV:N; a value that came from `os.environ` is not.

## The sanitizers that actually break a flow

A sanitizer must match the sink's grammar. Escaping for a different grammar is
not a sanitizer. Strong sanitizers in the registry:

| Registry name | Breaks |
| --- | --- |
| `sql-parameterize`, `parameterized-query`, `sqlalchemy-orm`, `sequelize-orm`, `knex-parameterize`, `django-orm` | sql-execution |
| `html-escape`, `html-escape-js`, `jinja2-autoescape`, `react-autoescape`, `django-template-autoescape` | xss |
| `path-normalize`, `path-basename`, `path-join-safe` | path-traversal |
| `subprocess-argv`, `shlex-quote` | command-execution |
| `yaml-safe-load`, `json-loads-safe` | deserialization |
| `url-validate` | open-redirect, ssrf |
| `regex-escape` | regex-dos |

Three semantics to hold onto:

1. **The chain, not the last call.** A state carries `sanitizer_chain`, because
   nesting `A(B(x))` with two sanitizers loses one if you keep only a single
   field. A flow is neutralized when a chain entry neutralizes, judged over the
   whole chain.
2. **`os.path.basename` is a strong sanitizer for path traversal** and is
   registered as such. `os.path.join(BASE, os.path.basename(user_input))` does
   not traverse. Joining the raw value does.
3. **An allowlist-guarded ternary is a guard, not a gap.**
   `dest if dest in ALLOWED else DEFAULT` is recognized: a single `In`
   comparison whose guard variable matches the body variable, against a literal
   collection or a named allowlist. That pattern does not open-redirect.
   Inverting it (`if dest not in ALLOWED: ...`) does not get this treatment.

Two more exemptions to respect:

- **An argv list without `shell=True` does not command-inject.**
  `subprocess.run(["ls", user_input])` passes one argument; there is no shell to
  inject into. The exemption requires a non-empty list/tuple literal as the
  first argument, no constant taint in the first element, and no `shell=True`.
  Adding `shell=True` to the same call removes the exemption -- correctly.
- **A constant-composed query has no source.**

## False positives (do NOT report)

- **The test suite.** `'; DROP TABLE users; --` in `tests/test_sqli.py` is the
  test for the fix.
- **A sanitizer applied to the wrong variable.** Confirm the sanitizer output is
  what reaches the sink, not a sibling variable.
- **A parameterized query.** Already safe.
- **`subprocess.run([...])` with a literal argv and no `shell=True`.** Exempt.
- **`os.path.join(BASE, os.path.basename(p))`.** Sanitized.
- **A ternary open-redirect guarded by a real allowlist.** Guarded.
- **A sink in dead code or a fixture.** Note it, do not report it.
- **A generic `execute(` name match with no SQL grammar.** The sink names above
  are the reportable set; a user-defined `execute()` is not one.

## Severity

Derive the vector from what the trigger proves:

| Class | Typical vector |
| --- | --- |
| SQLi, unauthenticated, table read | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| Command injection, authenticated user | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |
| Reflected XSS | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N` |
| SSRF, internal network reach | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:H/SI:N/SA:N` |

Give the vector and the calculator link
(`https://www.first.org/cvss/calculator/4.0#<vector>`); never a computed number,
and never all-High because "it's serious" -- each of VC/VI/VA/SC/SI/SA needs its
own justification.

## Remediation

Remove the grammar crossing at the sink, not at the source. Parameterize rather
than escape; pass argv as a list rather than quoting; autoescape rather than
filtering; `basename` + allowlist rather than blacklisting `..`. See the
per-class skill for exact code: `skills/09-sql-injection.md`,
`skills/10-xss.md`, `skills/11-command-injection.md`,
`skills/12-path-traversal.md`, `skills/16-ssrf-and-redirects.md`,
`skills/17-deserialization.md`.

## Verify the fix

For each class: add a regression test that sends the payload shape and asserts
the safe behaviour (zero rows, one argument, escaped output, no traversal), then
grep that the vulnerable form no longer appears in the file. A WAF rule in front
of an unsanitized sink is mitigation with a bypass, not a fix -- do not accept it
as one.
