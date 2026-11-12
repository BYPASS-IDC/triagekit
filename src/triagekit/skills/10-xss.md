# Cross-Site Scripting (CWE-79)

## What it is

Attacker-controlled data reaches an HTML, attribute, URL, JavaScript, or CSS
parsing context in the victim's browser without the escaping that context
requires. The trust boundary crossed is the one between the application's
server-side/trusted code and the document that the server authored: the browser
trusts bytes inside a `<script>` block or an `href` value because the origin
delivered them, so injected markup executes with the privileges of the site.

## Detection

TriageKit's taint registry supplies both ends of the chain. Sources relevant to
XSS are `express-req-query`, `express-req-body`, `express-req-params`,
`browser-url-search`, `fetch-response`, and (for server-rendered apps) `input`
and `flask-request`. Sinks are whichever of these the tainted value lands in:

| Sink | Meaning | Typical shape |
| --- | --- | --- |
| `innerHTML-sink` | DOM write, HTML parsing context | `el.innerHTML = tainted` |
| `react-dangerously` | React raw HTML escape hatch | `<div dangerouslySetInnerHTML={{__html: tainted}} />` |
| `angular-bypass` | Angular sanitizer bypass | `bypassSecurityTrustHtml(tainted)` |
| `html-response` | Server writes user data into the response body | string concatenation into a rendered page |
| `response-send` | Express `res.send` / `res.write` of a built string | `res.send("<b>" + q + "</b>")` |
| `eval-sink` | String executed as code | `eval(tainted)`, `new Function(tainted)` |
| `template-render` | Server-side template output context subtlety | template that disables auto-escaping |

The sanitizer that legitimately clears XSS taint is `html-escape-js`. If taint
does not pass through it (or an equivalent context-aware encoder), the finding
stands.

The distinction that decides whether a finding is real is **which parsing
context the value lands in**. The same string is harmless in one and executable
in another:

- HTML body (`<div>TAINT</div>`): needs `<`, `>`, `&` -> `&lt;`, `&gt;`, `&amp;`.
- Quoted attribute (`<div title="TAINT">`): needs `"` and `&` escaped; the closing quote is the escape.
- Unquoted attribute: also needs spaces escaped, or the attacker just writes ` onmouseover=...` and never needs a quote at all.
- JavaScript string (`<script>var x = "TAINT";</script>`): needs `\`, `"`, and `<` (to block `</script>` early-close). HTML escaping does **not** stop this; the browser unescapes entities inside `<script>` in no case, but a `"` closes the string and `</script>` ends the block.
- URL context (`<a href="TAINT">`, `location.href = TAINT`): the sink is the URL parser, so `javascript:` and `data:` are the payload; HTML escaping does not remove them.
- CSS context (`<style>body{background:TAINT}</style>`): needs CSS escaping; payload shape is `url(...)` or an early `}` plus a declaration.

Reflected XSS (value goes request -> response in the same request), stored XSS
(value is persisted and rendered later), and DOM-based XSS (source and sink both
in the browser; `browser-url-search`/`location.hash` -> `innerHTML`) have the
same sinks but different sources: reflected uses `express-req-query`, DOM-based
uses `browser-url-search`, stored uses data that was once request data and is
now read from storage.

React/JSX specifics: JSX interpolates as text (auto-escaped), so the only
framework-native holes are `dangerouslySetInnerHTML`, `javascript:` URLs passed
to `href`, and spread attributes (`{...props}`) that can carry a dangerous prop
name. Vue specifics: `v-html` is the HTML sink; `{{ }}` interpolation and `:attr`
bindings are escaped, but `:href` is not scheme-checked. Angular specifics:
`[innerHTML]` is sanitized by default; `bypassSecurityTrustHtml/Url/Style/ResourceUrl`
turns that off, which is exactly the `angular-bypass` sink.

## How it works (attack mechanics)

Two parts must line up: the attacker controls the byte sequence, and the value
arrives in a context where those bytes are parsed as more than text.

HTML body, reflected, on a local fixture route `GET /greet?name=`:

```js
// fixture shape
app.get("/greet", (req, res) => {
  res.send("<h1>Hello " + req.query.name + "</h1>");
});
// payload sent as the query value:
// tk"><img src=x onerror=alert(1)>
```

The `"` ends the (nonexistent) attribute or text run, `>` closes the element,
and the injected tag is parsed by the HTML tokenizer, not by JavaScript string
rules. Nothing the server said prevented it because the server never escaped.

DOM-based, no server involvement:

```js
// fixture shape
const q = new URLSearchParams(location.search).get("msg");
document.getElementById("out").innerHTML = "Result: " + q;
// payload in the URL fragment/query:
// <svg onload=alert(1)>
```

Attribute context:

```html
<!-- payload for an unquoted or quote-breakable attribute -->
" onfocus=alert(1) autofocus="
<!-- payload that stays inside a quoted attribute but breaks out of a JS string later -->
x");alert(1);//
```

URL context:

```html
<!-- payload for href / location assignment -->
javascript:alert(1)
<!-- payloads that smuggle past a naive scheme check -->
JaVaScRiPt:alert(1)
java\tscript:alert(1)      (control characters are stripped by URL parsers)
&#106;avascript:alert(1)    (entity form; only decoded if the value passes through HTML)
```

The stored variant is the same payload with a persistence step (a comment, a
profile field, a filename) and the sink rendered into a page later, which is why
it is the one variant that affects users who never touch the attacker's link.

## Is it actually exploitable? (exploitability test)

1. **Is the value in an HTML-parsing context, or only in a text/URL context?**
   A value reflected into a `text/plain` response, into a JSON field consumed by
   `JSON.parse`, or assigned to `textContent` is not XSS. Check the surrounding
   bytes, not the variable.
2. **Does it cross a context-correct encoder?** `html-escape-js` (or Helmet's
   default + template auto-escaping) in HTML body context clears the finding.
   The same encoder in a URL or JS-string context does not. Ask which context
   the encoder was written for.
3. **Can the attacker control the whole value, or only part of it?** If a fixed
   prefix/suffix prevents reaching `</script>` or the closing quote, the sink is
   unreachable from input; that is a hardening note, not a vulnerability.
4. **Does the response get parsed as HTML by the browser?** Confirm
   `Content-Type` and the presence of `X-Content-Type-Options: nosniff`
   (see `skills/19-headers-and-cookies.md`). A JSON API returning
   `application/json` with user-controlled strings is not XSS.
5. **Is a CSP in place that blocks it?** A CSP without `unsafe-inline`/
   `unsafe-eval` is a real mitigation. Note it in the finding; do not delete the
   finding, because CSP is a second line of defense and bypasses exist.
6. **Is it self-XSS only?** A payload an attacker can only get into their own
   browser is a robustness bug, not a vulnerability. Report at low severity or
   not at all, and say which one you chose.

## False positives (do NOT report)

- Assignments to `element.textContent` / `innerText`, or `node.data`. The value
  is never parsed as markup.
- JSX text interpolation (`<div>{value}</div>`) and Vue `{{ value }}`. These are
  auto-escaped by the compiler. Only `dangerouslySetInnerHTML`, `v-html`, and
  `[innerHTML]` without a sanitizer are sinks.
- `href={value}` or `:href="value"` where `value` is built from constants or a
  router path, not from a query parameter or storage. No attacker-controlled
  scheme.
- Values that pass through a vetted sanitizer (DOMPurify, `bleach.clean`,
  `sanitize-html`) before reaching the sink. The sanitizer is a valid
  `html-escape-js`-equivalent on this path.
- Server templates with auto-escaping enabled (Jinja2 `{{ var }}`, EJS
  `<%= v %>`, Handlebars `{{v}}`, Django). The `template-render` sink only
  matters where auto-escaping is off (`|safe`, `<%- %>`, `{{{ }}}`, `v-html`).
- Values HTML-escaped in an HTML body context. That is the correct fix; the
  same value in a JS-string context is still a real finding, so check context
  before dismissing either way.
- Reflection that happens inside a `<script>` block but is
  `JSON.stringify`'d or `.replace(/</g,"\\u003c")`'d first: the early-close
  vector is closed.
- A JSON API returning attacker data with a correct `application/json` content
  type and `nosniff`. Not XSS; if the app also renders it, the XSS is at the
  rendering site.

## Severity

CVSS v4.0, no numeric score. Representative vectors:

- Stored, admin view, no CSP:
  `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N`
- Reflected, needs a click, single-victim:
  `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N`
- Self-XSS only (report low, or do not report):
  `CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`

Metrics that move: `UI` from `A` (must click a link) to `P` (rendered
automatically once stored); `VC`/`VI` to `H` when the session cookie lacks
`HttpOnly` (see `skills/19-headers-and-cookies.md`) or the page holds a token;
`PR` to `L` when the affected surface is admin-only; `SC`/`SI` to `H` for stored
XSS in a multi-tenant app. Always emit the vector and the calculator link:
`https://www.first.org/cvss/calculator/v4.0#CVSS:4.0/<vector>`.

## Remediation

Server-rendered, reflected, before:

```js
res.send("<h1>Hello " + req.query.name + "</h1>");
```

After (escape by context; the template engine below does it for you):

```js
app.set("view engine", "ejs");          // <%= %> escapes, <%- %> does not
res.render("greet", { name: req.query.name });
```

DOM sink, before:

```js
document.getElementById("out").innerHTML = "Result: " + msg;
window.location.href = nextFromQuery;
```

After:

```js
document.getElementById("out").textContent = "Result: " + msg;
// scheme-check anything used as a URL
const dest = new URL(nextFromQuery, location.origin);
window.location.href =
  dest.origin === location.origin ? dest.pathname + dest.search : "/";
```

React, before:

```jsx
<div dangerouslySetInnerHTML={{ __html: comment.body }} />
<a href={userProvided}>profile</a>
```

After:

```jsx
<div>{comment.body}</div>                       // auto-escaped text
<a href={safePath}>profile</a>                  // safePath: sanitized, same-origin
```

Vue, before:

```html
<div v-html="comment.body"></div>
<a :href="userProvided">profile</a>
```

After:

```html
<div>{{ comment.body }}</div>
<a :href="safePath">profile</a>
```

Angular, before:

```ts
this.html = this.sanitizer.bypassSecurityTrustHtml(userHtml);
```

After: remove the bypass and let Angular's built-in sanitizer run; if you must
allow rich HTML, sanitize with a library first and bind the result, and never
`bypassSecurityTrustUrl` on a value that began as a query parameter.

Python (Flask) equivalent, before:

```python
return "<h1>Hello " + request.args.get("name", "") + "</h1>"
```

After:

```python
# Jinja2 auto-escapes in templates; never use |safe on request data
return render_template("greet.html", name=request.args.get("name", ""))
```

If a raw HTML sink is genuinely required, run the value through
`html.escape(value, quote=True)` (HTML body context) or a sanitizer, and only
then assign it into `innerHTML`.

## Verify the fix

1. Send the fixture payload and confirm the encoded form in the response:
   `curl -s "http://localhost:PORT/greet?name=tk%3E%3Cimg%20src%3Dx%3E" | grep -F 'tk&gt;&lt;img'`
   A grep that still matches `tk><img` means the sink is untouched.
2. Grep the shipped diff for raw sinks and confirm none of them receive request
   data: `rg -n "innerHTML|dangerouslySetInnerHTML|v-html|document\.write|eval\(" src/`
3. Add one regression test per sink that asserts the encoded output, for example
   `assert "&lt;img" in resp.text and "<img" not in resp.text`.
4. In the browser, confirm the payload renders as visible text and that the DOM
   inspector shows a text node, not an element.
5. Re-check `skills/19-headers-and-cookies.md`: the CSP present after the fix
   should be reported alongside the finding so a reviewer can see the second
   line of defense.
