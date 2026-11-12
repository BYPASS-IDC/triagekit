# Web adviser (reading a web scan as a deployment, not a codebase)

## What it is

A web scan is a different kind of evidence from a repo scan. There is no source
to trace; there are responses, headers, cookies, and fetched scripts. This skill
is how to read that evidence, and -- more importantly -- how to know what the
web scanner did **not** check.

The trust boundary here is between "the server said so" and "the server is so".
A response header, a banner, and a path that returns 200 are all claims by the
deployment, and each can be stale, misleading, or shared infrastructure.

## Procedure

### 1. Confirm the mode first

The web adviser is **read-only by default** and can escalate. Read
`skills/01-authorized-use.md` before running it: a payload placed in a query
string is active probing even though it is a GET, and `--no-paths` only removes
sensitive-path *checks*, not any payloaded probe the tool performs.

    triagekit webscan <url> --json           # read-only posture
    triagekit webscan <url> --no-paths       # skip sensitive path checks
    triagekit webscan <url> --no-agent       # skip the AI brief

### 2. What the scan actually collects

Verified from `src/triagekit/core/analyzers/web_scan.py`:

- **Transport and edge posture** -- HTTPS/HSTS, cookie attributes, CORS
  (`Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials`), and the
  security header set.
- **Cookie parsing** -- `_parse_set_cookie_headers` / `_parse_set_cookie` read
  the flags (`HttpOnly`, `Secure`, `SameSite`, `Path`, `Domain`) off real
  `Set-Cookie` headers. A flag that is absent from the header is a finding; a
  flag the tool did not see is `NOT_ASSESSED`.
- **Fingerprints** -- `_fingerprint(headers, body, paths)` derives technology
  guesses from those three inputs. These are *guesses*. A `X-Powered-By` and a
  body substring are weak evidence, and a framework name can be inherited from
  shared infrastructure, a CDN, or a template.
- **Client-side analysis** -- referenced JS files are fetched (bounded by
  `max_js_files`, default 20, configurable 1-100) and inline scripts are
  analyzed by `_analyze_js`, which also harvests **API/URL hints**: string
  candidates beginning with `/`, `http`, or `ws`, truncated to 300 characters,
  deduplicated, capped at 100 in the result.
- **Host recon** -- `_recon_host(host)` performs host-level checks.
- **Sensitive paths** -- probed unless `--no-paths`.

### 3. Read it in this order

1. **Cookie flags.** A `Set-Cookie` with `HttpOnly` missing or `Secure` missing
   on an HTTPS origin is a concrete finding with a one-line fix.
2. **CORS.** The dangerous shape is a *reflected* origin paired with
   `Access-Control-Allow-Credentials: true`, not the literal `*`. See
   `skills/20-api-and-graphql.md`.
3. **Transport.** Plain HTTP reachable, HSTS absent or short `max-age`, a mixed
   active resource.
4. **Headers.** CSP, `X-Content-Type-Options`, `Referrer-Policy`,
   `X-Frame-Options`. Absence is a hardening finding, not an exploitable one --
   say which.
5. **API hints.** Use them as a *test list*, never as a finding. A hint is a
   string in a bundle; it is a place to look, not a vulnerability.
6. **Fingerprints.** Use them to choose which class skills to apply -- not as
   findings. A wrong fingerprint sends the whole report in the wrong direction.

## How it works (attack mechanics)

Three mechanics, each needing a different prerequisite:

- **Cookie theft.** Without `HttpOnly`, JavaScript on the origin reads the
  session cookie. That requires script execution on the origin -- usually XSS.
  So a missing `HttpOnly` is a *severity amplifier* for an XSS finding, and a
  weak standalone finding. Report it as amplification.
- **Cross-origin read.** A reflected origin with `ACAC: true` lets any page hold
  a credentialed request and read the response. Requires the victim to visit a
  page the attacker controls, so `UI:A`.
- **Info disclosure.** Verbose error bodies, a `Server`/`X-Powered-By` banner, a
  stack trace, `.git/` or a backup file reachable. Low impact alone; it hands the
  attacker the version string that turns a generic CVE into a targeted one.

## Is it actually exploitable?

1. **Is the finding about *this* application or its edge?** A CDN, WAF, or
   shared host injects headers the app never set. Confirm the origin direct if
   the finding depends on it.
2. **Does the reflected-origin CORS matter?** If the API authenticates with a
   bearer token held in JavaScript rather than a cookie the browser attaches,
   there is no ambient credential to ride -- report hygiene, not a live
   cross-origin read.
3. **Is the JS actually served from this origin?** `_analyze_js` skips off-host
   scripts (`_same_host`). A finding in a third-party bundle is that vendor's
   bug, not this app's.
4. **Does the sensitive path return the real thing?** A 200 on `/backup.sql`
   that is a login page is not a disclosure; a 200 that serves bytes is.
5. **Are the JS findings deduplicated and bounded?** Only the first
   `max_js_files` referenced scripts were fetched. A large bundle list means the
   coverage is partial -- that is a coverage limit, not a clean bill.

## False positives (do NOT report)

- **A fingerprint with no corroboration.** A `Server: nginx` and the word
  "WordPress" in a body substring is not a WordPress install.
- **A framework banner on shared hosting or a CDN.** Inherited, not chosen.
- **`Access-Control-Allow-Origin: *` with no credentials.** Browsers reject that
  pair, so it is a hygiene fix, not a live cross-origin read.
- **A static origin allowlist.** `cors({origin: ["https://app.example"]})` is the
  fix, already applied.
- **A security header missing on a non-document endpoint.** CSP on an API
  returning JSON is not meaningful.
- **An API hint.** A hint is a place to look.
- **A JS bundle on a third-party CDN.** Not this app's code.
- **A cookie without `Secure` on a plain-HTTP-only origin.** The flag would do
  nothing; report the HTTP reachability instead.
- **A sensitive path that returns 200 with a login redirect.**

## Severity

Read-only info disclosure from a verbose banner or a reachable path:

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N
https://www.first.org/cvss/calculator/4.0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N
```

`VC:L`, not `H` -- a version string is not the database. A reflected-origin CORS
with credentials is
`AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` because the victim must
visit an attacker-controlled page. Missing `HttpOnly` on its own is
`AV:N/AC:H/AT:P/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` -- it requires an XSS to
be worth anything, so it is amplification, not a standalone finding. Never
hand-compute the number.

## Remediation

    # before                                    # after
    Set-Cookie: session=...                     Set-Cookie: session=...; HttpOnly; Secure; SameSite=Lax
    Access-Control-Allow-Origin: *              Access-Control-Allow-Origin: https://app.example
    (no header)                                 Strict-Transport-Security: max-age=31536000; includeSubDomains
    (no header)                                 Content-Security-Policy: default-src 'self'; object-src 'none'
    res.setHeader("ACAO", req.headers.origin)   const ACAO = ALLOWED.has(req.headers.origin)
                                               ? req.headers.origin : null

Header fixes are deployment fixes: name the file (the framework's middleware
config, the reverse proxy config, the CDN rule set), not just the header. A
finding that says "add HSTS" without saying where is a note.

## Verify the fix

    curl -sI https://fixture.example/ | grep -iE 'strict-transport|content-security|x-content-type'
    curl -sI https://fixture.example/ | grep -i 'set-cookie'      # assert HttpOnly, Secure, SameSite
    curl -sI -H 'Origin: https://attacker.example' https://fixture.example/ | grep -i 'access-control'

Re-run the same command with the same flags and confirm the header set changed
and the JS finding count did not grow. If `max_js_files` was raised and new
scripts were fetched, new findings appearing is the scan working.
