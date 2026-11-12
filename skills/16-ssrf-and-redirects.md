# Server-Side Request Forgery and Open Redirect (CWE-918, CWE-601)

## What it is

SSRF: the application accepts a URL (or host) from the caller and fetches it,
so attacker-controlled input controls the destination of a request that the
server makes. CWE-601: the application sends the client to a
Location/redirect target derived from input, so the attacker controls where the
victim's browser goes. The trust boundary crossed in SSRF is the network
boundary between the public application and internal services (cloud metadata,
databases, admin panels); in an open redirect it is the boundary between the
legitimate host and an attacker-chosen origin.

## Detection

CWE-918. The source chain is the standard request-expression family; the sink
is the request-issuing node:

| File shape | Node |
| --- | --- |
| `requests.get(string-concat)`, `urllib.request.urlopen(url)` with request data | `ssrf-http-request` |
| `fetch(url)` / `axios.get(url)` where `url` contains `req.query`/`req.body` | `ssrf-http-request` |
| Jinja2 `render_template_string(user_input)` | `template-render` (SSTI reached by the same `q`/`path` parameter family) |

The detection heuristic is "look for a request-issuing call whose argument or
its base contains any member access on `req.query`, `req.body`, `req.params`,
`request.args`, `request.form`, or `request.values` that is not dominated by an
allowlist check on a list of hostnames or on the URL scheme". Concrete
node types: `requests.get`, `requests.post`, `requests.request`,
`urllib.request.urlopen`, `httpx.get/post`, `http.get`, `https.get`,
`axios.get/post`, `fetch`, and `res.redirect` / `http.request` with a
tainted path. Pay attention to the *string* forms: `req.query.url`,
`req.body.target`, `req.query.host`, `req.query.callback`,
`req.query.path`, `req.query.domain`, `req.query.file`.

The web scanner additionally probes `?redirect=`, `?next=`, `?url=`,
`?return=`, `?goto=`, `?callback=` on the live target and reports
`CWE-601` when the response's `Location` header reflects the canary value.

CWE-601. Detection is "an HTTP redirect response (301/302/303/307/308) or a
server-side call that sets `Location`, whose argument derives from request
input". Shapes:

```js
// redirect to a parameter: open redirect
app.get("/go", (req, res) => {
  res.redirect(req.query.next);          // -> node name: redirect-express
});
```

```js
// response writes a Location header manually
res.setHeader("Location", req.headers.referer || "/");
```

```python
# Flask/Django
return redirect(request.args.get("next", "/"))
```

```js
// client-side navigation from a URL parameter
window.location.href = new URLSearchParams(location.search).get("returnTo");
```

The sink node names in TriageKit for this class are `redirect-express` (Express
`res.redirect` with a tainted argument) and, when the handler writes the
Location header or body directly instead of calling `res.redirect`,
`response-send` (a built response string) or `html-response` (a redirect page
rendered from input). Client-side navigation from `browser-url-search` into
`window.location` has no dedicated sink node today: it surfaces as a
`browser-url-search` source with no sanitizer and must be judged by hand using
the same allowlist test. A `res.redirect("/support")` with a literal is not a
sink; the same call with `req.query.next` is.

In both cases, note whether the request goes through the `html-escape-js`
sanitizer, which is **not** a URL validator and does not clear SSRF or redirect
findings. Only a scheme+host allowlist clears these.

## How it works (attack mechanics)

SSRF. The attacker does not control the code; they control the *string* that
the code fetches. Three sub-cases matter operationally.

(a) Plain internal fetch. The app is a webhook previewer, image proxier, or
PDF/thumbnail service:

```text
POST /preview  {"url": "http://169.254.169.254/openstack/latest/meta_data.json"}
```

The server performs the request from inside the VPC, so the cloud instance
metadata endpoint is reachable and the response body is rendered into the
output. The payload shape is simply a URL whose host resolves to a
non-routable address or a link-local metadata address.

(b) Protocol and parser confusion. Even with an allowlist check on the
*string*, the URL parser and the HTTP client disagree:

```text
http://expected-host@169.254.169.254/          userinfo confusion
http://169.254.169.254%2523@expected-host/     percent-encoded fragment: the
                                               server and the checker disagree
                                               on where the host ends
http://[::ffff:169.254.169.254]/               IPv4-mapped IPv6 form
http://2130706433/                              decimal-encoded 127.0.0.1
http://0x7f000001/                              hex-encoded
http://localtest.me/                            DNS name that resolves to 127.0.0.1
```

(c) Redirect chaining. The allowlist check passes on the initial URL, the
client follows the redirect, and the `Location` from the internal host points
at the metadata service or another internal port. Any SSRF fix must therefore
disable or re-validate redirects, not just validate the first URL.

Open redirect. The attacker needs a page the victim trusts that hands off
navigation to an arbitrary URL:

```text
GET /go?next=https://attacker.example/login HTTP/1.1
HTTP/1.1 302 Found
Location: https://attacker.example/login
```

The victim arrived from a link on the real host, sees the login page hosted by
the attacker, and types credentials. The variant with a `data:` or
`javascript:` scheme is the same bug class but executes immediately in the
origin's context, which is CWE-79.

## Is it actually exploitable? (exploitability test)

1. **Does the value actually control the destination?** If the host is pinned
   (`"https://api.internal/" + req.query.path`) and the path cannot escape the
   base (no leading `..`, and the fetch client does not normalize a scheme into
   the path), the finding is a hardening note. If the whole URL is
   attacker-controlled, it is a finding.
2. **Is there a scheme check?** Without one, `file://`, `gopher://`, `ftp://`,
   and `dict://` are all reachable and turn the bug into a read primitive or a
   protocol-smuggling primitive. Check for `http:`/`https:` enforced *after*
   parsing, not by substring on the raw string.
3. **Is there a host allowlist, and is it enforced on the resolved IP?** A
   string allowlist is bypassed by userinfo (`@`), percent-encoded paths, IPv6
   forms, and decimal/hex encodings. The test that matters is whether the code
   resolves the host and checks the IP before the connection, or only compares
   the hostname string.
4. **Does the client follow redirects?** If yes, a validated initial URL is not
   enough; re-validation is required per hop.
5. **For CWE-601: is the target open to arbitrary hosts, or restricted to a
   known set of marketing paths?** A redirect list built from a lookup table
   (`{"home": "/", "billing": "/billing"}`) is not a vulnerability. A
   `res.redirect(req.query.next)` with no check is.
6. **Is it self-redirect only?** If the parameter can only be set by an
   authenticated user for their own session and the app validates the target,
   report at low severity. If a victim can be lured into clicking a link on the
   real site, it is high.

## False positives (do NOT report)

- Requests with a hardcoded URL, or with a URL built only from a literal base
  plus a path segment that the code constrains (e.g. `urljoin(BASE, "v1/" +
  str(id))` where `id` is an integer validated upstream).
- A host allowlist implemented as a resolved-IP check with redirect following
  disabled. That is the correct control, not the bug.
- An open redirect to a same-origin path only (`/login?next=/dashboard` where
  `next` must start with `/` and not `//`), or to a lookup-table key. Only a
  redirect that can reach another origin is a finding.
- `res.redirect("/")` and other literal redirects.
- `Referer`-based redirects where the referrer is only used to bounce back to
  the same origin, and the code checks origin equality before redirecting.
- Internal-only endpoints: a service that receives a URL from another service
  on a trusted network, with no path from user input to that parameter. Say so
  explicitly and report nothing.
- A URL passed to `new URL(value, base)` only to be re-derived and normalized
  into a fixed-origin fetch (path join). That is canonicalization, not SSRF.
- Callbacks/webhooks where the destination is registered by an admin at
  configuration time, not by the requesting user.

## Severity

No numeric score. Representative CVSS v4.0 vectors:

- SSRF, internet-facing app, cloud metadata reachable, no auth on the
  vulnerable endpoint:
  `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- SSRF restricted to internal network reconnaissance, authenticated app:
  `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`
- Open redirect used for credential phishing:
  `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`

Metrics that move: `PR` rises to `H` when the endpoint requires admin; `VC`
rises to `H` when the metadata response is returned to the caller (which is a
credential leak, and then see `skills/13-secrets-and-tokens.md`); `UI` for
CWE-601 is almost always `A` because a victim must follow a link. Emit the
vector plus `https://www.first.org/cvss/calculator/v4.0#CVSS:4.0/<vector>`.

## Remediation

SSRF, before:

```js
const url = req.query.url;                       // e.g. ?url=http://169.254.169.254/
const resp = await fetch(url);
res.send(await resp.text());
```

After (parse, enforce scheme, resolve, check the IP range, no auto-redirect):

```js
const ALLOWED_HOSTS = new Set(["api.example.com"]);
const u = new URL(req.query.url);
if (u.protocol !== "https:") return res.status(400).send("bad scheme");
if (!ALLOWED_HOSTS.has(u.hostname)) return res.status(400).send("bad host");
const resp = await fetch(u, { redirect: "manual" });   // never auto-follow
res.send(await resp.text());
```

For an IP-level guard, resolve the hostname and reject RFC1918, loopback,
link-local, and IPv4-mapped addresses before connecting:

```js
const dns = require("node:dns").promises;
const { address } = (await dns.lookup(u.hostname, { all: true }))[0];
const bad = (a) =>
  /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|0\.|::1$|^f)/i
    .test(a);
if (bad(address)) return res.status(400).send("bad ip");
```

Python (requests), before:

```python
target = request.args["url"]
r = requests.get(target)              # follows redirects by default
return r.text
```

After:

```python
from urllib.parse import urlparse
import ipaddress, socket

target = request.args["url"]
u = urlparse(target)
if u.scheme not in ("http", "https"):
    abort(400)
ip = ipaddress.ip_address(socket.gethostbyname(u.hostname))
if ip.is_private or ip.is_loopback or ip.is_link_local:
    abort(400)
r = requests.get(target, allow_redirects=False)
return r.text
```

Open redirect, before:

```js
app.get("/go", (req, res) => res.redirect(req.query.next));
```

After:

```js
const ALLOWED = new Set(["/login", "/dashboard", "/support"]);
app.get("/go", (req, res) => {
  const next = req.query.next;
  res.redirect(ALLOWED.has(next) ? next : "/");
});
```

Python:

```python
from urllib.parse import urlparse

def safe_next(raw, default="/"):
    if not raw:
        return default
    u = urlparse(raw)
    # only same-origin relative paths; blocks "//evil.com" and "https://evil.com"
    if u.scheme or u.netloc or not raw.startswith("/") or raw.startswith("//"):
        return default
    return raw

return redirect(safe_next(request.args.get("next")))
```

## Verify the fix

1. Send the internal-target payload shape against the deployed code and confirm
   a 400 and an unchanged outbound request log:
   `curl -s -o /dev/null -w "%{http_code}\n" -X POST localhost:PORT/preview -d '{"url":"http://169.254.169.254/"}'`
   Expect `400`. A `200` with a body means the guard is not applied.
2. Confirm the parser-confusion payloads also 400: the `@` userinfo form, the
   decimal IP, the IPv6-mapped form, and a redirecting local URL. Any one of
   these returning 200 means the check is string-based.
3. For redirects, verify `allow_redirects=False` / `redirect: "manual"` is in
   the diff, not just an earlier allowlist.
4. For CWE-601, confirm the only accepted `?next` values are the allowlisted
   set: `for p in "https://evil.example" "//evil.example" "/%2fevil.example"; do curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" "localhost:PORT/go?next=$p"; done`
   All must answer `302 http://localhost:PORT/` (or the configured default).
5. Grep the fix for `res.redirect`, `location.href`, and `urlopen`/`fetch` with
   a variable argument; each hit must be dominated by an allowlist assertion in
   the same function.
