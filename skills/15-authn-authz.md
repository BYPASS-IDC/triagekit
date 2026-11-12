# Authentication and access control (CWE-287 / CWE-284)

## What it is

**Authentication** is proving who you are. **Authorization** is deciding what
that identity may do. They fail in different ways and the distinction matters in
a report: a broken login lets the wrong person in, and broken access control lets
the right person do the wrong thing.

The trust boundary crossed is between "this identity was checked" and "this
action was permitted". In source, that boundary is almost always an `if` -- and
almost every finding in this class is an `if` that is missing, inverted, or
checking the wrong thing.

## Detection

### Authentication defects

| Look for | Problem |
| --- | --- |
| `if password == stored:` | Plaintext comparison; timing-observable; no hash |
| `if user_input == "admin123":` | Credential in source |
| A `login` route that never touches a session or token library | No real auth |
| `session['user'] = True` set before validation | Trust established without proof |
| A decorator that only logs, `@require_login` defined as `pass` | Declared control, no control |
| `jwt.decode(token, verify=False)` | Signature not verified |
| `jwt.decode(token, algorithms=["none"])` | Algorithm confusion |
| A comparison `==` on a token where the library offers `compare_digest` | Timing oracle |
| No rate limit or lockout on a login endpoint | Online brute force |
| Password recovery that returns the token in the response body | Recovery bypass |

### Authorization defects

| Look for | Problem |
| --- | --- |
| An object fetched by id with no ownership check (IDOR) | `note = Note.query.get(note_id)` where `note_id` came from the request |
| A route with no decorator where sibling routes have one | The missing decorator is the finding |
| `if user:` or `if request.user is not None` for an admin check | Authenticated, not authorized |
| A role check on a string rather than a set | `role == "admin"` matches `"administrator"`; `role in "admin"` matches `"admi"` |
| Horizontal escalation: `/users/<id>/profile` with no `id == current_user.id` | Any user reads any user |
| A hidden field or client-supplied `is_admin` / `role` | Mass assignment; client sets privilege |
| A UUID used as the only access control for a predictable enumeration target | Obfuscation, not authorization |
| `@csrf_exempt` on a state-changing route | CSRF protection removed |

### The membership bug that survived review

    ADMIN_ROLES = "admin"          # a string, not a collection
    if role in ADMIN_ROLES:        # True for role == "a", "d", "m", "i", "n", "ad", "dm"...

and the loosened comparison:

    # before                        # after (a regression, not a refactor)
    if path.startswith(BASE):       if BASE in path:

Both are authorization bugs that look like cleanups. See `skills/02-pr-triage.md`.

## How it works (attack mechanics)

For an IDOR the attack is one request with a changed identifier:

    GET /api/notes/1042          # the attacker's own note -- 200 OK
    GET /api/notes/1043          # someone else's note -- also 200 OK

There is no payload. The attack is the increment. That is what makes this class
so common and so invisible: the vulnerable request is byte-for-byte the same
shape as a legitimate one.

For authentication, the mechanic depends on the defect: a timing oracle leaks a
prefix match bit by bit, an unverified JWT lets the attacker forge their own
token with `alg: none`, and a missing rate limit makes brute force a throughput
question rather than a feasibility one.

## Is it actually exploitable?

1. **Is the identity actually unproven, or just unusually proven?** A weak hash
   on an internal admin console is a different finding from a public login.
2. **Can the attacker reach the unchecked path without another credential?**
   Test by removing your own session and repeating the request; if it still
   succeeds, the check was decorative.
3. **Does the object reference come from the client?** If the id is server-derived
   (from the session, a scoped query joined on the current user), it is not an
   IDOR.
4. **Is there an authorization check somewhere else in the stack?** A middleware
   that already scopes every query by tenant makes a per-route check redundant --
   but confirm the middleware actually covers this route, and that the route is
   not `@csrf_exempt` or in a blueprint that bypasses it.

## False positives (do NOT report)

- **A framework's own auth decorator, correctly used.** `@login_required`,
  `@jwt_required()`, `[Authorize]`.
- **A check performed in middleware or a base class.** Confirm it runs before
  reporting a missing per-route check.
- **An internal endpoint with network-level access control.** Note it, with the
  assumption stated, if the control is a firewall rule rather than code.
- **A public endpoint by design.** `/health`, `/login`, `/register`,
  `/password/forgot` are meant to be unauthenticated.
- **A role string compared with `==` where the set of roles is closed and the
  value is server-derived.** Note it as brittle, not as a finding.
- **An admin console documented as internal.** Say the assumption explicitly
  rather than reporting it as an unauthenticated finding.

A missing-check finding asserted against a route that a middleware already
protects is the fastest way to lose a team's trust, because the maintainer knows
in one glance that you did not read the stack.

## Severity

Unauthenticated horizontal access to other users' records:

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
https://www.first.org/cvss/calculator/4.0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
```

If the same defect also permits writes, VI:H as well -- the two must be justified
separately, not defaulted to High because the finding feels serious. A
horizontal privilege escalation that requires an authenticated session moves
`PR:N` to `PR:L`. Never compute the number by hand.

## Remediation

    # before -- IDOR                            # after -- scoped fetch
    note = Note.query.get(note_id)              note = Note.query.filter_by(
        return serialize(note)                          id=note_id,
                                                          owner=current_user.id
                                                     ).first_or_404()

    # before -- client-set privilege            # after -- server-set privilege
    user = User(**request.json)                 user = User(**request.json)
                                                   del user.role
                                                   user.role = "member"

    # before -- string membership               # after -- a real collection
    if role in ADMIN_ROLES:                     if role in {"admin", "owner"}:

General rules that hold across languages: authorize on the server, against the
object, every time -- not once at login and not in the client. Deny by default:
an unrecognized role gets no access rather than a fallback. Use the framework's
authorization primitive rather than a hand-written `if`, so the check lives in
one auditable place.

## Verify the fix

- A test that, as user A, requests user B's object id and asserts 403 or 404 --
  not 200 with a different body.
- A test that, with no session, repeats the same request and asserts 401.
- A test that posts `{"role": "admin"}` to the create/update endpoint and asserts
  the stored role is unchanged.
- `grep -rn 'csrf_exempt' --include='*.py' .` returning nothing on
  state-changing routes.
- A test that enumerates the whole route table and asserts every route except an
  explicit public allowlist has an authorization check. This is the only check
  that catches the missing decorator, because nothing else reads the route table.
