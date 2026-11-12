# PR triage (reading a diff as an attacker)

## What it is

A pull request is the highest-signal security artifact a repository produces.
It is a small, deliberate, human-generated change, made with intent, by someone
who will read your comment. This skill is how to read that change the way an
attacker would, and how to write a comment the author will act on.

The trust boundary in a PR is between what the change claims to do and what it
actually does. A refactor that "just cleans up" a query can be the one line
that removes a parameter binding.

## Procedure

### 1. Read the diff twice, in two passes

**Pass 1 -- changes only.** Ignore the intent stated in the description. What
lines were added, removed, or moved?

**Pass 2 -- as an attacker.** For every changed line, ask: does this line make
attacker-controlled data reach something that acts on it?

Only pass 2 produces findings. Pass 1 is calibration, so you know the size of
the change you are reasoning about.

### 2. Classify each changed line

| Line kind | Signal |
| --- | --- |
| New **source** (reads request/user/env input) | High -- feeds everything else |
| New **sink** (query, shell, file, template, response) | High -- must trace what feeds it |
| New **sanitizer** (escape/bind/validate/allowlist) | High, but in the *good* direction -- check it covers the right sink |
| Removed **sanitizer** | Highest -- this is the regression that ships |
| Removed **authorization check** | Highest -- a deleted `if not is_admin:` is a finding |
| New **dependency** | High -- a new CVE surface, see `skills/18-dependency-cve.md` |
| **Loosened comparison** (`==` -> `in`, added `or`, widened a type) | Medium-high |
| Comments, formatting, renames | None -- unless the rename hides a source |

A PR that adds a source and a sink together in the same hunk is the single most
common shape of a real vulnerability reaching `main`.

### 3. Trace, do not grep

The question is not "does this file contain `execute(`". It is "can the value
added in line 40 of this hunk reach the `execute(` at line 12 of the file it
now calls?" Follow the data:

    hunk +12:  email = request.args.get("email")                      [new source]
    hunk +14:  return lookup(email)                                   [new call]
    file db.py line 88 (unchanged, but now reachable):
                  cursor.execute("SELECT * FROM users WHERE email = '" + email + "'")

The dangerous line is not in the diff. That is the whole point of tracing.

### 4. Hidden security changes

Watch for these specifically; they are the ones that survive review:

- **A refactor that changes a call from parameterized to interpolated.**
  "Simplified the query builder" is where a binding becomes a concatenation.
- **A widening of an existing check.** `if path.startswith(BASE)` ->
  `if BASE in path`. `if role == "admin"` -> `if role in ADMIN_ROLES` where
  `ADMIN_ROLES` is now a string containing `"adminread"`.
- **A new default.** A function gains `def render(template, autoescape=False)`.
  The caller does not change; the behaviour does.
- **A dependency bump that is not a patch bump.** Major version in a
  "chore(deps)" commit.
- **Error handling that becomes permissive.** A bare `except: pass` around a
  validation block, or `except Exception: return True`.
- **A test that is weakened.** `assert result == expected` ->
  `assert result is not None`. See rule 3 below.

### 5. CI traps in the PR

- `pull_request_target` with a `checkout` of the PR head: the workflow now runs
  with a privileged token against attacker-controlled code.
- A new workflow that echoes a secret into a log, or passes it to a third-party
  action.
- `if: github.event.pull_request.head.repo.full_name == github.repository`
  guards that look protective but are satisfiable from a fork branch.

See `skills/25-docker-and-supply-chain.md`.

## The comment that works

A PR comment is read by one person who is busy and slightly defensive. Order
matters.

    Security: SQL injection in find_user_by_email

    The email query parameter reaches an interpolated query:
    - app/api/users.py:118  email = request.args.get("email")   (added in this PR)
    - app/db/queries.py:42   cursor.execute("... '" + email + "'")

    Trigger: GET /users?email=' OR '1'='1 returns every row in users.

    Suggested change:
      cursor.execute("SELECT * FROM users WHERE email = ?", (email,))

    Happy to re-review once that's in.

Five sentences. Location, path, trigger, fix, offer. No lecture, no severity
table, no "this is critical!!" -- the author's trust in your comment is the
resource you are spending, and it is finite across a repository.

### What not to write

- "This looks like SQL injection, please sanitize input." -- no location, no
  path, not actionable.
- A severity score with no impact statement. The number is not the argument.
- "This is a critical vulnerability." without showing the trigger. Authors
  discount the next 9 findings when one was overstated.

## False positives (do NOT report)

- **A test fixture with an injected payload.** `tests/test_sqli.py` containing
  `"'; DROP TABLE users; --"` is the test *for* the fix, not the bug.
- **A constant-composed query.** `cursor.execute("SELECT * FROM users WHERE id = " + str(ID))`
  where `ID` is a module-level literal. No user input, no flow.
- **A parameterized query.** `cursor.execute("... email = ?", (email,))` -- this
  is the fix, already applied.
- **A sanitizer added in this PR.** If the hunk adds `shlex.quote()` around a
  command argument, that is the improvement. Confirm it covers the sink and say
  so.
- **A rename.** `q` -> `query` changes nothing about the flow.
- **A dependency bump within the same major version** with a lockfile change
  only. Note it; do not raise it as a finding without an advisory ID.

A false positive on a PR comment costs more than a missed one: the author now
has evidence the reviewer is not reading carefully.

## Severity

For PR comments, prefer "here is the path and the fix" over a vector. If a
vector is needed for the record, derive it from the impact the trigger proves
(e.g. unauthenticated read of a user table -> `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H`),
and give the vector plus the FIRST.org calculator link, never a computed
number.

## Remediation

The fix in the comment must be the minimal change. If the correct fix is larger
than three lines, say what the first step is and that you will help with the
rest.

## Verify the fix

Re-read after the author pushes. Confirm the sanitizer is applied to the sink
you named, not to a different sink, and that no new hunk reintroduces the
source. If the fix is correct, say that in one line and close.
