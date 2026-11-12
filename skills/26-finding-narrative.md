# Finding narrative (how to write one finding)

## What it is

A finding is a claim that a specific piece of code lets an attacker do a
specific thing. This skill is how to write that claim so a reviewer can
disprove it, and a developer can fix it, without asking you anything.

The trust boundary in a finding is between what you assert and what you can
show. A narrative that crosses it -- asserting impact without showing the path
-- is a false positive wearing a confident tone.

## The seven parts, in order

1. **Title** -- `sink + source + effect`, not a class name.
2. **Location** -- file, line, and the exact expression.
3. **The tainted path** -- source -> intermediate steps -> sink, each with a line.
4. **Trigger** -- the concrete request or input a user would send.
5. **Impact** -- stated as attacker capability, not as a CWE label.
6. **Fix** -- exact code, not advice.
7. **Verify** -- the check that proves the fix worked.

## Titles

| Bad | Why | Good |
| --- | --- | --- |
| `SQL Injection` | Class name; 50 places in the report say this | `SQL injection in find_user_by_email via the email query parameter` |
| `Command Execution` | Says nothing about reachability | `OS command injection in /restart via the host query parameter (shell=True)` |
| `XSS` | Not actionable | `Reflected XSS in the search results heading (unescaped q parameter)` |

The title must survive being read alone, out of context, in a list of 40.

## Location

Give the file, the line, and the expression. If the flow spans files, give the
sink line first (that is where the damage happens) and the source line second.

    sink:  app/db/queries.py:42  cursor.execute("SELECT * FROM users WHERE email = '" + email + "'")
    source: app/api/users.py:118  email = request.args.get("email")

Do not paraphrase the expression. Quote it. A developer must be able to find
the line from the finding alone.

## The tainted path

Each step gets one line, with the line number, in the order the data moves.
If a step is an assignment, name the variable. If a step is a call, name the
function.

    app/api/users.py:118   email = request.args.get("email")      [source: express-req-query]
    app/api/users.py:120   return find_user_by_email(email)
    app/db/queries.py:38   def find_user_by_email(email):
    app/db/queries.py:42   cursor.execute("... '" + email + "'")   [sink: sql-execute]

If the analyzer reported `is_sanitized`, say so and file it as an auditable
record, not a finding. A sanitizer that genuinely breaks the flow means there
is no claim to make.

## Trigger

What a user sends, concretely. For a local fixture this is a shape, not a
working exploit against a real product.

    GET /users?email=' OR '1'='1

One line. If you cannot write it, you do not have a finding -- you have a
guess about a code shape.

## Impact: attacker capability, not a label

Write what the attacker gains, in the terms a developer can act on.

| Bad | Good |
| --- | --- |
| `CWE-89, high severity` | `An unauthenticated attacker reads every row in users, including password hashes, and can stack a second statement` |
| `RCE` | `An attacker who can reach /restart runs arbitrary commands as the service account (UID of the app process)` |
| `XSS` | `JavaScript runs in the victim's session on this origin: session token theft and any action the victim can take, performed silently` |

State the privilege required. "Unauthenticated" and "requires an admin
session" are different findings with different vectors.

## Fix

Exact code, before and after, per language. Not "use parameterized queries".

    # before                                     # after
    cursor.execute(                              cursor.execute(
        "SELECT * FROM users WHERE "                 "SELECT * FROM users WHERE "
        "email = '" + email + "'",                   "email = ?",
    )                                               (email,),
                                                )

The fix must be the smallest change that removes the vulnerability. Adding a
WAF rule in front of an unsanitized sink is not a fix; it is mitigation with a
bypass.

## Verify

Name the check that proves the fix worked.

- A regression test that calls the endpoint with `' OR '1'='1` and asserts zero
  rows.
- A grep that the concatenation form no longer appears in that file.
- For a dependency bump, the advisory ID plus the fixed version, and the
  lockfile showing it.

If the verification is "it looks right now", say that instead of inventing a
test.

## Worked example

### BAD

> **SQL Injection** (CWE-89, high) User input reaches a database query without
> sanitization. Recommend using parameterized queries.

Fails every part: no location, no path, no trigger, no capability, no fix, no
verification. A reviewer cannot confirm or refute it. A developer cannot act on
it.

### GOOD

> **SQL injection in `find_user_by_email` via the `email` query parameter**
>
> - Sink: `app/db/queries.py:42` --
>   `cursor.execute("SELECT * FROM users WHERE email = '" + email + "'")`
> - Source: `app/api/users.py:118` -- `email = request.args.get("email")`,
>   served by `GET /users` with no authentication.
> - Path: the two lines above, with no intervening sanitizer.
> - Trigger: `GET /users?email=' OR '1'='1` returns every row in `users`.
> - Impact: an unauthenticated attacker reads all user records including
>   password hashes, and controls the statement text (a second statement is
>   possible if the driver permits stacking).
> - Fix: bind the parameter --
>   `cursor.execute("SELECT * FROM users WHERE email = ?", (email,))`
> - Verify: regression test asserting the payload above returns zero rows;
>   `grep -n "execute(" app/db/queries.py` shows no concatenation form.
> - Vector: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
>   (no numeric score -- compute it at the FIRST.org calculator)

## Severity

This is a reporting-quality control, not a vulnerability class, so there is no
CVSS vector for the skill itself. Its effect shows up as a multiplier: a report
of BAD findings is unusable no matter how severe each one is, and a reviewer
who finds one fabricated impact discounts every other finding in the file. That
is the cost this skill exists to avoid.

## Remediation

Enforce the seven parts. If a finding cannot supply a location, a trigger, or a
capability, it is a NOTE, not a finding -- move it to a notes section and say
why. A report with 8 verified findings and 12 notes is stronger than one with
20 claims.

## Verify the fix

Pick any finding at random from the report and attempt to reach the sink from
the stated source using only what the finding says. If you cannot, the
narrative is incomplete. Run this on three findings per report; if any of the
three fails, the narrative standard is not being met.
