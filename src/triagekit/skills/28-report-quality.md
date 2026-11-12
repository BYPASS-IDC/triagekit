# Report quality (what makes a report usable)

## What it is

A security report has exactly one job: let a developer fix the right thing and
let a reviewer verify the claim, without asking the scanner's author anything.
This skill is the standard the report is held to.

The trust boundary in a report is between what it asserts and what it can show.
Everything else -- formatting, severity, ordering -- exists to protect that.

## The structure

    1. Authorization line       (what was scanned, under what authority, in which mode)
    2. Scope and coverage       (what was read, and what was NOT read)
    3. Findings                 (numbered, each complete)
    4. Notes                    (patterns that matched but did not prove out)
    5. Not assessed              (what could not be examined, and why)

The authorization line and the coverage section are not padding. A report
without the authorization line is not a TriageKit report; a report that omits
its coverage limits is claiming more than it examined. See
`skills/01-authorized-use.md` and `skills/03-repo-scan.md`.

## Per-finding completeness

Each finding carries the seven parts from `skills/26-finding-narrative.md`:

    Title      SQL injection in find_user_by_email via the email query parameter
    Location   file:line and the exact expression, sink first, source second
    Path       source -> steps -> sink, each with a line number
    Trigger    GET /users?email=' OR '1'='1
    Impact     what the attacker gains, stated as capability
    Fix        exact code, before and after
    Verify     the test or grep that proves the fix

A finding missing a location, a trigger, or a capability is a NOTE. Move it, and
say why, in the same report.

## Ordering

Order by what a developer should fix first, which is almost never "highest CVSS
number". Use this order:

1. **Unauthenticated remote code execution** -- act today.
2. **Unauthenticated data read** (SQLi, path traversal to a secret, SSRF to an
   internal endpoint).
3. **Authenticated privilege escalation** (broken access control, IDOR).
4. **Authenticated injection** and stored XSS.
5. **Client-side and header/cookie hardening** findings.
6. **Dependency CVEs**, ordered by reachability of the vulnerable function, not
   by advisory date. A CVE in a transitive dependency whose vulnerable function
   is never called ranks below a medium in the main request path.

When two findings share a root cause, group them and fix once. Say so.

## Titles

A title must survive being read alone in a list of 40. `SQL Injection` does not;
`SQL injection in find_user_by_email via the email query parameter` does. The
test: could a developer who has never seen the repo find the line from the title
alone?

## Impact statements

Write capability, not class. `CWE-89, high` tells a developer nothing about what
to protect. "An unauthenticated attacker reads every row in `users`, including
password hashes, and controls the statement text" tells them exactly what is at
stake and how urgently to act.

State the privilege required in the impact sentence. "Unauthenticated" and
"requires an admin session" are different findings and must not read alike.

## Severity and vectors

CVSS v4.0 is a lookup table. Emit the vector and the FIRST.org calculator link
with the vector as the fragment:

    CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N
    https://www.first.org/cvss/calculator/4.0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N

Never a hand-computed number. Never all-High on every metric because the finding
feels serious -- each of VC/VI/VA and SC/SI/SA is justified separately or
flagged `[ASSUMED]`. Watch the common migration errors: prerequisites and race
conditions belong in AT, not AC; v3.1's UI:R split into UI:P and UI:A; a
dependency serving only this system is inside the boundary, so its impact is
scored in VC/VI/VA, not counted again in SC/SI/SA.

## Encoding

The report is written to a cp1252 console on this platform. Any byte above 0x7E
in the report text raises `UnicodeEncodeError` and can abort a run mid-emit,
which produces a truncated file with no error banner. So:

- ASCII only. `->` not an arrow. `--` not an em-dash. Straight quotes.
- If you must include a non-ASCII byte copied from the target's source, escape
  it or replace it, and say that you did.
- Verify the emitted file parses (valid JSON for `--json`, valid JSON for
  `--sarif`) and that the byte count is non-zero.

A truncated report is the worst outcome this tool can produce: it looks
authoritative and is silently incomplete.

## Machine-readable output

`--json` and `--sarif` exist so CI can consume the result. Two requirements:

- **Counts must match the findings present.** Incrementally maintained counters
  drift after deduplication; recompute them from the surviving list.
- **Coverage must be in the payload.** The dependency coverage block -- unparsed
  manifests, skipped-over-cap packages, query errors -- belongs in the JSON, not
  only in the human summary. A CI gate that reads only the finding count cannot
  see the gap.

## What never appears in a report

- A fabricated trigger. If the payload was not reasoned about, do not show it.
- A CVSS number typed by hand.
- An impact claim the path does not support.
- A silent coverage gap. If the cap skipped packages, say how many.
- Advice in place of a fix. "Sanitize input" is not remediation; the exact code
  is. See `skills/07-remediation-playbook.md`.

## Verify the report

Before shipping: pick three findings at random and walk each from source to sink
using only the report's own text. Confirm the JSON parses and the counts match.
Confirm the coverage section is present. If any of those three fails, the report
is not ready.
