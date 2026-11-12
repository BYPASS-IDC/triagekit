# False-positive control (proving a finding before reporting it)

## What it is

Every scanner finding is a claim, and most claims a scanner makes are about code
shapes, not about reachable behaviour. This skill is the discipline that turns a
claim into either a reportable finding or an honest note.

The trust boundary here is between "the pattern matched" and "an attacker can do
this". Crossing it without proof is how a scanner earns a reputation that makes
people ignore it -- and a scanner that is ignored is worse than one that was
never installed.

## The rule

**A finding is reported only when the path is walked, the source is evaluated,
the sink is reachable, and no chain entry neutralizes the flow.**

If any of those four fails, it is a NOTE. A report with 8 verified findings and
12 notes is stronger than one with 20 claims, because a reviewer can act on all
of it.

## The four checks

### 1. Walk the path, do not read the pattern

Open the source line and the sink line. Read every step between them. If the
path says the data moves through a variable that the code never assigns on this
route, the finding is dead.

    claimed:  app/api.py:118 email = request.args.get("email")
              app/api.py:120 return find_user_by_email(email)
              app/db.py:42   cursor.execute("... '" + email + "'")

    check:    does find_user_by_email at app/db.py:38 take email as a parameter?
              is it the same find_user_by_email the comment names?

If `find_user_by_email` at line 38 is a different function that takes a user ID,
the path is fabricated by the analyzer's naming and the finding is wrong.

### 2. Confirm the source evaluates

A pattern can match inside a docstring, a comment, a `# noqa`-style dead branch,
or a code path guarded by a constant `False`. Confirm the enclosing function is
called, and called with attacker-controlled input.

### 3. Confirm reachability and privilege

Two questions, in order:

- **Can an attacker reach this code path?** A sink in a CLI subcommand run only
  by an operator, or behind `if __name__ == "__main__"` in an imported library,
  has a different attack surface than a route handler.
- **What privilege does the attacker need?** Unauthenticated and
  requires-an-admin-session produce different vectors and different priorities.

### 4. Check the sanitizer chain, not the last call

A taint state carries a chain of sanitizers, and a flow is neutralized when any
entry in the chain neutralizes it -- for the sink's grammar specifically. Read
the whole chain:

    value = escape_html(request.args.get("q"))     # html-escape
    query = "SELECT ... '" + value + "'"            # sql-execution sink

This is NOT sanitized for the sink. `escape_html` targets the HTML grammar; the
SQL grammar is still crossed. Conversely:

    cursor.execute("SELECT ... email = ?", (email,))   # parameterized

This IS sanitized -- the parameter binding removes the grammar crossing rather
than trying to filter the bytes.

Grammar matching is the whole test: a sanitizer for the wrong grammar is a
false sense of safety, and a sanitizer for the right grammar is a real fix.

## The structural exemptions

These are deliberately not reported. Re-reporting them is the most common way a
scanner loses credibility:

| Pattern | Why it is exempt |
| --- | --- |
| `subprocess.run(["cmd", arg])` with no `shell=True` | One argument, no shell grammar to cross |
| `os.path.join(BASE, os.path.basename(p))` | `basename` strips the traversal primitives |
| `dest if dest in ALLOWED else DEFAULT` | Allowlist guard; a single `In` compare against a literal or named allowlist |
| `cursor.execute("... ?", (x,))` | Parameter binding |
| `"{{ x }}"` in a Jinja2 template with autoescape on | Escaped by the engine |
| A constant-composed query | No source reaches it |

Each of these has a regression test that also proves the exemption is not
over-broad: the same patterns with `shell=True`, with a tainted first argv
element, with `os.path.join(BASE, p)` and no `basename`, with `not in`, and with
a ternary guarding a different variable are all still reported.

## Deduplication

Before reporting, dedupe. The same sink reached by two different sources is one
finding with a stronger trigger, not two findings. The same file:line reported
by two scanners is one finding. Counts must describe the findings that actually
survive -- recompute them after dedup rather than trusting a running total that
was incremented before the duplicates were removed.

## Confidence language

Use three levels, and never upgrade one to sound like another:

- **Finding** -- all four checks passed. Report it, with the path and trigger.
- **Note** -- the pattern matched but a check failed, or reachability depends on
  deployment. Say which check failed and what would resolve it.
- **Not assessed** -- the code was not read (skipped by the cap, skipped by the
  directory skip list, unparsed manifest, an OSV query error). Name the reason.

`NOT_ASSESSED` is a legitimate result. A clean result is not.

## Severity

False-positive control is a reporting-quality control, not a vulnerability
class, so it carries no CVSS vector. Its effect is a multiplier on the whole
report: one overstated finding makes a reviewer discount every other one in the
file. That is the cost this skill exists to avoid.

## Remediation

When a false positive survives review, fix the scanner, not the report. The fix
belongs in the registry (a pattern that is too broad), the analyzer (a flow step
that does not model reality), or the correlation stage (a dedup key that is too
narrow). Add a regression test that proves the fix did not over-suppress: the
safe pattern and its dangerous variant must both be covered.

## Verify the fix

Pick any three findings from a report at random and attempt to reach the sink
from the stated source using only what the finding says. If any of the three
cannot be walked, the control is not being applied and the report should not
ship. Do this every report -- the drift is always in the direction of more
claims and less proof.
