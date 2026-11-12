# SKILL STYLE GUIDE (read before writing or editing any skills/*.md)

This guide is the contract every skill file in `skills/` must satisfy. It is
loaded by the skill writer, not by the LLM at scan time.

## Why the format is fixed

TriageKit findings are reviewed by third-party security teams and delivered to
the people who must fix the issues. A skill that says "use parameterized
queries" produces a report nobody can act on and no reviewer can verify. Each
skill must therefore carry enough operational detail that the agent can (a) find
the defect, (b) prove to itself that the defect is real, (c) explain the attack
in terms a developer recognises, and (d) hand over a concrete fix.

## Required sections (in this order)

```
# <Title> (<CWE-n>)

## What it is
Two or three sentences. Name the trust boundary that is crossed.

## Detection
Code shapes per language, as concrete fenced examples. Regex-level hints only
where they carry no false positives; prefer "look for" over "match".

## How it works (attack mechanics)
What the attacker controls, what the sink does with it, and the concrete
payload shape. No working exploit for a real product is included; the payload
is a *shape* that proves the sink is reachable.

## Is it actually exploitable? (exploitability test)
The three or four questions that separate a real finding from a false positive.
This is the section that makes the tool trustworthy.

## False positives (do NOT report)
Named, specific safe patterns. Reporting these is the failure mode that
destroys trust in a scanner fastest -- a false positive on idiomatic code costs
more credibility than a missed bug.

## Severity
How CVSS v4.0 metrics move for this class. Give a representative vector and the
FIRST.org calculator link pattern, not a numeric score (v4.0 is a lookup table;
never compute one by hand).

## Remediation
Exact code, before and after, per language. Not advice.

## Verify the fix
The check that proves the remediation worked (a test, a grep, a request).
```

## Rules

1. **ASCII only.** The console is cp1252; a single non-ASCII byte raises
   `UnicodeEncodeError` and aborts the run mid-report. Use `->`, `<=`, `"`, not
   the typographic characters.
2. **No attack against a real target.** Payloads are shapes against a local
   fixture. Authorized, defensive analysis only.
3. **Named, testable claims.** "Prefer X" is banned. Say what to run.
4. **False positives are mandatory.** A skill with no FP section is incomplete;
   the FP section is what keeps the report usable.
5. **No numeric CVSS.** Emit the vector and the calculator link.
6. **Cross-reference by filename.** `see skills/18-dependency-cve.md` beats
   "the CVE skill".
7. **Target 120-350 lines.** Dense and complete beats exhaustive.

## What a finished skill looks like

A reviewer reading only the skill should be able to reproduce the finding,
disagree with the agent's judgement with a citation, and apply the fix without
guessing at intent.
