# Branch scanning (comparing a ref against what is already merged)

## What it is

Scanning `main` tells you what the codebase is vulnerable to today. Scanning a
branch *relative to its base* tells you what a pull request is about to change.
That difference is the entire value: a finding that exists on both `main` and the
branch is pre-existing debt, and a finding that exists only on the branch is a
regression this PR introduces.

This skill is how to produce that comparison so it is trustworthy -- and how to
avoid the several ways a naive diff produces a confident wrong answer.

The trust boundary here is between "this finding is new" and "this finding is
new relative to the ref you compared against". Both are usually true; the second
is the claim you must actually make.

## Procedure

### 1. Establish the base explicitly

The base branch is a fact you must record, not assume. `main` and `master` both
exist in the wild, and a fork's default branch may be stale by weeks.

    git merge-base HEAD origin/main     # the true fork point
    git rev-parse origin/main           # the tip, which may be ahead of the base

**Compare against the merge-base, not the tip.** If `origin/main` advanced since
the PR branched, a diff against the tip mixes the other PRs' changes into yours
and produces findings you did not introduce. Record which you used, in the
report.

### 2. Scan both refs with identical parameters

    triagekit scan . --branch <ref> --json --max-files 8000 > branch.json
    triagekit scan <base-worktree> --json --max-files 8000 > base.json

Identical parameters are load-bearing: a different `--max-files`, a different
package cap, or `--no-cve` on one side and not the other produces differences
that are artifacts of the run, not of the code. `--no-cve` on one side will show
every CVE on the other side as "new".

### 3. Key the findings, then diff

Sort both sets by a stable key before comparing. A stable key is
`(rule_id, file, line, sink_name)` -- not the finding's array index and not its
title, both of which move with ordering:

    key = (f.rule_id, f.file, f.line, f.sink)

Then:

- **On the branch only** -- a new finding. This is the PR's contribution.
- **On the base only** -- a finding this PR *removed*. Verify it is genuinely
  gone (the line was deleted or fixed) and not merely moved (line numbers shift
  when lines are added above; a moved finding looks like one removal plus one
  addition).
- **On both** -- pre-existing debt. Report it as context, not as a PR comment.

The moved-line problem is the most common false "new finding". Normalize by
matching on the file and the *sink expression* when the line number shifted, or
use a git-blame-aware key if the tool supplies one.

### 4. Report the three buckets separately

Never merge them. A PR comment that lists 40 findings where 38 are pre-existing
will be ignored entirely, and correctly. Split:

    New in this PR (N)          -- blocking, this is what you are asking them to fix
    Fixed by this PR (M)        -- say so, in one line; it is the good news
    Pre-existing (K)            -- context, or a separate issue

### 5. Coverage must match too

If the base run had 40 packages queried and the branch run had 12 because a
manifest changed shape and is now unparsed, every CVE that disappeared is an
artifact. Read `dependency_coverage` on both sides before concluding a finding
was fixed. A dependency manifest that the parser does not recognize is reported
as unparsed, not silently empty -- check that list on the branch run.

## Is it actually exploitable?

For a *new* finding, the standard test from
`skills/27-false-positive-control.md` applies in full -- walk the path, confirm
the source evaluates, check the sanitizer chain. For a *diff*, add three
questions:

1. **Is the finding in a line this PR touched?** A finding in an untouched hunk
   is pre-existing regardless of what the key comparison says.
2. **Is the base worktree at the merge-base, not at a stale or advanced tip?**
3. **Would the same code on the base produce it?** If yes, it is not new, it is
   newly *visible* -- because a moved function, a renamed import, or a changed
   call site brought it into the analyzer's reach. Say that, rather than
   claiming the PR introduced the bug.

## False positives (do NOT report)

- **A pre-existing finding reported as new** because line numbers shifted or a
  function moved into a file the base run parsed differently.
- **A finding in an untouched hunk.** Everything the base also reports is debt.
- **A coverage artifact.** A CVE that "disappeared" because the manifest is now
  unparsed, or a package that fell over the cap.
- **A test fixture added by this PR.** New tests containing payload strings are
  the fix's tests.
- **A moved finding** -- one removal plus one addition with the same expression.
  Normalize the key and report once.
- **A parameter difference.** `--no-cve`, a different `--max-files`, or a
  different cap between the two runs.
- **A newly visible finding** in code the PR did not change.

## Severity

No CVSS vector applies to this skill; it is a comparison procedure. Its effect is
the signal-to-noise ratio of every PR comment you file: a comment that lists
pre-existing debt trains the author to dismiss the next comment, including the
one about the real regression.

## Remediation

Produce the base scan as an artifact of the PR job, not as an ad-hoc local run,
so the base ref and the parameters are recorded and reproducible. Make the
stable key part of the tooling, so moved lines do not manufacture findings. Split
the three buckets in the tooling, not in the prose.

## Verify the fix

Take a PR known to introduce no security change and run the comparison: it should
report zero new findings. If it reports any, the key is order-sensitive or the
parameters differed. Then take a PR that introduces a genuine regression: it must
report exactly that finding, and not also twelve pre-existing ones. Run both
checks whenever the comparison logic changes.
