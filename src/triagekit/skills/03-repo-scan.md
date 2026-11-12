# Repo scan (reading a whole tree as an attack surface)

## What it is

A repo scan answers one question: across every file in this tree, where does
attacker-controlled data reach something that acts on it? This skill is the
operating procedure for that answer -- what the scan runs, in what order, what
its output means, and what its output does NOT mean.

The trust boundary in a repo scan is between "we read every file" and "we
understood every flow". A repo is not a web app: there is no running process,
no request, no response. Every flow is inferred from source, so every finding
carries an inference you can be wrong about.

## Procedure

### 1. The scan order

TriageKit runs these stages, and the order matters because later stages consume
earlier results:

1. **Discovery** -- enumerate files under the target, applying the skip list
   (`node_modules`, `.git`, `.venv`, `dist`, `build`, `vendor`, `__pycache__`,
   `site-packages`, and similar). A path on that list was never read; a finding
   cannot come from it.
2. **Manifest discovery** -- find dependency manifests case-insensitively,
   including any filename containing `requirements` that ends in `.txt`
   (`dev-requirements.txt`, `requirements.dev.txt`).
3. **Dependency scan** -- parse each manifest, query OSV per package, subject to
   the configured package cap (the CLI sets 40, or 0 when `--no-cve` is passed;
   there is no `--max-packages` flag). See `skills/18-dependency-cve.md`.
4. **Static taint analysis** -- AST-based for Python
   (`src/triagekit/core/taint/analyzer.py`), regex-based for JS/TS
   (`src/triagekit/core/taint/js_analyzer.py`). See `skills/06-injection-surface.md`.
5. **Heuristic security pass** -- pattern-level checks that do not need a flow.
6. **Correlation and deduplication** -- merge, dedupe, recount. See
   `skills/27-false-positive-control.md`.

### 2. Run it

```
triagekit scan <path>                      # passive, full tree
triagekit scan <path> --sarif              # SARIF for CI upload
triagekit scan <path> --no-cve             # skip OSV (offline, no API calls)
triagekit scan <path> --json               # machine-readable
triagekit scan <path> --max-files 8000     # file cap (default 8000)
triagekit scan <path> --branch <ref>       # also scan a non-default ref
```

`--no-cve` sets the dependency scanner's package cap to 0, which disables OSV
lookup entirely. It is a real switch, not a no-op: if a report says CVE
findings are 0, check whether this flag was set before concluding the tree is
clean.

### 3. Read the coverage section before the findings

TriageKit emits a "Scan coverage limits" section listing:

- **Manifests that were found but not parsed.** An unparsed manifest means the
  dependency stage could not enumerate its packages. This is a gap, not a clean
  result. `extract_packages` returns an empty package list for an unknown
  format rather than guessing an ecosystem, so an unrecognised manifest shows up
  here.
- **Packages skipped over the cap.** When more packages exist than the cap
  allows, the remainder is unqueried. The count is reported; the identities are
  not. Raise the cap if the tree is dependency-heavy.
- **Query errors.** OSV is a network call. Failures are reported, not swallowed.

Report these limits in the same breath as the findings. A scan that skipped 300
packages over the cap and reports 0 CVEs has not shown the tree is clean -- it
has shown 40 packages are. Never let a coverage limit read as a passing grade.

### 4. Read the findings

Each finding carries the sink, the source, the tainted path with line numbers,
and `is_sanitized`. Order of reading:

1. **Sink first.** That is where damage happens.
2. **Trace the path backwards** to the source. If any step does not actually
   carry the data, the finding is wrong -- see `skills/27-false-positive-control.md`.
3. **Check `is_sanitized`.** A genuine sanitizer breaks the flow; the path is an
   auditable record, not a finding.
4. **Check reachability.** A sink in a test fixture, a `__py__` helper, or a
   function nothing calls is not the same as a sink in a request handler.

### 5. What the score and grade are

The score is a penalty sum over live findings (critical 18, high 8, medium 3,
low 1), clamped to 0..100, with grades A/B/C/D/F at 90/75/60/40. It is derived
from the findings that survived deduplication -- not an average, not a
placeholder. A grade of F on a deliberately vulnerable fixture is the correct
output, and a grade of A on a real codebase with findings is a bug.

## Is it actually exploitable?

For each finding, four questions separate real from noise:

1. **Does the source exist in this tree?** The pattern must match real code, and
   the matched expression must actually be evaluated.
2. **Does data really move along every step?** An assignment the path names must
   be on the executed route.
3. **Is there a sanitizer in the chain?** `skills/06-injection-surface.md` lists
   the strong sanitizers the analyzer honours.
4. **Can the attacker reach it?** Unauthenticated and requires-an-admin-session
   are different findings.

## False positives (do NOT report)

- **Test fixtures.** `tests/` payload strings are the test *for* the fix.
- **Unreachable sinks.** A sink in a function no caller reaches, or behind a
  `if __name__ == "__main__"` block in a library, is a note.
- **Sanitized flows.** A path the analyzer marked `is_sanitized` -- confirm the
  sanitizer is the right one for the sink, then file it as audited.
- **Constant composition.** `"... WHERE id = " + str(ID)` with a module-level
  literal `ID` has no source.
- **Skipped directories.** Do not report on files under the skip list as though
  they were read.
- **Lockfile churn.** A version bump with no advisory is not a finding.

## Severity

Score the finding, not the scan. Take the impact the trigger actually proves and
derive the vector: an unauthenticated read of a table is
`AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`; give the vector plus
`https://www.first.org/cvss/calculator/4.0#<vector>` and let the calculator
produce the number. Never hand-compute a v4.0 score -- it is a lookup table.

## Remediation

Per finding, not per scan: see the per-class skill and
`skills/07-remediation-playbook.md` for ordering. When many findings share one
root cause (a single unsanitised helper called from 12 handlers), fix the helper
once and say so -- twelve separate tickets is a worse remediation than one.

## Verify the fix

Re-run the same command with the same flags and confirm the finding is gone and
the coverage section has not grown. If the cap was raised and new packages were
queried, new CVEs appearing is the scan working, not a regression.
