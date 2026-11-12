# Progress and CI (running the scanner where nobody is watching)

## What it is

A scan run interactively is judged by a human who can see it working. A scan run
in CI is judged by an exit code and a machine-readable artifact, with no human in
the loop to notice that the run was truncated, that the package cap skipped half
the tree, or that the process died on an encoding error halfway through the
report.

This skill covers the substitution for operational sections from the style guide:
"Detection" becomes **what a CI job must check**, "How it works" becomes **the
failure modes of an unattended run**, and the remaining sections keep their
meaning.

## What a CI job must check

A scan that exits 0 has proved almost nothing on its own. Check these, in order:

1. **The output file is non-empty and parses.** A truncated report is the worst
   outcome this tool can produce -- it looks authoritative and is silently
   incomplete.
2. **The JSON parses and its counts equal the findings present.** Counts are
   recomputed after deduplication for this reason; a count that disagrees with
   the array length means the run is unreliable.
3. **The coverage block is in the payload.** Unparsed manifests, skipped-over-cap
   packages, and query errors. A CI gate reading only the finding count cannot
   see a coverage gap, and a coverage gap reads as clean.
4. **The exit code reflects a policy, not a count.** Decide the gate before the
   run: fail on any critical, fail on any high, or fail only on a new finding
   relative to the base ref.
5. **Nothing was written outside the intended paths.**

## The failure modes of an unattended run

| Failure | Cause | Mitigation |
| --- | --- | --- |
| Report file is truncated | A non-ASCII byte raised `UnicodeEncodeError` mid-emit on the cp1252 console | ASCII-only output; assert the file parses before publishing it |
| Output is empty, exit 0 | The target path was wrong, or skip-list filtering removed everything | Assert the file is non-empty AND that `manifests_total` or a file count is > 0 |
| CVEs are 0 on a big tree | The package cap (CLI default 40) skipped most packages | Read `dependency_coverage`; treat cap skips as a gate failure |
| CVEs are 0 on an offline runner | OSV is unreachable | Check the query-error count; fail the gate on network errors rather than reading 0 as clean |
| Findings differ between runs | Non-deterministic ordering feeding a diff | Sort findings by file then line before diffing |
| The job passes after a regression | The gate counts total findings and the count is dominated by pre-existing ones | Gate on *new* findings relative to the base ref (see `skills/21-branch-scanning.md`) |
| A scan times out | A huge tree or a slow OSV round trip | Set `--max-files` explicitly, raise the timeout, and log what was dropped |

**Never silently cap coverage.** If the run bounded itself -- a file cap, a
package cap, a timeout, a skipped directory -- emit what was dropped. A silent
truncation reads as "covered everything" when it did not.

## A working CI job

```yaml
security-scan:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - name: Scan
      run: |
        triagekit scan . --json --sarif \
          --max-files 8000 > scan.json 2>scan.err || true
    - name: Assert the artifact is usable
      run: |
        test -s scan.json          # non-empty
        python -c "import json;d=json.load(open('scan.json'));\
          n=len(d.get('findings',[]));\
          c=sum(d.get('counts',{}).values());\
          assert n==c, f'counts {c} != findings {n}';\
          cov=d.get('dependency_coverage',{});\
          print('coverage:',cov)"
    - name: Gate on new critical/high findings
      run: python scripts/ci_gate.py scan.json --baseline main --fail-on critical,high
    - uses: github/codeql-action/upload-sarif@v3
      with: { sarif_file: scan.sarif }
    - name: Always publish the artifact
      if: always()
      uses: actions/upload-artifact@v4
      with: { name: triagekit-scan, path: scan.json }
```

Two details that matter more than they look:

- **`if: always()` on the artifact upload.** A scan that failed its gate is
  exactly the run whose report you need to read.
- **Publish the scan to a place with access control.** A security report is a map
  of the vulnerabilities. A public artifact on a public repo is a disclosure --
  see `skills/01-authorized-use.md`.

## Encoding and progress in a non-TTY

The console uses `rich`. In a non-TTY, `Progress`, `SpinnerColumn`, and
`BarColumn` produce no useful output, and rich's console can raise on a cp1252
stream. So:

- Redirect output to a file and assert the file, not the console.
- Keep emissions ASCII-only; when a byte must be copied from the target's source,
  escape it and say that you did.
- Prefer `--json` or `--sarif` for CI; the human-readable markdown and table
  output is for a terminal that supports it.

If a progress indicator is expected and the console is a pipe, do not treat the
absence of spinner output as a hang -- check the artifact file.

## Severity

No CVSS vector applies: this is a procedure, not a defect class. The exposure it
guards against is a CI job that reports green on a run that examined almost
nothing, which is worse than no CI job because it manufactures confidence.

## Remediation

1. Assert the artifact parses and its counts match, before any severity gate.
2. Put `dependency_coverage` in the gate, not just the finding count.
3. Gate on new findings relative to the base ref, so pre-existing findings do not
   mask a regression.
4. Upload the artifact with `if: always()`.
5. Keep scan output out of public artifacts and public logs.

## Verify the fix

Break it deliberately and confirm the gate catches it: feed the gate a JSON with
a count that disagrees with the findings array, a truncated file, and a run with
a coverage limit -- each must fail. A gate that passes all three is not a gate.
