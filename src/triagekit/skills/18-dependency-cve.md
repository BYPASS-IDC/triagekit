# Dependency CVEs (CWE-1395: vulnerable third-party component)

## What it is

A dependency CVE is a vulnerability in code you did not write, do not audit, and
cannot fix directly. TriageKit sources them from the OSV vulnerability database
(`api.osv.dev/v1/query`), one query per resolved package-version pair.

The trust boundary crossed is between "a library is a dependency" and "a
dependency is attack surface". Every package in the tree is executable code that
runs with the application's privileges; the only question is whether the
vulnerable part of it is reachable from your code.

## Detection

### What TriageKit actually does

`src/triagekit/core/analyzers/cve.py` parses manifests, resolves
package + version + ecosystem, and queries OSV. Verified behaviours:

- **Eleven manifest formats are parsed**, including `package-lock.json`,
  `yarn.lock`, `pnpm-lock.yaml`, `Pipfile.lock`, `Cargo.lock`, `cargo.toml`,
  `go.mod` (both single-line and block form), `pyproject.toml`,
  `requirements*.txt`, and `Pipfile`.
- **An unrecognised manifest is reported, not guessed.** `extract_packages`
  returns an empty ecosystem and an empty package list for an unknown format.
  Anything in `requirements*.txt` form is treated as PyPI, so
  `dev-requirements.txt` and `requirements.dev.txt` are both picked up.
- **A version specifier is not a version.** `^1.2.3`, `~1.2`, `>=1.0` and a bare
  package name resolve incompletely. A dependency with no resolved version
  cannot be queried, and that is a coverage gap.
- **The package cap is real.** Packages beyond the configured cap (CLI default
  40) are not queried. The count is reported in the coverage section.
- **Skip list.** `node_modules`, `.git`, `.venv`, `dist`, `build`, `vendor`,
  `site-packages`, `__pycache__` and similar are not walked.
- **`query_osv` records** the ecosystem, `aliases` (the CVE and GHSA ids for the
  same record), `cwes`, `references`, `published`, `modified`, and `withdrawn`.

### Reading an OSV record

```
id          GHSA-xxxx-yyyy-zzzz
aliases     [CVE-2024-12345]          <- the same record, another registry
cwes        [CWE-502]
references  [advisory URL, patch commit, PoC URL]
published   2024-01-15
modified    2024-06-02
withdrawn   2024-03-01  or  null     <- null means still valid
```

`withdrawn` is non-null when the advisory was retracted or duplicated. A withdrawn
record is not a finding; report it as superseded and name the record that
replaced it.

## How it works (attack mechanics)

There is no payload to send here -- the attack is the library's own. What this
class contributes is the decision about *ordering*, and that is where most
reports get it wrong:

**A CVE in a package whose vulnerable function your code never calls is not a
finding you can act on today.** A CVE in the direct request-handling path is.
The reverse of "sort by CVSS" and the reverse of "sort by advisory date".

Two facts change urgency sharply:

- **Is the package direct or transitive?** A transitive dependency is fixed by
  bumping the direct one, which may be a breaking change. A direct dependency is
  a version line.
- **Is there a public PoC?** That changes exploit maturity (E), not existence.
  A known-good patch with no PoC still needs the patch.

## Is it actually exploitable?

1. **Is the version in the affected range?** A range `>=1.0,<1.2.9` with the tree
  at `1.2.4` is in range. A tree at `1.2.9` is not, and a lockfile already
  containing `1.2.9` means the report is stale.
2. **Is the vulnerable function reachable from your code?** Grep the import and
  the call sites. `import requests` plus `requests.get(url, verify=False)` is
  reachable; `import requests` never called is not.
3. **Is the affected sub-feature enabled?** Many CVEs are conditional on a config
   flag, a cipher, a protocol version, or a driver being present. Read the
   advisory's conditions, not just its summary line.
4. **Is there a fixed version, and can you take it?** Check the release notes for
   a breaking change before recommending the bump.

## False positives (do NOT report)

- **A version already above the fixed version.** Check the lockfile, not the
  manifest's declared range.
- **A withdrawn or superseded advisory.** Name the replacement instead.
- **A dev-only dependency.** A CVE in a test runner, linter, or build tool that
  never ships. Note it with the reason.
- **An unreachable transitive dependency.** Note it as a hygiene item, not as a
  finding to fix today.
- **A version range that resolves to a fixed version.** `^1.2.9` resolving to
  `1.2.11` is not vulnerable to a `1.2.4` advisory.
- **A version that could not be resolved at all.** That is a `NOT_ASSESSED`, not
  a clean result.
- **A CVE whose CWE does not match anything in the codebase** -- say so as a
  note with the reasoning, rather than as a finding.

The most expensive false positive in this class is recommending a bump that
breaks the build. State the breaking change if there is one.

## Severity

Score the vulnerability the library actually has, in the context of how you call
it -- then derive the vector. A deserialization RCE in an unreachable parser:

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
https://www.first.org/cvss/calculator/4.0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
```

But if the vulnerable function is unreachable from attacker input, the honest
answer is `AT:P` (a prerequisite -- the attacker must first cause the code path
to be exercised) or a NOTE, not a full-severity finding. If the library is a
direct dependency whose function is called on every request, drop `AT` to `N`.
Flag assumed metrics `[ASSUMED]`. Never hand-compute the number.

## Remediation

Ordering, not just a bump:

1. **Direct dependency, reachable, fix available** -- bump and pin. This is the
   first thing you do.
2. **Direct dependency, reachable, no fix** -- mitigate (disable the feature,
   add a WAF-shaped guard at the boundary, replace the dependency) and say which
   you did.
3. **Transitive, reachable** -- bump the direct parent; if that is a breaking
   change, add an override/constraint rather than hand-patching `node_modules`.
4. **Unreachable** -- hygiene. Batch it with the next dependency-rotation PR.

Mechanically: update the manifest, regenerate the lockfile
(`pip-compile`, `npm install <pkg>@<fixed>`, `cargo update -p <pkg>`), and never
edit a lockfile by hand. Then run the test suite -- a dependency bump is a code
change.

## Verify the fix

- `triagekit repo . --no-cve` re-run, or the same scan, shows the advisory id
  gone and the resolved version at or above the fixed version.
- The lockfile shows the new version, and the manifest's declared range admits
  it.
- `grep` the import and call sites confirm the fixed function is still in use, so
  the bump is exercised.
- If the fix was a mitigation rather than a bump, the compensating control has its
  own test -- a WAF rule with no test is a note, not a fix.
