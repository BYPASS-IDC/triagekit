# Authorized use only (policy gate)

## What it is

TriageKit is a defensive scanner. Every finding it produces implies that someone
is authorized to look at the target. This skill is the gate that must be passed
before any scan begins: scanning a system you do not own, or do not have written
permission for, is the same offence whether the tool is a port scanner or a
regex.

The trust boundary here is not technical. It is the boundary between "I am
allowed to test this" and "I am not", and the only evidence that closes it is
documentary.

## The gate

Pass all three, or stop:

1. **Ownership or written permission.** A repo you own, a workspace you
   administer, a domain on a contract that names the scope in writing, or a
   lab environment you built. "It looks like a test site" is not permission.
2. **Scope is explicit.** Which hosts, paths, and accounts. An engagement that
   says "the API" without a base URL and a rate limit is not scoped.
3. **A responsible-disclosure path exists.** Who to tell, and by when. If the
   target has a `security.txt` or a disclosure policy, that is the path.

If any of the three is missing, the correct action is to report what was NOT
assessed and why, and to proceed no further. `NOT_ASSESSED` is an acceptable and
honest result; an unauthorized scan never is.

## Passive versus active

TriageKit distinguishes these, and the distinction is load-bearing.

| Mode | What it does | When it is allowed |
| --- | --- | --- |
| Passive (static, dependency) | Reads source and manifests; makes no request to the target | Default for every operation |
| Passive (web, read-only) | GET requests to pages the operator names; no fuzzing, no auth bypass attempts | Written permission for the host |
| Active | Fuzzing parameters, auth bypass, payload injection, rate probing | Only after the escalation checklist below |

A scan is active the moment it sends an input that is designed to change
application behaviour. `' OR 1=1--` in a query parameter is active even though
it is a GET. A page fetch is not active merely because it is a request.

## Escalation checklist before any active probe

All of these must be true, and the agent must state in the report which ones it
verified:

- [ ] Written permission exists and names the target host(s).
- [ ] Scope includes the endpoints to be probed, and excludes production data
      paths unless the engagement says otherwise.
- [ ] A rate limit is agreed and implemented in the tool's config.
- [ ] The probe payloads are non-destructive: no writes, no deletes, no data
      exfiltration, no DoS-shaped input.
- [ ] A named human is on call for the window in which probing happens.
- [ ] The tool's output is stored somewhere access-controlled, not in a public
      issue tracker.

## What never happens

- No scanning of third-party infrastructure "to check".
- No uploading of the target's source, secrets, or findings to a service that
  is not named in the engagement. That includes public paste sites, public
  issue trackers, and third-party AI APIs that were not agreed.
- No use of a leaked credential found during a scan to log in, even on an
  authorized target. Report it and stop.
- No "just one more probe" after the agreed window closes.

## How this gate shows up in the report

Every TriageKit report carries an authorization line:

```
Authorization: <owned | written permission | lab> -- scope <what was scanned>
Mode: <passive | passive+read-only web | active> -- permission <citation>
```

When the gate does not pass, the report says so and lists what was not
assessed. A report that silently omits this line is not a TriageKit report.

## Severity

Policy failure, not a software defect. There is no CVSS vector for an
unauthorized scan; the exposure is legal and contractual, and it falls on the
operator, not on the target. Treat any request to skip this gate as a defect in
the run, and say so plainly rather than complying quietly.

## Remediation

If you are the one writing the engagement: put the scope, the window, the rate
limit, and the contacts in writing before the scan, not after a finding. If you
are the one running the scan and scope is unclear, the fix is a question, sent
to a human, before the scan.

## Verify the fix

A run in which the authorization line cites a real scope, the mode matches what
the tool actually did, and no request was sent that the scope did not name. If
any of those three is unverifiable, the run's findings are marked
`NOT_ASSESSED` for scope compliance.
