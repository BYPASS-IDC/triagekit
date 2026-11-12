# Remediation playbook (fixing what the scan found)

## What it is

A finding without a fix is a cost with no benefit. This skill is how a finding
becomes a change a developer can merge, ordered by what to fix first, and worded
so the fix survives contact with an existing codebase.

The trust boundary in remediation is between "this removes the vulnerability"
and "this hides the symptom". Filters, blocklists, and WAF rules hide symptoms;
the grammar crossing stays.

## The ordering

Fix in this order. It is not the CVSS order.

1. **Unauthenticated RCE.** Command injection, deserialization reaching a shell,
   template injection in an unauthenticated path. Fix today, patch the surface.
2. **Unauthenticated data read.** SQL injection, path traversal to credentials,
   SSRF to an internal network.
3. **Privilege escalation.** Broken access control, IDOR, mass assignment. These
   are usually a missing check, not a parsing bug.
4. **Authenticated injection and stored XSS.** Exploitable but requires a foothold.
5. **Client-side and hardening.** Reflected XSS, missing headers, weak TLS config.
6. **Dependency CVEs.** Ordered by whether the vulnerable function is reachable
   from your code, not by advisory date.

When several findings share one root cause -- one unsanitised helper called from
twelve handlers -- that is ONE remediation. Twelve tickets is worse than one,
because it invites twelve rounds of review on the same decision.

## The fix, per class

Each fix below is the smallest change that removes the grammar crossing.

### SQL injection

    # before                                    # after
    cursor.execute(                              cursor.execute(
        "SELECT * FROM users "                       "SELECT * FROM users "
        "WHERE email = '" + email + "'",             "WHERE email = ?",
    )                                               (email,),
                                                 )

Parameterize. Do not escape -- escaping is one forgotten edge case away from
breaking, and the driver already did this correctly.

### Command injection

    # before                                    # after
    subprocess.run("ping " + host, shell=True)   subprocess.run(["ping", host])

Pass argv as a list and drop `shell=True`. `shell=True` re-introduces the shell
grammar and removes the argv-list exemption.

### Path traversal

    # before                                    # after
    open(os.path.join(BASE, name))               open(os.path.join(BASE, os.path.basename(name)))

plus, if the value must select a known resource, an allowlist:

    name = name if name in ALLOWED_FILES else DEFAULT_FILE

`basename` alone prevents traversal but not reading an unintended file in `BASE`;
the allowlist closes that.

### XSS

    # before                                    # after
    return "<h1>" + q + "</h1>"                  return render_template("r.html", q=q)

Escape on output, at the template engine, with autoescaping on. Do not filter
`<script>` on input -- there are a dozen ways to write a script tag and one way
to escape.

### SSTI

    # before                                    # after
    render_template_string(t)                    render_template("page.html", t=t)

Never pass user input to a template *string*. Pass it as *data* to a template
file.

### SSRF / open redirect

    # before                                    # after
    requests.get(user_url)                       if user_url in ALLOWED_HOSTS:
                                                     requests.get(user_url)
                                                   else:
                                                     raise ValueError

Allowlist the destination. A scheme/host blocklist is bypassable; an allowlist
is a question, not a race.

### Deserialization

    # before                                    # after
    pickle.loads(blob)                           json.loads(blob)

Use a format that cannot carry objects. `yaml.load` -> `yaml.safe_load`.

### Secrets

    # before                                    # after
    TOKEN = "ghp_..."                            TOKEN = os.environ["TOKEN"]

Move it to the environment, then rotate it -- a secret that was ever in source is
compromised regardless of the fix.

## The fix must be merge-shaped

Match what the codebase already does. If the project uses SQLAlchemy sessions,
the fix is the ORM, not a raw cursor with `?`. If the project has an existing
escape helper, use it and say so -- inventing a parallel helper invites drift.

Name the file, the line, and the exact replacement text. A developer should be
able to apply the fix without opening the skill.

## What is NOT a fix

| Not a fix | Why |
| --- | --- |
| A WAF rule / input filter in front of the sink | Bypassable; the crossing remains |
| A blocklist (`..`, `;`, `'`) | Breakable; there is always another spelling |
| `try/except` around the sink | The payload still executed; you only hid the error |
| Removing the vulnerable parameter | Breaks the feature; the flow returns next sprint |
| Escaping for the wrong grammar | `escape_html` does not stop SQL injection |
| Disabling the endpoint | A control, not a fix -- say which it is |

Say plainly when a change is mitigation rather than a fix. A report that calls a
WAF rule a fix trains the reader to distrust the rest of it.

## Severity

No CVSS vector belongs to this skill; it is a procedure, not a defect class. Its
effect is measured in time-to-fix: a remediation a developer can apply in one
commit closes the finding, and a recommendation they must interpret costs a
sprint of back-and-forth.

## Verify the fix

Every remediation names its check, and the check is executable:

| Class | Check |
| --- | --- |
| SQLi | Test asserting the payload returns zero rows; grep that no concatenation form remains in the file |
| Command | Test asserting the argv list is length 1 and no shell spawned; grep for `shell=True` in the file |
| Traversal | Test asserting `../../etc/passwd` resolves inside `BASE`; grep for `basename` on the path |
| XSS | Test asserting `<` is emitted as `&lt;` in the response |
| SSRF | Test asserting a non-allowlisted host raises |
| Deserialization | Test asserting the object form is rejected |
| Secret | Rotate it; grep the repo and history for the old value |

If the check is "it looks right now", write that instead of inventing a test.
An honest unverifiable fix is more useful than a fabricated verification.
