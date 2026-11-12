# Secrets and tokens (CWE-798: hardcoded credentials)

## What it is

A hardcoded secret is any credential, key, token, or private value written
literally into source that should come from configuration or a secret store. It
is the highest-density real finding in any repository scan because it requires no
dataflow reasoning: the literal is either there or it is not.

The trust boundary crossed is between "code is public to the team" and "code is
public to the world". A secret in source is a secret in git history, in every
clone, in every CI log that printed the file, and in every backup.

## Detection

### The shape of the value, not the name of the variable

Match on the *shape of the value* where possible. Variable names lie; high-entropy
prefixes do not.

| Provider | Prefix / shape | Example grep |
| --- | --- | --- |
| AWS access key | `AKIA[0-9A-Z]{16}` | `grep -rE 'AKIA[0-9A-Z]{16}' .` |
| AWS secret | 40 base64 chars adjacent to an `aws` name | `grep -rEi 'aws(.{0,20})?(secret\|key)' .` |
| GitHub PAT | `ghp_[A-Za-z0-9]{36}`, `gho_`, `ghu_`, `ghs_`, `ghr_`, fine-grained `github_pat_` | `grep -rE 'gh[pousr]_[A-Za-z0-9]{36}' .` |
| Slack | `xox[baprs]-[A-Za-z0-9-]{10,}` | `grep -rE 'xox[baprs]-' .` |
| Google API | `AIza[0-9A-Za-z_-]{35}` | `grep -rE 'AIza[0-9A-Za-z_-]{35}' .` |
| Stripe | `sk_live_`, `rk_live_`, `pk_live_` | `grep -rE '(sk|rk|pk)_live_' .` |
| Private key | `-----BEGIN .* PRIVATE KEY-----` | `grep -rE 'BEGIN [A-Z ]*PRIVATE KEY' .` |
| JWT | `eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.` | `grep -rE 'eyJ[A-Za-z0-9_-]+\.eyJ' .` |
| Generic bearer | `Authorization: Bearer <literal>` | `grep -rEn 'Bearer [A-Za-z0-9._-]{20,}' .` |

Also flag: `password = "..."`, `passwd = "..."`, `secret = "..."`,
`api_key = "..."`, `token = "..."` with a non-empty literal, and connection
strings embedding credentials (`postgres://user:pass@host/db`).

In this analyzer, `os-environ` (`os.environ[`, `os.getenv(`) is a registered
taint source -- a secret read from the environment is the correct pattern and is
already recognized as flowing input, not a literal.

### Config and environment files

Check `.env` files committed to the repo, `.env.example` with real values filled
in, `docker-compose.yml` `environment:` blocks, Kubernetes manifests with
`secretKeyRef` replaced by a literal, and CI workflow files with `env:` blocks.
`.env.example` should contain placeholders only.

## How it works (attack mechanics)

The attacker does not exploit the secret through the application at all. They:

1. Clone or browse the repo (public repos are indexed continuously).
2. Read git history with `git log -p` -- deleting the line in a later commit does
   not remove it from any earlier commit object.
3. Use the credential where it works, usually hours after publication.

The "payload" here is passive: a clone. There is no request to send. That is why
this class is unauthenticated and remote by definition -- the repo is the
network service.

## Is it actually exploitable?

1. **Is it live?** An AWS key pair is live unless rotated; a Stripe test key
   `sk_test_` is not money; `pk_live_` is a publishable key by design and is not
   a secret.
2. **Is it a real secret or a placeholder?** `"changeme"`, `"YOUR_KEY_HERE"`,
   `"xxx"`, `""`, `<your-token>`, and `os.environ["KEY"]` are not secrets.
3. **Is it reachable?** A key in a test fixture pointing at a local mock is not
   the same as a production key in the request path.
4. **Is it already rotated?** If the credential has been revoked, it is a
   historical finding. Say so, do not drop it -- history matters for the
   disclosure.

## False positives (do NOT report)

- **Publishable keys.** Stripe `pk_live_`, a Firebase web API key, a Google Maps
  browser key restricted by referrer. Designed to be public.
- **Placeholders and docs.** `"YOUR_API_KEY"`, `"<token>"`, `sk_test_`, and
  values read from `os.environ` / a secret manager.
- **Test fixtures.** A token literal under `tests/`, `spec/`, `fixtures/`, or
  `__fixtures__/` pointing at a local mock.
- **`__pycache__`, `dist/`, `build/`, lockfiles, vendored dependencies.** If the
  directory is on the skip list it was not read; do not report from it.
- **Checksums, hashes, salts, nonces, and public keys.** Not credentials.
- **The strings inside this skill.** They are detection patterns, not leaked
  credentials.

Reporting a publishable key as a leaked secret is the classic false positive of
this class, and it is the one that most reliably teaches a reviewer to ignore
your next ten findings.

## Severity

Live credential, reachable, unauthenticated -- a network attacker who can read the
repo gains whatever the credential grants:

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N
https://www.first.org/cvss/calculator/4.0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N
```

VC:H and VI:H because a cloud credential typically reads and often writes
infrastructure; VA stays N unless the credential can also delete or scale
resources -- do not assume it can. If the credential only ever had read scope,
VI drops to N. Never compute the number yourself.

## Remediation

1. **Rotate first, then remove.** The secret is compromised the moment it was
   committed, independently of whether you delete the line. Removing without
   rotating leaves the credential live.
2. Read it from the environment or a secret manager:

   ```python
   # before                                # after
   AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/"   AWS_SECRET = os.environ["AWS_SECRET_ACCESS_KEY"]
   ```

3. Purge history only after rotation: `git filter-repo --path <file>`, or
   BFG. Coordinate, because a history rewrite invalidates every clone.
4. Add a pre-commit secret scan (`gitleaks`, `detect-secrets`) so the next one
   is caught before it lands.
5. For a CI-workflow secret, replace the literal with a repository secret
   reference and confirm the log no longer echoes it.

Removing the line while leaving the credential active is mitigation of the
symptom only. Say which you did.

## Verify the fix

- `git log -p --all -S '<first 8 chars of the secret>'` returns no commit. If it
  returns one, the credential is still in history and still compromised.
- `grep -rE '<the pattern>' .` across the working tree returns nothing.
- The credential is confirmed revoked at the provider (a console entry, an API
  call that now returns 401), not just deleted from the file.
- A test asserting the config raises a clear error when the environment variable
  is absent, so the value is never defaulted to a literal.
