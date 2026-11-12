# Cryptography and TLS (CWE-327: broken hash, CWE-295: certificate validation)

## What it is

Two classes that look alike in a scan and are not alike in impact. **Weak
cryptography** is using an algorithm or mode that an attacker can break --
MD5 or SHA-1 for a security decision, a non-AEAD cipher mode, a short RSA key, a
hardcoded IV, ECB mode. **Broken certificate validation** is failing to check the
TLS identity of the peer, which turns encryption into obfuscation: the traffic is
unreadable to a bystander and fully readable to the attacker who is in the path.

The trust boundary crossed is different for each. Broken crypto crosses the
boundary by making a secret computable; broken validation crosses it by removing
the check that established who you were talking to.

## Detection

### Weak hashes and ciphers

| Look for | Problem | Replace with |
| --- | --- | --- |
| `hashlib.md5(`, `hashlib.sha1(` | Collision-broken; fine for checksums, not for security | `hashlib.sha256(` or `hashlib.sha3_256(` |
| `hashlib.new('md5')`, `Crypto.Hash.MD5` | Same | as above |
| `DES.new(`, `Blowfish.new(`, `ARC4.new(` | Broken or obsolete block sizes | `AES.new(key, AES.MODE_GCM)` |
| `AES.MODE_ECB` | Deterministic; leaks plaintext structure | `AES.MODE_GCM` |
| `random.` for a token, key, nonce, or IV | Not a CSPRNG; predictable from observed outputs | `secrets.token_urlsafe()`, `secrets.token_bytes()` |
| `iv = b'0' * 16`, a constant IV with CBC | Identical plaintext blocks encrypt identically | `os.urandom(16)` per message, or use AEAD |
| `rsa.generate(1024)`, `EC_KEY_SIZE = 160` | Too small to resist factoring/discrete log | RSA >= 3072, EC >= 256 |
| `verify=False` anywhere in an HTTP call | Certificate validation disabled | Remove the flag |

The registry carries `weak-hash` as a weak-cryptography sink; a taint path into
it from a source is reportable, and the same pattern with no taint source is a
note.

### TLS and validation

    requests.get(url, verify=False)            # CWE-295, the big one
    ssl._create_default_https_context = ssl._create_unverified_context
    ssl.CERT_NONE
    requests.get(url, verify="/path/to/cert")  # fine, but pinning -- note it
    urllib3.disable_warnings()                 # hides the warning, not the risk

`urllib3.disable_warnings()` is almost always found next to `verify=False` and is
strong evidence of the pattern even when the `verify=False` is in another file.

### TLS configuration

Minimum TLS version, cipher list, and HSTS. `ssl.PROTOCOL_TLSv1` and
`PROTOCOL_TLSv1_1` are deprecated; `PROTOCOL_TLS_CLIENT` picks the best available.
Cipher strings that still permit `RC4`, `3DES`, or `aNULL`/`eNULL` are findings.

## How it works (attack mechanics)

**Collision.** MD5 and SHA-1 are collision-broken, not preimage-broken. For
password hashing or a signature, a collision is not directly the attack; the
attack is that the construction (`md5(password)`, `sha1(file) == known_hash`)
admits a better forgery or a rainbow-table lookup. Where a hash is used for
password storage, the real defect is usually the absence of a salt and a KDF --
so look for `md5(password)` and fix it to `argon2`/`bcrypt`/`scrypt`, not to
`sha256(password)`, which is only marginally better.

**Predictable randomness.** `random.random()` and `random.randint()` are seeded
Mersenne Twister. Observing ~624 outputs recovers the state and every subsequent
value, so a token or password reset code generated with `random` is predictable
after enough observation. No network position required, just repeated requests.

**MITM.** With `verify=False`, the client accepts any certificate. Any party who
can intercept the connection -- a hostile Wi-Fi AP, a compromised router, an
on-path ISP, a DNS poisoning -- presents their own certificate and reads the
session. The traffic looks encrypted in a packet capture and is not confidential.

## Is it actually exploitable?

1. **Is the primitive used for a security decision?** An MD5 checksum for cache
   invalidation is a note; an MD5 hash for password recovery is a finding.
2. **Is the random value predictable, and does unpredictability matter?** A
   random pick for a test fixture does not need `secrets`; a password reset code
   does.
3. **Is `verify=False` in production code or test code?** In `tests/` against a
   local mock it is near-universal and is a note. In the request path it is a
   finding, and the impact is total.
4. **Is the input to the hash attacker-controlled?** A hash over a value the
   attacker cannot influence is a lower-severity finding.

## False positives (do NOT report)

- **Test and fixture code.** `verify=False` in a test, `md5` on a fixture, a
  constant IV in a unit test.
- **Non-security hashes.** MD5 as a cache key, a deduplication checksum, a
  file-content hash compared against a known-good value with a length check.
- **`hashlib.sha256` used for a password.** Correct hash algorithm, wrong
  construction -- note it with the KDF recommendation rather than reporting it
  as "weak hash".
- **Public keys and fingerprints.** A hardcoded certificate thumbprint used for
  pinning is a control, not a secret.
- **Deprecation notices only.** A flagged `sha1` with a comment explaining it is
  required by an external protocol integration is a note.

## Severity

Certificate validation disabled, network-adjacent attacker in the path:

```
CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N
https://www.first.org/cvss/calculator/4.0#CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N
```

`AC:H` is wrong here -- being in the path is a **prerequisite**, which is `AT:P`,
not a security mechanism to evade (`AC`). `SC/SI:H` because the intercepted
subsequent system traffic is exposed. Predictable randomness in a reset token is
`AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` -- no prerequisite, the
attacker just needs outputs to observe. Never hand-compute the number.

## Remediation

```python
# TLS validation
requests.get(url)                                   # not verify=False
requests.get(url, verify="/etc/ssl/certs/ca.pem")   # when pinning is intended

# Hashing
hashlib.sha256(data)                                # not md5/sha1
hashlib.blake2b(data)                               # faster, also fine

# Passwords
from argon2 import PasswordHasher
PasswordHasher().hash(password)                     # not md5(password)

# Randomness
import secrets
token = secrets.token_urlsafe(32)                   # not random.random()

# Encryption
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
AESGCM(key).encrypt(nonce, plaintext, aad)          # not ECB, not a constant IV
```

For password storage the fix is a KDF (argon2id, bcrypt, scrypt) with a per-password
salt -- not a faster hash. For encrypted data the fix is an AEAD mode (GCM,
ChaCha20-Poly1305) which authenticates as well as encrypts; CBC provides no
integrity and invites padding-oracle attacks.

## Verify the fix

- `grep -rn 'verify=False' --include='*.py' .` excluding `tests/` returns nothing.
- `grep -rn 'md5\|sha1' --include='*.py' .` excluding tests and checksum helpers
  returns nothing.
- `grep -rn 'random\.' --include='*.py' .` in files handling tokens returns nothing.
- A test asserting the client raises on an untrusted certificate
  (`pytest.raises(requests.exceptions.SSLError)` against a self-signed host).
- A test asserting two identical inputs produce different hashes, proving the
  salt is per-record.
