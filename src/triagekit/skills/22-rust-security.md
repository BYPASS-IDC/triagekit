# Rust security review (memory safety boundaries, not garbage collection)

## What it is

Rust removes the class of bug that dominates C/C++ reports -- use-after-free,
double-free, buffer overflow -- at compile time. What it does not remove is every
other class: command injection, path traversal, TLS validation disabled, weak
hashing, and unsafe deserialization are all fully available in safe Rust. And the
`unsafe { ... }` block is exactly where the compiler stops helping.

The trust boundary crossed in Rust is rarely a memory-safety boundary. It is
almost always the same boundary as everywhere else: attacker-controlled bytes
reaching a construct that interprets part of its input as instructions. Review
Rust for that, and treat `unsafe` as a separate, smaller review.

## Detection

TriageKit ships a Rust rule pack (`src/triagekit/core/analyzers/lang/rust_rules.py`).
Nine patterns, applied to `.rs` files. Cite the rule id in a finding:

| Rule id | Severity | CWE | Pattern |
| --- | --- | --- | --- |
| `rs-shell-command` | high | CWE-78 | `Command::new("sh"/"bash")` |
| `rs-cmd-format` | medium | CWE-78 | `.arg(... + ...)` or `.args(... format!(...))` |
| `rs-unsafe` | low | CWE-676 | any `unsafe {` block |
| `rs-unchecked` | medium | CWE-704 | `from_utf8_unchecked`, `transmute<` |
| `rs-path` | medium | CWE-22 | `std::fs::...` with `..`, or `PathBuf::from(...format!(...))` |
| `rs-tls-off` | high | CWE-295 | `danger_accept_invalid_certs(true)` |
| `rs-md5` | medium | CWE-328 | `md5::`, `Md5::`, `digest::MD5` |
| `rs-deser` | low | CWE-502 | `serde_json::from_str`, `from_slice(...)` |
| (general) `docker-*` | varies | CWE-250 | Dockerfile rules apply to `.rs` projects too |

### Rust-specific shapes to read by hand

    // 1. A panicking unwrap on untrusted input -> a remote DoS with a stack trace
    let id: u32 = user_input.parse().unwrap();          // panics on bad input

    // 2. Indexing by an untrusted value -> panic (safe Rust, still a DoS)
    let item = items[user_index];                        // no bounds check, panics

    // 3. unsafe used to skip a validation the safe API would enforce
    unsafe { std::str::from_utf8_unchecked(raw) }       // UB on malformed UTF-8

    // 4. A Command built from a string rather than arguments
    let cmd = format!("ls {}", user_dir);
    Command::new("sh").arg("-c").arg(cmd).output()       // rs-shell-command + rs-cmd-format

    // 5. TLS validation disabled to "make it work" in staging, left on
    Client::builder().danger_accept_invalid_certs(true).build()   // rs-tls-off

    // 6. Arc<Mutex<T>> poisoned by a panic, then .unwrap() on lock -> cascading panic
    let guard = state.lock().unwrap();                   // panics again after any panic

## How it works (attack mechanics)

The mechanics are the same as every other language; only the safety net differs.

- **Command injection.** `Command::new("sh").arg("-c").arg(format!("ls {}", d))`
  hands the whole string to a shell, so `d = "x; rm -rf /"` is parsed as shell
  grammar. The fix is `Command::new("ls").arg(d)` -- no shell, one argument.
- **Panic as denial of service.** `unwrap()` and unchecked indexing panic. A panic
  in a request handler unwinds that request; in an `actix-web` or `axum` handler
  the process usually survives, but the `?`-less unwrap pattern in a middleware
  or a `Drop` impl turns one bad request into an outage. There is no memory
  corruption, so the impact is availability only.
- **`unsafe`.** Inside `unsafe`, invariants you must maintain by hand become
  UB when violated. The common production cases are `transmute` between types of
  different sizes, `from_utf8_unchecked` on bytes from the network, and raw
  pointer aliasing. The exploitability question is whether the invariant can be
  broken by attacker-controlled input -- usually via a length or an encoding.

## Is it actually exploitable?

1. **`rs-shell-command`: does the argument come from outside the process?** A
   literal `Command::new("sh").arg("-c").arg("make all")` is a build script, not
   a finding.
2. **`rs-unsafe`: what invariant does the block rely on, and can input break it?**
   An `unsafe` block around a `static mut` in single-threaded init code is a
   different finding from one wrapping `from_utf8_unchecked` on a socket read.
3. **`rs-unchecked`: is the byte source untrusted?** `from_utf8_unchecked` on a
   compile-time constant is safe and should be a note, if that.
4. **Can the attacker cause the panic?** `.unwrap()` on a value the code
   constructed itself is a code-quality issue. `.unwrap()` on `user_input.parse()`
   is a remote DoS.
5. **`rs-deser`: is the deserialized value schema-validated before use?**
   `serde_json::from_str` alone is low severity -- it constructs plain data and
   does not execute. It becomes a finding when the value then reaches an unsafe
   sink without validation.

## False positives (do NOT report)

- **`unsafe` in `tests/` or a fixture.** Test code routinely breaks invariants on
  purpose.
- **`Command::new("sh")` with only literal arguments.** A build or release script.
- **`from_utf8_unchecked` on data the program produced.** Only untrusted bytes
  make it a finding.
- **`serde_json::from_str`.** Constructs data; does not execute. Low severity by
  design -- the rule is `low` for this reason.
- **`unwrap()` on an internal invariant** the code just established.
- **`transmute` between types of identical size and representation** in hot-path
  code with a documented invariant. Note it; a finding requires a way to break it.
- **`.arg(... + ...)` where the concatenated part is a literal.** Check before
  reporting.

The over-reporting trap in Rust is `unsafe`. A file with 40 `unsafe` blocks is
not 40 findings. It is one review of what the unsafe blocks assume.

## Severity

Command injection via a shell string, unauthenticated, as the service account:

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
https://www.first.org/cvss/calculator/4.0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
```

VA:H only if the attacker can actually crash the process -- `Command` gives them
arbitrary code, so they can, but justify it rather than assuming. TLS validation
disabled is `AV:A/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N`: `AV:A`
because the attacker must be on the path, and `AT:P` because being on the path is
a prerequisite. A panic-only unwrap is `AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`
-- `VA:L` because a single request crash is usually not a sustained denial, and
it must not be inflated. Never hand-compute the number.

## Remediation

```rust
// before
let cmd = format!("ls {}", user_dir);
Command::new("sh").arg("-c").arg(cmd).output()

// after -- no shell, so no grammar for an attacker to cross
Command::new("ls").arg(user_dir).output()

// before                                  // after
Client::builder()                          Client::builder()
    .danger_accept_invalid_certs(true)         // (deleted: validate by default)
    .build()                                   .build()

// before                                  // after
let id = user_input.parse().unwrap();      let id: u32 = match user_input.parse() {
                                                Ok(v) => v,
                                                Err(_) => return Err(BadRequest),
                                            };

// before                                  // after
unsafe { str::from_utf8_unchecked(raw) }   std::str::from_utf8(raw)?;
```

For `unsafe`, the remediation is not always deletion: it is a comment stating the
invariant and a debug assertion that checks it, so the assumption is testable.
For hashing, `rs-md5` -> `sha2::Sha256` or, for passwords, `argon2`/`bcrypt` with
a per-password salt -- not a faster hash.

## Verify the fix

- `grep -rn 'danger_accept_invalid_certs' --include='*.rs' .` excluding tests
  returns nothing.
- `grep -rn 'Command::new("sh"\|Command::new("bash"' --include='*.rs' .` returns
  nothing outside build scripts.
- `grep -rn 'from_utf8_unchecked\|transmute' --include='*.rs' .` -- each remaining
  hit has a stated invariant and an assertion above it.
- A test asserting a malformed UTF-8 or out-of-range payload returns an error
  response, not a panic (`should_panic` inverted).
- `cargo audit` and `cargo clippy -- -D warnings` clean, so the dependency and
  lint layers agree with the manual review.
