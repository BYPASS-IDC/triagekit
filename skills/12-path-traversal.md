# Path Traversal (CWE-22)

## What it is

Path traversal happens when text an attacker controls is used to build a
filesystem path, so the process reads or writes a file outside the directory it
intended to serve. The trust boundary crossed is request data (or CLI
argument, environment variable, file, or a stored filename from an upload) into
a filesystem operation. TriageKit reports this class as CWE-22 under the
finding category `taint-path-traversal`.

## Detection

### Python (the AST taint analyzer; the precision claims below are Python-only)

Taint is seeded at a recognized source (`request.args`, `request.form`,
`request.headers`, `request.cookies`, `sys.argv[...]`, `os.environ[...]`,
`input()`, `open(...).read()`, `.fetchone()` and friends) and followed through
assignments, `+`, `%`, f-strings, containers, and calls into functions defined
in the same file.

Sink shapes matched:

```python
open(path) / with open(path) as f:
os.path.join(base, part)
pathlib.Path(base, part)
send_file(path)
send_from_directory(base, name)
safe_join(base, name)
```

Reported shapes (each of these IS reported):

```python
name = request.args["report"]

open(os.path.join(REPORTS, name))          # join with a tainted later argument
open("/var/data/" + name)                  # concatenation
pathlib.Path(BASE, name)                   # pathlib join
send_file("/var/data/" + name)             # served to the client
open(name)                                 # absolute path swap: /etc/passwd
open(os.path.join(base_dir_from_user, "app.conf"))   # tainted base itself
```

Not reported shapes (each of these is NOT reported):

```python
open(os.path.join(REPORTS, os.path.basename(name)))     # basename strips dirs
p = pathlib.Path(REPORTS, os.path.basename(name))
with open(p) as f:
    ...
send_file(os.path.join(REPORTS, os.path.basename(name)))
open(name if name in ALLOWED else "index.html")         # allowlist ternary
open(ALLOWED[name])                                     # constant mapping index
```

Precise analyzer semantics, so the report can state them without guessing:

- The sink checks argument 0 (the path itself). For `os.path.join`,
  `pathlib.Path`, `safe_join` and `send_from_directory` this means the BASE is
  the checked argument. A tainted filename in a LATER argument of a join is not
  reported at the join; it is reported at the sink the joined value flows into
  (`open(...)`, `send_file(...)`). A tainted base in argument 0 is reported at
  the join call itself. Point the developer at the line the finding names, and
  say which of the two it is.
- `os.path.basename(x)` is a recognized neutralizing sanitizer for path
  traversal. Applied anywhere in the chain (innermost or outermost), it breaks
  the flow and the path is recorded as a sanitized, auditable flow rather than
  a finding.
- `os.path.join(dir, user_input)` WITHOUT basename is still reported. The join
  is recorded as an encountered transform, not as protection: it resolves `..`
  against the base at the filesystem level, which is exactly the failure mode.
- `os.path.normpath`, `os.path.realpath` and `pathlib.Path.resolve()` are
  recorded as encountered but do NOT neutralize the flow, because they keep
  `..` in the string. A finding that lists one of these in
  `sanitizers_encountered` is still a finding; the developer must add a
  containment check or a basename, or close it manually with evidence.
- An allowlist-guarded ternary (`value if value in ALLOWED else "safe"`) is
  recognized as validated: the tainted branch is only reached when the value
  passed a membership test, and the other branch is a constant. `not in` does
  NOT count, because it inverts the test rather than validating the value.
- A subscript of a constant container (`ALLOWED[name]`) does not propagate
  taint from the key, so a mapping lookup is clean. `ALLOWED.get(name)` DOES
  propagate taint, because a call passes the value through.
- `open(...)` is also a source: its result is tainted file contents. A flow
  from `open(user_path).read()` into another sink is real but is a second-order
  flow, and the narrative must say so.

### Other languages (pattern-level, not taint-tracked)

Look for `fs.readFile`, `fs.createReadStream`, `path.join` and `res.sendFile`
in JS/TS, and `fopen`, `file_get_contents`, `include`, `readfile` in PHP.
Archive extraction (zip-slip) sinks are registered by name pattern only; verify
member names by hand with the check in Remediation rather than trusting a
finding to appear.

## How it works (attack mechanics)

The path the process opens is base + attacker text. If no component strips or
rejects `..`, the attacker climbs out of the base. Payload shapes, against a
local fixture directory only:

- Climb: `../../../../etc/passwd`, repeated until the path escapes.
- Absolute swap: `/etc/passwd` as the whole value, which makes the join base
  irrelevant on POSIX because `os.path.join` discards the base when the second
  part is absolute.
- Encoded traversal: `%2e%2e%2f` or `..%2f`, which the web framework decodes
  before the handler sees it, so a check on the raw string is bypassed.
- Windows variants: backslash separators and drive letters (`..\..\boot.ini`,
  `C:\windows\...`), which a POSIX-shaped validator misses.
- Symlink follow: the path stays lexically inside the base but resolves
  outside it through a link planted earlier.
- Upload flows: a stored filename (`member.filename`, `attachment.filename`)
  used later in a download path. The boundary is crossed at the second flow,
  so the upload handler's own check is the only line of defence.

## Is it actually exploitable? (exploitability test)

1. Which argument does the finding point at, and what is in it? If the path is
   built from a constant base plus a sanitized component, the remaining risk is
   an absolute-path swap, which `os.path.join` alone does not stop.
2. Is the component user-controlled at the trust boundary, or does it come from
   internal code with a fixed set of values? A stored filename chosen by an
   earlier uploader is still attacker data; a value from a hardcoded mapping is
   not.
3. Read or write? `open(name)` defaults to read; `open(name, "w")` or
   `send_file` after a write turns a confidentiality finding into an integrity
   and availability finding (arbitrary file overwrite, config or key swap).
4. Does the process have the privilege to reach the target? A worker running
   as an unprivileged user cannot read `/etc/shadow`; a root or
   filesystem-capable container can. Check the deployment, not the code.
5. Is the check applied to the same encoding the handler receives? A check on
   the raw query string is bypassed by percent-encoding; check the decoded
   value, after the framework has parsed it.

## False positives (do NOT report)

- `open(os.path.join(DIR, os.path.basename(name)))`,
  `pathlib.Path(DIR, os.path.basename(name))` and
  `send_file(os.path.join(DIR, os.path.basename(name)))`. basename removes
  every directory component, so `../` is discarded. Not reported.
- `open(name if name in ALLOWED else "index.html")` and any ternary whose test
  is a positive membership check on the same variable and whose other branch is
  a constant. Not reported. `x if y in ALLOWED else "/"` guards `y`, not `x`,
  and is still reported if `x` is what flows to the sink.
- `open(ALLOWED[request.args["report"]])` where `ALLOWED` maps keys to constant
  filenames. The subscript does not propagate taint from the key, and the text
  reaching the path is a value the code chose.
- A join where every component is a constant or deployment configuration:
  `open(os.path.join(CONFIG["data_dir"], "schema.sql"))`.
- Taint in a non-path argument. The sink checks argument 0, so
  `open(TEMPLATE_PATH, mode=...)` with a tainted mode is not a traversal
  finding. Do not report it as one.
- `os.path.normpath(...)` or `Path.resolve()` used alone as the defence. These
  are reported (they do not remove `..`), which is correct: a normalizer that
  is not followed by a containment check is not a sanitizer. If the code has a
  real containment check, close it with evidence via
  skills/27-false-positive-control.md rather than reporting a bare normpath as
  a finding.
- `safe_join` / `send_from_directory` with a tainted BASE. The finding is real
  in shape (an attacker-named directory), but verify the actual value: a base
  assembled from constants is not reachable, and close it with evidence.

## Severity

Representative vector for an unauthenticated handler that serves files from a
configurable root on a single-tenant application host:

    CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N

Calculator: `https://www.first.org/cvss/calculator/v4.0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`

How the metrics move, without computing a score (v4.0 is a lookup table; never
produce a number by hand): VC is H for arbitrary read. VI and VA rise from N to
H when the same path is a write or an overwrite of a config, key or code file.
AV is N for a web handler, L for a local CLI. PR rises from N when the endpoint
requires a session. AT rises to P when the payload must be planted earlier
(symlink or upload). SC, SI and SA rise when the process can read other
tenants' data or shared infrastructure files.

## Remediation

Strip every directory component with basename, before and after:

```python
# before
name = request.args["report"]
return send_file(os.path.join(REPORTS, name))

# after
name = os.path.basename(request.args["report"])
return send_file(os.path.join(REPORTS, name))
```

Prefer a mapping from a fixed set of keys, before and after:

```python
# before
return send_file(os.path.join(REPORTS, request.args["report"]))

# after -- the value that reaches the path is a constant the code chose
REPORTS = {"summary": "summary.csv", "errors": "errors.csv"}
key = request.args["report"]
if key not in REPORTS:                      # or: REPORTS[key] with a 400 handler
    abort(404)
return send_file(os.path.join(BASE, REPORTS[key]))
```

Keep the containment check as a second line of defence when the input is a path
rather than a key:

```python
base = pathlib.Path(REPORTS).resolve()
target = (base / os.path.basename(name)).resolve()
if base not in target.parents:
    abort(404)
with open(target, "rb") as f:
    ...
```

Note for the reviewer: `resolve()` and `normpath` are not recognized as
neutralizing, so a flow guarded only by the containment check above (no
basename) is still reported. That is deliberate; the containment check is
correct but the finding must be closed with evidence.

For uploads and archives, validate member names before extracting:

```python
# before
with zipfile.ZipFile(upload) as z:
    z.extractall(dest)                      # a member may escape dest

# after
root = pathlib.Path(dest).resolve()
with zipfile.ZipFile(upload) as z:
    for member in z.namelist():
        target = (root / member).resolve()
        if root not in target.parents:
            raise BadZipFile("unsafe member path")
    z.extractall(dest)
```

Also: re-encode on the way out. A filename echoed into a `Content-Disposition`
header is an injection surface of its own; quote it or send a fixed name (see
skills/19-headers-and-cookies.md for header injection).

## Verify the fix

1. Behavioural test, against a scratch directory:

```python
def test_report_name_cannot_escape_base(client, tmp_path):
    base = tmp_path / "reports"
    base.mkdir()
    for payload in ("../../etc/passwd", "../etc/passwd", "..%2f..%2fetc/passwd"):
        r = client.get("/report", query_string={"name": payload})
        assert r.status_code in (400, 404)
        assert b"root:" not in r.content
    assert set(p.name for p in base.iterdir()) <= {"summary.csv", "errors.csv"}
```

2. Source check for sinks that still take raw request data:

```
grep -rnE '(open\(|os\.path\.join|pathlib\.Path|send_file|send_from_directory|safe_join)' --include='*.py' .
```

Every hit must be reviewed for a `basename`, a mapping index, or a containment
check on the path it produces.

3. Re-scan and confirm the finding is gone:

```
triagekit scan <path> --json
```

There must be no finding with category `taint-path-traversal` pointing at the
touched file. A basename-guarded path produces no finding at all; the flow is
recorded as sanitized, not re-scored.

Cross-reference: skills/06-injection-surface.md for how this class is routed
into triage, skills/26-finding-narrative.md for the trace wording, and
skills/27-false-positive-control.md when a reported flow must be closed as a
false positive with evidence.
