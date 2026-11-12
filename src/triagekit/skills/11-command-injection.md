# Command Injection (CWE-78)

## What it is

Command injection happens when text an attacker controls reaches an OS command
execution primitive and is parsed by a shell as syntax rather than passed to a
program as one argument. The trust boundary crossed is request data (or CLI
argument, environment variable, file, or prior process output) into a process
spawn. TriageKit reports this class as CWE-78 under the finding category
`taint-command-execution`.

## Detection

### Python (the AST taint analyzer; the precision claims below are Python-only)

Taint is seeded at a recognized source (`request.args`, `request.form`,
`request.headers`, `request.cookies`, `sys.argv[...]`, `os.environ[...]`,
`input()`, `open(...).read()`, `.fetchone()` and friends) and followed through
assignments, `+`, `%`, f-strings, lists and tuples, and calls into functions
defined in the same file. The sink consumes argument 0.

Sink shapes matched:

```python
os.system(cmd)
subprocess.call(cmd) / subprocess.run(cmd) / subprocess.Popen(cmd)
subprocess.check_output(cmd)
os.popen(cmd) / subprocess.getoutput(cmd) / subprocess.getstatusoutput(cmd)
commands.getstatusoutput(cmd) / commands.getoutput(cmd)   # py2 spelling
subprocess.run(cmd, shell=True)                            # shape sink
```

Reported shapes (each of these IS reported):

```python
host = request.args["host"]

os.system("ping -c 1 " + host)                        # string form
os.system(f"ping -c 1 {host}")                        # f-string form
subprocess.run("ping -c 1 " + host)                   # string arg, shell parsed
subprocess.run(f"ping -c 1 {host}", shell=True)       # f-string + shell=True
subprocess.call(["sh", "-c", "ping " + host], shell=True)
subprocess.run(["ping", host], shell=True)            # list, but shell=True
prog = request.args["prog"]
subprocess.run([prog, "-c", "1"])                     # tainted element 0
subprocess.run(["ping"] + [host])                     # program not a literal
subprocess.check_output("grep -r " + pat, shell=True)
os.popen("grep " + pat + " " + path)
commands.getstatusoutput("host " + host)
```

Not reported shapes (each of these is NOT reported):

```python
subprocess.run(["ping", "-c", "1", host])             # argv list, constant program
subprocess.Popen(["convert", src, dst])               # constant program
subprocess.run(["ping", "-c", "1", host], shell=False)
subprocess.run([sys.executable, "app.py", arg])       # constant program
os.system("ping -c 1 " + shlex.quote(host))           # quoted shell arg
subprocess.run("ping -c 1 " + shlex.quote(host))
```

Precise analyzer semantics, so the report can state them without guessing:

- An argv list (argument 0 is a non-empty list or tuple literal) with no
  `shell=True` and a literal first element is treated as safe: no shell parses
  the arguments, so metacharacters are inert data. The flow is recorded as a
  sanitized, auditable flow, never as a finding.
- That exemption requires ALL THREE conditions. It is lost when `shell=True`
  is passed (the first element becomes a shell command line), when element 0 is
  not a literal constant (the program name itself is attacker-controlled), or
  when argument 0 is not a list literal at all (a plain string is parsed by the
  shell on POSIX).
- `shlex.quote(...)` is evaluated as a neutralizing sanitizer for command
  execution. A quoted value inside a string, `%`-format or f-string breaks the
  flow and is not reported.
- The sink checks argument 0. Taint in a later argument (`cwd=`, `env=`,
  `input=`, or an argv element of an exempted list) does not produce a finding
  on its own.
- Interprocedural flows are reported at the sink line inside the callee, with
  the caller's source in the trace.

Known gap to state honestly when triaging: `subprocess.check_call(...)` is not
in the sink list, so a tainted command passed to `check_call` produces no
taint finding. Treat such a call as a finding on manual review and say in the
narrative that the taint engine did not cover it.

### Other languages (pattern-level, not taint-tracked)

Look for `child_process.exec` / `execSync` / `execFile` / `spawn` in JS/TS and
`exec` / `shell_exec` / `system` / `passthru` / backtick shell in PHP. In JS,
`exec` runs a shell; `spawn` and `execFile` do not, so the same
list-versus-string distinction applies. These findings come from the pattern
scanners, so they carry lower confidence than a Python taint trace.

## How it works (attack mechanics)

In the string and `shell=True` forms, the command is parsed by `/bin/sh -c`, so
shell metacharacters in the tainted region terminate the intended command and
start another one. Payload shapes, against a local fixture only:

- Sequencing: `; rm -rf target` or `&& curl ...`.
- Substitution: backticks and `$(...)`, which run even inside double quotes.
- Redirection and pipes: `> file`, `| sh`.
- Newline, which `sh` treats as a command separator.

In the argv-list form the kernel receives an argv array through `execve`; no
shell parses it, so `; rm -rf /` is one inert argument to `ping`. The two ways
that form still fails are a tainted element 0 (the program name is arbitrary,
so the attacker runs any binary) and `shell=True` (which rebuilds a command
line from the list before parsing it).

## Is it actually exploitable? (exploitability test)

1. Is the form a string or `shell=True`, or an argv list? Check the sink line:
   `os.system(x)` and `subprocess.run(x, shell=True)` are shell-parsed;
   `subprocess.run([...])` with a constant element 0 is not.
2. If it is an argv list, is element 0 a literal? `["ping", host]` is inert;
   `[request.args["prog"], "-c", "1"]` runs an attacker-named binary and is a
   finding even though it is a list.
3. Does the tainted value actually reach argument 0 of the sink, or does it
   stop in a helper, a log line, or an unrelated argument? The trace's last
   hop names the sink call; the `evidence` field lists every hop before it.
4. Is the input constrained upstream? A strict charset check such as
   `^[A-Za-z0-9._-]+$` applied before the sink removes every metacharacter, so
   the flow is real but not exploitable as written; say so and recommend the
   fix anyway, because the check is one refactor away from being dropped.
5. Is the sink reachable unauthenticated, and does the process run with more
   privilege than the request deserves? A worker running as root that spawns a
   shell from a web parameter is the worst case in this class.

## False positives (do NOT report)

- `subprocess.run(["ping", "-c", "1", host])`, `subprocess.Popen([...])` and
  every other argv list whose element 0 is a string literal and which passes no
  `shell=True`. This is the recommended fix; reporting it punishes correct
  code.
- `subprocess.run(["ping", "-c", "1", host], shell=False)` and
  `subprocess.check_output(["git", "rev-parse", "HEAD"])` with constant
  programs.
- A shell argument wrapped in `shlex.quote(...)`, for example
  `os.system("ping -c 1 " + shlex.quote(host))`. The analyzer neutralizes this
  and records it as a sanitized flow.
- Commands assembled entirely from constants and deployment configuration:
  `subprocess.run([CONFIG["editor"], CONFIG["file"]])`. No taint, no finding.
- A list assembled at runtime with `+` (for example `[cmd] + extra`) IS still
  reported, because argument 0 is not a list literal in the AST even though the
  runtime behavior is the same as an argv list. Verify element 0 is constant,
  then close it with skills/27-false-positive-control.md and cite this section.
- A CLI tool whose only source is `sys.argv[1]` passed to a fixed subcommand
  through an argv list. The exemption covers it: the value is one argument.

## Severity

Representative vector for an unauthenticated web handler that spawns a shell
on the application host:

    CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N

Calculator: `https://www.first.org/cvss/calculator/v4.0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`

How the metrics move, without computing a score (v4.0 is a lookup table; never
produce a number by hand): AV is N for a web handler, L for a build or CI
runner invoked locally. AT rises to P when the payload must be delivered by a
scheduled job or a second user action. PR rises from N when the endpoint
requires a session. VC, VI and VA stay H for arbitrary command execution as
the service account. SC, SI and SA stay N when the process is containerized
with no lateral access, and rise when it can reach other hosts or a cluster
control plane.

## Remediation

String form to argv list, before and after:

```python
# before
os.system("ping -c 1 " + host)

# after
subprocess.run(["ping", "-c", "1", host], check=True, timeout=10)
```

`shell=True` removed, before and after:

```python
# before
subprocess.run(f"ping -c 1 {host}", shell=True)

# after
subprocess.run(["ping", "-c", "1", host], check=True, timeout=10)
```

Attacker-named program, before and after. The program must come from a mapping
the code owns:

```python
# before
tool = request.args["tool"]
subprocess.run([tool, "--version"])

# after -- a constant mapping, indexed; the value that reaches execve is one
# of a fixed set of programs the code chose
PINGS = {"ping": ["ping", "-c", "1"], "traceroute": ["traceroute", "-n"]}
spec = PINGS[request.args["tool"]]          # unknown key -> KeyError -> 400
subprocess.run(spec, check=True, timeout=10)
```

Use a subscript, not `.get()`: a `.get()` call propagates taint and the flow is
reported again.

When a shell is genuinely required (shell pipelines, globbing, `&&` between
fixed commands), keep the fixed parts as constants and quote every variable:

```python
# before
subprocess.run(f"grep {pattern} {path}", shell=True)

# after -- quoting makes the injected value a single literal argument
subprocess.run(
    ["sh", "-c", "grep " + shlex.quote(pattern) + " " + shlex.quote(path)],
    check=True,
)
```

Add `check=True` and `timeout=` on every spawn: a hung child is an availability
problem even without injection. Log the argv list, never a rendered shell line,
so logs cannot be used as a second injection surface.

## Verify the fix

1. Behavioural test, against a scratch directory:

```python
def test_host_metacharacters_are_inert(client, tmp_path):
    marker = tmp_path / "pwned"
    r = client.get("/ping", query_string={"host": f"127.0.0.1; touch {marker}"})
    assert not marker.exists()
    assert r.status_code == 200
```

2. Source check for shell-form leftovers:

```
grep -rnE '(os\.system|os\.popen|shell\s*=\s*True|commands\.get)' --include='*.py' .
```

Every hit must be a test fixture or a startup script that builds its command
from constants. There must be no `shell=True` in request-handling code.

3. Re-scan and confirm the finding is gone:

```
triagekit scan <path> --json
```

There must be no finding with category `taint-command-execution` pointing at
the touched file, and the argv-list call that produced a sanitized flow must
still produce no finding after the change.

Cross-reference: skills/06-injection-surface.md for how this class is routed
into triage, skills/26-finding-narrative.md for the trace wording, and
skills/27-false-positive-control.md when a reported flow must be closed as a
false positive with evidence.
