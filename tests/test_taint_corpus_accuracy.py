"""Regression tests for analyzer defects found by the author's own probes.

HARNESS CONTRACT (read before editing this file)
------------------------------------------------
1. Every fixture is a self-contained source string written to a unique temp
   directory and removed in a ``finally`` block, so cleanup survives a failed
   assertion.
2. Analysis goes through ``analyze_python_file`` with a FRESH analyzer per call.
   The class method ``analyze_file`` accumulates state across calls on one
   instance (see ``test_shared_analyzer_instance_leaks_state_between_files`` in
   ``test_taint_analysis.py``), so it is not used here.
3. Output is ASCII only -- the console on this platform is cp1252 and raises
   ``UnicodeEncodeError`` on non-ASCII, which aborted a test run mid-suite.
4. Each test names the defect it guards against.  All of these were RED before
   the fix they name; the grouping is by defect, not by feature, so the point of
   each block is "this specific gap must not reopen".

THE DEFECTS
-----------
D-A  Every subprocess call matched the command-execution sink, so the
     recommended safe form -- an argv list with a constant program and no shell
     -- was reported as RCE.  The safe corpus scored like the vulnerable one.
D-B  ``os.path.basename`` was not registered as a path sanitizer, so the
     standard safe idiom ``open(join(base, basename(user)))`` was reported as
     traversal.
D-C  Nested sanitizers lost the strong inner one: ``join`` (weak) wrapping
     ``basename`` (strong) left only the weak sanitizer on the taint state.
D-D  An allowlist-guarded ternary -- ``redirect(x if x in allowed else "/")``,
     the recommended fix for open redirect -- was reported as a vulnerability.
D-E  Call-form Flask sources (``request.get_data()``, ``request.get_json()``)
     were absent from the registry, so handlers reading the raw body directly
     produced no finding.
D-F  SSTI written as ``Environment().from_string(...)`` (the common form after
     ``from jinja2 import Environment``) produced no finding.
"""

from __future__ import annotations

import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path

from triagekit.core.taint.analyzer import analyze_python_file


@contextmanager
def temp_python_file(source: str):
    """Yield a unique temp file holding ``source``; always cleaned up."""
    tmpdir = Path(tempfile.mkdtemp(prefix="triagekit_corpus_"))
    try:
        target = tmpdir / "case.py"
        target.write_text(source, encoding="utf-8")
        yield target
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def analyze(source: str) -> list:
    """Analyze ``source`` as a standalone file with a fresh analyzer."""
    with temp_python_file(source) as path:
        return analyze_python_file(str(path))


# ---------------------------------------------------------------------------
# D-A: command-injection false positive on the argv-list form
# ---------------------------------------------------------------------------


def test_argv_list_without_shell_is_not_command_injection():
    paths = analyze(
        "import subprocess\n"
        "from flask import request\n"
        "def f():\n"
        '    host = request.args.get("host")\n'
        '    return subprocess.run(["ping", "-c", "1", host], capture_output=True)\n'
    )
    assert paths == [], "argv-list subprocess must not be reported as RCE"


def test_argv_tuple_without_shell_is_not_command_injection():
    paths = analyze(
        "import subprocess\n"
        "from flask import request\n"
        "def f():\n"
        '    host = request.args.get("host")\n'
        '    return subprocess.run(("ping", host))\n'
    )
    assert paths == [], "an argv tuple is as inert as an argv list"


def test_argv_list_with_explicit_shell_false_is_not_reported():
    paths = analyze(
        "import subprocess\n"
        "from flask import request\n"
        "def f():\n"
        '    host = request.args.get("host")\n'
        '    return subprocess.run(["ping", host], shell=False)\n'
    )
    assert paths == []


def test_argv_list_with_shell_true_is_still_reported():
    """shell=True turns element 0 into a shell command line, so the list form
    is not a defence here."""
    paths = analyze(
        "import subprocess\n"
        "from flask import request\n"
        "def f():\n"
        '    host = request.args.get("host")\n'
        '    return subprocess.run(["ping", host], shell=True)\n'
    )
    assert len(paths) == 1, "shell=True with a list is still injectable"


def test_tainted_program_name_in_argv_list_is_still_reported():
    """A tainted element 0 runs an arbitrary binary; no shell required."""
    paths = analyze(
        "import subprocess\n"
        "from flask import request\n"
        "def f():\n"
        '    prog = request.args.get("p")\n'
        '    return subprocess.run([prog, "-c", "1"])\n'
    )
    assert len(paths) == 1, "a tainted program name must still be reported"


def test_shell_true_with_concatenated_command_is_reported():
    paths = analyze(
        "import subprocess\n"
        "from flask import request\n"
        "def f():\n"
        '    host = request.args.get("host")\n'
        '    return subprocess.run("ping -c 1 " + host, shell=True)\n'
    )
    assert len(paths) == 1


def test_shell_true_with_fstring_is_reported():
    paths = analyze(
        "import subprocess\n"
        "from flask import request\n"
        "def f():\n"
        '    host = request.args.get("host")\n'
        '    return subprocess.run(f"ping {host}", shell=True)\n'
    )
    assert len(paths) == 1


def test_os_system_is_reported():
    paths = analyze(
        "import os\n"
        "from flask import request\n"
        "def f():\n"
        '    host = request.args.get("host")\n'
        '    return os.system("ping " + host)\n'
    )
    assert len(paths) == 1


# ---------------------------------------------------------------------------
# D-B: os.path.basename is a genuine path-traversal sanitizer
# ---------------------------------------------------------------------------


def test_os_path_basename_is_not_path_traversal():
    paths = analyze(
        "import os\n"
        "from flask import request\n"
        "def f():\n"
        '    name = request.args.get("f", "")\n'
        '    with open(os.path.join("/var/data", os.path.basename(name))) as fh:\n'
        "        return fh.read()\n"
    )
    assert paths == [], "basename strips every directory component"


def test_os_path_basename_alone_still_blocks_traversal():
    """The same value without the join wrapper."""
    paths = analyze(
        "import os\n"
        "from flask import request\n"
        "def f():\n"
        '    name = request.args.get("f", "")\n'
        '    return open(os.path.basename(name)).read()\n'
    )
    assert paths == []


def test_join_without_basename_is_still_traversal():
    paths = analyze(
        "import os\n"
        "from flask import request\n"
        "def f():\n"
        '    name = request.args.get("f", "")\n'
        '    return open(os.path.join("/var/data", name)).read()\n'
    )
    assert len(paths) == 1, "an unbasenamed join must still be reported"


# ---------------------------------------------------------------------------
# D-C: a strong sanitizer must survive an outer weak one
# ---------------------------------------------------------------------------


def test_strong_sanitizer_survives_an_outer_weak_one():
    paths = analyze(
        "import os\n"
        "from flask import request\n"
        "def f():\n"
        '    name = request.args.get("f", "")\n'
        '    p = os.path.join("/var/data", os.path.basename(name))\n'
        "    return open(p).read()\n"
    )
    assert paths == []


# ---------------------------------------------------------------------------
# D-D: an allowlist-guarded ternary is not an open redirect
# ---------------------------------------------------------------------------


def test_allowlist_membership_ternary_is_not_open_redirect():
    paths = analyze(
        "from flask import request, redirect\n"
        "def f():\n"
        '    allowed = {"/home", "/about"}\n'
        '    nxt = request.args.get("next", "/home")\n'
        '    return redirect(nxt if nxt in allowed else "/home")\n'
    )
    assert paths == [], "the ternary guard is the recommended fix"


def test_unguarded_redirect_is_still_reported():
    paths = analyze(
        "from flask import request, redirect\n"
        "def f():\n"
        '    nxt = request.args.get("next", "/home")\n'
        "    return redirect(nxt)\n"
    )
    assert len(paths) == 1


def test_ternary_guarding_a_different_variable_is_still_reported():
    """``redirect(x if y in allowed else safe)`` does not validate x."""
    paths = analyze(
        "from flask import request, redirect\n"
        "def f():\n"
        '    a = request.args.get("a")\n'
        '    b = request.args.get("b")\n'
        '    return redirect(a if b in {"x"} else "/")\n'
    )
    assert len(paths) == 1, "a guard on another variable validates nothing"


def test_not_in_membership_ternary_is_still_reported():
    """``not in`` inverts the check; it does not validate the value."""
    paths = analyze(
        "from flask import request, redirect\n"
        "def f():\n"
        '    allowed = {"/home"}\n'
        '    nxt = request.args.get("next", "/home")\n'
        '    return redirect(nxt if nxt not in allowed else "/home")\n'
    )
    assert len(paths) == 1


# ---------------------------------------------------------------------------
# D-E: call-form Flask sources read attacker-controlled bodies
# ---------------------------------------------------------------------------


def test_request_get_data_is_a_source():
    paths = analyze(
        "import yaml\n"
        "from flask import request\n"
        "def f():\n"
        "    d = request.get_data()\n"
        "    return yaml.load(d)\n"
    )
    assert len(paths) == 1, "get_data() is the raw request body"


def test_request_get_json_is_a_source():
    paths = analyze(
        "from jinja2 import Environment\n"
        "from flask import request\n"
        "def f():\n"
        "    return Environment().from_string(request.get_json()).render()\n"
    )
    assert len(paths) == 1


def test_bare_request_data_is_a_source():
    paths = analyze(
        "import yaml\n"
        "from flask import request\n"
        "def f():\n"
        "    d = request.data\n"
        "    return yaml.load(d)\n"
    )
    assert len(paths) == 1, "a bare attribute read is as tainted as a subscript"


# ---------------------------------------------------------------------------
# D-F: SSTI written the common way produced no finding
# ---------------------------------------------------------------------------


def test_bare_environment_from_string_is_reported():
    paths = analyze(
        "from jinja2 import Environment\n"
        "from flask import request\n"
        "def f():\n"
        '    return Environment().from_string(request.args["n"]).render()\n'
    )
    assert len(paths) == 1


def test_bare_environment_call_is_reported():
    paths = analyze(
        "from jinja2 import Environment\n"
        "from flask import request\n"
        "def f():\n"
        '    t = request.args["n"]\n'
        '    return Environment().from_string(t).render()\n'
    )
    assert len(paths) == 1


# ---------------------------------------------------------------------------
# Standalone runner -- the corpus is also drivable without pytest.
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    tests = [
        (name, obj)
        for name, obj in sorted(globals().items())
        if name.startswith("test_") and callable(obj)
    ]
    passed = failed = 0
    for name, test in tests:
        try:
            test()
            passed += 1
            print("[PASS] %s" % name)
        except Exception as exc:  # noqa: BLE001 - report every failure
            failed += 1
            print("[FAIL] %s: %s: %s" % (name, type(exc).__name__, exc))
    print("")
    print("=" * 50)
    print("Results: %d passed, %d failed" % (passed, failed))
    print("=" * 50)
    raise SystemExit(1 if failed else 0)
