"""Regression tests for the Python taint analyzer.

HARNESS CONTRACT (read before editing this file)
------------------------------------------------
1. Every fixture is written into a unique temporary directory created for that
   single test and removed in a ``finally`` block, so cleanup survives a failed
   assertion and no two tests can collide on the same path.
2. All analysis goes through ``analyze_python_file`` / ``analyze_python_directory``.
   Those module helpers construct a FRESH ``PythonTaintAnalyzer`` per call.  The
   class method ``PythonTaintAnalyzer.analyze_file`` accumulates state across
   calls on one instance (verified: ``test_shared_analyzer_instance_leaks_state_between_files``),
   so a test must only reuse an instance when it is testing that defect.
3. Output is ASCII only.  The console on this platform is cp1252 and raises
   ``UnicodeEncodeError`` on emoji, which previously aborted tests mid-run.
4. Tests assert analyzer behaviour, not merely "no exception was raised".

KNOWN DEFECTS
-------------
Thirteen analyzer defects were verified against ``master`` on 2026-11-09 and
each was encoded as a test decorated with ``@known_defect(expected, actual)``
that was expected to FAIL until the analyzer was repaired, with
``KNOWN_ANALYZER_DEFECTS`` recording expected versus actual behaviour so that
each failure was a specification rather than a surprise.  Deleting or weakening
those tests to obtain a green run would have hidden a genuine false negative or
false positive, so the analyzer was repaired instead and each marker removed as
its defect was fixed.  The registry is now empty and all thirteen live on below
as ordinary regression tests with their original assertions intact.

The decorator and the registry are retained so that the next defect can be
labelled the same way; ``test_known_defect_registry_is_documented`` fails if a
labelled test and the registry disagree.
"""

from __future__ import annotations

import ast
import os
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path

from triagekit.core.taint.analyzer import (
    PythonTaintAnalyzer,
    analyze_python_directory,
    analyze_python_file,
)
from triagekit.core.taint.models import TaintKind

# ---------------------------------------------------------------------------
# Known-defect registry: test name -> (expected behaviour, actual behaviour)
# ---------------------------------------------------------------------------

KNOWN_ANALYZER_DEFECTS: dict[str, tuple[str, str]] = {}


def known_defect(expected: str, actual: str):
    """Label a test as encoding a verified analyzer defect (expected to fail)."""

    def decorator(func):
        func.__known_defect__ = (expected, actual)  # type: ignore[attr-defined]
        KNOWN_ANALYZER_DEFECTS[func.__name__] = (expected, actual)
        return func

    return decorator


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


@contextmanager
def temp_python_file(source: str, filename: str = "case.py"):
    """Yield a unique temp file holding ``source``; always cleaned up."""
    tmpdir = Path(tempfile.mkdtemp(prefix="triagekit_taint_"))
    try:
        target = tmpdir / filename
        target.write_text(source, encoding="utf-8")
        yield target
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@contextmanager
def temp_python_directory(files: dict[str, str]):
    """Yield a unique temp directory populated with ``{name: source}``."""
    tmpdir = Path(tempfile.mkdtemp(prefix="triagekit_taint_dir_"))
    try:
        for name, source in files.items():
            (tmpdir / name).write_text(source, encoding="utf-8")
        yield tmpdir
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def analyze(source: str, filename: str = "case.py") -> list:
    """Analyze ``source`` as a standalone file with a fresh analyzer."""
    with temp_python_file(source, filename) as path:
        return analyze_python_file(str(path))


def analyze_dir(files: dict[str, str]) -> list:
    """Analyze a directory of files with a fresh analyzer."""
    with temp_python_directory(files) as tmpdir:
        return analyze_python_directory(str(tmpdir), 100)


def line_of_call(source: str, dotted_name: str) -> int:
    """Return the 1-based line of the first call to ``dotted_name``."""
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call) and ast.unparse(node.func) == dotted_name:
            return node.lineno
    raise AssertionError("fixture contains no call to %s" % dotted_name)


def line_of_def(source: str, name: str) -> int:
    """Return the 1-based line of the ``def`` for ``name``."""
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node.lineno
    raise AssertionError("fixture contains no def %s" % name)


def describe(paths: list) -> str:
    """Compact ASCII rendering of taint paths for assertion messages."""
    return "; ".join(
        "%s(%s) line %s in %s sanitized=%s"
        % (p.source.name, p.source.category, p.sink_line, os.path.basename(p.sink_file), p.is_sanitized)
        for p in paths
    ) or "<no paths>"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SQL_FSTRING = '''
import sqlite3


def get_user(name):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    conn = sqlite3.connect('test.db')
    cursor = conn.execute(query)
    return cursor.fetchall()


if __name__ == "__main__":
    user = input("Enter name: ")
    get_user(user)
'''

SQL_PERCENT = '''
import sqlite3


def get_user(name):
    query = "SELECT * FROM users WHERE name = '%s'" % name
    conn = sqlite3.connect('test.db')
    conn.execute(query)
    return conn.fetchall()


if __name__ == "__main__":
    user = input("Enter name: ")
    get_user(user)
'''

SQL_PARAMETERIZED = '''
import sqlite3


def get_user(name):
    query = "SELECT * FROM users WHERE name = ?"
    conn = sqlite3.connect('test.db')
    conn.execute(query, (name,))
    return conn.fetchall()


if __name__ == "__main__":
    user = input("Enter name: ")
    get_user(user)
'''

CMD_MODULE_LEVEL = '''
import os

user = input("Enter: ")
os.system(user)
'''

CMD_VIA_FUNCTION = '''
import os


def run_cmd(user_input):
    os.system(user_input)


if __name__ == "__main__":
    user = input("Enter command: ")
    run_cmd(user)
'''

FLASK_CMD = '''
from flask import request
import subprocess


def handle_request():
    user_input = request.args.get('cmd')
    subprocess.run(user_input, shell=True)


if __name__ == "__main__":
    handle_request()
'''

FLASK_PATH_TRAVERSAL = '''
from flask import request


def read_file():
    filename = request.args.get('file')
    with open(filename) as f:
        return f.read()


if __name__ == "__main__":
    read_file()
'''

SYS_ARGV = '''
import sys
import os

if __name__ == "__main__":
    user = sys.argv[1]
    os.system(user)
'''

OS_ENVIRON = '''
import os


def run_cmd():
    cmd = os.environ.get('USER_CMD', '')
    os.system(cmd)


if __name__ == "__main__":
    run_cmd()
'''

KEYWORD_ARG = '''
import subprocess


def run_cmd(cmd, shell=True):
    subprocess.run(cmd, shell=shell)


if __name__ == "__main__":
    user = input("Enter: ")
    run_cmd(cmd=user)
'''

POSITIONAL_ARG_NONZERO = '''
import os


def run_cmd(cmd, arg):
    os.system(cmd + " " + arg)


if __name__ == "__main__":
    user = input("Enter: ")
    run_cmd("echo", user)
'''

NESTED_CALLS = '''
import sqlite3


def level1(name):
    return level2(name)


def level2(name):
    return level3(name)


def level3(name):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    conn = sqlite3.connect('test.db')
    conn.execute(query)


if __name__ == "__main__":
    user = input("Enter: ")
    level1(user)
'''

CROSS_FUNCTION = '''
import sqlite3


def process_name(name):
    return f"Name: {name}"


def query_db(user_input):
    processed = process_name(user_input)
    query = f"SELECT * FROM users WHERE name = '{processed}'"
    conn = sqlite3.connect('test.db')
    conn.execute(query)


if __name__ == "__main__":
    user = input("Enter: ")
    query_db(user)
'''

MULTIPLE_PATHS = '''
import os
import sqlite3


def query_db(name):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    conn = sqlite3.connect('test.db')
    conn.execute(query)


def run_cmd(cmd):
    os.system(cmd)


if __name__ == "__main__":
    user1 = input("Enter name: ")
    user2 = input("Enter cmd: ")
    query_db(user1)
    run_cmd(user2)
'''

SAFE_CODE = '''
import sqlite3
import os


def get_user_safe(name):
    # Parameterized query - SAFE
    query = "SELECT * FROM users WHERE name = ?"
    conn = sqlite3.connect('test.db')
    conn.execute(query, (name,))
    return conn.fetchall()


def run_cmd_safe(cmd):
    # Fixed command - SAFE
    os.system("ls -la")


def main():
    user = input("Enter name: ")
    get_user_safe(user)
    run_cmd_safe("")


if __name__ == "__main__":
    main()
'''

# Deduplication fixtures.  These are deliberately MODULE LEVEL: an
# interprocedural path reports the callee's def line rather than the sink call
# site (see test_sink_line_points_to_sink_call_not_function_definition), which
# would collapse two sinks on different lines into one reported location and
# confound this test.  Module-level paths report accurate line numbers.
SAME_LINE_DUPLICATE_SINK = (
    "import os\n"
    "user = input('Enter: ')\n"
    "os.system(user); os.system(user)\n"
)

DIFFERENT_LINE_DUPLICATE_SINK = (
    "import os\n"
    "user = input('Enter: ')\n"
    "os.system(user)\n"
    "os.system(user)\n"
)

VULNERABLE_FILE = (
    "import sqlite3\n"
    "def get_user(name):\n"
    '    query = f"SELECT * FROM users WHERE name = \'{name}\'"\n'
    "    conn = sqlite3.connect('test.db')\n"
    "    conn.execute(query)\n"
    "if __name__ == '__main__':\n"
    "    user = input('Enter: ')\n"
    "    get_user(user)\n"
)

SAFE_FILE = (
    "import sqlite3\n"
    "def get_user(name):\n"
    '    query = "SELECT * FROM users WHERE name = ?"\n'
    "    conn = sqlite3.connect('test.db')\n"
    "    conn.execute(query, (name,))\n"
)


# ============================================================================
# GROUP A - verified analyzer behaviour (these tests must pass)
# ============================================================================


def test_input_to_sql_execution():
    """input() into an f-string SQL query reaches a SQL sink.

    EXPECTED: at least one stdlib-input -> sql-execution path, critical severity,
    high confidence, and a trace containing source, interprocedural and sink steps.
    ACTUAL (verified 2026-11-09): exactly that.
    """
    paths = analyze(SQL_FSTRING)

    assert len(paths) >= 1, "Expected >=1 taint path, got %s" % describe(paths)

    tpath = paths[0]
    assert tpath.source.name == "stdlib-input", tpath.source.name
    assert tpath.sink.category == "sql-execution", tpath.sink.category
    assert tpath.severity == "critical", tpath.severity
    assert tpath.confidence > 0.7, tpath.confidence
    assert tpath.is_sanitized is False, "unsanitized f-string SQL must not be marked sanitized"

    descriptions = [t.description for t in tpath.traces]
    assert any("source: stdlib-input" in d for d in descriptions), descriptions
    assert any("interprocedural" in d.lower() for d in descriptions), descriptions
    assert any("sink" in d.lower() for d in descriptions), descriptions
    assert tpath.traces[0].kind in (TaintKind.DIRECT, TaintKind.INDIRECT), tpath.traces[0].kind


def test_input_to_command_execution():
    """input() reaching os.system() through a function parameter (index 0)."""
    paths = analyze(CMD_VIA_FUNCTION)

    assert len(paths) >= 1, "Expected >=1 taint path, got %s" % describe(paths)

    tpath = paths[0]
    assert tpath.source.name == "stdlib-input", tpath.source.name
    assert tpath.sink.category == "command-execution", tpath.sink.category
    assert tpath.severity == "critical", tpath.severity
    assert tpath.confidence > 0.7, tpath.confidence


def test_module_level_taint_propagation():
    """Taint assigned and consumed at module level (no function boundary).

    EXPECTED: one path whose sink line is the os.system() call itself.
    ACTUAL (verified 2026-11-09): sink_line == line of 'os.system' (3). Module
    level location reporting is accurate; only interprocedural paths are not.
    """
    paths = analyze(CMD_MODULE_LEVEL)

    assert len(paths) >= 1, "Expected >=1 taint path, got %s" % describe(paths)

    tpath = paths[0]
    assert tpath.source.name == "stdlib-input", tpath.source.name
    assert tpath.sink.category == "command-execution", tpath.sink.category

    expected_line = line_of_call(CMD_MODULE_LEVEL, "os.system")
    assert tpath.sink_line == expected_line, (
        "module-level sink line %s != actual call line %s" % (tpath.sink_line, expected_line)
    )

    descriptions = [t.description for t in tpath.traces]
    assert any("source: stdlib-input" in d for d in descriptions), descriptions
    assert any("sink" in d.lower() for d in descriptions), descriptions


def test_cross_function_taint_propagation():
    """Taint crossing one function boundary and passing through a helper call."""
    paths = analyze(CROSS_FUNCTION)

    assert len(paths) >= 1, "Expected >=1 taint path, got %s" % describe(paths)

    tpath = paths[0]
    assert tpath.source.name == "stdlib-input", tpath.source.name
    assert tpath.sink.category == "sql-execution", tpath.sink.category

    descriptions = [t.description for t in tpath.traces]
    assert any("interprocedural" in d.lower() for d in descriptions), descriptions


def test_unsanitized_percent_format_sql_is_detected():
    """Percent-formatted SQL is a real injection sink.

    EXPECTED: one unsanitized stdlib-input -> sql-execution path.
    ACTUAL (verified 2026-11-09): exactly that.
    """
    paths = analyze(SQL_PERCENT)

    assert len(paths) >= 1, "Expected >=1 taint path, got %s" % describe(paths)

    tpath = paths[0]
    assert tpath.source.name == "stdlib-input", tpath.source.name
    assert tpath.sink.category == "sql-execution", tpath.sink.category
    assert tpath.is_sanitized is False, tpath.is_sanitized


def test_multiple_source_to_sink_paths():
    """Two independent flows in one file are reported independently."""
    paths = analyze(MULTIPLE_PATHS)

    assert len(paths) >= 2, "Expected >=2 taint paths, got %s" % describe(paths)
    assert any(p.sink.category == "sql-execution" for p in paths), describe(paths)
    assert any(p.sink.category == "command-execution" for p in paths), describe(paths)


def test_severity_preservation():
    """Sink severity survives into the reported path for both sink families."""
    paths = analyze(MULTIPLE_PATHS)

    assert len(paths) >= 2, "Expected >=2 taint paths, got %s" % describe(paths)
    for p in paths:
        assert p.severity == "critical", "%s for %s" % (p.severity, p.sink.category)


def test_confidence_calculation():
    """Confidence stays inside the documented 0.7..1.0 band for a direct flow."""
    paths = analyze(SQL_FSTRING)

    assert len(paths) >= 1, "Expected >=1 taint path, got %s" % describe(paths)
    confidence = paths[0].confidence
    assert 0.7 <= confidence <= 1.0, confidence


def test_trace_ordering():
    """A trace runs source first and sink last.

    EXPECTED: traces[0] describes the source and traces[-1] describes the sink,
    with the sink classified as a direct or interprocedural hop.
    ACTUAL (verified 2026-11-09): holds.  Step numbering is asserted separately
    by test_trace_step_numbers_are_sequential, which currently fails.
    """
    paths = analyze(SQL_FSTRING)

    assert len(paths) >= 1, "Expected >=1 taint path, got %s" % describe(paths)
    traces = paths[0].traces

    assert len(traces) >= 2, "Expected a multi-step trace, got %d step(s)" % len(traces)
    assert "source" in traces[0].description.lower(), traces[0].description
    assert "sink" in traces[-1].description.lower(), traces[-1].description
    assert traces[-1].kind in (TaintKind.DIRECT, TaintKind.INTERPROCEDURAL), traces[-1].kind

    # Every step must carry a line number or the finding is not actionable.
    for trace in traces:
        assert trace.line_number > 0, (trace.step_number, trace.description)


def test_deduplicates_identical_sink_on_same_line():
    """Two identical sink calls on ONE line collapse to a single finding.

    EXPECTED: 1 command-execution path.  The dedup key is
    source+sink+file+line, so two calls sharing a line are one finding.
    ACTUAL (verified 2026-11-09): 1, at line 3.
    """
    paths = analyze(SAME_LINE_DUPLICATE_SINK)
    hits = [p for p in paths if p.sink.name == "command-execution"]

    assert len(hits) == 1, "Expected 1 deduplicated path, got %s" % describe(hits)


def test_distinct_sink_lines_are_reported_separately():
    """Identical sink calls on DIFFERENT lines are distinct findings.

    EXPECTED: 2 command-execution paths with distinct, accurate line numbers.
    ACTUAL (verified 2026-11-09): 2, at lines 3 and 4.  The pre-repair version
    of this suite asserted a single deduplicated path and was wrong: the dedup
    key includes sink_line, so distinct lines are distinct findings.
    """
    paths = analyze(DIFFERENT_LINE_DUPLICATE_SINK)
    hits = [p for p in paths if p.sink.name == "command-execution"]

    assert len(hits) == 2, "Expected 2 distinct paths, got %s" % describe(hits)
    assert len({p.sink_line for p in hits}) == 2, describe(hits)

    for p in hits:
        expected_line = line_of_call(DIFFERENT_LINE_DUPLICATE_SINK, "os.system")
        assert p.sink_line >= expected_line, (
            "sink_line %s is before the first os.system call on line %s"
            % (p.sink_line, expected_line)
        )


def test_repeated_analysis_is_stable():
    """Repeated analysis in the same process returns identical results.

    EXPECTED: the same count on every call, and earlier results unchanged by
    later calls.
    ACTUAL (verified 2026-11-09): [1, 1, 1]; the first result list is not
    mutated by subsequent calls when the module-level helper is used.
    """
    with temp_python_file(SQL_FSTRING) as path:
        target = str(path)
        counts = [len(analyze_python_file(target)) for _ in range(3)]
        first = analyze_python_file(target)
        baseline = len(first)
        analyze_python_file(target)
        assert len(first) == baseline, "earlier result was mutated by a later analysis"

    assert counts == [counts[0]] * 3, counts


def test_directory_analysis_reports_the_vulnerable_file():
    """A directory holding one vulnerable file yields its findings.

    Only one vulnerable file is used so the result cannot depend on the
    per-file state leak documented in
    ``test_directory_analysis_is_order_independent``.
    """
    paths = analyze_dir({"vuln.py": VULNERABLE_FILE})

    assert len(paths) >= 1, "Expected >=1 taint path, got %s" % describe(paths)
    for p in paths:
        assert os.path.basename(p.sink_file) == "vuln.py", p.sink_file


def test_known_defect_registry_is_documented():
    """Every labelled defect is decorated, listed and self-describing.

    This guards the labelling requirement: a test carrying ``__known_defect__``
    that is absent from ``KNOWN_ANALYZER_DEFECTS`` (or vice versa) fails here
    instead of silently looking like an unexplained regression.

    The registry opened with 13 entries on 2026-11-09.  Six were fixed and
    un-labelled first, then the remaining seven; as of this revision it is
    empty, which is the expected steady state.  When a new defect is
    discovered, decorate its test with ``@known_defect(expected, actual)`` and
    this assertion will require the count to be updated deliberately.
    """
    decorated = {
        name
        for name, obj in sorted(globals().items())
        if name.startswith("test_") and callable(obj) and hasattr(obj, "__known_defect__")
    }

    assert decorated == set(KNOWN_ANALYZER_DEFECTS), (
        "decorated tests %s do not match registry %s"
        % (sorted(decorated), sorted(KNOWN_ANALYZER_DEFECTS))
    )

    assert len(KNOWN_ANALYZER_DEFECTS) == 0, (
        "registry holds %d entries; all 13 originally registered analyzer "
        "defects are now fixed, so the registry must be empty (0)"
        % len(KNOWN_ANALYZER_DEFECTS)
    )

    for name, (expected, actual) in KNOWN_ANALYZER_DEFECTS.items():
        assert expected and actual, (name, expected, actual)


# ============================================================================
# GROUP B - verified analyzer defects (all 13 now fixed; kept as regressions)
# ============================================================================
# This group began as the labelled-failure registry: 13 verified defects, each
# encoded as a test decorated with @known_defect(expected, actual) so that every
# failure was a written specification rather than a surprise.  Six defects were
# repaired first, then the remaining seven once call-site-sensitive
# interprocedural propagation landed.  Each test below is now an ordinary
# regression test -- the assertions were never weakened, and no test was removed.


def test_parameterized_query_is_not_reported():
    """A parameterized query is safe parameter binding, not injection.

    REGRESSION TEST.  Previously the sql-parameterize sanitizer pattern
    (``(execute|executemany)\\s*\\([^,]+,\\s*[\\(\\[]``) could never match, because the
    analyzer handed the registry a bare call name.  The candidate strings are
    now derived from the AST, so ``conn.execute(query, (name,))`` is recognised
    as bound parameters travelling out of band from the statement text.

    The companion rule is equally important and is asserted by
    test_unsanitized_percent_format_sql_is_detected and test_input_to_sql_execution:
    a tuple of bound parameters does NOT make an interpolated statement safe.
    """
    paths = analyze(SQL_PARAMETERIZED)

    assert len(paths) == 0, (
        "Expected 0 taint paths for a parameterized query (sanitized), got %s"
        % describe(paths)
    )


def test_flask_request_source_to_command_execution():
    """Flask request.args.get() is an http-request source reaching a command sink.

    Regression for the source-matching defect where the pattern was evaluated
    against the bare call name and the .get() accessor hid the container.
    """
    paths = analyze(FLASK_CMD)

    assert len(paths) >= 1, (
        "Expected >=1 taint path from the Flask request source, got %s" % describe(paths)
    )

    tpath = paths[0]
    assert tpath.source.category == "http-request", tpath.source.category
    assert tpath.sink.category == "command-execution", tpath.sink.category


def test_flask_request_source_to_path_traversal():
    """Flask request.args.get() reaching open() inside a with-statement.

    Covers both the Flask source-matching fix and the previously unhandled
    ``with`` statement, whose context expression is itself a sink call.
    """
    paths = analyze(FLASK_PATH_TRAVERSAL)

    assert len(paths) >= 1, (
        "Expected >=1 taint path from the Flask request source, got %s" % describe(paths)
    )

    tpath = paths[0]
    assert tpath.source.category == "http-request", tpath.source.category
    assert tpath.sink.category == "path-traversal", tpath.sink.category


def test_sys_argv_source_to_command_execution():
    """sys.argv subscription is a user-input source reaching a command sink.

    Regression for the subscript source-matching defect.
    """
    paths = analyze(SYS_ARGV)

    assert len(paths) >= 1, (
        "Expected >=1 taint path from sys.argv, got %s" % describe(paths)
    )

    tpath = paths[0]
    assert tpath.source.name == "sys-argv", tpath.source.name
    assert tpath.sink.category == "command-execution", tpath.sink.category


def test_os_environ_source_to_command_execution():
    """os.environ.get() is an environment source reaching a command sink.

    Regression for the container-accessor source-matching defect.
    """
    paths = analyze(OS_ENVIRON)

    assert len(paths) >= 1, (
        "Expected >=1 taint path from os.environ, got %s" % describe(paths)
    )

    tpath = paths[0]
    assert tpath.source.category == "environment", tpath.source.category
    assert tpath.sink.category == "command-execution", tpath.sink.category


def test_keyword_argument_taint_propagation():
    """Taint passed as a keyword argument reaches the sink.

    REGRESSION TEST.  Call-site propagation now binds arguments by name as well
    as by position, so ``run_cmd(cmd=user)`` marks the callee's ``cmd``
    parameter tainted.
    """
    paths = analyze(KEYWORD_ARG)

    assert len(paths) >= 1, (
        "Expected >=1 taint path through the keyword argument, got %s" % describe(paths)
    )

    tpath = paths[0]
    assert tpath.source.name == "stdlib-input", tpath.source.name
    assert tpath.sink.category == "command-execution", tpath.sink.category


def test_positional_argument_at_nonzero_index():
    """Taint at a non-zero positional index reaches the sink.

    REGRESSION TEST.  The old interprocedural pass compared the argument index
    against ``sink.vulnerable_param``, which is 0 for every sink in the
    registry, so ``run_cmd('echo', user)`` was invisible.  Propagation is now
    driven by the argument-to-parameter binding rather than a fixed index.
    """
    paths = analyze(POSITIONAL_ARG_NONZERO)

    assert len(paths) >= 1, (
        "Expected >=1 taint path through the positional argument, got %s" % describe(paths)
    )

    tpath = paths[0]
    assert tpath.source.name == "stdlib-input", tpath.source.name
    assert tpath.sink.category == "command-execution", tpath.sink.category


def test_nested_calls_multi_level_propagation():
    """Taint is followed through a multi-level call chain.

    REGRESSION TEST.  Propagation used to expand a callee exactly once, so
    ``level1 -> level2 -> level3 -> conn.execute`` produced nothing.  The
    engine is now depth-bounded (``_MAX_CALL_DEPTH``) with an active-call
    signature set, so chains are followed transitively and recursion still
    terminates.
    """
    paths = analyze(NESTED_CALLS)

    assert len(paths) >= 1, (
        "Expected >=1 taint path through the nested calls, got %s" % describe(paths)
    )

    tpath = paths[0]
    assert tpath.source.name == "stdlib-input", tpath.source.name
    assert tpath.sink.category == "sql-execution", tpath.sink.category

    inter_count = sum(1 for t in tpath.traces if "interprocedural" in t.description.lower())
    assert inter_count >= 2, "Expected >=2 interprocedural traces, got %d" % inter_count


def test_sink_line_points_to_sink_call_not_function_definition():
    """A finding points at the vulnerable operation, not at the enclosing def.

    REGRESSION TEST.  Interprocedural paths used to record the callee's
    definition line, sending a reader to ``def get_user`` instead of the
    ``conn.execute()`` that actually runs the attacker-controlled query.  The
    sink call node is now used for both ``sink_line`` and the trace step.
    """
    paths = analyze(SQL_FSTRING)

    assert len(paths) >= 1, "Expected >=1 taint path, got %s" % describe(paths)

    expected_line = line_of_call(SQL_FSTRING, "conn.execute")
    def_line = line_of_def(SQL_FSTRING, "get_user")
    assert paths[0].sink_line == expected_line, (
        "sink_line %s points at the function definition (line %s), not the "
        "sink call on line %s" % (paths[0].sink_line, def_line, expected_line)
    )


def test_directory_analysis_is_order_independent():
    """Directory results must not depend on the order files are analysed.

    Regression for the per-analysis state leak in analyze_directory().

    The vulnerable file legitimately yields two findings because two registered
    SQL sink patterns both match ``conn.execute`` ('sql-execute' and
    'sqlalchemy-execute'); that duplication is a registry-overlap issue, not the
    defect under test.  What is asserted here is that each of those findings is
    reported exactly once per sink name, regardless of directory order.
    """
    failures = []

    for label, filenames in (
        ("vulnerable first", {"a_vuln.py": VULNERABLE_FILE, "z_safe.py": SAFE_FILE}),
        ("safe first", {"a_safe.py": SAFE_FILE, "z_vuln.py": VULNERABLE_FILE}),
    ):
        paths = analyze_dir(filenames)

        vuln_hits = [p for p in paths if os.path.basename(p.sink_file).endswith("vuln.py")]
        safe_hits = [p for p in paths if os.path.basename(p.sink_file).endswith("safe.py")]

        for sink_name in ("sql-execute", "sqlalchemy-execute"):
            count = sum(1 for p in vuln_hits if p.sink.name == sink_name)
            if count != 1:
                failures.append(
                    "%s: expected exactly 1 '%s' finding from the vulnerable file, got %d"
                    % (label, sink_name, count)
                )

        if safe_hits:
            failures.append(
                "%s: expected no findings from the sanitized file, got %s"
                % (label, describe(safe_hits))
            )

    assert not failures, "; ".join(failures)


def test_shared_analyzer_instance_leaks_state_between_files():
    """One analyzer instance must not accumulate findings across files.

    Regression for the per-instance state leak and the aliased result list.
    """
    with temp_python_directory(
        {"a_vuln.py": VULNERABLE_FILE, "z_safe.py": SAFE_FILE}
    ) as tmpdir:
        analyzer = PythonTaintAnalyzer()

        first = analyzer.analyze_file(str(tmpdir / "a_vuln.py"))
        first_len = len(first)
        second = analyzer.analyze_file(str(tmpdir / "z_safe.py"))
        first_after_second = len(first)

    # The vulnerable file yields two findings: 'sql-execute' and
    # 'sqlalchemy-execute' both match conn.execute.
    assert first_len == 2, "expected 2 findings from the vulnerable file, got %d" % first_len
    assert len(second) == 0, (
        "expected 0 findings from the sanitized file, got %d (%s)"
        % (len(second), describe(second))
    )
    assert first_after_second == first_len, (
        "the result list of the first analysis was mutated by the second "
        "analysis (%d -> %d)" % (first_len, first_after_second)
    )


def test_taint_through_non_sanitizing_call_wrapper():
    """Taint survives a call that is not a source, sink or sanitizer.

    REGRESSION TEST.  ``os.system(str(user))`` produced nothing because a Call
    node in the sink's argument position was never resolved back to its tainted
    argument.  A wrapper such as ``str``, ``.strip()`` or ``os.path.join``
    passes taint through to its result, so it is now propagated (and the
    resulting step is labelled as a pass-through, not a sanitization).
    """
    wrapper = "import os\n\nuser = input('Enter: ')\nos.system(str(user))\n"
    paths = analyze(wrapper)

    assert len(paths) >= 1, (
        "Expected >=1 taint path through the wrapper call, got %s" % describe(paths)
    )


def test_trace_step_numbers_are_sequential():
    """Trace step numbers run 1..N with no gaps or repeats.

    REGRESSION TEST.  ``_create_trace`` derived its number from how many traces
    the tainted variable already carried, which produced [1, 1, 3, 4] for a
    four-step flow.  A consumer must be able to order a trace deterministically,
    so the sequence is normalised to list order when the path is recorded.
    """
    paths = analyze(SQL_FSTRING)

    assert len(paths) >= 1, "Expected >=1 taint path, got %s" % describe(paths)
    traces = paths[0].traces

    numbers = [t.step_number for t in traces]
    assert numbers == list(range(1, len(traces) + 1)), (
        "step numbers %s are not the sequence 1..%d" % (numbers, len(traces))
    )


# ============================================================================
# GROUP C - sanitizer effectiveness is decided per sink (correctness)
# ============================================================================
# A sanitizer used to clear taint as soon as ``is_strong`` was set, which made
# every strong sanitizer a universal mute button: html.escape() silenced
# os.system(), and a bound-parameter tuple silenced an interpolated statement.
# Effectiveness is now decided when the flow reaches a sink, from the
# sanitizer's own metadata (is_strong, action, handles_kinds, cwe_ids,
# category) against that sink.  These cases pin the behaviour down.


HTML_ESCAPE_TO_COMMAND = (
    "import os\n"
    "from html import escape\n"
    "user = input('cmd: ')\n"
    "os.system(escape(user))\n"
)

HTML_ESCAPE_TO_RESPONSE = (
    "from django.http import HttpResponse\n"
    "from html import escape\n"
    "user = input('name: ')\n"
    "return HttpResponse(escape(user))\n"
)

PATH_JOIN_TO_OPEN = (
    "import os\n"
    "user = input('file: ')\n"
    "path = os.path.join('/data', user)\n"
    "with open(path) as handle:\n"
    "    return handle.read()\n"
)

NORMPATH_TO_OPEN = (
    "import os\n"
    "user = input('file: ')\n"
    "path = os.path.normpath('/data/' + user)\n"
    "return open(path).read()\n"
)

SHLEX_QUOTE_TO_COMMAND = (
    "import os\n"
    "import shlex\n"
    "user = input('cmd: ')\n"
    "os.system(shlex.quote(user))\n"
)

SHLEX_QUOTE_TO_SQL = (
    "import sqlite3\n"
    "import shlex\n"
    "user = input('name: ')\n"
    "conn = sqlite3.connect('app.db')\n"
    "conn.execute(shlex.quote(user))\n"
)

SQL_INTERPOLATED_WITH_BOUND_PARAMS = (
    "import sqlite3\n"
    "user = input('name: ')\n"
    "query = \"SELECT * FROM users WHERE name = '%s'\" % user\n"
    "conn = sqlite3.connect('app.db')\n"
    "conn.execute(query, (user,))\n"
)

SUBPROCESS_SHELL_FALSE = (
    "import subprocess\n"
    "user = input('cmd: ')\n"
    "subprocess.run(user, shell=False)\n"
)


def test_strong_sanitizer_does_not_neutralize_an_unrelated_sink():
    """html.escape() must not silence command injection.

    html-escape is strong and takes an ESCAPE action, but it is written for
    CWE-79.  os.system() is CWE-78: escaping HTML metacharacters leaves the
    shell metacharacters exactly as the attacker typed them, so the flow must
    still be reported.
    """
    paths = analyze(HTML_ESCAPE_TO_COMMAND)

    assert len(paths) >= 1, (
        "html.escape() suppressed a command-execution finding; got %s" % describe(paths)
    )
    assert paths[0].sink.category == "command-execution", paths[0].sink.category
    assert paths[0].is_sanitized is False, paths[0].is_sanitized


def test_weak_path_join_does_not_break_path_traversal():
    """os.path.join('/data', user) reaching open() stays a path traversal.

    path-join-safe is weak and only VALIDATEs, so it can never break a flow.
    It must still be visible as a sanitizer that was encountered, so a reviewer
    can see why it did not help.
    """
    paths = analyze(PATH_JOIN_TO_OPEN)

    assert len(paths) >= 1, (
        "os.path.join() suppressed a path-traversal finding; got %s" % describe(paths)
    )
    assert paths[0].sink.category == "path-traversal", paths[0].sink.category
    assert paths[0].is_sanitized is False, paths[0].is_sanitized
    encountered = [s.name for s in paths[0].sanitizers_encountered]
    assert "path-join-safe" in encountered, (
        "the weak sanitizer was dropped from the diagnostics: %s" % encountered
    )


def test_weak_normpath_does_not_neutralize_path_traversal():
    """os.path.normpath() is not a traversal defence on its own.

    path-normalize is a TRANSFORM with is_strong=False: it collapses ``..``
    lexically but an absolute path, a symlink, or a prefix that merely starts
    with the base directory all survive it.  It therefore cannot mark the flow
    as sanitized.
    """
    paths = analyze(NORMPATH_TO_OPEN)

    assert len(paths) >= 1, (
        "os.path.normpath() suppressed a path-traversal finding; got %s" % describe(paths)
    )
    assert paths[0].sink.category == "path-traversal", paths[0].sink.category
    assert paths[0].is_sanitized is False, paths[0].is_sanitized
    encountered = [s.name for s in paths[0].sanitizers_encountered]
    assert "path-normalize" in encountered, (
        "the weak sanitizer was dropped from the diagnostics: %s" % encountered
    )


def test_shlex_quote_is_evaluated_in_its_actual_shell_context():
    """shlex.quote() protects a command sink and nothing else.

    The same call is judged twice: against os.system() it is a genuine CWE-78
    defence and breaks the flow, and against a SQL sink it protects nothing.
    Both halves must hold, otherwise the analyzer is either muting command
    injection or reporting shell escaping as irrelevant noise.
    """
    command_paths = analyze(SHLEX_QUOTE_TO_COMMAND)
    assert len(command_paths) == 0, (
        "shlex.quote() did not neutralize a command-execution flow: %s"
        % describe(command_paths)
    )

    sql_paths = analyze(SHLEX_QUOTE_TO_SQL)
    assert len(sql_paths) >= 1, (
        "shlex.quote() suppressed a SQL finding: %s" % describe(sql_paths)
    )
    assert sql_paths[0].sink.category == "sql-execution", sql_paths[0].sink.category
    assert sql_paths[0].is_sanitized is False, sql_paths[0].is_sanitized


def test_html_escape_still_neutralizes_html_output():
    """The other half of the html.escape() contract still holds.

    Sink-context awareness must not be implemented by refusing to suppress
    anything: an HTML-escaped value reaching an HTML response is the exact case
    html-escape() is written for, so the flow is broken.
    """
    with temp_python_file(HTML_ESCAPE_TO_RESPONSE) as path:
        analyzer = PythonTaintAnalyzer()
        findings = analyzer.analyze_file(str(path))

    assert len(findings) == 0, (
        "html.escape() did not neutralize an XSS flow: %s" % describe(findings)
    )
    assert len(analyzer.sanitized_flows) == 1, (
        "the neutralized flow was dropped instead of recorded: %d"
        % len(analyzer.sanitized_flows)
    )
    neutralized = analyzer.sanitized_flows[0]
    assert neutralized.sink.category == "xss", neutralized.sink.category
    assert neutralized.is_sanitized is True, neutralized.is_sanitized
    assert neutralized.breaking_sanitizer is not None
    assert neutralized.breaking_sanitizer.name == "html-escape", (
        neutralized.breaking_sanitizer.name
    )


def test_parameterized_query_is_still_not_reported():
    """Genuine parameter binding still suppresses SQL injection.

    A constant statement with the values in a bound sequence is safe parameter
    binding.  This is the counterpart to
    test_bound_parameters_do_not_launder_interpolated_sql: the suppression must
    survive, so sink-context awareness is a narrowing and not a blanket refusal.
    """
    paths = analyze(SQL_PARAMETERIZED)

    assert len(paths) == 0, (
        "parameterized query reported: %s" % describe(paths)
    )


def test_bound_parameters_do_not_launder_interpolated_sql():
    """A bound tuple beside an interpolated statement is still injection.

    The statement text is attacker-controlled and the bound values travel out
    of band, so they cannot repair it.  The sql-parameterize sanitizer is only
    ever recorded against the values it is applied to -- never against the
    statement text -- otherwise this flow would be reported as safe.
    """
    paths = analyze(SQL_INTERPOLATED_WITH_BOUND_PARAMS)

    assert len(paths) >= 1, (
        "bound parameters laundered an interpolated statement: %s" % describe(paths)
    )
    assert paths[0].sink.category == "sql-execution", paths[0].sink.category
    assert paths[0].is_sanitized is False, paths[0].is_sanitized


def test_strong_sanitizer_that_matches_the_sink_is_recorded_as_neutralized():
    """A real defense is auditable, not silently discarded.

    subprocess.run(..., shell=False) is a genuine CWE-78 defense.  The flow is
    withheld from the findings, but it is kept with the sanitizer that broke
    it and the reason, so the decision can be reviewed.
    """
    with temp_python_file(SUBPROCESS_SHELL_FALSE) as path:
        analyzer = PythonTaintAnalyzer()
        findings = analyzer.analyze_file(str(path))

    assert len(findings) == 0, (
        "subprocess argv suppression regressed: %s" % describe(findings)
    )
    assert len(analyzer.sanitized_flows) == 1, (
        "expected the neutralized flow to be recorded, got %d"
        % len(analyzer.sanitized_flows)
    )
    record = analyzer.sanitized_flows[0]
    assert record.breaking_sanitizer is not None
    assert record.breaking_sanitizer.name == "subprocess-argv", (
        record.breaking_sanitizer.name
    )
    assert record.breaking_sanitizer.cwe_ids == ["CWE-78"], record.breaking_sanitizer.cwe_ids
    assert record.metadata.get("sanitizer_verdict"), (
        "no verdict recorded for a broken flow: %s" % record.metadata
    )


def test_weak_sanitizer_cannot_terminate_propagation():
    """No weak sanitizer in the registry may break a flow.

    Walks the loaded registry rather than a hard-coded list, so a sanitizer
    added later is covered by the same rule.  The decision is exercised against
    a sink whose CWE the sanitizer claims to mitigate, which is the most
    favourable case for suppression: if it cannot break the flow there, it
    cannot break one anywhere.
    """
    from triagekit.core.taint.analyzer import TaintState
    from triagekit.core.taint.models import SanitizerAction

    analyzer = PythonTaintAnalyzer()
    python_sanitizers = [
        s for s in analyzer.registry.sanitizers if "python" in (s.languages or [])
    ]
    assert python_sanitizers, "no python sanitizers loaded"

    weak = [
        s for s in python_sanitizers
        if not s.is_strong
        or s.action not in (SanitizerAction.REMOVE, SanitizerAction.ESCAPE)
    ]
    assert weak, "expected at least one weak/non-neutralizing sanitizer to exist"

    for sanitizer in weak:
        for sink in analyzer.registry.sinks:
            if not set(sanitizer.cwe_ids) & set(sink.cwe_ids):
                continue
            state = TaintState(
                variable="user",
                is_tainted=True,
                source=analyzer.registry.sources[0],
                taint_kind=TaintKind.DIRECT,
                traces=[],
                confidence=0.9,
                sanitizer=sanitizer,
            )
            assert analyzer._neutralizing_sanitizer(state, sink) is None, (
                "%s (is_strong=%s action=%s) broke a flow to %s"
                % (sanitizer.name, sanitizer.is_strong, sanitizer.action, sink.name)
            )


def test_strong_sanitizer_is_inert_against_a_sink_it_does_not_cover():
    """A strong sanitizer only defends the weakness it names.

    Exercises every strong python sanitizer against every python sink and
    asserts the verdict is exactly the CWE/category overlap: a sanitizer may
    only break a flow when it names the sink's CWE and belongs to a class that
    covers the sink's category.  Anything stronger is a mute button, anything
    weaker is a regression.
    """
    from triagekit.core.taint.analyzer import TaintState
    from triagekit.core.taint.models import SanitizerAction

    analyzer = PythonTaintAnalyzer()
    strong = [
        s for s in analyzer.registry.sanitizers
        if "python" in (s.languages or []) and s.is_strong
    ]
    assert strong, "no strong python sanitizers loaded"

    breaking = []
    for sanitizer in strong:
        for sink in analyzer.registry.sinks:
            if "python" not in (sink.languages or []):
                continue
            state = TaintState(
                variable="user",
                is_tainted=True,
                source=analyzer.registry.sources[0],
                taint_kind=TaintKind.DIRECT,
                traces=[],
                confidence=0.9,
                sanitizer=sanitizer,
            )
            if analyzer._neutralizing_sanitizer(state, sink) is not None:
                breaking.append((sanitizer.name, sink.name))

    # The neutralizations that must exist, otherwise removal would be a
    # blanket refusal to suppress anything.
    assert ("html-escape", "html-response") in breaking, breaking
    assert ("shlex-quote", "command-execution") in breaking, breaking
    assert ("subprocess-argv", "command-execution") in breaking, breaking
    # Cross-context pairs that must NOT be suppressed.
    for forbidden in (
        ("html-escape", "command-execution"),
        ("html-escape", "sql-execute"),
        ("shlex-quote", "sql-execute"),
        ("shlex-quote", "path-traversal"),
        ("sql-parameterize", "command-execution"),
        ("path-normalize", "path-traversal"),
        ("path-join-safe", "path-traversal"),
        ("url-validate", "command-execution"),
    ):
        assert forbidden not in breaking, (
            "%s was allowed to neutralize %s" % forbidden
        )


# ============================================================================
# MAIN TEST RUNNER (ASCII only - the console encoding is cp1252)
# ============================================================================

if __name__ == "__main__":
    import sys

    tests = [
        (name, obj)
        for name, obj in sorted(globals().items())
        if name.startswith("test_") and callable(obj)
    ]

    passed = 0
    failed = 0

    for name, test in tests:
        label = "%s [known defect]" % name if hasattr(test, "__known_defect__") else name
        try:
            test()
            passed += 1
            print("[PASS] %s" % label)
        except Exception as exc:  # noqa: BLE001 - standalone runner reports all failures
            failed += 1
            print("[FAIL] %s: %s: %s" % (label, type(exc).__name__, exc))

    print("")
    print("=" * 50)
    print("Results: %d passed, %d failed" % (passed, failed))
    print("Known analyzer defects still open: %d" % len(KNOWN_ANALYZER_DEFECTS))
    print("=" * 50)

    if failed > 0:
        sys.exit(1)
