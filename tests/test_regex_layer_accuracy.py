"""Regression tests for the regex pattern layer: guards, rules, and D3/D39.

HARNESS CONTRACT (read before editing this file)
------------------------------------------------
1. Every fixture is a source string written to a unique temp directory and
   removed in a ``finally`` block, so cleanup survives a failed assertion.  Two
   corpora live in the repository (``dev/corpora/js_vuln`` and
   ``dev/corpora/js_safe``) because the numbers in ``dev/AUTONOMOUS_TODO.md`` are
   measured against them; those assertions read the real files, so editing a
   corpus fails here instead of silently moving the benchmark.
2. Analysis goes through ``scan_repository`` (the repository scanner's regex
   layer) with a fresh call per test.
3. Output is ASCII only -- the console on this platform is cp1252 and raises
   ``UnicodeEncodeError`` on non-ASCII.
4. Each test names the defect it guards against.

THE DEFECTS
-----------
D3   ``static_analysis`` and ``heuristic_security`` read
     ``context.metadata["files_data"]``, which nothing ever populated for a local
     scan, so both returned zero findings while looking like they had run.  The
     payload is now synthesized from the local tree and labelled as synthesized.
D37  The ``xss-eval`` regex fired on the *fixed* form:
     ``el.innerHTML = DOMPurify.sanitize(x)``.
D38  ``sensitive-log`` fired on ``console.log('query=' + q)``.  CWE-532 is about
     sensitive information in logs; the rule matched a *method name*.
D39  The regex layer and the taint layer both reported the same line and the
     report never said which to trust.  ``CrossLayerResolver`` now folds the
     weaker layer into the stronger and records the corroboration.
D40  ``command-injection`` matched ``subprocess.run(cmd_list)`` -- an argv list
     passed through a variable -- and every ``cur.execute(...)``.
D41  Every ``"integrity": "sha512-..."`` in a package-lock.json was reported as a
     high-entropy secret (~100 false positives in a normal JS repository).
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from triagekit.core.analyzers.repo_scan import scan_repository

REPO_ROOT = Path(__file__).resolve().parent.parent
JS_VULN = REPO_ROOT / "dev" / "corpora" / "js_vuln" / "src" / "app.js"
JS_SAFE = REPO_ROOT / "dev" / "corpora" / "js_safe" / "src" / "app.js"
PY_VULN = REPO_ROOT / "dev" / "corpora" / "vuln_app"
PY_SAFE = REPO_ROOT / "dev" / "corpora" / "safe_app"


def scan(source: str, name: str = "case.py") -> list:
    """Scan a single source string as a one-file repository."""
    tmpdir = Path(tempfile.mkdtemp(prefix="triagekit_regex_"))
    try:
        (tmpdir / name).write_text(source, encoding="utf-8")
        return scan_repository(tmpdir, max_files=50).findings
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def rules(findings: list) -> set[str]:
    return {f.rule_id for f in findings}


def at_line(findings: list, line: int) -> list:
    return [f for f in findings if f.line == line]


# ---------------------------------------------------------------------------
# D37 -- the sanitized XSS idiom is the fix, not the vulnerability.
# ---------------------------------------------------------------------------

def test_sanitized_innerhtml_is_not_reported():
    findings = scan(
        "import DOMPurify\n"
        "el.innerHTML = DOMPurify.sanitize(user_html)\n"
    )
    assert "xss-eval" not in rules(findings), (
        "the fixed form of XSS was reported: "
        + ", ".join(f"L{f.line}/{f.rule_id}" for f in findings)
    )


def test_sanitized_dangerously_set_inner_html_is_not_reported():
    findings = scan(
        "import { sanitize } from 'dompurify'\n"
        "html = <div dangerouslySetInnerHTML={{__html: sanitize(raw)}} />\n",
        name="case.jsx",
    )
    assert "xss-framework" not in rules(findings)


def test_raw_innerhtml_still_reported():
    """The guard must not become a blanket suppression."""
    findings = scan("el.innerHTML = location.hash.substring(1)\n", name="case.js")
    assert "xss-eval" in rules(findings)


def test_js_safe_corpus_reports_nothing():
    findings = scan_repository(JS_SAFE.parent.parent, max_files=50).findings
    assert findings == [], (
        "false positives on the safe JS corpus: "
        + ", ".join(f"{f.file}:{f.line}/{f.rule_id}" for f in findings)
    )


# ---------------------------------------------------------------------------
# D38 -- a log call is only a finding when something sensitive reaches it.
# ---------------------------------------------------------------------------

def test_console_log_of_a_uri_encoded_query_is_not_a_finding():
    findings = scan(
        "const q = encodeURIComponent(req.query.q || '');\n"
        "console.log('query=' + q);\n",
        name="case.js",
    )
    assert "sensitive-log" not in rules(findings)


def test_console_log_of_a_password_is_a_finding():
    findings = scan(
        "console.log('login attempt for ' + user.password);\n", name="case.js"
    )
    assert "sensitive-log" in rules(findings)


def test_logging_the_whole_request_object_is_a_finding():
    """No line of it need be named "password" for this to leak everything."""
    findings = scan("app.use((req, res, next) => { console.log(req.body); next(); });\n",
                    name="case.js")
    assert "request-object-logged" in rules(findings)


# ---------------------------------------------------------------------------
# D40 -- argv lists, shlex-quoted arguments, and database cursors are not shells.
# ---------------------------------------------------------------------------

def test_subprocess_with_a_list_variable_is_not_command_injection():
    findings = scan(
        "import subprocess\n"
        "def run(cmd_list):\n"
        "    return subprocess.run(cmd_list, capture_output=True)\n"
    )
    assert "command-injection" not in rules(findings)


def test_subprocess_with_an_inline_argv_list_is_not_command_injection():
    findings = scan(
        "import subprocess\n"
        "subprocess.run(['ping', '-c', '1', host], capture_output=True)\n"
    )
    assert "command-injection" not in rules(findings)


def test_shlex_quoted_argument_is_not_command_injection():
    """The Python taint analyzer models shlex.quote; the regex layer must agree."""
    findings = scan(
        "import shlex, subprocess\n"
        "subprocess.run(shlex.split('ping -c 1 ' + shlex.quote(host)))\n"
    )
    assert "command-injection" not in rules(findings)


def test_shell_true_is_command_injection():
    findings = scan(
        "import subprocess\n"
        "subprocess.call(cmd, shell=True)\n"
    )
    assert "command-injection" in rules(findings)


def test_os_system_is_command_injection():
    findings = scan("import os\nos.system('echo ' + host)\n")
    assert "command-injection" in rules(findings)


def test_parameterized_cursor_execute_is_not_sql_injection():
    """``cur.execute(sql, params)`` was reported as command injection before."""
    findings = scan(
        "def q(sql, params=()):\n"
        "    return conn.execute(sql, params).fetchall()\n"
    )
    assert rules(findings) & {"command-injection", "sql-injection"} == set()


def test_python_safe_corpus_reports_nothing():
    findings = scan_repository(PY_SAFE, max_files=50).findings
    assert findings == [], (
        "false positives on the safe Python corpus: "
        + ", ".join(f"{f.file}:{f.line}/{f.rule_id}" for f in findings)
    )


# ---------------------------------------------------------------------------
# The vulnerable corpora must still be found, and now find more.
# ---------------------------------------------------------------------------

def test_python_vuln_corpus_finds_every_planted_flaw():
    findings = scan_repository(PY_VULN, max_files=50).findings
    got = rules(findings)
    for expected in ("hardcoded-secret", "sql-injection", "command-injection",
                     "path-traversal", "unsafe-deserialization", "ssrf",
                     "template-injection", "weak-hash-md5"):
        assert expected in got, f"{expected} not reported by the regex layer"


def test_cur_execute_sql_is_found():
    """``cur.execute`` (not ``cursor.execute``) was invisible to the SQL rule."""
    findings = scan(
        "name = request.args.get('name')\n"
        "cur.execute(\"SELECT * FROM users WHERE name = '%s'\" % name)\n"
    )
    assert "sql-injection" in rules(findings)


def test_destructured_child_process_exec_is_found():
    findings = scan(
        "const { exec } = require('child_process');\n"
        "app.get('/ping', (req, res) => { exec('ping -c 1 ' + req.query.host); });\n",
        name="case.js",
    )
    assert "command-injection" in rules(findings)


def test_regex_execution_is_not_command_injection():
    """``pattern.exec(str)`` is a JavaScript regex match."""
    findings = scan(
        "const m = /\\d+/.exec(input);\n"
        "return m ? m[0] : '';\n",
        name="case.js",
    )
    assert "command-injection" not in rules(findings)


# ---------------------------------------------------------------------------
# D41 -- package-manager integrity hashes are not secrets.
# ---------------------------------------------------------------------------

def test_lockfile_integrity_hash_is_not_a_secret():
    findings = scan(
        "{\n"
        '  "packages": { "": { "integrity": '
        '"sha512-Aup7aUOfpbAUg2ROOJN6Iw5f9DMBlzu0mIkm/malLQFN/YQgO" } }\n'
        "}\n",
        name="package-lock.json",
    )
    assert "high-entropy-string" not in rules(findings)


# ---------------------------------------------------------------------------
# A scanner pointed at another scanner must not report its own rule tables.
# ---------------------------------------------------------------------------

def test_a_regex_table_row_is_not_a_vulnerability():
    findings = scan(
        "INJECTION = [\n"
        '    (r"innerHTML\\s*=|eval\\s*\\(", "xss-eval", "high", "CWE-79"),\n'
        '    (r"\\bmd5\\s*\\(", "weak-hash-md5", "medium", "CWE-328"),\n'
        "]\n"
    )
    assert rules(findings) & {"xss-eval", "weak-hash-md5", "unsafe-deserialization"} == set()


def test_a_real_call_inside_a_file_that_also_defines_patterns_is_found():
    """The pattern guard must not suppress a genuine sink on another line."""
    findings = scan(
        "PATTERN = re.compile(r'^[a-z]+$')\n"
        "el.innerHTML = location.hash\n",
        name="case.js",
    )
    assert "xss-eval" in rules(findings)


# ---------------------------------------------------------------------------
# D3 -- the PR-diff scanners must produce findings on a local directory.
# ---------------------------------------------------------------------------

def _synthesized_payload():
    from triagekit.core.analyzers.files_data import synthesize_files_data

    return synthesize_files_data(str(PY_VULN))


def test_synthesized_payload_is_labelled_as_synthesized():
    payload = _synthesized_payload()
    assert payload.files_data, "no files synthesized from a real corpus directory"
    for entry in payload.files_data:
        assert entry["status"] == "synthesized", (
            f"{entry['filename']} claims to be a PR diff"
        )
        # Zero churn on purpose: fabricated churn drives compute_static_risk into
        # its "very large diff" branch on every repository over 1000 lines.
        assert entry["additions"] == 0 and entry["deletions"] == 0


def test_synthesized_patch_is_line_addressable():
    payload = _synthesized_payload()
    entry = next(e for e in payload.files_data if e["filename"].endswith("server.py"))
    server = (PY_VULN / "app" / "server.py").read_text(encoding="utf-8").splitlines()
    added = [ln[1:] for ln in entry["patch"].splitlines() if ln.startswith("+")]
    assert added[0] == server[0]
    assert added[-1] == server[-1]


def test_static_scanner_reports_findings_on_a_local_directory():
    import asyncio

    from triagekit.core.scanners.base import ScanContext
    from triagekit.core.scanners.static_scanner import StaticAnalysisScanner

    result = asyncio.run(
        StaticAnalysisScanner().scan(ScanContext(target=str(PY_VULN)))
    )
    assert result.findings, "static_analysis produced nothing on a vulnerable app"
    assert any(f.category == "risk-score" for f in result.findings)
    score = result.metadata["static_score"]
    assert score > 0, f"composition-only risk score was {score}"
    assert result.metadata["basis"] == "synthesized-from-local-tree"
    assert any("synthesized" in w.lower() for w in result.warnings), (
        "the report does not say the payload was synthesized"
    )


def test_static_scanner_content_flags_cover_what_paths_miss():
    """app/server.py matches no security/critical/api path fragment."""
    from triagekit.core.analyzers.static import content_flags

    server = (PY_VULN / "app" / "server.py").read_text(encoding="utf-8")
    flags = content_flags(server)
    assert "security-sensitive" in flags
    assert "critical-path" in flags
    assert "api-surface" in flags


def test_heuristic_scanner_reports_findings_with_real_line_numbers():
    import asyncio

    from triagekit.core.scanners.base import ScanContext
    from triagekit.core.scanners.heuristic_scanner import HeuristicSecurityScanner

    result = asyncio.run(
        HeuristicSecurityScanner().scan(ScanContext(target=str(PY_VULN)))
    )
    assert result.findings, "heuristic_security produced nothing on a vulnerable app"
    located = [f for f in result.findings if f.line_number]
    assert located, "no heuristic finding carried a line number"
    # utils.py line 3 is `return hashlib.md5(pw.encode()).hexdigest()`.
    assert {f.line_number for f in located} & {3, 14, 29, 33}, (
        f"line numbers look wrong: {sorted(f.line_number for f in located)}"
    )
    assert all(f.layer == "regex" for f in located)


def test_heuristic_scanner_hunk_header_line_numbers_are_real():
    """A real PR patch carries hunk headers; the numbers must come from them."""
    from triagekit.core.analyzers.security import _added_lines_with_numbers

    patch = (
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -10,3 +10,4 @@ def f():\n"
        " context\n"
        "-old\n"
        "+added one\n"
        "+added two\n"
    )
    # The hunk header says the new file's first line here is 10, which is the
    # context line; the deleted line does not advance it, so the two added lines
    # land on 11 and 12.
    assert _added_lines_with_numbers(patch) == [
        (11, "added one"),
        (12, "added two"),
    ]


def test_heuristic_scanner_keeps_one_finding_per_defect_not_per_file():
    """Dedup was keyed on (type, file), collapsing five SQL injections into one."""
    from triagekit.core.analyzers.security import scan_diff_for_security

    files = [{
        "filename": "app/queries.py",
        "status": "modified",
        "additions": 5,
        "deletions": 0,
        "patch": (
            "+cur.execute(\"SELECT 1 FROM t WHERE a = '\" + a + \"'\")\n"
            "+cur.execute(\"SELECT 2 FROM t WHERE b = '\" + b + \"'\")\n"
            "+cur.execute(\"SELECT 3 FROM t WHERE c = '\" + c + \"'\")\n"
        ),
    }]
    found = scan_diff_for_security(files)
    assert len([f for f in found if f["type"] == "sql-injection-risk"]) == 3
    assert {f["line"] for f in found if f["type"] == "sql-injection-risk"} == {1, 2, 3}


def test_heuristic_scanner_shares_the_repository_guards():
    """The two regex layers must never disagree about whether a line is clean."""
    from triagekit.core.analyzers.security import scan_diff_for_security

    files = [{
        "filename": "app/view.js",
        "status": "modified",
        "additions": 1,
        "deletions": 0,
        "patch": "+el.innerHTML = DOMPurify.sanitize(req.query.html);\n",
    }]
    found = scan_diff_for_security(files)
    assert [f["type"] for f in found if f["type"] == "xss-eval-risk"] == []


# ---------------------------------------------------------------------------
# D39 -- cross-layer precedence.
# ---------------------------------------------------------------------------

def _finding(layer, category, path, line, sink_category=None):
    from triagekit.core.scanners.base import (
        ScanType,
        Severity,
        UnifiedFinding,
    )

    return UnifiedFinding(
        scanner_name=f"{layer}_scanner",
        scanner_version="1.0",
        scan_type=ScanType.REPOSITORY_SCAN,
        title=f"{layer} {category}",
        description="test",
        severity=Severity.HIGH,
        category=category,
        file_path=path,
        line_number=line,
        layer=layer,
        scanner_metadata={"sink_category": sink_category} if sink_category else {},
    )


def test_taint_wins_over_regex_for_the_same_defect():
    from triagekit.core.scanners.correlation import CrossLayerResolver

    regex_f = _finding("regex", "xss-eval", "src/app.js", 16)
    taint_f = _finding("taint", "taint-xss", "C:/repo/src/app.js", 16, sink_category="xss")
    surviving, merges = CrossLayerResolver().resolve([regex_f, taint_f])

    assert len(surviving) == 1 and surviving[0].layer == "taint"
    assert len(merges) == 1
    assert merges[0]["corroborating"]["id"] == regex_f.id
    assert merges[0]["authoritative"]["id"] == taint_f.id
    assert taint_f.scanner_metadata["corroborated_by"] == ["regex_scanner"]
    assert "cross-layer-confirmed" in taint_f.tags
    assert taint_f.layer_authority == "taint"


def test_regex_finding_with_no_taint_counterpart_survives():
    """Folding must not become suppression."""
    from triagekit.core.scanners.correlation import CrossLayerResolver

    regex_f = _finding("regex", "weak-hash-md5", "src/util.py", 3)
    surviving, merges = CrossLayerResolver().resolve([regex_f])
    assert len(surviving) == 1 and merges == []


def test_a_different_defect_at_the_same_line_is_not_folded():
    from triagekit.core.scanners.correlation import CrossLayerResolver

    regex_f = _finding("regex", "sql-injection", "src/app.js", 9)
    taint_f = _finding("taint", "taint-command-execution", "src/app.js", 9,
                       sink_category="command-execution")
    surviving, _ = CrossLayerResolver().resolve([regex_f, taint_f])
    assert len(surviving) == 2, "an unrelated taint flow absorbed a regex finding"


def test_end_to_end_scan_folds_the_layers_and_says_so():
    import asyncio

    from triagekit.core.scanners.orchestrator import OrchestratorConfig, ScannerOrchestrator

    orchestrator = ScannerOrchestrator(OrchestratorConfig(
        enabled_scanners=["repository_scanner", "taint_analysis",
                          "static_analysis", "heuristic_security"],
    ))
    result = asyncio.run(orchestrator.run_scan(str(JS_VULN.parent.parent)))

    # Nine planted flaws; every layer agreed on some of them; the report must not
    # inflate that into more findings than flaws.
    total = result.summary["total_findings"]
    assert 7 <= total <= 12, f"expected ~9 findings for 9 flaws, got {total}"
    assert result.summary["cross_layer_folded"] > 0
    assert "taint" in result.summary["layers_represented"]
    assert "precedence" in result.summary["cross_layer_note"]

    taint = next(r for r in result.scan_results if r.scanner_name == "taint_analysis")
    confirmed = [f for f in taint.findings if f.scanner_metadata.get("corroborated_by")]
    assert confirmed, "no taint finding records which layers corroborated it"
    assert all("cross-layer-confirmed" in f.tags for f in confirmed)


# ---------------------------------------------------------------------------
# The two regex layers are now one rule table.
# ---------------------------------------------------------------------------

def test_diff_layer_and_tree_layer_agree_on_every_line():
    """The layers share rules, so a clean line is clean in both.

    Before, ``security.py`` kept its own hand-written copies and reported
    ``cur.execute(...)`` and ``subprocess.run(cmd)`` that ``repo_scan`` did not.
    """
    from triagekit.core.analyzers.security import INJECTION_PATTERNS
    from triagekit.core.analyzers.repo_scan import INJECTION

    canonical = [pattern for pattern, *_ in INJECTION]
    assert [p for p, _ in INJECTION_PATTERNS] == canonical, (
        "the diff layer's injection patterns have drifted from the canonical table"
    )


def test_diff_layer_carries_a_cwe_for_every_language_rule():
    """A Java/Rust/C# rule in a pull request must not arrive undescribed."""
    from triagekit.core.analyzers.security import cwe_for

    for lang_rule in ("java-sqli-risk", "rs-shell-command-risk", "cs-process-risk",
                      "py-pickle-risk", "cpp-system-risk", "swift-process-risk"):
        assert cwe_for(lang_rule), f"{lang_rule} has no CWE"


def test_diff_layer_reports_remediation_text_for_every_finding():
    from triagekit.core.analyzers.repo_scan import RECS
    from triagekit.core.analyzers.security import canonical_rule_ids

    for ftype in ("sql-injection-risk", "ssrf-risk", "template-injection-risk",
                  "weak-hash", "java-sqli-risk"):
        texts = [RECS.get(rid) for rid in canonical_rule_ids(ftype)]
        assert any(texts), f"{ftype} has no canonical remediation text"


def test_diff_layer_covers_the_language_packs():
    """A Java pull request previously got no signal from the diff layer."""
    from triagekit.core.analyzers.security import scan_diff_for_security

    files = [{
        "filename": "src/main/java/Auth.java",
        "status": "modified",
        "additions": 2,
        "deletions": 0,
        "patch": (
            "+Statement st = conn.createStatement();\n"
            "+st.executeQuery(\"SELECT * FROM users WHERE name = '\" + name + \"'\");\n"
        ),
    }]
    types = {f["type"] for f in scan_diff_for_security(files)}
    assert types & {"java-sqli-risk", "sql-injection-risk"}, (
        f"Java SQL injection not reported by the diff layer: {types}"
    )


def test_sql_built_as_a_string_outside_a_cursor_call_is_found():
    """``query = f"SELECT ... {user}"`` has no execute() call on its line."""
    findings = scan("query = f\"SELECT * FROM users WHERE name={user}\"\n")
    assert "sql-injection" in rules(findings)


def test_a_shell_true_mention_in_prose_is_not_a_finding():
    """Remediation text that quotes ``shell=True`` is not a second finding."""
    findings = scan(
        "def fix(cmd):\n"
        "    # Pass an argument array; never build a command string with shell=True.\n"
        "    return cmd\n"
    )
    assert "shell-injection" not in rules(findings)


def test_a_fixed_endpoint_is_not_ssrf():
    """``httpx.post(OSV_QUERY, ...)`` names a constant, not a target."""
    findings = scan(
        "OSV_QUERY = 'https://api.osv.dev/v1/query'\n"
        "r = httpx.post(OSV_QUERY, json=payload, timeout=20.0)\n"
    )
    assert "ssrf" not in rules(findings)


def test_a_variable_endpoint_is_ssrf():
    """The same rule must still fire when the target is a variable."""
    findings = scan(
        "u = request.args.get('url')\n"
        "return requests.get(u).text\n"
    )
    assert "ssrf" in rules(findings)


# ---------------------------------------------------------------------------
# A scanner must not report its own documentation.
# ---------------------------------------------------------------------------

def test_docstring_line_numbers_spans_the_whole_block():
    from triagekit.core.analyzers.guards import docstring_line_numbers

    lines = [
        '"""Summary of the function.',
        "",
        "It documents ``el.innerHTML = raw`` as an example.",
        '"""',
        "def f():",
        "    return 1",
    ]
    assert docstring_line_numbers(lines) == frozenset({0, 1, 2, 3})


def test_docstring_line_numbers_ignores_a_one_line_literal():
    from triagekit.core.analyzers.guards import docstring_line_numbers

    lines = ['x = f"""innerHTML = {y}"""', "z = 1"]
    # The line carries its own delimiters, so it is covered by is_prose_mention;
    # a single-line literal must not open a span that swallows the rest.
    assert docstring_line_numbers(lines) == frozenset()


def test_docstring_line_numbers_ignores_an_unterminated_span():
    """On a real PR patch the delivered lines are a subset -- do not suppress."""
    from triagekit.core.analyzers.guards import docstring_line_numbers

    lines = ['"""opened in an earlier hunk', "still documentation", "el.innerHTML = raw"]
    assert docstring_line_numbers(lines) == frozenset()


def test_a_docstring_example_of_a_sink_is_not_a_finding():
    findings = scan(
        "def handler(request):\n"
        '    """Render the page.\n'
        "\n"
        "    The dangerous form is ``el.innerHTML = location.hash``;\n"
        "    the fixed form sanitizes first.\n"
        '    """\n'
        "    return safe_render(request)\n"
    )
    assert "xss-eval" not in rules(findings)


def test_the_scanners_own_docstrings_do_not_flag_themselves():
    """The project documents its own sinks; scanning it must not report them."""
    findings = scan_repository(REPO_ROOT / "src", max_files=3000).findings
    flagged = [f for f in findings if f.rule_id in ("xss-eval", "shell-injection")]
    assert flagged == [], (
        "self-scan flags its own documentation: "
        + ", ".join(f"{f.file}:{f.line}/{f.rule_id}" for f in flagged)
    )
