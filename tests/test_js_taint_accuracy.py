"""Regression tests for the JavaScript/TypeScript taint analyzer.

HARNESS CONTRACT (read before editing this file)
------------------------------------------------
1. Every fixture is a self-contained source string written to a unique temp
   directory and removed in a ``finally`` block, so cleanup survives a failed
   assertion.  Two fixtures live in the repository instead
   (``dev/corpora/js_vuln/src/app.js`` and ``dev/corpora/js_safe/src/app.js``)
   because they are the corpora the accuracy numbers in ``dev/AUTONOMOUS_TODO.md``
   are measured against; those two assertions read the real files, so a corpus
   edit fails here rather than silently changing the benchmark.
2. Analysis goes through ``analyze_js_file`` with a FRESH analyzer per call.
3. Output is ASCII only -- the console on this platform is cp1252 and raises
   ``UnicodeEncodeError`` on non-ASCII.
4. Each test names the defect it guards against.

THE DEFECTS
-----------
D10  The JS analyzer reported **0 findings** on a deliberately vulnerable
     Express file.  Root cause: ``FUNCTION_PATTERN`` / ``ARROW_FUNCTION_PATTERN``
     only matched *named* declarations, so ``app.get('/x', (req, res) => {...})``
     -- the shape every Node.js handler actually takes -- was never extracted,
     and with no function context there was no analysis at all.
D11  No per-file state reset, so ``analyze_directory`` results depended on file
     order: ``taint_paths`` grew monotonically and a flow found in the third
     file was attributed to the first.
D12  No module-level analysis, so a top-level flow was invisible.  (The Python
     analyzer has ``_analyze_module_level``; the JS one did not.)
D29  Registry/analyzer vocabulary mismatch.  The JS sink patterns are
     *line-shaped* (``child_process\\.exec\\s*\\(``) but the analyzer passed bare
     callee names (``exec``) to ``find_sinks``, so nothing ever matched.  The
     same mismatch hid destructured ``require`` calls, ``db.query`` whose SQL was
     assembled on a previous line, and every ``obj.prop = <source>`` DOM sink.
D30  Over-broad source propagation.  Any expression *mentioning* a request value
     was treated as tainted, so ``crypto.createHmac(...).update(req.query.msg)``
     -- an HMAC, not user input -- was reported.  A call now consumes its
     arguments unless it is a registered pass-through.
D31  Safe shapes scored like vulnerable ones: ``path.basename`` was not
     registered as a JS sanitizer, so ``sendFile(join(dir, basename(user)))`` --
     the standard safe idiom -- was reported as traversal.
D32  ``execFile('ping', ['-c', '1', host])`` with an argv array was matched as
     command execution.  Only a shell form, an interpolated command, or an
     explicit ``{shell: true}`` may fire.
D33  Environment variables propagated as attacker input.  ``process.env.X`` is
     deployment configuration, not attacker-controlled data.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from triagekit.core.taint.js_analyzer import JSTaintAnalyzer, analyze_js_file


REPO_ROOT = Path(__file__).resolve().parent.parent
VULN_CORPUS = REPO_ROOT / "dev" / "corpora" / "js_vuln" / "src" / "app.js"
SAFE_CORPUS = REPO_ROOT / "dev" / "corpora" / "js_safe" / "src" / "app.js"


def analyze(source: str, suffix: str = ".js") -> list:
    """Analyze ``source`` as a standalone file with a fresh analyzer."""
    tmpdir = Path(tempfile.mkdtemp(prefix="triagekit_js_"))
    try:
        target = tmpdir / ("case" + suffix)
        target.write_text(source, encoding="utf-8")
        return analyze_js_file(str(target))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def categories(paths: list) -> list[str]:
    return sorted({p.sink.category for p in paths})


def lines(paths: list) -> list[int]:
    return sorted(p.sink_line for p in paths)


# ---------------------------------------------------------------------------
# D10 / D29 -- the vulnerable corpus.  Nine flows, and only those nine.
# ---------------------------------------------------------------------------

def test_vuln_corpus_reports_the_nine_intended_flows():
    """The headline defect: a file of nine vulnerabilities reported zero."""
    paths = analyze_js_file(str(VULN_CORPUS))
    assert len(paths) == 9, (
        f"expected 9 flows, got {len(paths)}: "
        + ", ".join(f"L{p.sink_line}/{p.sink.category}" for p in paths)
    )


def test_express_callback_is_extracted_and_analyzed():
    """An anonymous callback passed to a call is a function context."""
    analyzer = JSTaintAnalyzer()
    src = "app.get('/ping', (req, res) => { exec('ping ' + req.query.host); });\n"
    paths = analyze(src)
    assert paths, "no flow reported for an inline Express handler (D10)"
    assert paths[0].sink.category == "command-execution"
    assert paths[0].sink_line == 1


def test_concise_arrow_handler_is_analyzed():
    """``(req, res) => res.redirect(req.query.to)`` has no brace body."""
    paths = analyze("app.get('/go', (req, res) => res.redirect(req.query.to));\n")
    assert [p.sink.category for p in paths] == ["open-redirect"]


def test_destructured_child_process_is_a_sink():
    """``const { exec } = require('child_process')`` then ``exec(...)``."""
    paths = analyze(
        "const { exec } = require('child_process');\n"
        "app.get('/x', (req, res) => { exec('ping ' + req.query.host); });\n"
    )
    assert [p.sink.category for p in paths] == ["command-execution"]


def test_sql_built_on_a_previous_line_reaches_db_query():
    """``sql-concat`` needs the ``+`` inside the call; real code does not."""
    paths = analyze(
        "app.get('/u', (req, res) => {\n"
        "  const q = \"SELECT * FROM u WHERE n = '\" + req.query.name + \"'\";\n"
        "  db.query(q, (e, r) => res.json(r));\n"
        "});\n"
    )
    assert [p.sink.category for p in paths] == ["sql-execution"]


def test_member_assignment_dom_sinks_are_reachable():
    """``el.innerHTML = location.hash`` is an assignment, not a call."""
    paths = analyze("el.innerHTML = location.hash.substring(1);\n")
    assert [p.sink.category for p in paths] == ["xss"]


def test_dom_sink_on_a_computed_receiver():
    """``document.getElementById('out').innerHTML = ...`` is the real form."""
    paths = analyze(
        "document.getElementById('out').innerHTML = location.hash;\n"
    )
    assert [p.sink.category for p in paths] == ["xss"]


def test_prototype_pollution_via_json_parse():
    """``merge(target, JSON.parse(userInput))`` is CWE-1321."""
    paths = analyze("function merge(a, b) { for (const k in b) a[k] = b[k]; }\n"
                    "merge(config, JSON.parse(userInput));\n")
    assert [p.sink.category for p in paths] == ["prototype-pollution"]


def test_fs_operation_on_a_destructured_require():
    """``const fs = require('fs')`` then ``fs.readFileSync(...)``."""
    paths = analyze(
        "const fs = require('fs');\n"
        "app.get('/r', (req, res) => res.send(fs.readFileSync('/d/' + req.query.f)));\n"
    )
    assert "path-traversal" in categories(paths)


def test_typescript_handler_with_typed_params():
    """``(req: Request, res: Response)`` must still extract ``req``."""
    paths = analyze(
        "import { Request, Response } from 'express';\n"
        "app.get('/x', (req: Request, res: Response) => {\n"
        "  res.redirect(req.query.to);\n"
        "});\n",
        suffix=".ts",
    )
    assert [p.sink.category for p in paths] == ["open-redirect"]


# ---------------------------------------------------------------------------
# D10 / D32 -- the three safe variants in the vulnerable corpus must not fire.
# ---------------------------------------------------------------------------

def test_parameterized_query_is_not_sql_injection():
    paths = analyze(
        "app.get('/safe', (req, res) => {\n"
        "  db.query('SELECT * FROM u WHERE n = ?', [req.query.name], (e, r) => res.json(r));\n"
        "});\n"
    )
    assert paths == [], "a placeholder plus a parameter array was reported (D32)"


def test_dompurify_sanitized_html_is_not_xss():
    paths = analyze(
        "app.get('/safe2', (req, res) => res.send(DOMPurify.sanitize(req.query.html)));\n"
    )
    assert paths == [], "an allowlist HTML sanitizer was reported (D32)"


def test_argv_array_execfile_is_not_command_injection():
    paths = analyze(
        "app.get('/safe3', (req, res) => execFile('ping', ['-c', '1', req.query.host]));\n"
    )
    assert paths == [], "an argv array with no shell was reported (D32)"


# ---------------------------------------------------------------------------
# D31 / D33 -- the safe corpus must score zero.
# ---------------------------------------------------------------------------

def test_safe_corpus_reports_nothing():
    """Twelve idiomatic fixed forms, zero findings."""
    paths = analyze_js_file(str(SAFE_CORPUS))
    assert paths == [], (
        "false positives on the safe corpus: "
        + ", ".join(f"L{p.sink_line}/{p.sink.category}/{p.sink.name}" for p in paths)
    )


def test_path_basename_is_a_sanitizer():
    """D31: the standard safe path idiom."""
    paths = analyze(
        "const path = require('path');\n"
        "app.get('/safe-read', (req, res) => {\n"
        "  res.sendFile(path.join(DATA_DIR, path.basename(req.query.f)));\n"
        "});\n"
    )
    assert paths == [], "path.basename was not modelled as a path sanitizer (D31)"


def test_spawn_with_argv_array_is_not_command_injection():
    paths = analyze(
        "app.get('/x', (req, res) => { spawn('ls', ['-la', req.query.dir]); res.end(); });\n"
    )
    assert paths == []


def test_environment_variable_is_not_attacker_input():
    """D33: an HMAC keyed from process.env is not an injection finding."""
    paths = analyze(
        "app.get('/safe-token', (req, res) => {\n"
        "  const token = process.env.API_TOKEN;\n"
        "  const mac = crypto.createHmac('sha256', token).update(req.query.msg).digest('hex');\n"
        "  res.json({ mac });\n"
        "});\n"
    )
    assert paths == [], "an environment-derived value was treated as attacker input (D33)"


def test_textcontent_is_not_an_xss_sink():
    """The DOM API that treats its argument as data."""
    paths = analyze(
        "app.get('/x', (req, res) => {\n"
        "  document.getElementById('out').textContent = req.query.name;\n"
        "  res.end();\n"
        "});\n"
    )
    assert paths == []


def test_constant_redirect_target_is_not_open_redirect():
    paths = analyze("app.get('/x', (req, res) => res.redirect('/dashboard'));\n")
    assert paths == []


# ---------------------------------------------------------------------------
# D11 -- per-file state must not leak between calls.
# ---------------------------------------------------------------------------

def test_shared_analyzer_instance_does_not_leak_state_between_files():
    """D11: ``analyze_directory`` reuses one instance across files."""
    analyzer = JSTaintAnalyzer()
    tmpdir = Path(tempfile.mkdtemp(prefix="triagekit_js_order_"))
    try:
        clean = tmpdir / "clean.js"
        dirty = tmpdir / "dirty.js"
        clean.write_text(
            "app.get('/x', (req, res) => res.send('constant'));\n", encoding="utf-8"
        )
        dirty.write_text(
            "app.get('/y', (req, res) => res.redirect(req.query.to));\n", encoding="utf-8"
        )
        # Safe file first: any flow attributed to it belongs to the dirty one.
        first = analyzer.analyze_file(str(clean))
        assert first == [], "state from an earlier call leaked into a clean file (D11)"
        second = analyzer.analyze_file(str(dirty))
        assert [p.sink.category for p in second] == ["open-redirect"]
        third = analyzer.analyze_file(str(clean))
        assert third == [], "taint_paths grew monotonically instead of resetting (D11)"
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_directory_analysis_finds_flows_in_every_file():
    paths = JSTaintAnalyzer().analyze_directory(str(REPO_ROOT / "dev" / "corpora" / "js_vuln"))
    assert len(paths) == 9, f"expected 9 flows across the directory, got {len(paths)}"
    assert {Path(p.sink_file).name for p in paths} == {"app.js"}


# ---------------------------------------------------------------------------
# D12 -- module-level flows.
# ---------------------------------------------------------------------------

def test_module_level_flow_is_analyzed():
    """Python has ``_analyze_module_level``; JS now has a synthetic context."""
    paths = analyze(
        "const target = process.argv[2];\n"
        "res.redirect(target);\n"
    )
    assert [p.sink.category for p in paths] == ["open-redirect"]


def test_module_level_line_numbers_are_the_real_ones():
    """The synthetic context holds non-contiguous lines, so counts do not map."""
    src = (
        "const a = 1;\n"                      # 1
        "app.get('/x', (req, res) => {\n"     # 2
        "  res.send('ok');\n"                 # 3
        "});\n"                               # 4
        "const b = 2;\n"                      # 5
        "res.redirect(location.hash);\n"      # 6
    )
    paths = analyze(src)
    assert lines(paths) == [6], f"expected the flow on line 6, got {lines(paths)}"


# ---------------------------------------------------------------------------
# Documented limitations -- asserted so they cannot silently become "no issues".
# ---------------------------------------------------------------------------

def test_allowlist_guarded_redirect_is_a_known_limitation():
    """Nothing models the guard, so the taint still reaches the sink.

    This is a *documented* false positive, not a regression.  If a future change
    makes it disappear, the assertion below is what tells you the guard model was
    added -- and this test should then be rewritten, not deleted.

    Note the contrast with the ``new URL()`` form, which is *not* reported (see
    ``test_new_url_validated_redirect_is_not_a_false_positive``): there the sink
    consumes a locally built value rather than the request string itself, so
    nothing propagates.  Only the form that redirects the request value directly
    is a false positive.
    """
    paths = analyze(
        "app.get('/go', (req, res) => {\n"
        "  const next = req.query.next;\n"
        "  if (!/^\\/[a-z]+$/.test(next)) return res.redirect('/');\n"
        "  res.redirect(next);\n"
        "});\n"
    )
    assert "open-redirect" in categories(paths)


def test_new_url_validated_redirect_is_not_a_false_positive():
    """``new URL(req.query.to)`` produces a locally built value.

    ``url-validate-js`` is registered as VALIDATE (is_strong=False), which is
    correct: a parsed URL is not the attacker's string.  Nothing propagates the
    request value through the constructor, so the guarded redirect is clean.
    """
    paths = analyze(
        "const ALLOWED = new Set(['example.com']);\n"
        "app.get('/go', (req, res) => {\n"
        "  const t = new URL(req.query.to);\n"
        "  if (ALLOWED.has(t.hostname)) res.redirect(t.toString());\n"
        "});\n"
    )
    assert paths == []


def test_path_join_without_basename_is_a_known_limitation():
    """``path.join`` is VALIDATE (is_strong=False), so it does not neutralise.

    Correct behaviour: join preserves an absolute path, so ``join(base,
    '/etc/passwd')`` escapes the base.  Only ``basename`` removes it, and a
    *weak* sanitizer must not erase the taint -- that is what made this shape
    look clean before.
    """
    paths = analyze(
        "const path = require('path');\n"
        "app.get('/r', (req, res) => {\n"
        "  fs.readFileSync(path.join(DATA_DIR, req.query.f));\n"
        "});\n"
    )
    assert "path-traversal" in categories(paths)


def test_object_assign_with_parsed_payload_is_reported():
    """The unguarded merge is the vulnerability; only a key-filter is the fix."""
    paths = analyze(
        "app.get('/m', (req, res) => {\n"
        "  const merged = Object.assign(Object.create(null), DEFAULTS, JSON.parse(req.query.cfg));\n"
        "  res.json(merged);\n"
        "});\n"
    )
    assert "prototype-pollution" in categories(paths)


def test_key_filtered_merge_is_not_reported():
    """The fix: skip __proto__/constructor/prototype before assigning."""
    paths = analyze(
        "app.get('/m', (req, res) => {\n"
        "  const body = JSON.parse(req.query.cfg || '{}');\n"
        "  for (const k of Object.keys(body)) {\n"
        "    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;\n"
        "    DEFAULTS[k] = body[k];\n"
        "  }\n"
        "  res.json(DEFAULTS);\n"
        "});\n"
    )
    assert paths == []


def test_template_literal_sql_is_reported():
    paths = analyze(
        "app.get('/u', (req, res) => {\n"
        "  db.query(`SELECT * FROM u WHERE n = '${req.query.name}'`);\n"
        "});\n"
    )
    assert "sql-execution" in categories(paths)


def test_transparent_method_call_carries_taint():
    """``name.trim()`` is still ``name``; a transform is not assumed to fix it."""
    paths = analyze(
        "app.get('/x', (req, res) => {\n"
        "  const host = req.query.host.trim();\n"
        "  exec('ping ' + host);\n"
        "});\n"
    )
    assert [p.sink.category for p in paths] == ["command-execution"]
