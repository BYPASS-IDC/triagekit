"""Regression cover for the web scanner's signal-to-noise defects.

WHY THIS FILE EXISTS
----------------------
The web scanner produced 25 findings against a 5-route Flask application, of
which 11 were the same sentence with a different parameter name in it, 2 named
a stack that was not installed, and the form count was double the truth.  A
report shaped like that cannot be handed to a third party: the reader has to
re-derive which lines are real, and the tool has already spent its credibility
on the ones that are not.

Each test below names the defect it locks down:

D4  -- one endpoint that echoes any query value produced one probe finding PER
       PARAMETER NAME TRIED, all of them saying the same thing.
D5  -- the stack fingerprint was derived from the scanner's own guess list, so
       a probed-and-404d ``/actuator`` "proved" Spring Boot on a Flask app.
D6  -- the home page was parsed twice and the same form recorded twice.

The live-target tests bind a throwaway HTTP server to an ephemeral port on
127.0.0.1, so the whole probe path is exercised for real (real responses, real
reflection, real crawl) with no network egress.
"""

from __future__ import annotations

import re
import socket
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qsl, urlparse

from triagekit.core.analyzers.web_scan import (
    _fingerprint,
    _fold_probe_signals,
    _form_key,
    _normalize_url,
    _probe_parameter,
    scan_website,
)

# ---------------------------------------------------------------------------
# A local target that reflects any query value verbatim.  This is the "generic
# echo" shape: it answers every parameter name we invent, which is exactly the
# condition under which the old per-parameter reporting exploded.
# ---------------------------------------------------------------------------

ECHO_PAGE = (
    "<html><head><title>echo</title></head><body>"
    "<h1>echo</h1><p>you sent:</p>"
    "<form action='/search' method='get'>"
    "<input type='text' name='q'><input type='submit' name='go' value='Send'>"
    "</form>"
    "<script>document.write('<b>'+location.hash+'</b>');</script>"
    "</body></html>"
)


class EchoHandler(BaseHTTPRequestHandler):
    """Reflects every query parameter back into the body, unescaped.

    ``do_GET``/``do_POST``/``do_OPTIONS`` all dispatch through ``_page`` so a
    subclass can change the page without re-binding the verb methods: assigning
    ``do_GET = _respond`` in a class body captures the function object, and a
    subclass that only overrides ``_respond`` would keep serving the parent's
    page.
    """

    def log_message(self, *args) -> None:  # silence the per-request noise
        return

    def _page(self) -> bytes:
        parsed = urlparse(self.path)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        echoed = "".join(f"{k}={v};" for k, v in pairs)
        body = ECHO_PAGE.replace("<h1>echo</h1>", f"<h1>echo</h1><div>{echoed}</div>")
        return body.encode("utf-8")

    def _respond(self) -> None:
        raw = self._page()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    do_GET = _respond
    do_POST = _respond
    do_OPTIONS = _respond


# A page that reflects nothing: the probe must stay silent against it.
QUIET_PAGE = (
    "<html><head><title>quiet</title></head><body>"
    "<h1>nothing to see</h1><p>this page echoes no user input.</p>"
    "</body></html>"
)


class QuietHandler(EchoHandler):
    def _page(self) -> bytes:
        return QUIET_PAGE.encode("utf-8")


class _LocalSite:
    """A real HTTP server on an ephemeral port, shut down deterministically."""

    def __init__(self, handler=EchoHandler) -> None:
        self.server = HTTPServer(("127.0.0.1", 0), handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> str:
        self.thread.start()
        return f"http://127.0.0.1:{self.port}/"

    def __exit__(self, *exc) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def _has_free_loopback_port() -> bool:
    """Binding 127.0.0.1:0 must be allowed for the live tests to mean anything."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# D4: one defect, one line
# ---------------------------------------------------------------------------

class ProbeFoldingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.param = "q"

    @staticmethod
    def _signal(**over) -> dict:
        base = {
            "family": "ssti",
            "outcome": "reflected",
            "endpoint": "/",
            "param": "q",
            "probe": "ssti_curly",
            "meaning": "Template-like markers reflected without evaluation evidence.",
            "headline": "Template syntax reflected without evaluation",
            "severity": "low",
            "confidence": "low",
            "cwe": "CWE-94",
            "recommendation": "Ensure template engines do not evaluate untrusted strings.",
            "facts": ["marker reflected verbatim; no evaluation evidence"],
        }
        base.update(over)
        return base

    def test_many_parameters_fold_into_one_finding(self) -> None:
        signals = [self._signal(param=p) for p in
                   ("q", "search", "s", "query", "id", "file", "path", "template", "name", "message")]
        got = _fold_probe_signals(signals)
        self.assertEqual(len(got), 1, "ten parameter names, one defect, one line")
        finding = got[0]
        self.assertEqual(finding.category, "probe-ssti")
        # Every parameter survives the fold -- folding removes lines, not facts.
        self.assertEqual(finding.evidence, "params=q,search,s,query,id,file,path,template,name,message; probes=ssti_curly")
        self.assertIn("10 parameter positions", finding.detail)
        self.assertIn("name", finding.detail)

    def test_a_single_parameter_is_named_directly_in_the_title(self) -> None:
        got = _fold_probe_signals([self._signal(param="id")])
        self.assertEqual(len(got), 1)
        self.assertIn("?id=", got[0].title)
        self.assertNotIn("parameters)", got[0].title)

    def test_distinct_endpoints_do_not_fold_together(self) -> None:
        signals = [
            self._signal(endpoint="/", param="q"),
            self._signal(endpoint="/search", param="q"),
        ]
        self.assertEqual(len(_fold_probe_signals(signals)), 2)

    def test_distinct_outcomes_at_one_endpoint_stay_separate(self) -> None:
        # "the marker came back" (low) and "the expression was evaluated" (high)
        # are two different facts about the same endpoint; folding them would
        # hide the worse one or invent a severity neither measurement supports.
        signals = [
            self._signal(outcome="reflected", severity="low", confidence="low",
                         headline="Template syntax reflected without evaluation"),
            self._signal(outcome="evaluated", severity="high", confidence="medium",
                         headline="Template expression evaluated (probe returned 49)"),
        ]
        got = _fold_probe_signals(signals)
        self.assertEqual(len(got), 2)
        by_sev = {f.severity for f in got}
        self.assertEqual(by_sev, {"low", "high"})

    def test_folding_takes_the_worst_severity_and_confidence(self) -> None:
        signals = [
            self._signal(param="a", severity="low", confidence="low"),
            self._signal(param="b", severity="high", confidence="medium"),
        ]
        got = _fold_probe_signals(signals)
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].severity, "high")
        self.assertEqual(got[0].confidence, "medium")

    def test_no_signals_produce_no_findings(self) -> None:
        self.assertEqual(_fold_probe_signals([]), [])


class ProbeDetectionTests(unittest.TestCase):
    """The probe's own measurements must survive the refactor."""

    def test_signals_carry_the_measurements_that_made_them(self) -> None:
        import httpx

        with _LocalSite(EchoHandler) as base:
            with httpx.Client() as client:
                baseline = {
                    "len": len(ECHO_PAGE),
                    "status": 200,
                    "body": ECHO_PAGE,
                }
                signals = _probe_parameter(
                    client, base, "q", "ce8d0f9f98", lambda *a: None, baseline, timeout=8.0
                )
        self.assertTrue(signals, "an echoing site must yield probe signals")
        for sig in signals:
            for key in ("family", "outcome", "param", "probe", "severity",
                        "confidence", "cwe", "recommendation", "facts"):
                self.assertIn(key, sig)
            self.assertEqual(sig["endpoint"], "/")

    def test_a_quiet_site_yields_no_signals(self) -> None:
        import httpx

        with _LocalSite(QuietHandler) as base:
            with httpx.Client() as client:
                baseline = {"len": len(QUIET_PAGE), "status": 200, "body": QUIET_PAGE}
                signals = _probe_parameter(
                    client, base, "q", "ce8d0f9f98", lambda *a: None, baseline, timeout=8.0
                )
        self.assertEqual(signals, [], "no reflection, no signal")

    def test_an_empty_payload_prefix_is_not_reflection_evidence(self) -> None:
        # ``"{{7*7}}".split("{")[0]`` is the empty string, and ``"" in body`` is
        # always true.  Left alone, the SSTI reflection rule fired on every
        # target for every parameter with nothing reflected at all.
        import httpx

        with _LocalSite(QuietHandler) as base:
            with httpx.Client() as client:
                baseline = {"len": len(QUIET_PAGE), "status": 200, "body": QUIET_PAGE}
                signals = _probe_parameter(
                    client, base, "id", "ce8d0f9f98", lambda *a: None, baseline, timeout=8.0
                )
        self.assertEqual([s for s in signals if s["family"] == "ssti"], [])


# ---------------------------------------------------------------------------
# D7: referenced JS assets are fetched and analyzed, not just inline blocks
# ---------------------------------------------------------------------------

ASSET_PAGE = (
    "<!doctype html><html><head><title>assets</title>"
    "<script src='/static/vendor.js'></script>"
    "</head><body><h1>asset test</h1>"
    "<form action='/search' method='get'><input name='q'></form>"
    "<script>document.write('<i>'+location.search+'</i>');</script>"
    "<script src='/static/app.js'></script>"
    "</body></html>"
)

DIRTY_BUNDLE = (
    "var token = 'ghp_aB3dEf7hIj2kLm9nOpQ4rSt5uVw6xYz8AB';\n"
    "document.write('<b>' + location.hash + '</b>');\n"
    "function load(o){ $.ajax({url: '/api/v2/tokens/' + o.id}); }\n"
)

CLEAN_BUNDLE = (
    "function pad(n){ return (n < 10 ? '0' : '') + n; }\n"
    "export const VERSION = '1.0.0';\n"
)


class AssetHandler(EchoHandler):
    """A page that references two external bundles plus a dirty inline block."""

    def _page(self) -> bytes:
        path = urlparse(self.path).path
        if path == "/static/app.js":
            return DIRTY_BUNDLE.encode("utf-8")
        if path == "/static/vendor.js":
            return CLEAN_BUNDLE.encode("utf-8")
        return ASSET_PAGE.encode("utf-8")


@unittest.skipUnless(_has_free_loopback_port(), "cannot bind a loopback port")
class ReferencedAssetTests(unittest.TestCase):
    def setUp(self) -> None:
        import httpx  # noqa: F401  (the scanner needs httpx at import time)

    def test_referenced_assets_are_fetched(self) -> None:
        with _LocalSite(AssetHandler) as base:
            result = scan_website(url=base, check_sensitive_paths=False, crawl=True)
        urls = [jf.get("url", "") for jf in result.js_files]
        self.assertIn("/static/app.js", " ".join(urls))
        self.assertIn("/static/vendor.js", " ".join(urls))

    def test_a_dirty_external_bundle_is_analyzed(self) -> None:
        with _LocalSite(AssetHandler) as base:
            result = scan_website(url=base, check_sensitive_paths=False, crawl=True)
        external = [
            f for f in result.findings
            if "static/app.js" in (f.detail or "") or "static/app.js" in (f.evidence or "")
        ]
        categories = {f.category for f in external}
        self.assertIn("js-secret", categories)
        self.assertIn("js-sink", categories)
        self.assertIn("js-domxss", categories)

    def test_a_clean_external_bundle_produces_no_findings(self) -> None:
        with _LocalSite(AssetHandler) as base:
            result = scan_website(url=base, check_sensitive_paths=False, crawl=True)
        clean = [
            f for f in result.findings
            if "static/vendor.js" in (f.detail or "") or "static/vendor.js" in (f.evidence or "")
        ]
        self.assertEqual(clean, [], "a clean bundle must not be reported")

    def test_inline_scripts_are_still_analyzed(self) -> None:
        # The external-asset path must not replace the inline one.
        with _LocalSite(AssetHandler) as base:
            result = scan_website(url=base, check_sensitive_paths=False, crawl=True)
        inline = [f for f in result.findings if "#inline" in (f.detail or "")]
        self.assertTrue(inline, "inline scripts must still be analyzed")

    def test_api_hints_are_extracted_from_external_bundles(self) -> None:
        with _LocalSite(AssetHandler) as base:
            result = scan_website(url=base, check_sensitive_paths=False, crawl=True)
        self.assertIn("/api/v2/tokens/", result.api_hints)


@unittest.skipUnless(_has_free_loopback_port(), "cannot bind a loopback port")
class LiveTargetTests(unittest.TestCase):
    def test_an_echo_site_reports_one_probe_finding_per_defect(self) -> None:
        with _LocalSite(EchoHandler) as base:
            result = scan_website(url=base, check_sensitive_paths=False, crawl=True)
        probe = [f for f in result.findings if f.category.startswith("probe-")]
        # The site reflects every parameter at every endpoint it exposes, so
        # each family reports ONCE PER ENDPOINT -- never once per parameter name
        # tried.  Two endpoints are two defects, not noise.
        by_defect: dict[tuple, int] = {}
        for f in probe:
            by_defect[(f.category, f.endpoint)] = by_defect.get((f.category, f.endpoint), 0) + 1
        for defect, count in by_defect.items():
            self.assertEqual(count, 1, f"{defect}: one defect, one line, got {count}")
        self.assertGreater(len(by_defect), 1, "the coverage fix must probe more than the root")

    def test_the_echo_site_is_not_reported_as_wordpress_or_spring(self) -> None:
        with _LocalSite(EchoHandler) as base:
            result = scan_website(url=base, check_sensitive_paths=False, crawl=True)
        self.assertNotIn("WordPress", result.technologies)
        self.assertNotIn("Spring Boot", result.technologies)

    def test_the_echo_sites_single_form_is_recorded_once(self) -> None:
        with _LocalSite(EchoHandler) as base:
            result = scan_website(url=base, check_sensitive_paths=False, crawl=True)
        self.assertEqual(len(result.forms), 1, "one form on the page, one record")

    def test_a_quiet_site_produces_no_probe_findings(self) -> None:
        with _LocalSite(QuietHandler) as base:
            result = scan_website(url=base, check_sensitive_paths=False, crawl=True)
        probe = [f for f in result.findings if f.category.startswith("probe-")]
        self.assertEqual(probe, [])

    def test_a_reflecting_form_endpoint_gets_the_full_probe_matrix(self) -> None:
        # The probe used to aim its whole matrix at the root URL alone.  A page
        # whose form targets /search?q= gets no SQLi/SSTI/XSS probe at all when
        # / itself reflects nothing -- which is the ordinary case, so the deep
        # probes missed essentially every real defect.
        with _LocalSite(EchoHandler) as base:
            result = scan_website(url=base, check_sensitive_paths=False, crawl=True)
        probe = [f for f in result.findings if f.category.startswith("probe-")]
        self.assertTrue(probe, "a reflecting form endpoint must yield probe findings")
        # The finding must point at the form's endpoint, not at "/" alone.
        self.assertTrue(
            any(f.endpoint == "/search" for f in probe),
            f"probe findings should name /search, got {[f.endpoint for f in probe]}",
        )
        # And it must be ONE line per defect, not one per parameter.
        by_category: dict[str, int] = {}
        for f in probe:
            by_category[f.category] = by_category.get(f.category, 0) + 1
        for category, count in by_category.items():
            self.assertLessEqual(count, 2, f"{category}: got {count} findings")


# ---------------------------------------------------------------------------
# D5: a fingerprint is a claim about the target, so it needs observed evidence
# ---------------------------------------------------------------------------

class FingerprintTests(unittest.TestCase):
    def test_the_scanners_own_guess_list_is_not_evidence(self) -> None:
        # Every path below is one THIS SCANNER GUESSES.  They all 404'd.  The
        # old code still labelled the target WordPress + Spring Boot.
        guesses = ["/actuator", "/wp-content/debug.log", "/wp-json/wp/v2/users",
                   "/wp-login.php", "/xmlrpc.php", "/telescope"]
        techs = _fingerprint(
            {"Server": "Werkzeug/3.1.9 Python/3.9.13"},
            "<html><body>nothing here</body></html>",
            guesses,
        )
        self.assertNotIn("WordPress", techs)
        self.assertNotIn("Spring Boot", techs)

    def test_a_guessed_path_is_never_evidence(self) -> None:
        # ``/actuator`` is on this scanner's own guess list.  The old bug passed
        # guesses that had 404'd and labelled the target Spring Boot; the fix
        # refuses every guess path outright, so the invariant holds no matter
        # what a caller believes about the response status.
        techs = _fingerprint(
            {"Server": "Werkzeug/3.1.9 Python/3.9.13"},
            "<html><body>ok</body></html>",
            ["/actuator", "/wp-login.php", "/wp-content/debug.log"],
        )
        self.assertNotIn("Spring Boot", techs)
        self.assertNotIn("WordPress", techs)

    def test_a_path_the_site_itself_referenced_is_evidence(self) -> None:
        # A path the target linked to is independent evidence: we did not ask
        # for it, the site offered it.
        body = '<a href="/actuator/health">health</a>'
        self.assertIn("Spring Boot", _fingerprint({}, body, []))

    def test_a_real_wordpress_body_is_still_labelled(self) -> None:
        body = ('<link rel="stylesheet" href="/wp-content/themes/x/style.css">'
                '<meta name="generator" content="WordPress 6.4">')
        self.assertIn("WordPress", _fingerprint({}, body, []))

    def test_the_word_react_is_not_the_react_framework(self) -> None:
        # Old needle: ``"react" in blob``.
        body = "<html><body><p>How do you react to this? A serene reaction.</p></body></html>"
        self.assertNotIn("React", _fingerprint({}, body, []))

    def test_a_period_after_vue_is_not_vue(self) -> None:
        # Old needle: ``"vue."`` -- matched "revue." and "argue.".
        body = "<html><body><p>the revue. we argue. a virtue.</p></body></html>"
        self.assertNotIn("Vue", _fingerprint({}, body, []))

    def test_real_react_markup_is_labelled(self) -> None:
        body = '<div id="root"></div><script src="/static/react-dom.js"></script>'
        self.assertIn("React", _fingerprint({}, body, []))

    def test_jquery_is_labelled_from_a_script_src(self) -> None:
        body = '<script src="/static/jquery-1.4.2.min.js"></script>'
        self.assertIn("jQuery", _fingerprint({}, body, []))

    def test_server_and_x_powered_by_are_reported_verbatim(self) -> None:
        techs = _fingerprint({"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4"}, "", [])
        self.assertIn("Server: nginx/1.18.0", techs)
        self.assertIn("X-Powered-By: PHP/7.4", techs)

    def test_technology_labels_are_not_duplicated(self) -> None:
        body = '<link href="/wp-content/a.css"><img src="/wp-content/b.png">'
        techs = _fingerprint({}, body, [])
        self.assertEqual(techs.count("WordPress"), 1)


# ---------------------------------------------------------------------------
# D6: the same form is one form
# ---------------------------------------------------------------------------

class FormDedupTests(unittest.TestCase):
    def test_two_identical_records_have_the_same_key(self) -> None:
        a = {"action": "http://x/search", "method": "GET", "inputs": ["q:text", "go:submit"]}
        b = {"action": "http://x/search/", "method": "get", "inputs": ["go:submit", "q:text"]}
        self.assertEqual(_form_key(a), _form_key(b))

    def test_forms_differing_in_any_dimension_stay_distinct(self) -> None:
        base = {"action": "http://x/search", "method": "GET", "inputs": ["q:text"]}
        other_action = dict(base, action="http://x/other")
        other_method = dict(base, method="POST")
        other_inputs = dict(base, inputs=["q:text", "extra:text"])
        keys = {_form_key(base), _form_key(other_action), _form_key(other_method), _form_key(other_inputs)}
        self.assertEqual(len(keys), 4)

    def test_input_order_is_not_a_distinction(self) -> None:
        # The HTML parser emits attributes in document order, which carries no
        # meaning for two records of the same form.
        a = {"action": "http://x/f", "method": "GET", "inputs": ["a", "b", "c"]}
        b = {"action": "http://x/f", "method": "GET", "inputs": ["c", "a", "b"]}
        self.assertEqual(_form_key(a), _form_key(b))


class URLNormalizationTests(unittest.TestCase):
    def test_a_scheme_is_added_when_missing(self) -> None:
        self.assertTrue(_normalize_url("127.0.0.1:8000").startswith("https://"))

    def test_a_url_with_a_scheme_is_left_alone(self) -> None:
        url = "http://127.0.0.1:8971/search?q=1"
        self.assertEqual(_normalize_url(url), url)

    def test_an_empty_url_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _normalize_url("   ")


if __name__ == "__main__":
    unittest.main()
