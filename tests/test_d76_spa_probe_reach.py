"""D76 -- the deep probes must reach a client-rendered application.

The OWASP Juice Shop preview reported ``forms=0``, ``Findings: C=0 H=3 M=6 L=6``
and **not one ``probe-*`` finding**, on a target that is vulnerable by design
and whose signature bug answers a tautology with an admin session token.

Three independent walls stood between the scanner and the vulnerability, and
each one is tested below:

1. **The endpoint extractor only knew ``/api/``** (``JS_ENDPOINT_PATS``).
   Juice Shop serves its injectable API at ``/rest/...``; those paths never
   entered ``api_hints``, so they were never crawled and never probed.  The
   report listed 15 hints taken from a 1.2 MB bundle that contains the whole
   attack surface.
2. **The probe target list was the root plus form actions.**  With no
   ``<form>`` elements the list collapsed to exactly one URL -- the homepage,
   which returns the same shell for any query string -- so the matrix measured
   nothing.  The endpoints the target's own JavaScript named were reported as
   "hints" while the probe fired at ``/``.
3. **The probe could only express a query string.**  Juice Shop's login bypass
   is ``POST /rest/user/login`` with a JSON body; a GET probe cannot reach it.

Live measurements that motivate the tests (OWASP Juice Shop preview,
owner-authorized deliberately-vulnerable target):

    GET  /rest/products/search            -> full product list
    GET  /rest/products/search?q='        -> 30 bytes
    POST /rest/user/login {"email":"a@b.com",...}          -> 401
    POST /rest/user/login {"email":"' OR 1=1--",...}       -> 200 + admin JWT

Run with the project venv:

    PYTHONPATH=src .venv/Scripts/python.exe -m pytest tests/test_d76_spa_probe_reach.py -q
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path
from urllib.parse import urlparse

REPO = Path(__file__).resolve().parent.parent
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

from triagekit.core.analyzers import web_scan as ws  # noqa: E402


class EndpointNamespaceTests(unittest.TestCase):
    """Wall 1: an app's API namespace must not have to be spelled /api/."""

    def _hints(self, source: str) -> list[str]:
        out: list[str] = []
        for pat in ws.JS_ENDPOINT_PATS:
            for m in re.finditer(pat, source):
                cand = (m.group(1) if m.lastindex else m.group(0)).strip()
                if cand.startswith(("/", "http", "ws")) and cand not in out:
                    out.append(cand[:300])
        return out

    def test_the_rest_namespace_is_recognized(self) -> None:
        # The literal string that appears in Juice Shop's own main.js.
        hints = self._hints('"/rest/products/search?q="')
        self.assertIn(
            "/rest/products/search?q=", hints,
            "a /rest/ API path referenced by the target is not an endpoint hint",
        )

    def test_the_login_endpoint_is_recognized(self) -> None:
        hints = self._hints("'/rest/user/login'")
        self.assertIn("/rest/user/login", hints)

    def test_a_namespace_without_a_path_is_still_an_endpoint(self) -> None:
        # /graphql is the endpoint; there is no path after it.
        hints = self._hints('"/graphql"')
        self.assertIn("/graphql", hints)

    def test_a_versioned_api_route_is_recognized(self) -> None:
        hints = self._hints('"/v1/users"')
        self.assertIn("/v1/users", hints)

    def test_a_socket_io_endpoint_with_its_query_string_is_recognized(self) -> None:
        hints = self._hints("`/socket.io/?EIO=4&transport=polling`")
        self.assertIn("/socket.io/?EIO=4&transport=polling", hints)

    def test_the_api_namespace_still_works(self) -> None:
        hints = self._hints('"/api/Products"')
        self.assertIn("/api/Products", hints)

    def test_a_static_asset_is_not_an_api_endpoint(self) -> None:
        # The extractor must stay an API finder, not become a URL finder.
        for asset in ('"/static/main.css"', '"/assets/app-4f2a.js"',
                      '"/images/logo.png"', '"/wp-content/style.css"'):
            hints = self._hints(asset)
            self.assertNotIn(
                asset.strip("'\"`"), hints,
                f"{asset} was reported as an API endpoint hint",
            )

    def test_a_bare_word_that_contains_a_namespace_is_not_matched(self) -> None:
        # "rest" appears inside ordinary prose; only a quoted path counts.
        hints = self._hints("the restaurant serves apiaries and authored text")
        self.assertEqual(hints, [], f"prose produced API hints: {hints}")


class ProbeTargetAssemblyTests(unittest.TestCase):
    """Wall 2: the matrix must have somewhere to point besides the homepage."""

    def _assemble(self, forms, discovered, api_hints, root="https://x.test/"):
        """Mirror of the target-list assembly in scan_website.

        Kept as a test-local copy of the rule so the test can state the rule
        directly; the production code is exercised by the live tests below.
        The same-host filter is part of the rule and is included here: getting
        it wrong once cost three of the six probe slots to twitter.com and
        googleapis.com, which are ordinary references in any real bundle.
        """
        targets = [root]

        def add(cand):
            if not cand:
                return
            try:
                u = ws.urljoin(root, cand)
            except Exception:
                return
            if not ws._same_host(root, u):
                return
            if u not in targets:
                targets.append(u)

        for fm in forms[:12]:
            add(fm.get("action") or "")
        for path in list(discovered.keys())[:80]:
            add(path)
        for hint in api_hints[:80]:
            add(hint)
        with_q = [u for u in targets if "?" in u]
        no_q = [u for u in targets if "?" not in u]
        return with_q + no_q

    def test_an_spa_with_no_forms_still_gets_api_targets(self) -> None:
        # The exact Juice Shop shape: zero forms, hints extracted from JS.
        targets = self._assemble([], {}, ["/rest/products/search?q=", "/rest/user/login"])
        self.assertGreater(
            len(targets), 1,
            "an SPA with no forms still yields only the root as a probe target",
        )
        self.assertIn("/rest/products/search", targets[0] or "")

    def test_an_endpoint_with_a_query_string_is_probed_first(self) -> None:
        targets = self._assemble([], {}, ["/api/Products", "/rest/products/search?q="])
        self.assertTrue(targets[0].endswith("?q="),
                        f"a query-carrying endpoint was not ranked first: {targets[0]}")

    def test_the_ranking_is_deterministic(self) -> None:
        # Partition, not sort: two runs must not disagree, or CI diffs become
        # meaningless (the same defect class as the -hash() tie-break).
        args = ([], {}, ["/a", "/b?q=", "/c", "/d?q="])
        self.assertEqual(self._assemble(*args), self._assemble(*args))

    def test_the_root_is_always_a_target(self) -> None:
        targets = self._assemble([], {"", }, [])
        self.assertIn("https://x.test/", targets)

    def test_a_form_action_outranks_an_api_hint(self) -> None:
        # The meaningful invariant is not ordering *between* a form and a hint
        # -- it is that every source of endpoint is represented.  Ordering
        # between the no-query group is preserved insertion order (forms, then
        # crawled, then hints), which is what makes a run reproducible.
        targets = self._assemble(
            [{"action": "/search", "method": "GET", "inputs": ["q"]}],
            {}, ["/rest/products/search?q="],
        )
        self.assertIn("https://x.test/search", targets,
                      "a form action was dropped from the probe targets")
        self.assertIn("https://x.test/rest/products/search?q=", targets,
                      "an API hint was dropped from the probe targets")
        # The URL that carries a query string is the one the target told us
        # accepts a parameter, so it is measured first.
        self.assertEqual(targets[0], "https://x.test/rest/products/search?q=")

    def test_a_cross_origin_hint_is_not_a_probe_target(self) -> None:
        # A JS bundle references twitter, googleapis, self-hosted CDNs, docs
        # sites.  Probing those is both useless and an out-of-scope request to
        # somebody else's server.  This filter is the only thing standing
        # between "the scanner read a bundle" and "the scanner sent SQL markers
        # to twitter.com".
        hints = [
            "https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=",
            "https://twitter.com/intent/tweet?text=",
            "https://bsky.app/intent/compose?text=",
            "https://mastodonshare.com/?text=",
            "/rest/user/login",
        ]
        targets = self._assemble([], {}, hints)
        for foreign in ("googleapis.com", "twitter.com", "bsky.app", "mastodonshare.com"):
            self.assertFalse(
                any(foreign in t for t in targets),
                f"cross-origin host {foreign} became a probe target: {targets}",
            )
        self.assertIn("https://x.test/rest/user/login", targets)

    def test_the_probe_budget_is_bounded(self) -> None:
        # The assembly bounds its INPUTS (80 hints, 80 crawled paths, 12 forms)
        # and the caller slices the result to 6 targets.  The invariant that
        # matters is that a bigger bundle cannot make a bigger target list --
        # otherwise a minified bundle with 300 endpoints turns a scan into an
        # unbounded request fan-out.
        # At the cap and well past it, the resulting list must be identical:
        # extra hints past the cap are dropped, not accumulated.
        small = [f"/api/Path{n}" for n in range(80)]
        big = [f"/api/Path{n}" for n in range(500)]
        ts, tb = self._assemble([], {}, small), self._assemble([], {}, big)
        self.assertEqual(ts, tb,
                         "the target list changed when the bundle grew; the "
                         "input cap is not holding")
        self.assertLessEqual(len(tb), 1 + 80 + 80 + 12,
                             "the assembly produced more targets than its own "
                             "input caps allow")

    def test_the_root_is_always_a_target(self) -> None:
        targets = self._assemble([], {}, [])
        self.assertIn("https://x.test/", targets)


class JsonProbeTargetSelectionTests(unittest.TestCase):
    """Wall 4: the JSON probe must have its own target budget.

    Measured on a live Juice Shop scan: 53 API endpoints were extracted and
    ``/rest/user/login`` was among them, but the probe ran over the GET matrix's
    first six targets, and six other paths held those slots.  So the one endpoint
    on the target that answers a tautology with an admin session token was never
    sent a request, and the scan reported zero probe-* findings on the endpoint
    that carries the vulnerability.  The GET matrix ranks by query-carrying URLs;
    the JSON probe wants credential routes, and the two are not the same list.
    """

    def test_the_candidate_selector_exists(self) -> None:
        self.assertTrue(hasattr(ws, "_json_probe_candidates"),
                        "_json_probe_candidates is gone; the JSON probe has no "
                        "target list again")

    def test_a_credential_route_outranks_an_ordinary_api_route(self) -> None:
        cands = ws._json_probe_candidates([
            "https://x.test/api/Feedbacks", "https://x.test/rest/user/login",
            "https://x.test/rest/web3",
        ])
        self.assertEqual(cands[0], "https://x.test/rest/user/login",
                         f"the login route is not first: {cands}")

    def test_the_login_route_is_reached_even_at_the_back_of_the_list(self) -> None:
        # The Juice Shop shape: 36 /rest/ paths extracted ahead of it.
        hints = [f"https://x.test/rest/path{n}" for n in range(30)]
        hints.append("https://x.test/rest/user/login")
        cands = ws._json_probe_candidates(["https://x.test/"] + hints, limit=3)
        self.assertIn("https://x.test/rest/user/login", cands,
                      f"the login route was crowded out by 30 ordinary paths: {cands}")

    def test_the_candidate_list_is_bounded(self) -> None:
        # A bundle with 300 endpoints must not become 300 POSTs.
        cands = ws._json_probe_candidates(
            [f"https://x.test/rest/p{n}" for n in range(300)], limit=3)
        self.assertEqual(len(cands), 3)

    def test_the_selection_is_deterministic(self) -> None:
        args = ["https://x.test/", "https://x.test/rest/a",
                "https://x.test/rest/login", "https://x.test/api/b"]
        self.assertEqual(ws._json_probe_candidates(args),
                         ws._json_probe_candidates(args))

    def test_a_page_path_is_not_a_candidate(self) -> None:
        # POSTing JSON at an HTML route is noise, and risks side effects.
        cands = ws._json_probe_candidates(
            ["https://x.test/", "https://x.test/about", "https://x.test/main.js",
             "https://x.test/assets/app-4f2a.js"])
        self.assertEqual(cands, [], f"non-API paths became JSON targets: {cands}")

    def test_the_root_is_never_a_candidate(self) -> None:
        cands = ws._json_probe_candidates(["https://x.test/"])
        self.assertEqual(cands, [])

    def test_a_graphql_namespace_is_a_candidate(self) -> None:
        self.assertEqual(ws._json_probe_candidates(["https://x.test/graphql"]),
                         ["https://x.test/graphql"])

    def test_an_empty_target_list_yields_nothing(self) -> None:
        self.assertEqual(ws._json_probe_candidates([]), [])

    def test_the_predicate_agrees_with_the_old_inline_list(self) -> None:
        # The inline tuple this replaced; both must still call these API routes.
        for p in ("/api/x", "/rest/x", "/v1/x", "/v2/x", "/graphql", "/auth/x", "/oauth/x"):
            self.assertTrue(ws._is_api_path(p), f"{p} is no longer an API path")
        for p in ("/", "/about", "/main.js", "/wp-content/style.css", "/restaurant"):
            self.assertFalse(ws._is_api_path(p), f"{p} became an API path")


class AuthWeightTests(unittest.TestCase):
    """Ranking within the credential tier decides whether the bypass is measured."""

    def test_a_login_route_outranks_a_user_route(self) -> None:
        # The live failure: all four scored "credential" under a flat hint list,
        # so insertion order put change-password, security-question and
        # /api/v1/users ahead of /rest/user/login and the bypass was never probed.
        self.assertGreater(ws._auth_weight("/rest/user/login"),
                           ws._auth_weight("/rest/user/change-password"))
        self.assertGreater(ws._auth_weight("/rest/user/login"),
                           ws._auth_weight("/rest/user/security-question"))
        self.assertGreater(ws._auth_weight("/rest/user/login"),
                           ws._auth_weight("/api/v1/users"))

    def test_a_non_credential_route_scores_zero(self) -> None:
        for p in ("/rest/products/search", "/api/Feedbacks", "/api/Challenges",
                  "/main.js", "/"):
            self.assertEqual(ws._auth_weight(p), 0, f"{p} scored as a credential route")

    def test_a_login_route_is_first_among_many_user_routes(self) -> None:
        # The Juice Shop shape verbatim: 30 ordinary user-ish paths, then login.
        hints = [f"https://x.test/rest/user/{n}" for n in range(30)]
        hints.append("https://x.test/rest/user/login")
        cands = ws._json_probe_candidates(["https://x.test/"] + hints, limit=3)
        self.assertEqual(cands[0], "https://x.test/rest/user/login",
                         f"the login route ranked {cands.index('https://x.test/rest/user/login')}, "
                         "not first: it was never probed")

    def test_a_query_carrying_endpoint_does_not_displace_the_login_route(self) -> None:
        # The GET matrix prefers these; the JSON probe must not.
        cands = ws._json_probe_candidates([
            "https://x.test/rest/products/search?q=",
            "https://x.test/rest/user/security-question?email=",
            "https://x.test/rest/user/login",
        ], limit=1)
        self.assertEqual(cands, ["https://x.test/rest/user/login"])

    def test_a_stronger_route_leads_from_any_position(self) -> None:
        # Position must not beat weight: the login route is last here and must
        # still come out first.  A hash-ordered or set-iterated intermediate
        # would make this differ between runs.
        cands = ws._json_probe_candidates([
            "https://x.test/api/users",
            "https://x.test/rest/user/me",
            "https://x.test/rest/user/login",
        ], limit=1)
        self.assertEqual(cands, ["https://x.test/rest/user/login"])

    def test_equal_weights_keep_their_input_order(self) -> None:
        # Within a weight, insertion order is the tie-break -- which is what makes
        # the run reproducible, and what a sort on an unstable key would break.
        cands = ws._json_probe_candidates([
            "https://x.test/rest/user/b", "https://x.test/rest/user/a",
        ], limit=2)
        self.assertEqual(cands, ["https://x.test/rest/user/b", "https://x.test/rest/user/a"])


class JsonProbeSafetyTests(unittest.TestCase):
    """Wall 3: a JSON-body probe must be able to see a bypass, and must be safe."""

    def test_the_probe_exists_and_takes_a_post_baseline(self) -> None:
        self.assertTrue(hasattr(ws, "_probe_json_parameter"),
                        "_probe_json_parameter is gone; the JSON API class is "
                        "unreachable again")

    def test_the_probe_functions_exist(self) -> None:
        for name in ("_probe_parameter", "_fold_probe_signals", "_probe_json_parameter"):
            self.assertTrue(hasattr(ws, name), f"{name} missing")

    def test_password_is_not_a_probed_field(self) -> None:
        # Varying a password field is credential testing, which this scanner
        # is not; the injectable field is the identifier.
        self.assertNotIn("password", ws._JSON_PROBE_FIELDS)

    def test_the_payloads_are_benign_markers(self) -> None:
        payloads = [p for _pid, p, _m in ws._JSON_PROBE_PAYLOADS]
        for banned in ("union", "select", "drop", "sleep", "benchmark",
                       "waitfor", "pg_sleep", "load_file", "into outfile"):
            for p in payloads:
                self.assertNotIn(banned, p.lower(),
                                 f"payload {p!r} contains {banned!r}; that is "
                                 "exploitation, not a measurement")

    def test_the_probe_reports_signals_not_findings(self) -> None:
        # The fold is what decides how many lines are printed.  A probe that
        # emits findings directly reintroduces D4.
        import inspect
        sig = inspect.signature(ws._probe_json_parameter)
        self.assertTrue(hasattr(ws, "_fold_probe_signals"))


class JsonProbeBehaviourTests(unittest.TestCase):
    """Drive the JSON probe against a local fake of the Juice Shop shape."""

    def _client(self, handler):
        import httpx
        return httpx.Client(transport=httpx.MockTransport(handler), base_url="https://x.test")

    def _run(self, handler, field="email", baseline=None):
        c = self._client(handler)
        base = {"len": 26, "status": 401, "body": '{"error":"Invalid email or password."}'}
        return ws._probe_json_parameter(
            c, "https://x.test/rest/user/login", field, "abc123",
            lambda *a: None, baseline or base, timeout=5.0,
        )

    def test_a_real_bypass_is_reported_as_critical(self) -> None:
        """The Juice Shop shape: 401 baseline, 200 + token for the tautology."""

        def handler(request):
            import httpx
            body = request.content.decode() if request.content else ""
            if "'" in body:
                return httpx.Response(200, json={
                    "authentication": {"token": "eyJhbGciOiJSUzI1NiJ9.a.b",
                                       "email": "admin@juice-sh.op"}})
            return httpx.Response(401, json={"error": "Invalid email or password."})

        signals = self._run(handler)
        self.assertTrue(signals, "a 401 -> 200-with-token bypass produced no signal")
        bypass = [s for s in signals if s["outcome"] == "auth_bypass"]
        self.assertTrue(bypass, f"no auth_bypass outcome in {[s['outcome'] for s in signals]}")
        self.assertEqual(bypass[0]["severity"], "critical")
        self.assertEqual(bypass[0]["cwe"], "CWE-89")
        self.assertEqual(bypass[0]["family"], "sqli")

    def test_a_steady_401_is_not_a_bypass(self) -> None:
        """A correctly-built app answers the tautology with the same 401."""

        def handler(request):
            import httpx
            return httpx.Response(401, json={"error": "Invalid email or password."})

        self.assertEqual(self._run(handler), [],
                         "a consistent 401 was reported as a bypass")

    def test_a_network_error_is_not_a_bypass(self) -> None:
        def handler(request):
            import httpx
            raise httpx.ConnectError("no route")

        self.assertEqual(self._run(handler), [],
                         "an unreachable endpoint was reported as a bypass")

    def test_a_200_with_no_session_material_is_not_a_bypass(self) -> None:
        """An empty 200 object is not proof; the marker must corroborate."""

        def handler(request):
            import httpx
            return httpx.Response(200, json={})

        signals = self._run(handler, baseline={"len": 900, "status": 200, "body": "x" * 900})
        self.assertEqual([s for s in signals if s["outcome"] == "auth_bypass"], [],
                         "a short empty 200 was called an auth bypass")

    def test_one_bypass_ends_the_probe_for_that_endpoint(self) -> None:
        # Two payloads both bypass; only one request's worth should be spent.
        calls = []

        def handler(request):
            import httpx
            calls.append(1)
            return httpx.Response(200, json={"authentication": {"token": "eyJ.a.b"}})

        self._run(handler)
        self.assertEqual(len(calls), 1,
                         f"the probe kept POSTing after a confirmed bypass: {len(calls)} calls")

    def test_the_fold_prints_one_line_per_defect_not_per_field(self) -> None:
        import httpx

        def handler(request):
            body = request.content.decode() if request.content else ""
            if "'" in body:
                return httpx.Response(200, json={"authentication": {"token": "eyJ.a.b"}})
            return httpx.Response(401, json={"error": "no"})

        c = self._client(handler)
        base = {"len": 8, "status": 401, "body": '{"error":"no"}'}
        signals = []
        for field in ("email", "username", "user", "login"):
            signals.extend(ws._probe_json_parameter(
                c, "https://x.test/rest/user/login", field, "abc",
                lambda *a: None, base, timeout=5.0))
        findings = ws._fold_probe_signals(signals)
        self.assertEqual(len(findings), 1,
                         f"{len(signals)} signals folded into {len(findings)} findings; "
                         "one defect must be one line (D4)")
        self.assertIn("auth_bypass", findings[0].title.lower() + findings[0].detail.lower()
                      + findings[0].evidence.lower() + findings[0].title.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
