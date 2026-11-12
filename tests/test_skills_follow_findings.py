"""The skills must follow the findings, not the operation name.

The user's report: a scan of OWASP Juice Shop -- a deliberately-vulnerable
application whose signature defect is a SQL injection -- returned Score
53.7/100 and "the results of the scan where useless".  Nothing in the output
was *wrong*; it was all beside the point.

Measured cause of the generic narrative.  ``SKILL_MAP["web_scan"]`` assigns
thirteen skills totalling 102,511 characters against a 60,000-character prompt
budget, so five are dropped on the floor -- and the injection classes
(09-sql-injection.md, 10-xss.md, 11-command-injection.md,
12-path-traversal.md, 17-deserialization.md) are not in that list at all.
For the exact scan the user ran, the model was never told what a SQL
injection is.  It was handed headers-and-cookies.md and asked to explain a
CWE-89, and it did what any competent model does with a topic it was not
briefed on: it restated the finding as procedure.

A second copy of the same defect sat in the crossing.  The CLI and both API
paths adapted ``WebFinding`` records into the agent's input by constructing
``Finding(...)`` field by field and omitted ``cwe`` and ``rule_id`` -- the two
attributes the selector matches the class from.  A CRITICAL CWE-89 finding
arrived at the skill selector with nothing to match.

These tests pin both halves.  Run with the project venv:

    PYTHONPATH=src .venv/Scripts/python.exe -m pytest tests/test_skills_follow_findings.py -q
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

from triagekit.core.skills import (  # noqa: E402
    _CATEGORY_SKILLS,
    _CWE_SKILLS,
    _MAX_SKILLS_TOTAL_CHARS,
    _finding_cwes,
    _get,
    _read_skill,
    assign_skills_for,
    load_skills_text,
    skill_system_prefix,
    skills_for_findings,
)
from triagekit.core.analyzers.security_agent import (  # noqa: E402
    web_findings_as_repo,
)
from triagekit.core.analyzers.web_scan import WebFinding  # noqa: E402


def _sqli_finding() -> WebFinding:
    """The exact record the probe fold emits for the Juice Shop bypass."""
    return WebFinding(
        severity="critical",
        category="probe-sqli",
        title="JSON API accepted a tautology as valid credentials",
        detail="401 -> 200 with session material in the response body.",
        recommendation="Use parameterized queries / prepared statements.",
        endpoint="https://preview.owasp-juice.shop/rest/user/login",
        cwe="CWE-89",
        confidence="high",
    )


class CweReadingTests(unittest.TestCase):
    """The class channel has to work on every finding shape in the project."""

    def test_a_cwe_string_is_normalised(self) -> None:
        self.assertEqual(_finding_cwes(_sqli_finding()), ["89"])

    def test_a_bare_number_is_accepted(self) -> None:
        self.assertEqual(_finding_cwes({"cwe_ids": ["89"]}), ["89"])
        self.assertEqual(_finding_cwes({"cwe_ids": ["CWE-89"]}), ["89"])

    def test_a_cwe_ids_list_is_read(self) -> None:
        self.assertEqual(_finding_cwes({"cwe_ids": ["CWE-79", "CWE-89"]}), ["79", "89"])

    def test_garbage_is_dropped_not_raised(self) -> None:
        for junk in (None, "", "not-a-cwe", "CWX-1", 89.0, [], {}):
            self.assertEqual(_finding_cwes({"cwe_ids": junk}), [])

    def test_a_dict_is_read_as_readily_as_an_object(self) -> None:
        # The PR path passes plain dicts; getattr-only reading returned None for
        # every one of them, which is "supports findings" that ignores them.
        d = {"severity": "high", "cwe_ids": ["CWE-287"], "category": "auth"}
        self.assertEqual(_finding_cwes(d), ["287"])
        self.assertEqual(_get(d, "severity"), "high")
        self.assertIsNone(_get(d, "nonexistent"))

    def test_a_missing_attribute_is_a_default_not_an_error(self) -> None:
        self.assertEqual(_get(_sqli_finding(), "no_such_field", "fallback"), "fallback")


class SeverityOrderingTests(unittest.TestCase):
    """The prompt budget is finite; the class that decides risk claims it first."""

    def test_a_critical_class_outranks_a_low_one(self) -> None:
        hdr = WebFinding(severity="low", category="headers", title="No HSTS",
                         detail="", recommendation="", cwe="CWE-319")
        chosen = skills_for_findings([hdr, _sqli_finding()])
        self.assertIn("09-sql-injection.md", chosen)
        self.assertEqual(chosen[0], "09-sql-injection.md",
                         f"a LOW class claimed the budget before the CRITICAL one: {chosen}")

    def test_an_unknown_severity_sorts_last_not_first(self) -> None:
        odd = {"severity": "", "cwe_ids": ["CWE-79"]}
        chosen = skills_for_findings([odd, _sqli_finding()])
        self.assertEqual(chosen[0], "09-sql-injection.md")

    def test_the_order_is_deterministic(self) -> None:
        findings = [_sqli_finding(),
                    WebFinding(severity="high", category="xss", title="DOM sink",
                               detail="", recommendation="", cwe="CWE-79")]
        self.assertEqual(skills_for_findings(findings), skills_for_findings(findings))

    def test_no_findings_yields_no_class_skills(self) -> None:
        self.assertEqual(skills_for_findings([]), [])
        self.assertEqual(skills_for_findings(None), [])


class PromptContentTests(unittest.TestCase):
    """The regression the user reported, expressed as an assertion."""

    def test_a_sqli_finding_puts_the_sqli_skill_in_the_prompt(self) -> None:
        text = load_skills_text("web_scan", findings=[_sqli_finding()])
        self.assertIn("### SKILL 09-sql-injection.md", text,
                      "a CRITICAL CWE-89 finding produced a prompt with no "
                      "SQL-injection skill in it")

    def test_the_static_list_alone_would_not_have_covered_it(self) -> None:
        # This is the measurement that motivated the whole change, kept as a
        # witness.  The operation default for web_scan does not assign the
        # injection skills; only the finding-driven path does.
        static = assign_skills_for("web_scan")
        self.assertNotIn("09-sql-injection.md", static)
        self.assertIn("09-sql-injection.md", assign_skills_for("web_scan", [_sqli_finding()]))

    def test_every_major_class_is_reachable_from_its_cwe(self) -> None:
        # A gap here is the defect itself: the model cannot be briefed on a
        # class the map does not route.
        for cwe, expected in (("89", "09-sql-injection.md"), ("79", "10-xss.md"),
                              ("78", "11-command-injection.md"), ("22", "12-path-traversal.md"),
                              ("918", "16-ssrf-and-redirects.md"), ("502", "17-deserialization.md"),
                              ("287", "15-authn-authz.md"), ("295", "14-crypto-and-tls.md"),
                              ("614", "19-headers-and-cookies.md"), ("942", "20-api-and-graphql.md")):
            self.assertEqual(_CWE_SKILLS.get(cwe), (expected,), f"CWE-{cwe} routing")

    def test_every_routed_skill_file_actually_exists(self) -> None:
        # A map entry pointing at a missing file is silently skipped by
        # _read_skill, which looks exactly like "the skill said nothing".
        for cwe, names in _CWE_SKILLS.items():
            for name in names:
                self.assertTrue(_read_skill(name), f"CWE-{cwe} -> missing {name}")
        for _needle, names in _CATEGORY_SKILLS:
            for name in names:
                self.assertTrue(_read_skill(name), f"category route -> missing {name}")

    def test_the_authorization_gate_is_never_dropped(self) -> None:
        for findings in (None, [], [_sqli_finding()]):
            text = load_skills_text("web_scan", findings=findings)
            self.assertIn("### SKILL 01-authorized-use.md", text,
                          "the authorization gate is the one skill whose absence "
                          "turns a defensive scan into an unauthorized one")

    def test_the_prompt_states_what_it_could_not_fit(self) -> None:
        # Silent truncation reads as "the skill said nothing about this".
        text = load_skills_text("web_scan", findings=[_sqli_finding()])
        self.assertIn("### SKILL", text)
        if "omitted to stay within the prompt budget" in text:
            self.assertIn("NOT_ASSESSED", text)


class BudgetTests(unittest.TestCase):
    """Finding-driven assembly must not blow the prompt it is going into."""

    def test_the_assembled_prompt_respects_the_budget(self) -> None:
        many = [_sqli_finding()] + [
            WebFinding(severity="medium", category="headers", title=f"H{n}",
                       detail="", recommendation="", cwe="CWE-614")
            for n in range(40)
        ]
        text = load_skills_text("repo_scan", findings=many)
        # +30% headroom: the always-include gate may exceed it by one skill.
        self.assertLessEqual(len(text), _MAX_SKILLS_TOTAL_CHARS * 1.3,
                             f"assembled prompt is {len(text)} chars")

    def test_no_skill_is_cut_mid_sentence(self) -> None:
        # The truncation must land on a heading, not inside an instruction: a
        # partial instruction reads as a complete one.
        text = load_skills_text("repo_scan", findings=[_sqli_finding()])
        for block in text.split("### SKILL ")[1:]:
            body = block.split("\n", 1)[1] if "\n" in block else ""
            if "truncated at a section boundary" in body:
                self.assertFalse(body.rstrip().endswith(","),
                                 f"a skill was cut mid-clause: ...{body[-80:]!r}")

    def test_a_critical_class_is_not_the_one_dropped(self) -> None:
        # Ordering is the whole point of the budget: a LOW header note may be
        # truncated, a CRITICAL injection may not.
        many = [_sqli_finding()] + [
            WebFinding(severity="low", category="headers", title=f"H{n}",
                       detail="", recommendation="", cwe="CWE-614")
            for n in range(30)
        ]
        text = load_skills_text("web_scan", findings=many)
        self.assertIn("### SKILL 09-sql-injection.md", text)


class CategoryFallbackTests(unittest.TestCase):
    """Not every layer sets a CWE; the class still has to be reachable."""

    def test_a_category_alone_selects_the_skill(self) -> None:
        chosen = skills_for_findings([{"severity": "high", "category": "probe-sqli"}])
        self.assertIn("09-sql-injection.md", chosen)

    def test_a_namespaced_category_matches(self) -> None:
        for cat, expected in (("probe-sqli", "09-sql-injection.md"),
                              ("js-domxss", "10-xss.md"),
                              ("probe-cmd_sep", "11-command-injection.md"),
                              ("graphql-introspection", "20-api-and-graphql.md"),
                              ("tls-legacy", "14-crypto-and-tls.md")):
            chosen = skills_for_findings([{"severity": "high", "category": cat}])
            self.assertIn(expected, chosen, f"category {cat!r} selected {chosen}")

    def test_a_dict_with_only_a_type_and_message_still_matches(self) -> None:
        # The PR scanner's records: type/message, no category and no CWE.
        chosen = skills_for_findings([{
            "severity": "critical", "type": "hardcoded-credential",
            "message": "Hardcoded credential in auth handling.",
        }])
        self.assertIn("13-secrets-and-tokens.md", chosen)

    def test_an_empty_finding_selects_nothing(self) -> None:
        self.assertEqual(skills_for_findings([{}]), [])


class WebToAgentCrossingTests(unittest.TestCase):
    """The adaptation must carry the CWE across, or the selector is blind."""

    def test_the_cwe_survives_the_crossing(self) -> None:
        adapted = web_findings_as_repo(
            [_sqli_finding()], url="https://x.test/", final_url="https://x.test/",
            score=53.7, grade="D",
        )
        self.assertEqual(len(adapted.findings), 1)
        f = adapted.findings[0]
        self.assertEqual(f.cwe, "CWE-89")
        self.assertEqual(f.severity, "critical")
        self.assertTrue(f.rule_id, "a finding with no rule_id cannot be grouped")

    def test_the_adapted_findings_still_select_the_class_skills(self) -> None:
        adapted = web_findings_as_repo(
            [_sqli_finding()], url="https://x.test/", final_url="https://x.test/",
        )
        text = load_skills_text("web_scan", findings=adapted.findings)
        self.assertIn("### SKILL 09-sql-injection.md", text)

    def test_an_empty_web_scan_adapts_cleanly(self) -> None:
        adapted = web_findings_as_repo([], url="https://x.test/")
        self.assertEqual(adapted.findings, [])
        self.assertEqual(adapted.root, "https://x.test/")

    def test_a_finding_with_no_optional_fields_does_not_raise(self) -> None:
        bare = WebFinding(severity="info", category="", title="", detail="",
                          recommendation="")
        adapted = web_findings_as_repo([bare], url="https://x.test/")
        self.assertEqual(len(adapted.findings), 1)
        self.assertEqual(adapted.findings[0].cwe, None)

    def test_the_prefix_advertises_what_it_loaded(self) -> None:
        prefix = skill_system_prefix("web_scan", [_sqli_finding()])
        self.assertIn("09-sql-injection.md", prefix.split("]")[0],
                      "the advertised skill list does not mention the skill "
                      "that was actually loaded")


if __name__ == "__main__":
    unittest.main(verbosity=2)
