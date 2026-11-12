r"""D85 -- the system prompt told the model to escape JSON with one backslash.

`core/prompts.py` defined `SYSTEM` as a plain (non-raw) triple-quoted literal.
Python decodes `\\` inside a normal string to a single `\`, so the security rule
that exists *to tell the model how to escape backslashes* read:

    - In strings, escape backslashes properly (use \\ for a single backslash).

...when what the model actually received was:

    - In strings, escape backslashes properly (use \ for a single backslash).

It was told to do the thing the rule forbids, which is the worst possible failure
mode for a prompt whose subject is escaping: a model that follows it emits invalid
JSON, and `LLMClient.complete_json` then falls back to the static-only report with
no stated cause. The two `\\p` and `\\'` spellings in the same line raised
`DeprecationWarning: invalid escape sequence` on import (and are a `SyntaxError`
in a future Python), which is why every run of the suite printed the warning from
this file and nobody looked at it.

The literal is now a raw string, so what is written is what the model reads.
"""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"

sys.path.insert(0, str(SRC))

from triagekit.core.prompts import SYSTEM  # noqa: E402


class PromptBackslashTests(unittest.TestCase):
    """The escaping rule must survive to the model unchanged."""

    def test_the_rule_names_a_double_backslash(self) -> None:
        """`use \\` -- a single backslash would tell the model to do it wrong."""
        rule = [ln for ln in SYSTEM.splitlines() if "backslash" in ln]
        self.assertEqual(len(rule), 1, f"expected one escaping rule, got {rule}")
        self.assertIn("use \\\\ for a single backslash", rule[0],
                      "the rule does not name a double backslash")

    def test_the_invalid_escape_examples_are_literal(self) -> None:
        """`\\p` and `\\'` must reach the model as written, not as `p` and `'`."""
        rule = [ln for ln in SYSTEM.splitlines() if "backslash" in ln][0]
        self.assertIn("\\p", rule)
        self.assertIn("\\'", rule)

    def test_importing_the_module_is_warning_free(self) -> None:
        """No `invalid escape sequence` DeprecationWarning on import."""
        proc = subprocess.run(
            [sys.executable, "-W", "error::DeprecationWarning", "-c",
             "import triagekit.core.prompts"],
            capture_output=True, text=True,
            env={"PYTHONPATH": str(SRC), "PYTHONIOENCODING": "utf-8",
                 "PATH": "", "SYSTEMROOT": "C:\\Windows"},
            timeout=120,
        )
        self.assertEqual(
            proc.returncode, 0,
            f"import raised a DeprecationWarning:\n{proc.stderr[-800:]}",
        )

    def test_the_system_literal_is_raw(self) -> None:
        """The `r` prefix is the fix; without it the class can recur."""
        text = (SRC / "triagekit" / "core" / "prompts.py").read_text(encoding="utf-8")
        self.assertRegex(
            text, r'(?m)^SYSTEM = r"""',
            "SYSTEM is not a raw literal -- every backslash in it is decoded by "
            "Python before the model ever sees it",
        )


if __name__ == "__main__":
    unittest.main()
