"""D70 -- documentation files are scanned as if they were source code.

Found by pointing TriageKit at real public repositories (`dev/corpora/realprs`),
which is the validation the tool is supposed to be able to survive.

Scanning `pallets/flask` at tag 0.12.4 -- 71 files, real code, shipped docs and
shipped examples -- produced 31 non-file-change findings, of which **17 (55%) of
the critical/high ones came from tests, examples and documentation** rather than
production code. The clearest::

    heuristic_security  hardcoded-secret  critical  setup.rst:34   Hardcoded Secret
    heuristic_security  open-redirect-risk high     fileuploads.rst:64
    heuristic_security  weak-hash         high      requestchecksum.rst:23
    heuristic_security  plaintext-password-compare high  views.rst:101

`setup.rst` is a *documentation* file. Reporting a critical hardcoded secret
inside shipped prose sends an owner to rotate a credential that exists only in a
paragraph of documentation, and -- worse -- it teaches the reader that this
scanner's criticals cannot be trusted, including the genuine ones.

Root cause: two file-selection paths exist and only one filters.

* ``repo_scan.py`` requires ``suffix in CODE_EXTS or name in SPECIAL_NAMES or
  docker or CI or name in DEP_FILES`` and ``continue``s otherwise. It is correct.
* ``analyzers/files_data.py::iter_candidates`` yields *every* file under root
  apart from ``SKIP_DIRS``/``SKIP_PATH_PARTS``, and ``_priority`` merely *orders*
  the unknown ones last (rank 4) -- it never excludes them. That payload is what
  the heuristic security scanner runs its secret and injection rules over.

So a `.rst`, `.md` or `.html` file reaches the secret scanner while the same
regex path, reached through ``repo_scan``, would have skipped it. The two paths
disagree, and the unfiltered one is the one that emits severities.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parent.parent
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

from triagekit.core.analyzers.files_data import synthesize_files_data  # noqa: E402


# The same credential-shaped literal in all three files, so the only variable is
# the file's extension.  A rule that fires on the .py and not the .rst is
# behaving correctly; one that fires on both is scanning prose as code.
SECRET = "AWS_SECRET_ACCESS_KEY = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def build_tree(root: Path) -> None:
    (root / "src").mkdir(parents=True, exist_ok=True)
    (root / "docs").mkdir(parents=True, exist_ok=True)
    (root / "src" / "settings.py").write_text(
        SECRET + "\n\ndef connect():\n    return None\n", encoding="utf-8")
    (root / "docs" / "setup.rst").write_text(
        "Configuring the client\n======================\n\n"
        "::\n\n    " + SECRET + "\n\n"
        "Replace this with your own key.\n", encoding="utf-8")
    (root / "README.md").write_text(
        "# Example\n\n```\n" + SECRET + "\n```\n", encoding="utf-8")


class DocumentationIsNotSourceCodeTests(unittest.TestCase):
    """Prose files must not reach the vulnerability rules at all."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        build_tree(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def _filenames(self) -> set[str]:
        synth = synthesize_files_data(self.root, include_patches=True)
        return {e["filename"] for e in synth.files_data}

    def test_a_documentation_file_is_not_in_the_payload(self):
        names = self._filenames()
        self.assertNotIn(
            "docs/setup.rst", names,
            "documentation prose was handed to the vulnerability scanners")

    def test_a_markdown_file_is_not_in_the_payload(self):
        self.assertNotIn(
            "README.md", self._filenames(),
            "a README is prose; scanning it for secrets produces findings "
            "whose only location is a fenced code example")

    def test_real_source_still_reaches_the_rules(self):
        self.assertIn(
            "src/settings.py", self._filenames(),
            "the filter removed genuine source code; the fix must not over-exclude")

    def test_the_payload_is_not_reduced_to_nothing(self):
        """Guard: the exclusion must not turn the payload into an empty set."""
        self.assertTrue(self._filenames(), "no files at all reached the scanners")


if __name__ == "__main__":
    unittest.main(verbosity=2)
