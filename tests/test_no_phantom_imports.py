"""No module in ``src/`` may import a name that does not exist.

Defect D82 was a web UI that had never worked: ``api/app.py`` did
``from triagekit.core.analyzers.repo_scan import scan_target``, and ``scan_target``
has never existed there.  Every request to both repo-scan endpoints answered
``ImportError``, and nothing caught it -- because every existing test imports a
module that loads cleanly, and a bad *call site* inside an unrelated module is
invisible to them until a request is actually made.

The same guard would have caught it in a second, and catches the class it belongs
to: the drift between the CLI's inline implementation and the UI's copy of it.
D79 (three duplicated agent input conversions, one of which dropped ``cwe``) and
D82 (the UI pointed at a name that only ever existed in a comment) are both "the
same logic written twice" failing in one of the two places.

So this test parses every module under ``src/triagekit`` and resolves every
``from triagekit... import NAME`` it finds, at module level *and* inside function
bodies -- the CLI's imports are almost all function-local, which is exactly where
D82 hid.  A name that does not resolve fails the test.
"""

from __future__ import annotations

import ast
import importlib
import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def _modules() -> list[Path]:
    return sorted(p for p in SRC.rglob("*.py") if "__pycache__" not in p.parts)


def _own_path(rel: Path) -> list[str]:
    """The dotted parts of a file's own module path.

    ``triagekit/core/scanners/registry.py`` -> ``['triagekit','core','scanners','registry']``
    ``triagekit/core/scanners/__init__.py`` -> the package path plus ``__init__``,
    so that "strip one part per leading dot" resolves level 1 to the containing
    package in both cases.
    """
    parts = list(rel.parts)
    if parts[-1] == "__init__.py":
        return parts[:-1] + ["__init__"]
    parts[-1] = parts[-1][: -len(".py")]
    return parts


class PhantomImportTests(unittest.TestCase):
    """Every ``from triagekit.* import NAME`` resolves to a real attribute."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.failures: list[str] = []
        cls.checked = 0
        cls.modules: dict[str, object] = {}

        for path in _modules():
            rel = path.relative_to(SRC)
            try:
                source = path.read_text(encoding="utf-8")
            except OSError:
                continue
            try:
                tree = ast.parse(source, filename=str(path))
            except SyntaxError as e:
                cls.failures.append(f"{rel}: not valid Python: {e}")
                continue

            # Resolve relative imports the way Python does: ``from .core import``
            # in triagekit/api is triagekit.core, ``from .. import`` is triagekit.
            # Skipping them is how a whole class of phantom import hides -- the
            # relative form is what this codebase uses almost everywhere.
            own = _own_path(rel)
            for node in ast.walk(tree):
                if not isinstance(node, ast.ImportFrom):
                    continue
                if node.module == "__future__":
                    continue
                if node.level:
                    # ``from ..core import`` -- strip one part per leading dot.
                    base = own[: len(own) - node.level]
                    module_name = ".".join(
                        base + ([node.module] if node.module else [])
                    )
                else:
                    # Absolute: the name is the module, never prefixed.
                    module_name = node.module or ""
                if not module_name.startswith("triagekit"):
                    continue
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    cls.checked += 1
                    try:
                        target = importlib.import_module(module_name)
                    except Exception as e:
                        cls.failures.append(
                            f"{rel}: importing {module_name} failed: "
                            f"{type(e).__name__}: {e}"
                        )
                        continue
                    if hasattr(target, alias.name):
                        continue
                    # A submodule import: ``from triagekit.core import scanners``.
                    sub = f"{module_name}.{alias.name}"
                    try:
                        importlib.import_module(sub)
                        continue
                    except Exception:
                        pass
                    cls.failures.append(
                        f"{rel}:{node.lineno}: "
                        f"'from {module_name} import {alias.name}' -- "
                        f"{alias.name} does not exist there"
                    )

    def test_no_phantom_imports(self) -> None:
        self.assertTrue(
            self.checked > 100,
            f"only {self.checked} triagekit imports were found -- the walk is "
            f"not covering the tree, so this test would pass by doing nothing",
        )
        self.assertEqual(
            self.failures, [],
            "imports naming things that do not exist:\n  "
            + "\n  ".join(self.failures),
        )

    def test_the_d82_name_is_not_imported_anywhere(self) -> None:
        """``scan_target`` is the D82 phantom name; no module may import it again."""
        hits = []
        for path in _modules():
            rel = path.relative_to(SRC)
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except (OSError, SyntaxError):
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    for alias in node.names:
                        if alias.name == "scan_target":
                            hits.append(f"{rel}:{node.lineno}")
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name == "scan_target":
                            hits.append(f"{rel}:{node.lineno}")
        self.assertEqual(hits, [], f"the D82 phantom name is still imported in {hits}")

    def test_the_shared_runner_is_what_both_surfaces_call(self) -> None:
        """The anti-drift invariant: one implementation, two callers.

        If the UI (or the CLI) grows its own orchestrator setup again, the two
        surfaces can disagree about the same repo -- which is how D82 happened.
        """
        cli_text = (SRC / "triagekit" / "cli.py").read_text(encoding="utf-8")
        app_text = (SRC / "triagekit" / "api" / "app.py").read_text(encoding="utf-8")
        self.assertIn("run_repo_scan", cli_text,
                      "the CLI no longer calls the shared runner")
        self.assertIn("run_repo_scan", app_text,
                      "the API no longer calls the shared runner")

        # ...and no surface builds its own orchestrator for a repo scan.
        for path, label in (
            (SRC / "triagekit" / "cli.py", "cli"),
            (SRC / "triagekit" / "api" / "app.py", "api"),
        ):
            text = path.read_text(encoding="utf-8")
            for node in ast.walk(ast.parse(text)):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    names = [a.name for a in node.names]
                    self.assertNotIn(
                        "ScannerOrchestrator", names,
                        f"{label} builds its own orchestrator instead of using "
                        f"the shared runner -- that is the drift that was D82",
                    )


if __name__ == "__main__":
    unittest.main()
