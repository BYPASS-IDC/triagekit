"""Language-specialized static rule packs for TriageKit general scanner."""

from .python_rules import RULES as PYTHON_RULES
from .rust_rules import RULES as RUST_RULES
from .swift_rules import RULES as SWIFT_RULES
from .csharp_rules import RULES as CSHARP_RULES
from .cpp_rules import RULES as CPP_RULES
from .java_rules import RULES as JAVA_RULES

# (pattern, rule_id, severity, cwe, languages|None for all)
ALL_LANG_RULES: list = []
for pack, langs in [
    (PYTHON_RULES, {"python", ".py"}),
    (RUST_RULES, {"rust", ".rs"}),
    (SWIFT_RULES, {"swift", ".swift"}),
    (CSHARP_RULES, {"csharp", ".cs"}),
    (CPP_RULES, {"cpp", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".c"}),
    (JAVA_RULES, {"java", ".java"}),
]:
    for pattern, rid, sev, cwe in pack:
        ALL_LANG_RULES.append((pattern, rid, sev, cwe, langs))


def rules_for_path(path: str) -> list:
    """Return language rules applicable to a file path."""
    p = path.lower().replace("\\", "/")
    out = []
    for pattern, rid, sev, cwe, langs in ALL_LANG_RULES:
        if any(p.endswith(x) if x.startswith(".") else x in p for x in langs):
            out.append((pattern, rid, sev, cwe))
    return out
