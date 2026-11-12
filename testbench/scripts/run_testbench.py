#!/usr/bin/env python3
"""Scanner self-test against local fixtures (not remote attacks)."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RS = ROOT / "src" / "triagekit" / "core" / "analyzers" / "repo_scan.py"
spec = importlib.util.spec_from_file_location("repo_scan", RS)
mod = importlib.util.module_from_spec(spec)
sys.modules["repo_scan"] = mod
spec.loader.exec_module(mod)
scan_repository = mod.scan_repository

FIX = ROOT / "testbench" / "fixtures"
EXP = ROOT / "testbench" / "expected"

CASES = [
    ("python/vuln_app.py", "python_vuln.json"),
    ("rust/vuln.rs", "rust_vuln.json"),
    ("cpp/vuln.cpp", "cpp_vuln.json"),
    ("java/Vuln.java", "java_vuln.json"),
    ("csharp/Vuln.cs", "csharp_vuln.json"),
    ("swift/vuln.swift", "swift_vuln.json"),
    ("safe_ok", "safe_ok.json"),
]


def main() -> int:
    failed = 0
    print("TriageKit testbench — scanner strength against known fixtures\n")
    for rel, exp_name in CASES:
        path = FIX / rel
        exp = json.loads((EXP / exp_name).read_text(encoding="utf-8"))
        scan_path = path if path.is_dir() else path.parent
        result = scan_repository(scan_path)
        findings = result.findings
        if path.is_file():
            findings = [f for f in findings if path.name in f.file.replace("\\", "/")]
        rules = {f.rule_id for f in findings}
        print(f"== {rel} :: {len(findings)} findings, rules={sorted(rules)}")
        if "min_hits" in exp and len(findings) < exp["min_hits"]:
            print(f"  FAIL min_hits {len(findings)} < {exp['min_hits']}")
            failed += 1
        if "require_any" in exp:
            if not any(r in rules for r in exp["require_any"]):
                print(f"  FAIL require_any {exp['require_any']} not in {rules}")
                failed += 1
            else:
                print("  OK require_any")
        if "max_high_or_above" in exp:
            bad = [f for f in findings if f.severity in ("critical", "high")]
            if len(bad) > exp["max_high_or_above"]:
                print(f"  FAIL safe target high+: {[b.rule_id for b in bad]}")
                failed += 1
            else:
                print("  OK safe target")
    print("\nRESULT:", "PASS" if failed == 0 else f"FAIL ({failed})")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
