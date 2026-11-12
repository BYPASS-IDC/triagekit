RULES = [
    (r"\bstrcpy\s*\(|\bstrcat\s*\(|\bgets\s*\(|\bsprintf\s*\(", "cpp-unsafe-str", "high", "CWE-120"),
    (r"\bsystem\s*\(|\bpopen\s*\(|\bexecl?\s*\(", "cpp-system", "high", "CWE-78"),
    (r"\bscanf\s*\(\s*[\"'][^\"']*%s", "cpp-scanf", "high", "CWE-120"),
    (r"\bmalloc\s*\([^)]*\)\s*;(?!.*free)", "cpp-malloc", "low", "CWE-401"),
    (r"reinterpret_cast\s*<|const_cast\s*<", "cpp-cast", "low", "CWE-704"),
    (r"memcpy\s*\([^,]+,\s*[^,]+,\s*strlen", "cpp-memcpy", "medium", "CWE-126"),
    (r"std::system\s*\(", "cpp-std-system", "high", "CWE-78"),
]
