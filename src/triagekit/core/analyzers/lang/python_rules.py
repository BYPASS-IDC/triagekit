RULES = [
    (r"subprocess\.(call|run|Popen)\([^)]*shell\s*=\s*True", "py-shell-true", "critical", "CWE-78"),
    (r"os\.system\s*\(", "py-os-system", "high", "CWE-78"),
    (r"eval\s*\(|exec\s*\(", "py-eval-exec", "high", "CWE-95"),
    (r"pickle\.loads?\s*\(", "py-pickle", "critical", "CWE-502"),
    (r"yaml\.load\s*\([^)]*\)", "py-yaml-load", "high", "CWE-502"),
    (r"cursor\.execute\s*\([^)]*%|execute\s*\([^)]*\+|execute\s*\([^)]*f[\"']", "py-sqli", "critical", "CWE-89"),
    (r"mark_safe\s*\(|safe\s*\|", "py-xss-safe", "medium", "CWE-79"),
    (r"verify\s*=\s*False|ssl\._create_unverified_context", "py-tls-off", "high", "CWE-295"),
    (r"debug\s*=\s*True", "py-debug-true", "medium", "CWE-489"),
    (r"hashlib\.md5\s*\(|\.md5\s*\(", "py-md5", "medium", "CWE-328"),
]
