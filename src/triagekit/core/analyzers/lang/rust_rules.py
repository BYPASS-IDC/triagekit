RULES = [
    (r"Command::new\s*\(\s*[\"']sh[\"']|Command::new\s*\(\s*[\"']bash[\"']", "rs-shell-command", "high", "CWE-78"),
    (r"\.arg\s*\([^)]*\+|\.args\s*\([^)]*format!", "rs-cmd-format", "medium", "CWE-78"),
    (r"unsafe\s*\{", "rs-unsafe", "low", "CWE-676"),
    (r"from_utf8_unchecked|transmute\s*\(", "rs-unchecked", "medium", "CWE-704"),
    (r"std::fs::.*\.\.|PathBuf::from\([^)]*format!", "rs-path", "medium", "CWE-22"),
    (r"reqwest::.*danger_accept_invalid|danger_accept_invalid_certs\s*\(\s*true", "rs-tls-off", "high", "CWE-295"),
    (r"md5::|Md5::|digest::MD5", "rs-md5", "medium", "CWE-328"),
    (r"serde_json::from_str|from_slice\([^)]*\)", "rs-deser", "low", "CWE-502"),
]
