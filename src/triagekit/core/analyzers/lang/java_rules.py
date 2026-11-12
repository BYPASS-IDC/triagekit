RULES = [
    (r"Runtime\.getRuntime\(\)\.exec|ProcessBuilder\s*\(", "java-exec", "high", "CWE-78"),
    (r"Statement\.execute(Query|Update)?\s*\([^)]*\+|createQuery\s*\([^)]*\+", "java-sqli", "critical", "CWE-89"),
    (r"ObjectInputStream|XMLDecoder|readObject\s*\(", "java-deser", "critical", "CWE-502"),
    (r"MessageDigest\.getInstance\s*\(\s*[\"']MD5[\"']", "java-md5", "medium", "CWE-328"),
    (r"setHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|TrustAll", "java-tls", "high", "CWE-295"),
    (r"DocumentBuilderFactory.*setFeature|XMLInputFactory", "java-xxe-hint", "medium", "CWE-611"),
    (r"ScriptEngineManager|eval\s*\(", "java-script-engine", "high", "CWE-94"),
    (r"File\s*\([^)]*\+|Paths\.get\s*\([^)]*\+", "java-path", "medium", "CWE-22"),
]
