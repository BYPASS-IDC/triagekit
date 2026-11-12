RULES = [
    (r"Process\s*\(|NSTask|/bin/sh", "swift-process", "high", "CWE-78"),
    (r"evaluatingJavaScript|WKWebView", "swift-js", "medium", "CWE-79"),
    (r"allowsAnyHTTPSCertificate|disabledSessionTrusted|serverTrust", "swift-tls", "high", "CWE-295"),
    (r"UserDefaults\.standard\.set\([^)]*password|kSecAttrAccessibleAlways", "swift-secrets", "medium", "CWE-922"),
    (r"try!\s*|as!", "swift-force", "low", "CWE-754"),
    (r"NSData\(contentsOfFile:|String\(contentsOfFile:", "swift-path", "medium", "CWE-22"),
]
