RULES = [
    (r"Process\.Start\s*\(|UseShellExecute\s*=\s*true", "cs-process", "high", "CWE-78"),
    (r"SqlCommand\s*\([^)]*\+|ExecuteReader\s*\([^)]*\+", "cs-sqli", "critical", "CWE-89"),
    (r"BinaryFormatter|NetDataContractSerializer|LosFormatter|SoapFormatter", "cs-deser", "critical", "CWE-502"),
    (r"MD5\.Create|new\s+MD5CryptoServiceProvider|HashAlgorithmName\.MD5", "cs-md5", "medium", "CWE-328"),
    (r"ServerCertificateValidationCallback\s*=\s*.*true|ServicePointManager\.ServerCertificateValidationCallback", "cs-tls", "high", "CWE-295"),
    (r"HttpClient[^;]*ServerCertificateCustomValidationCallback", "cs-tls2", "medium", "CWE-295"),
    (r"Assembly\.Load\s*\(|FromBase64String\s*\(", "cs-load", "medium", "CWE-94"),
    (r"ViewBag\.Html\s*\(|Html\.Raw\s*\(", "cs-xss", "high", "CWE-79"),
]
