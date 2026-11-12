"""God-mode repository scanner — deep static security, quality, and hygiene."""

from __future__ import annotations

import math
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from .guards import (
    docstring_line_numbers,
    is_pattern_definition,
    multiline_string_line_numbers,
    suppressed,
)

# ───────────────────────── pattern libraries ─────────────────────────

INJECTION = [
    # --- SQL: a query string built by concatenation / formatting ----------------
    # The first two rules catch the string wherever it is BUILT, not only where it
    # is executed.  A query assembled in one module and run in another is the
    # common shape, and matching only at execute()/query() silently missed it --
    # the old diff-layer rule caught this shape while the tree walker did not, so
    # the two layers disagreed about the same defect.
    (r"\bf[\"'][^\"']*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[^\"']*\{", "sql-injection", "critical", "CWE-89"),
    (r"[\"'][^\"']*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[^\"']*[\"']\s*\.format\s*\(", "sql-injection", "critical", "CWE-89"),
    (r"[\"'][^\"']*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[^\"']*[\"']\s*%\s*[\w$(]", "sql-injection", "critical", "CWE-89"),
    (r"\bexecute\w*\s*\(.*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|WHERE|VALUES)\b.*(\+|%|f[\"']|\.format\s*\()", "sql-injection", "critical", "CWE-89"),
    (r"\.query\s*\(.*(\+|%|f[\"']|\.format\s*\()", "sql-injection", "critical", "CWE-89"),
    (r"SELECT\s+.+\s+FROM\s+.+\s+WHERE\s+.+[\"']\s*\+", "sql-injection", "critical", "CWE-89"),
    (r"INSERT\s+INTO\s+.+\s*VALUES\s*\([^)]*[\"']\s*\+", "sql-injection", "critical", "CWE-89"),

    # --- Command execution ----------------------------------------------------
    # A shell interpreter is the sink.  These forms are ALWAYS a shell, so they
    # fire unconditionally -- unlike subprocess.* below.
    (r"(?<![\w$])(?:os\.)?(?:system|popen)\s*\(|shell_exec\s*\(|passthru\s*\(|proc_open\s*\(", "command-injection", "high", "CWE-78"),
    (r"\bRuntime\s*\.\s*(?:getRuntime\s*\(\s*\)\s*\.\s*)?exec\s*\(|ProcessBuilder\s*\(", "command-injection", "high", "CWE-78"),
    # subprocess with a SHELL, or a command string built inline.  A variable or a
    # list literal as the first argument is not matched: `subprocess.run(cmd)`
    # and `subprocess.run(["ping", host])` are the fixed forms.  This mirrors the
    # JS analyzer's rule (D32): only a shell form, an interpolated command, or an
    # explicit shell=True may fire.  Cross-line string building is the taint
    # layer's job -- see core/scanners/correlation.py for the precedence rule.
    (r"subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*(?:shell\s*=\s*True|[\"'][^\"']*[\"']\s*\+|\+\s*[\"']|f[\"']|\.format\s*\()", "command-injection", "high", "CWE-78"),
    (r"child_process\.exec\s*\(|execSync\s*\(|child_process\.execFileSync\s*\(|spawn\w*\s*\([^)]*shell\s*:\s*true", "command-injection", "high", "CWE-78"),
    # A RECEIVER-LESS exec(): JavaScript's destructured `const { exec } =
    # require('child_process')` form, and the builtin exec() of Python/PHP/Ruby.
    # The lookbehind excludes `.exec(`, `->exec(`, `.execute(` and `regex.exec(`,
    # which are a database cursor or a regex match rather than a process.
    (r"(?<![\w$.'\"])exec\s*\(", "command-injection", "high", "CWE-78"),

    # A shell template string that interpolates a value into an interpreter
    # name.  The former second alternative, ``shell\s*=\s*True``, fired on ANY
    # line that mentions the token -- including this project's own remediation
    # prose ("never build a command string ... shell=True") and the
    # recommendation builder that tests ``"shell=true" not in snip``.  An actual
    # shell=True is already reported by the subprocess rule above, which
    # requires the call itself; a bare mention is not a second finding.
    (r"\$\{[^}]+\}.*(sh|bash|cmd)", "shell-injection", "high", "CWE-78"),

    # --- XSS / JS evaluation ---------------------------------------------------
    (r"innerHTML\s*=|document\.write\s*\(|eval\s*\(|new Function\s*\(", "xss-eval", "high", "CWE-79"),
    (r"dangerouslySetInnerHTML|v-html\s*=", "xss-framework", "high", "CWE-79"),

    # --- Unsafe deserialization ------------------------------------------------
    (r"pickle\.loads|yaml\.load\s*\(|unserialize\s*\(|Marshal\.load|ObjectInputStream|BinaryFormatter", "unsafe-deserialization", "critical", "CWE-502"),

    # --- Path traversal --------------------------------------------------------
    (r"\.\./\.\./|\.\.\\\.\.\\", "path-traversal", "high", "CWE-22"),
    (r"open\s*\([^)]*\+|Path\s*\([^)]*\+.*request|send_file\s*\([^)]*request", "path-traversal", "high", "CWE-22"),

    # --- Open redirect ---------------------------------------------------------
    (r"redirect\s*\([^)]*request\.|header\s*\(\s*[\"']Location[\"']\s*,\s*request", "open-redirect", "medium", "CWE-601"),

    # --- SSRF ------------------------------------------------------------------
    # Only a non-literal first argument: `requests.get(URL)` with a constant is
    # not an SSRF, `requests.get(target)` is.  The variable-argument form cannot
    # tell a tainted variable from a module constant, which is why the taint
    # layer -- not this rule -- is the authority on SSRF.  An identifier written
    # in the conventional constant style (ALL CAPS) is excluded for the same
    # reason a string literal is: `httpx.post(OSV_QUERY, ...)` is a fixed
    # endpoint, not a request for one.  The exclusion is a SCOPED
    # case-sensitive group because every rule here is matched with re.I -- a
    # plain `[A-Z]` under re.I matches any letter and would exclude every
    # variable, which is how this exclusion first silently disabled the rule.
    (r"(?:requests|httpx|urllib)\s*\.?\s*\w*\s*\(\s*(?!(?-i:[A-Z][A-Z0-9_]*)[\"']?\s*[,)])"
     r"(?:[A-Za-z_$][\w$.]*\s*\+|[\"'][^\"']*[\"']\s*\+|[A-Za-z_$][\w$.]*\s*[,)])"
     r"|\burlopen\s*\(\s*(?![\"'])", "ssrf", "high", "CWE-918"),

    # --- Server-side template injection ---------------------------------------
    # `render_template_string` / `from_string` compile a STRING, so a non-literal
    # argument is the sink.  A literal template is safe and is excluded by the
    # lookahead.  Medium, not high: a named constant cannot be distinguished from
    # a tainted variable at this layer.
    (r"(?:render_template_string|from_string)\s*\(\s*(?![\"'])", "template-injection", "medium", "CWE-1336"),

    # --- PHP -------------------------------------------------------------------
    (r"\$_(GET|POST|REQUEST|COOKIE)\s*\[.*\].*(mysql_query|mysqli_query|->query\s*\()", "php-sqli", "critical", "CWE-89"),
    (r"\$_(GET|POST|REQUEST).*echo|print\s+\$_(GET|POST)", "php-xss", "high", "CWE-79"),
]

SECRETS = [
    (r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|passwd|private_key)\s*=\s*[\"'][^\"']{8,}[\"']", "hardcoded-secret", "critical", "CWE-798"),
    (r"(?i)\b(password)\s*=\s*[\"'][^\"']{6,}[\"']", "hardcoded-secret", "high", "CWE-798"),
    (r"-----BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----", "private-key", "critical", "CWE-321"),
    (r"AKIA[0-9A-Z]{16}", "aws-access-key", "critical", "CWE-798"),
    (r"ASIA[0-9A-Z]{16}", "aws-session-key", "critical", "CWE-798"),
    (r"ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}", "github-token", "critical", "CWE-798"),
    (r"sk-[A-Za-z0-9]{20,}|sk-proj-[A-Za-z0-9]{20,}", "openai-style-key", "high", "CWE-798"),
    (r"xox[baprs]-[0-9A-Za-z-]{10,}", "slack-token", "critical", "CWE-798"),
    (r"AIza[0-9A-Za-z_-]{30,}", "google-api-key", "high", "CWE-798"),
    (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "jwt-in-source", "medium", "CWE-798"),
    (r"nvapi-[A-Za-z0-9_-]{20,}", "nvidia-api-key", "high", "CWE-798"),
    (r"['\"]Bearer\s+[A-Za-z0-9_\-.]{20,}['\"]", "bearer-token-literal", "high", "CWE-798"),
]

CRYPTO_AUTH = [
    (r"\bmd5\s*\(|\bhashlib\.md5|MessageDigest\.getInstance\([\"']MD5|DigestUtils\.md5", "weak-hash-md5", "medium", "CWE-328"),
    (r"\bsha1\s*\(|\bhashlib\.sha1|getInstance\([\"']SHA-?1", "weak-hash-sha1", "medium", "CWE-328"),
    (r"verify\s*=\s*False|SSL_VERIFY_NONE|InsecureRequestWarning|rejectUnauthorized\s*:\s*false|CURLOPT_SSL_VERIFYPEER\s*,\s*false", "tls-verify-off", "high", "CWE-295"),
    (r"jwt\.decode\s*\([^)]*verify\s*=\s*False|algorithms\s*=\s*\[[\"']none[\"']\]", "jwt-verify-off", "high", "CWE-347"),
    (r"password\s*==|plain.?text.?password|strcmp\s*\(\s*\$.*password", "plaintext-password-compare", "high", "CWE-287"),
    (r"Math\.random\s*\(\s*\).*token|random\.random\s*\(\s*\).*secret", "weak-rng", "medium", "CWE-330"),
    (r"(?<![A-Za-z])DES(?![A-Za-z])|(?<![A-Za-z])RC4(?![A-Za-z])|Blowfish|Cipher\.getInstance\([\"']DES", "weak-cipher", "high", "CWE-327"),
]

QUALITY = [
    (r"\b(TODO|FIXME|XXX|HACK)\b", "todo-debt", "low", None),
    (r"except\s*:\s*(pass|continue)|except Exception:\s*pass", "bare-except", "medium", "CWE-390"),
    # D38: `console.log(` alone is not a finding.  CWE-532 is "insertion of
    # sensitive information into log file", so the rule requires a
    # credential-shaped token on the same line -- see analyzers/guards.py
    # CREDENTIAL_TOKEN.  Before this, every console.log in a JavaScript
    # repository was a medium finding, which trained readers to skip the class.
    (
        r"(?i)(?:console\.(?:log|dir|info|debug|warn|error)\s*\(.*\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|authorization|bearer|credential|session[_-]?id)\b"
        r"|print\s*\(.*(?:password|passwd|pwd|secret|token|credential)"
        r"|log(?:ger)?\s*\.\s*(?:info|debug|warn|error|trace)\s*\(.*\b(?:password|passwd|pwd|secret|token|api[_-]?key|credential|authorization)\b)",
        "sensitive-log", "medium", "CWE-532"),
    # Logging a whole request/context object leaks every field in it at once --
    # body, headers, cookies -- and is a real finding even when no line of it
    # happens to be named "password".
    (
        r"(?i)console\.(?:log|dir|info|debug|error|warn)\s*\(\s*(?:req|request|ctx|event)\b\s*(?:\)|\.\s*(?:body|headers|cookies|query|params|rawHeaders)\b)"
        r"|logger?\.(?:info|debug|warn|error)\s*\(\s*(?:req|request|ctx)\b\s*\)",
        "request-object-logged", "medium", "CWE-532"),
    (r"DEBUG\s*=\s*True|app\.debug\s*=\s*True|NODE_ENV\s*=\s*['\"]development['\"]", "debug-enabled", "medium", "CWE-489"),
    (r"cors\s*\(\s*\{[^}]*origin\s*:\s*['\"]?\*['\"]?", "cors-wildcard", "medium", "CWE-942"),
    (r"Access-Control-Allow-Origin:\s*\*", "cors-wildcard-header", "medium", "CWE-942"),
    (r"chmod\s*\(\s*0?777|os\.chmod\([^,]+,\s*0o777", "world-writable", "high", "CWE-732"),
    (r"assert\s+.*password|assert\s+.*token", "assert-security", "medium", "CWE-617"),
]

CONFIG_DOCKER = [
    (r"^\s*USER\s+root\s*$", "docker-user-root", "high", "CWE-250"),
    (r":latest\b", "docker-latest-tag", "medium", None),
    (r"^\s*ADD\s+", "docker-add-vs-copy", "low", None),
    (r"--privileged", "docker-privileged", "critical", "CWE-250"),
    (r"^\s*EXPOSE\s+(22|23|3306|5432|27017|6379|9200)\b", "docker-sensitive-port", "medium", None),
]

CI_PATTERNS = [
    (r"curl\s+[^\n]*\|\s*(ba)?sh", "ci-pipe-to-shell", "high", "CWE-78"),
    (r"wget\s+[^\n]*\|\s*(ba)?sh", "ci-pipe-to-shell", "high", "CWE-78"),
    (r"permissions:\s*write-all|contents:\s*write", "ci-overbroad-perms", "medium", None),
]

RECS = {
    "sql-injection": "Mechanism: query string built by concatenation/formatting with untrusted input. Impact: data theft, auth bypass, or data destruction. Fix: parameterized queries / prepared statements only. Verify: hostile quotes in inputs produce no SQL errors or altered result sets.",
    "php-sqli": "Mechanism: PHP request vars interpolated into SQL. Impact: full database compromise. Fix: PDO/mysqli prepared statements with bound parameters. Verify: dynamic queries no longer contain raw $_GET/$_POST fragments.",
    "command-injection": "Mechanism: user-influenced data may reach a shell/exec API. Impact: arbitrary command execution under the app user. Fix: pass argv arrays (no shell), allowlist commands, never concatenate untrusted strings. Verify: attempt metacharacters in staging inputs; confirm they are not interpreted.",
    "shell-injection": "Mechanism: shell metacharacters or unquoted expansions in command strings. Impact: command injection during runtime or init scripts. Fix: quote variables, avoid sed/eval on untrusted ENV, use structured config. Verify: values containing ; && $() do not alter control flow.",
    "xss-eval": "Mechanism: untrusted data flows into HTML/JS evaluation sinks. Impact: session theft, account actions as the victim. Fix: textContent/safe bindings; contextual encoding; CSP. Verify: markers like <tkxss> are encoded, not executed.",
    "xss-framework": "Sanitize HTML or use framework-safe binding; avoid raw HTML injection.",
    "php-xss": "Escape output (htmlspecialchars); never echo raw request params.",
    "unsafe-deserialization": "Never deserialize untrusted data with pickle/yaml.load/unserialize.",
    "path-traversal": "Mechanism: path joins include user input without normalization/allowlist. Impact: read/write outside intended directories. Fix: resolve paths, reject .., allowlist base directories. Verify: requests with ../ do not escape the data root.",
    "open-redirect": "Allowlist redirect targets; never redirect to raw user input.",
    "ssrf": "Mechanism: the outbound request target is chosen from request data. Impact: the server is used to reach internal services, cloud metadata (169.254.169.254), or the operator's own credentials. Fix: allowlist hosts and schemes; block private/link-local ranges at egress; do not follow redirects into them. Verify: request an internal address and confirm the connection is refused.",
    "template-injection": "Mechanism: a template is compiled from a string built with request data. Impact: arbitrary code execution inside the template engine -- file read, config disclosure, RCE. Fix: pass data as template VARIABLES, never build the template string itself; never call from_string/render_template_string on user input. Verify: a payload such as {{7*7}} renders literally.",
    "hardcoded-secret": "Mechanism: credential material embedded in source. Impact: repository readers gain production access. Fix: move to secret manager/env; rotate exposed secrets immediately. Verify: secret scanning clean; old credentials revoked.",
    "private-key": "Remove private keys from the repo immediately and rotate.",
    "aws-access-key": "Revoke and rotate AWS keys; use IAM roles / short-lived credentials.",
    "github-token": "Mechanism: GitHub token pattern present in source or fixtures. Impact: repo/org takeover if valid. Fix: revoke token; use short-lived OIDC/fine-scoped tokens from env. Verify: token rejected by API after revoke; only test placeholders remain in tests.",
    "tls-verify-off": "Never disable TLS verification in production.",
    "jwt-verify-off": "Always verify JWT signatures and algorithms explicitly.",
    "weak-hash-md5": "Use bcrypt/argon2/scrypt for passwords -- not MD5.",
    "weak-hash-sha1": "Prefer SHA-256+ or password KDFs; avoid SHA-1 for security.",
    "weak-cipher": "Use modern ciphers (AES-GCM); avoid DES/RC4.",
    "weak-rng": "Use cryptographically secure RNG (secrets module / crypto.getRandomValues).",
    "bare-except": "Catch specific exceptions; avoid silent pass.",
    "sensitive-log": "Mechanism: a credential-shaped value reaches a logging call. Impact: the secret lands in log files, log aggregation, and backups. Fix: log identifiers, never credential material; scrub at the logger. Verify: sample log output after the change and confirm no token or password appears.",
    "request-object-logged": "Mechanism: the whole request/context object is handed to a logger, so every field -- body, cookies, Authorization header -- is written at once. Impact: bulk credential and PII disclosure through logs. Fix: log an explicit allowlist of fields (method, path, status, request id). Verify: inspect a real log line after the change.",
    "debug-enabled": "Ensure DEBUG is false in production.",
    "cors-wildcard": "Restrict CORS origins to known frontends.",
    "docker-user-root": "Run containers as a non-root USER.",
    "docker-privileged": "Never run privileged containers unless absolutely required.",
    "docker-latest-tag": "Pin image digests or immutable version tags.",
    "ci-pipe-to-shell": "Do not pipe remote scripts into the shell; verify checksums.",
    "todo-debt": "Track security-related TODOs before release.",
    "py-shell-true": "Never use shell=True with untrusted input; pass argv lists to subprocess.",
    "py-os-system": "Replace os.system with subprocess and argv lists.",
    "py-eval-exec": "Avoid eval/exec on untrusted data; use safe parsers.",
    "py-pickle": "Never unpickle untrusted data; prefer JSON with schemas.",
    "py-yaml-load": "Use yaml.safe_load instead of yaml.load.",
    "py-sqli": "Use parameterized queries; never format SQL with user input.",
    "py-xss-safe": "Avoid mark_safe on user content; autoescape templates.",
    "py-tls-off": "Do not disable TLS verification in production.",
    "py-debug-true": "Ensure DEBUG is false in production deployments.",
    "py-md5": "Do not use MD5 for security; use SHA-256+ or password KDFs.",
    "rs-shell-command": "Avoid invoking sh/bash; use Command with separate args.",
    "rs-cmd-format": "Do not build command args via string format from untrusted input.",
    "rs-unsafe": "Minimize unsafe blocks; document invariants and audit carefully.",
    "rs-unchecked": "Avoid unchecked UTF-8/transmutes on untrusted data.",
    "rs-path": "Normalize and allowlist paths; reject .. components.",
    "rs-tls-off": "Do not disable certificate validation.",
    "rs-md5": "Avoid MD5 for security-sensitive digests.",
    "rs-deser": "Validate untrusted input before deserialization.",
    "swift-process": "Avoid shelling out with user-controlled arguments.",
    "swift-js": "Treat WebView JS evaluation as an XSS boundary.",
    "swift-tls": "Never disable TLS trust evaluation in production.",
    "swift-secrets": "Store secrets in Keychain with proper accessibility.",
    "swift-force": "Avoid force unwrap/cast on untrusted data paths.",
    "swift-path": "Validate file paths; do not use raw user strings.",
    "cs-process": "Avoid UseShellExecute with untrusted input.",
    "cs-sqli": "Use parameterized SqlCommand; never concatenate SQL.",
    "cs-deser": "Do not use BinaryFormatter on untrusted data.",
    "cs-md5": "Use SHA-256 or stronger; avoid MD5 for security.",
    "cs-tls": "Do not accept all certificates blindly.",
    "cs-tls2": "Validate TLS certificates properly.",
    "cs-load": "Avoid dynamic assembly load from untrusted bytes.",
    "cs-xss": "Encode output; avoid Html.Raw on user content.",
    "cpp-unsafe-str": "Replace strcpy/gets/sprintf with bounded APIs.",
    "cpp-system": "Avoid system/popen with untrusted input.",
    "cpp-scanf": "Avoid unbounded %s scanf; use width limits.",
    "cpp-malloc": "Pair allocation with free; prefer RAII.",
    "cpp-cast": "Review dangerous casts on trust boundaries.",
    "cpp-memcpy": "Ensure memcpy sizes are correct and bounded.",
    "cpp-std-system": "Avoid std::system with untrusted input.",
    "java-exec": "Avoid Runtime.exec/ProcessBuilder with untrusted input.",
    "java-sqli": "Use PreparedStatement; never concatenate SQL.",
    "java-deser": "Avoid Java deserialization of untrusted data.",
    "java-md5": "Do not use MD5 for security purposes.",
    "java-tls": "Do not trust all hostnames/certificates.",
    "java-xxe-hint": "Disable external entities on XML parsers.",
    "java-script-engine": "Do not eval untrusted scripts.",
    "java-path": "Normalize paths and constrain to a base directory.",

    "world-writable": "Avoid 0777 permissions on application files.",
}

SKIP_DIRS = {
    ".git", "node_modules", "vendor", "venv", ".venv", "dist", "build",
    "__pycache__", ".tox", ".mypy_cache", "target", "coverage", ".next",
    "pods", "Carthage", "bower_components", ".idea", ".vscode", "out",
    "bin", "obj", ".gradle", ".cargo", "site-packages",
    # third-party / minified noise (still scan first-party app code)
    "htmlpurifier", "HTMLPurifier", "phpmailer", "PHPMailer", "leaflet",
    "bootstrap", "jquery", "ckeditor", "tinymce", "fontawesome",
}

# Path fragments to skip (lowercase match)
SKIP_PATH_PARTS = (
    "/htmlpurifier/", "/phpmailer/", "/leaflet/", "/vendor/", "/node_modules/",
    "bootstrap.bundle.min.js", "leaflet.js", ".min.js",
)

CODE_EXTS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".java", ".rb", ".php",
    ".c", ".cpp", ".h", ".hpp", ".cs", ".kt", ".swift", ".scala", ".vue",
    ".svelte", ".m", ".mm", ".sql", ".sh", ".bash", ".ps1", ".pl", ".lua",
}

SPECIAL_NAMES = {
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml", "Makefile",
    "Jenkinsfile", ".env", ".env.example", ".env.local", ".env.production",
}

DEP_FILES = {
    "requirements.txt", "requirements-dev.txt", "Pipfile", "Pipfile.lock",
    "pyproject.toml", "package.json", "package-lock.json", "yarn.lock",
    "pnpm-lock.yaml", "go.mod", "go.sum", "Cargo.toml", "Cargo.lock",
    "composer.json", "composer.lock", "Gemfile", "Gemfile.lock",
    "pom.xml", "build.gradle", "build.gradle.kts",
}

CI_GLOBS = (".github/workflows/", ".gitlab-ci.yml", "azure-pipelines", "Jenkinsfile", ".circleci/")

# Machine-generated dependency data.  Recorded in ``dependency_files`` and
# analysed by the dependency/CVE layer, never by the source-pattern rules.
LOCKFILE_NAMES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "bun.lockb", "Cargo.lock", "poetry.lock", "Pipfile.lock", "composer.lock",
    "Gemfile.lock", "go.sum", "packages.lock.json", "paket.lock",
}


def is_scannable_source(name: str, suffix: str, rel: str) -> bool:
    """True when a file is something the source-pattern rules may read.

    ONE predicate, shared by every path that builds a file list.  There used to
    be two -- this one in ``repo_scan``'s walk, and no filter at all in
    ``files_data.iter_candidates`` -- and the unfiltered one is what feeds the
    heuristic security scanner.  That disagreement is defect D70: scanning
    ``pallets/flask@0.12.4`` reported ``[critical] Hardcoded Secret
    setup.rst:34`` and three more high findings from ``.rst`` documentation,
    which is 55% of that repo's critical/high findings located in docs, tests
    and examples rather than production code.  A reader who is told to rotate a
    credential that exists only in a paragraph of prose stops believing the
    criticals that are real.

    Prose, markup and data files are excluded, not demoted: they carry no
    executable statement a vulnerability scanner can act on.
    """
    is_docker = name == "Dockerfile" or name.startswith("Dockerfile.")
    is_ci = (rel.startswith(CI_GLOBS) or name in ("Jenkinsfile", ".gitlab-ci.yml")
             or any(rel == g.rstrip("/") for g in CI_GLOBS))
    is_code = suffix.lower() in CODE_EXTS or name in SPECIAL_NAMES or is_docker or is_ci
    return is_code or name in DEP_FILES


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    file: str
    line: Optional[int] = None
    snippet: Optional[str] = None
    recommendation: str = ""
    cwe: Optional[str] = None
    rule_id: str = ""


def _intel_lines(intel) -> list[str]:
    """The enrichment lines for one advisory inside a repo report.

    Kept as a plain function on the flat record so the report can be built
    without the scanner, and so the advisory's own body survives even when
    enrichment does.
    """
    out: list[str] = []
    # Imported here rather than at module scope: repo_scan is the local-scan
    # entry point and must not depend on the intel layer merely to render a
    # report that has no advisories in it.
    from .vuln_intel import cwe_guidance, metasploit_links

    if intel.aliases:
        out.append(f"- Identifiers: {', '.join(intel.aliases)}")
    for guide in cwe_guidance(intel.cwe_ids):
        out.append(
            f"- {guide['cwe']} ({guide['label']}): {guide['what_it_means']} "
            f"**Fix:** {guide['how_to_fix']} ({guide['url']})"
        )
    if intel.cvss_vector:
        src = ("advisory-supplied" if intel.cvss_source == "advisory"
               else "derived from the vulnerability class (not measured)")
        out.append(f"- CVSS v4.0 vector ({src}): `{intel.cvss_vector}`")
        if intel.cvss_link:
            out.append(f"  - Score at the FIRST.org calculator: {intel.cvss_link}")
    if intel.cvss_other_vector:
        # A 3.1/3.0 vector is real severity information, so it is kept and
        # linked on its own terms rather than relabelled as v4.0 (which the
        # v4.0 calculator cannot read) or dropped.
        from .vuln_intel import cvss_version

        version = cvss_version(intel.cvss_other_vector) or "?"
        out.append(
            f"- CVSS v{version} vector (advisory-supplied, not scored by this "
            f"build): `{intel.cvss_other_vector}`"
        )
        out.append(
            f"  - Score it at the FIRST.org v{version} calculator: "
            f"https://www.first.org/cvss/calculator/{version}#{intel.cvss_other_vector}"
        )

    links = metasploit_links(intel)
    if links:
        out.append("- Public attack reference (search only, not executed):")
        for link in links:
            out.append(f"  - {link['source']}: {link['url']}")
    return out


@dataclass
class RepoScanResult:
    root: str
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    dependency_files: list[str] = field(default_factory=list)
    cve_findings: list[dict] = field(default_factory=list)
    score: float = 100.0  # 100 = clean
    grade: str = "A"
    languages: dict = field(default_factory=dict)
    summary: str = ""
    advisories: list = field(default_factory=list)
    # Coverage facts the report must state: how much of the target was actually
    # analysed.  A scan that silently skipped manifests or hit a package cap is
    # not a clean scan, and an empty cve_findings list cannot express that.
    coverage: dict = field(default_factory=dict)

    def counts(self) -> dict[str, int]:
        c = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        for cf in self.cve_findings:
            sev = (cf.get("severity") or "medium").lower()
            if sev not in c:
                sev = "medium"
            c[sev] += 1
        return c

    def compute_score(self) -> None:
        weights = {"critical": 18, "high": 8, "medium": 3, "low": 1}
        penalty = 0.0
        for f in self.findings:
            penalty += weights.get(f.severity, 2)
        for cf in self.cve_findings:
            penalty += weights.get((cf.get("severity") or "medium").lower(), 3)
        # soft cap
        self.score = max(0.0, round(100.0 - min(penalty, 100.0), 1))
        if self.score >= 90:
            self.grade = "A"
        elif self.score >= 75:
            self.grade = "B"
        elif self.score >= 60:
            self.grade = "C"
        elif self.score >= 40:
            self.grade = "D"
        else:
            self.grade = "F"
        c = self.counts()
        self.summary = (
            f"Security score {self.score}/100 (grade {self.grade}). "
            f"{c['critical']} critical, {c['high']} high, {c['medium']} medium, {c['low']} low. "
            f"{len(self.cve_findings)} dependency advisories."
        )

    def to_markdown(self) -> str:
        self.compute_score()
        counts = self.counts()
        lines = [
            f"# Repository Security Scan — `{self.root}`",
            "",
            f"**Score:** {self.score}/100 · **Grade:** {self.grade}  ",
            f"**Files scanned:** {self.files_scanned}  ",
            f"**Static findings:** {len(self.findings)}  ",
            f"**CVE / advisory hits:** {len(self.cve_findings)}  ",
            f"**Severity:** critical={counts['critical']} high={counts['high']} "
            f"medium={counts['medium']} low={counts['low']}",
            "",
            self.summary,
            "",
        ]
        if self.languages:
            lines.append("## Languages detected")
            for lang, n in sorted(self.languages.items(), key=lambda x: -x[1])[:12]:
                lines.append(f"- {lang}: {n} files")
            lines.append("")
        if self.findings:
            try:
                from ..tree_view import build_finding_tree, render_ascii_tree
                tree = build_finding_tree(self.findings)
                lines.append("## Directory tree (findings)")
                lines.append("```")
                lines.append(render_ascii_tree(tree))
                lines.append("```")
                lines.append("")
            except Exception:
                pass
        if self.findings:
            lines.append("## Static findings")
            order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            for f in sorted(self.findings, key=lambda x: (order.get(x.severity, 9), x.file)):
                loc = f"`{f.file}`" + (f":{f.line}" if f.line else "")
                lines += [
                    f"### [{f.severity.upper()}] {f.title}",
                    f"- Rule: `{f.rule_id or f.title}`",
                    f"- Category: {f.category}",
                    f"- Location: {loc}",
                ]
                if f.snippet:
                    lines.append(f"- Snippet: `{f.snippet[:140]}`")
                if f.recommendation:
                    lines.append(f"- **Recommendation:** {f.recommendation}")
                if f.cwe:
                    lines.append(f"- {f.cwe}")
                lines.append("")
        if self.cve_findings:
            lines.append("## Dependency / CVE findings (OSV)")
            for cf in self.cve_findings:
                # Every manifest that pins the affected package, not just the
                # first one the walk happened to see.  The advisories are
                # deduplicated per package, so naming one file would leave the
                # maintainer to upgrade it and redeploy with the same pin still
                # live in the others (defect D66).
                all_manifests = cf.get("manifests") or [cf.get("manifest")]
                all_manifests = [m for m in all_manifests if m]
                manifest_line = (
                    " ".join(f"`{m}`" for m in all_manifests)
                    if len(all_manifests) > 1
                    else f"`{all_manifests[0]}`" if all_manifests else ""
                )
                lines += [
                    f"### [{(cf.get('severity') or 'medium').upper()}] {cf.get('id', 'advisory')}: {cf.get('package', '')}",
                    f"- {cf.get('summary', '')}",
                    f"- Manifest: {manifest_line}",
                ]
                if cf.get("fixed"):
                    lines.append(f"- Fixed in: {cf['fixed']}")
                # Enrichment is additive and must never cost the reader the
                # advisory itself, so a failure here leaves the block above
                # intact rather than dropping the whole finding.
                try:
                    from .vuln_intel import enrich_osv_record

                    intel = enrich_osv_record(cf)
                    lines += _intel_lines(intel)
                except Exception:
                    pass
                lines.append("")
        if self.dependency_files:
            lines += ["## Dependency manifests"] + [f"- `{d}`" for d in self.dependency_files] + [""]
        cov = getattr(self, "coverage", None) or {}
        dep_note = cov.get("dependency_scan")
        if dep_note:
            lines += ["", f"- **Dependency advisories:** {dep_note}."]
        if (cov.get("manifests_unparsed") or cov.get("packages_skipped_over_cap")
                or cov.get("query_errors") or dep_note
                or cov.get("packages_duplicated_across_manifests")):
            lines += ["## Scan coverage limits"]
            for rel in cov.get("manifests_unparsed") or []:
                lines.append(
                    f"- `{rel}` was found but its format is not parsed by this "
                    "build; its dependencies are NOT reflected in the findings above."
                )
            # A package pinned in more than one manifest is one vulnerability
            # but more than one place to fix, and the advisory lists every
            # manifest.  Stating it here keeps the reader from assuming each
            # finding above corresponds to exactly one file (defect D66).
            replicated = cov.get("packages_duplicated_across_manifests") or 0
            if replicated:
                lines.append(
                    f"- {replicated} package pin(s) appear in more than one manifest; "
                    "those advisories list every manifest and each one must be upgraded."
                )
            skipped = cov.get("packages_skipped_over_cap") or 0
            if skipped:
                lines.append(
                    f"- {skipped} package(s) were past the query cap and were NOT "
                    "queried against OSV; raise `max_packages` for full coverage."
                )
            if cov.get("query_errors"):
                lines.append(
                    f"- {cov['query_errors']} package quer(y/ies) failed against OSV; "
                    "those packages are NOT known to be clean."
                )
            if dep_note:
                lines.append(f"- {dep_note}.")
            lines.append("")
        if getattr(self, "relevance", None):
            try:
                from .exploit_relevance import relevance_markdown
                lines.append(relevance_markdown(self.relevance))
                lines.append("")
            except Exception:
                pass
        lines += [
            "---",
            "*TriageKit god-mode scan: multi-language heuristics + OSV. "
            "Not a replacement for CodeQL/Semgrep/full audit.*",
        ]
        return "\n".join(lines)

    def to_sarif(self) -> dict:
        """Minimal SARIF 2.1.0 document for CI integrations."""
        rules = {}
        results = []
        for f in self.findings:
            rid = f.rule_id or f.title.lower().replace(" ", "-")
            if rid not in rules:
                rules[rid] = {
                    "id": rid,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.recommendation or f.title},
                    "defaultConfiguration": {
                        "level": {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(f.severity, "warning")
                    },
                }
            results.append({
                "ruleId": rid,
                "level": {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(f.severity, "warning"),
                "message": {"text": f"{f.title}: {f.recommendation}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file},
                        "region": {"startLine": f.line or 1},
                    }
                }],
            })
        return {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {"driver": {"name": "TriageKit", "version": "1.2.0", "rules": list(rules.values())}},
                "results": results,
            }],
        }


def _lang_of(path: Path) -> str:
    return {
        ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".ts": "TypeScript",
        ".tsx": "TypeScript", ".go": "Go", ".rs": "Rust", ".java": "Java", ".rb": "Ruby",
        ".php": "PHP", ".c": "C", ".cpp": "C++", ".cs": "C#", ".kt": "Kotlin",
        ".swift": "Swift", ".vue": "Vue", ".sh": "Shell", ".sql": "SQL",
    }.get(path.suffix.lower(), path.suffix.lower() or "other")


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def _iter_files(root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            path = Path(dirpath) / name
            rel = str(path).replace("\\", "/").lower()
            if any(part in rel for part in SKIP_PATH_PARTS):
                continue
            if name.endswith(".min.js") or name.endswith(".min.css"):
                continue
            yield path


def _load_ignore(root: Path) -> list[re.Pattern]:
    patterns = []
    for name in (".triagekitignore", ".gitignore"):
        p = root / name
        if not p.is_file():
            continue
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # simple glob → regex
            esc = re.escape(line).replace(r"\*", ".*")
            try:
                patterns.append(re.compile(esc))
            except re.error:
                pass
    return patterns


def _ignored(rel: str, patterns: list[re.Pattern]) -> bool:
    return any(p.search(rel) for p in patterns)


def _lang_rules_for(rel: str) -> list:
    """Load language-specific rules; resilient to package import issues."""
    try:
        from .lang import rules_for_path
        return rules_for_path(rel)
    except Exception:
        pass
    try:
        import importlib.util
        import re as _re
        base = Path(__file__).resolve().parent / "lang"
        ext = Path(rel).suffix.lower()
        mapping = {
            ".py": "python_rules.py",
            ".rs": "rust_rules.py",
            ".swift": "swift_rules.py",
            ".cs": "csharp_rules.py",
            ".java": "java_rules.py",
            ".cpp": "cpp_rules.py",
            ".cc": "cpp_rules.py",
            ".cxx": "cpp_rules.py",
            ".c": "cpp_rules.py",
            ".h": "cpp_rules.py",
            ".hpp": "cpp_rules.py",
        }
        fname = mapping.get(ext)
        if not fname:
            return []
        spec = importlib.util.spec_from_file_location("_tk_lang", base / fname)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return list(getattr(mod, "RULES", []))
    except Exception:
        return []


def _scan_text(rel: str, text: str, extra_patterns: list) -> list[Finding]:
    lang_extra = _lang_rules_for(rel)

    findings: list[Finding] = []
    lines = text.splitlines()
    all_pats = INJECTION + SECRETS + CRYPTO_AUTH + QUALITY + extra_patterns + lang_extra
    # Lines inside a multi-line string are documentation, not code.  Python's
    # own parser answers this exactly for a .py file; other languages (and a
    # synthesized diff payload, which is not a parseable whole) fall back to the
    # delimiter scan, which is conservative about unterminated spans.
    if rel.lower().endswith(".py"):
        prose_lines = multiline_string_line_numbers(text)
    else:
        prose_lines = docstring_line_numbers(lines)
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
            continue
        if i - 1 in prose_lines:
            continue
        # A rule-table row is data about a pattern, not a call site.  Without
        # this, scanning any linter/WAF/scanner (this one included) reports its
        # own rule definitions as vulnerabilities.  See analyzers/guards.py.
        if is_pattern_definition(stripped):
            continue
        for pattern, label, sev, cwe in all_pats:
            if re.search(pattern, line, re.I):
                # D37/D32 parity: a line that wraps the value in a known
                # neutralising call is the fix, not the vulnerability.  See
                # analyzers/guards.py for what a guard can and cannot see.
                if suppressed(label, line):
                    continue
                findings.append(Finding(
                    severity=sev,
                    category=label.split("-")[0],
                    title=label.replace("-", " ").title(),
                    file=rel,
                    line=i,
                    snippet=stripped[:160],
                    recommendation=RECS.get(label, "Review and harden this pattern."),
                    cwe=cwe,
                    rule_id=label,
                ))
                break
        # high-entropy string heuristic (possible secrets)
        for m in re.finditer(r"[\"']([A-Za-z0-9+/=_\-]{32,})[\"']", line):
            token = m.group(1)
            if _shannon(token) >= 4.2 and not token.startswith("http"):
                findings.append(Finding(
                    severity="medium",
                    category="secret",
                    title="High Entropy String",
                    file=rel,
                    line=i,
                    snippet=stripped[:160],
                    recommendation="Verify this is not a leaked secret; move credentials to a secret store.",
                    cwe="CWE-798",
                    rule_id="high-entropy-string",
                ))
                break
    return findings




def _dedupe_and_filter(findings: list[Finding]) -> list[Finding]:
    """Drop obvious false positives; demote test-only noise."""
    out: list[Finding] = []
    seen = set()
    for f in findings:
        key = (f.file, f.line, f.rule_id or f.title)
        if key in seen:
            continue
        seen.add(key)
        snip = f.snippet or ""
        snip_l = snip.lower()
        rule = f.rule_id or ""

        if rule == "weak-cipher":
            if "description" in snip_l and not re.search(
                r"(?<![a-z])des(?![a-z])|rc4|blowfish|getinstance\s*\(", snip_l
            ):
                continue
            if not re.search(r"(?<![a-z])des(?![a-z])|rc4|blowfish|getinstance", snip_l):
                continue

        if rule == "todo-debt" and not re.search(r"\b(TODO|FIXME|XXX|HACK)\b", snip):
            continue

        if rule == "command-injection":
            if "subprocess.run" in snip_l and "shell=true" not in snip_l:
                if "subprocess.run([" in snip or re.search(r"subprocess\.run\(\s*\[", snip):
                    continue

        path_l = f.file.lower().replace("\\", "/")
        in_test = any(
            x in path_l
            for x in ("/test/", "tests/", "src/test", "benchmarks/")
        )
        if in_test and rule == "todo-debt":
            continue
        if in_test and rule in ("hardcoded-secret", "high-entropy-string", "github-token",
                                 "aws-access-key", "aws-session-key", "bearer-token",
                                 "openai-style-key", "command-injection", "shell-injection",
                                 "path-traversal", "todo-debt"):
            # Test fixtures often embed synthetic tokens/commands — demote heavily
            if rule == "todo-debt":
                continue
            f.severity = "low"
            f.recommendation = (f.recommendation or "") + " [test-path: verify not production credential]"

        if rule == "command-injection":
            # method names containing "system" in PHP comments / non-calls
            if not re.search(r"\b(system|exec|popen|shell_exec|passthru|proc_open)\s*\(", snip) \
               and not re.search(r"subprocess\.(call|run|Popen)|os\.system|Runtime\.exec", snip):
                if "shell=true" not in snip_l:
                    continue
        if rule == "path-traversal":
            # require real traversal or user-controlled path join
            if not re.search(r"\.\./|\.\.\\|open\s*\(|send_file|include\s*\(|require\s*\(|readfile\s*\(", snip):
                continue
        if rule == "xss-eval":
            # skip minified one-liners and library bundles already filtered
            if len(snip) > 300 and "function" in snip_l:
                continue
        if rule == "high-entropy-string":
            # alphabet / charset definitions are not secrets
            if re.search(r"abcdefgh|allowedrandom|charset|dictionary", snip_l):
                continue
            if re.search(r"3gpp|wimax|lucent|huawei|gigaword|dictionary\.", snip_l):
                continue

        out.append(f)
    return out


def scan_repository(
    root: str | Path,
    max_files: int = 8000,
    progress_cb=None,
    max_packages: int = 40,
    no_deps: bool = False,
) -> RepoScanResult:
    root_p = Path(root).resolve()
    result = RepoScanResult(root=str(root_p))
    ignore = _load_ignore(root_p)
    langs: Counter = Counter()
    n = 0

    for path in _iter_files(root_p):
        if progress_cb and n and n % 50 == 0:
            try:
                progress_cb(n, max_files, str(path.name))
            except Exception:
                pass
        try:
            rel = str(path.relative_to(root_p)).replace("\\", "/")
        except ValueError:
            continue
        if _ignored(rel, ignore):
            continue

        name = path.name
        if name in DEP_FILES or name.endswith(".lock"):
            result.dependency_files.append(rel)

        if not is_scannable_source(name, path.suffix, rel):
            continue
        # A lockfile is generated dependency DATA, not hand-written source.  It is
        # listed in dependency_files and handled by the dependency/CVE layer; the
        # source-pattern rules have nothing to find in it beyond ~100 integrity
        # hashes that read as high-entropy secrets.
        is_lockfile = name in LOCKFILE_NAMES or name.endswith(".lock")

        n += 1
        if n > max_files:
            break

        if path.suffix.lower() in CODE_EXTS:
            langs[_lang_of(path)] += 1

        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if len(text) > 2_000_000:
            continue

        extra = []
        if name == "Dockerfile" or name.startswith("Dockerfile."):
            extra = CONFIG_DOCKER
        if rel.startswith(CI_GLOBS) or name in ("Jenkinsfile", ".gitlab-ci.yml"):
            extra = extra + CI_PATTERNS

        if not is_lockfile:
            result.findings.extend(_scan_text(rel, text, extra))

    result.files_scanned = n
    result.languages = dict(langs)

    # de-dupe
    seen = set()
    unique = []
    for f in result.findings:
        key = (f.file, f.line, f.rule_id or f.title)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    
    result.findings = _dedupe_and_filter(unique)
    # Dependency advisories.  This function discovered the manifests above and
    # lists them in ``dependency_files``, but it used to stop there: it never
    # queried OSV, so ``cve_findings`` was always empty and the report stated
    # "0 dependency advisories" for a repository it had just measured and
    # named.  A clean result is only clean if something actually looked.
    if no_deps:
        result.coverage["dependency_scan"] = "disabled by configuration"
    elif result.dependency_files:
        try:
            from .cve import scan_dependencies

            cve_findings, dep_stats = scan_dependencies(
                root_p, result.dependency_files, max_packages
            )
            result.cve_findings = cve_findings
            result.coverage["dependency_stats"] = dep_stats
            # Flattened so the coverage block below reads one shape, not two.
            for key in ("manifests_unparsed", "packages_skipped_over_cap",
                        "packages_resolved", "packages_queried", "query_errors",
                        "packages_duplicated_across_manifests"):
                if key in dep_stats:
                    result.coverage[key] = dep_stats[key]
        except Exception as exc:
            # A failed OSV lookup is a coverage failure, not a clean repo.
            result.coverage["dependency_scan"] = f"advisory lookup failed: {exc}"
    # advisory relevance for stack languages / path hints
    try:
        from .exploit_relevance import analyze_exploit_relevance
        techs = list((result.languages or {}).keys())
        result.advisories = getattr(result, "advisories", []) or []
        result.relevance = analyze_exploit_relevance(
            techs, result.findings, use_llm=False, fetch_edb_pages=False, max_advisories=6
        )
    except Exception:
        result.relevance = []
    result.compute_score()
    return result
