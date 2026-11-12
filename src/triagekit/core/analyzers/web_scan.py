"""TriageKit Website Security Adviser — authorized targets only.

Deep assessment layers:
  1. Transport & edge posture (HTTPS, HSTS, cookies, CORS, headers)
  2. Attack-surface mapping (crawl, robots, sitemap, JS-extracted APIs)
  3. Leak & exposure hunting (sensitive paths, body secrets, backups)
  4. HTML/JS injury analysis (forms, CSRF, sinks/sources, hardcoded secrets)
  5. Safe active checks (reflection canaries, method probing, soft-404)
  6. Stack-aware guidance + prioritized remediation playbook

Not a weaponized exploit framework: no SQLi/XSS attack payloads, no brute force.
"""

from __future__ import annotations

import hashlib
import re
import ssl
import uuid
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Optional
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx

# ── catalogs ────────────────────────────────────────────────────────

SECURITY_HEADERS = {
    "strict-transport-security": (
        "HSTS", "high", "CWE-319",
        "Send Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    ),
    "content-security-policy": (
        "CSP", "high", "CWE-1021",
        "Deploy a tight Content-Security-Policy (default-src 'self'; object-src 'none'; base-uri 'self').",
    ),
    "x-content-type-options": (
        "X-Content-Type-Options", "medium", "CWE-693",
        "Set X-Content-Type-Options: nosniff on all responses.",
    ),
    "x-frame-options": (
        "X-Frame-Options", "medium", "CWE-1021",
        "Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.",
    ),
    "referrer-policy": (
        "Referrer-Policy", "low", "CWE-200",
        "Set Referrer-Policy: strict-origin-when-cross-origin (or stricter).",
    ),
    "permissions-policy": (
        "Permissions-Policy", "low", "CWE-250",
        "Restrict camera/microphone/geolocation via Permissions-Policy.",
    ),
    "x-xss-protection": (
        "X-XSS-Protection", "low", "CWE-79",
        "Prefer CSP; if legacy header is present set to 0 (modern browsers).",
    ),
}

SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.env.backup", "/.env.old",
    "/.git/HEAD", "/.git/config", "/.git/index", "/.svn/entries",
    "/.hg/store/00manifest.i", "/.bzr/README",
    "/backup.sql", "/dump.sql", "/db.sql", "/database.sql", "/backup.zip",
    "/site.zip", "/www.zip", "/backup.tar.gz", "/.ds_store",
    "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
    "/server-status", "/server-info",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/heapdump",
    "/actuator/mappings", "/actuator/configprops",
    "/api/swagger.json", "/swagger/v1/swagger.json", "/openapi.json",
    "/swagger-ui.html", "/swagger-ui/", "/graphql", "/graphiql",
    "/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.save",
    "/wp-content/debug.log", "/wp-json/wp/v2/users", "/xmlrpc.php",
    "/config.json", "/config.yml", "/config.yaml", "/application.properties",
    "/application.yml", "/web.config", "/web.config.bak",
    "/composer.json", "/package.json", "/package-lock.json",
    "/storage/logs/laravel.log", "/storage/framework/sessions",
    "/var/www/.env", "/admin", "/administrator", "/phpmyadmin",
    "/pma", "/_profiler", "/telescope", "/debug", "/elmah.axd",
    "/trace.axd", "/.well-known/security.txt",
    "/api/v1/users", "/api/users", "/api/config", "/api/env",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/id_rsa", "/id_rsa.pub", "/.ssh/id_rsa",
    "/proc/self/environ", "/.docker/config.json",
]

BACKUP_SUFFIXES = [".bak", ".old", ".orig", ".save", "~", ".swp", ".tmp", ".copy", ".1"]

STACK_PATHS = {
    "wordpress": ["/wp-json/wp/v2/users", "/xmlrpc.php", "/wp-content/debug.log",
                  "/wp-config.php.bak", "/?author=1", "/wp-login.php"],
    "laravel": ["/telescope", "/_ignition/health-check", "/storage/logs/laravel.log", "/.env"],
    "django": ["/admin/", "/__debug__/", "/static/admin/"],
    "spring": ["/actuator", "/actuator/env", "/actuator/heapdump", "/actuator/mappings"],
    "nextjs": ["/_next/", "/api/"],
    "drupal": ["/user/login", "/CHANGELOG.txt", "/core/install.php"],
}

LEAK_BODY = [
    (r"(?i)(api[_-]?key|apikey|api_secret)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}", "critical", "CWE-798", "API key material in response"),
    (r"(?i)(secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"][A-Za-z0-9_\-\.]{16,}", "critical", "CWE-798", "Token/secret in response"),
    (r"(?i)AKIA[0-9A-Z]{16}", "critical", "CWE-798", "AWS access key id pattern"),
    (r"(?i)(db_password|database_password|mysql_pwd|postgres_password)\s*[:=]", "critical", "CWE-200", "Database password reference"),
    (r"(?i)-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----", "critical", "CWE-321", "Private key PEM in response"),
    (r"(?i)(mongodb(\+srv)?:\/\/[^\s'\"<]+)", "critical", "CWE-200", "MongoDB connection string"),
    (r"(?i)(postgres(ql)?:\/\/[^\s'\"<]+)", "critical", "CWE-200", "Postgres connection string"),
    (r"(?i)(traceback \(most recent call last\)|stack trace:|unhandled exception)", "medium", "CWE-209", "Stack trace leakage"),
    (r"(?i)(sql syntax|mysql_fetch|pg_query|ora-\d{5}|sqlite3\.operationalerror)", "medium", "CWE-209", "Database error message leakage"),
    (r"(?i)(phpversion\(\)|loaded configuration file|document root)", "high", "CWE-200", "PHP environment disclosure"),
]

# Each rule: (regex, severity, cwe, title, kind, how_used, fix)
# Group 1 should be the secret/value when possible.
JS_SECRET_RULES = [
    (
        r"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]",
        "high", "CWE-798", "Hardcoded API key in JavaScript",
        "api_key",
        "Often used to call third-party or backend APIs from the browser. Anyone can extract it from the JS bundle.",
        "Do not put long-lived API keys in frontend bundles. Use a backend proxy; if a public key is required (e.g. Stripe publishable), confirm it is a *publishable* key and restrict it by domain/referrer in the provider dashboard.",
    ),
    (
        r"(?i)(?:secret[_-]?key|client[_-]?secret)\s*[:=]\s*['\"]([A-Za-z0-9_\-\.]{16,})['\"]",
        "critical", "CWE-798", "Hardcoded client/secret key in JavaScript",
        "client_secret",
        "Client secrets authenticate your app to a provider. In browser JS they are fully public.",
        "Remove immediately, rotate the secret at the provider, and keep secrets only on the server.",
    ),
    (
        r"(?i)(?:auth[_-]?token|access[_-]?token)\s*[:=]\s*['\"]([A-Za-z0-9_\-\.]{20,})['\"]",
        "high", "CWE-798", "Hardcoded access/auth token in JavaScript",
        "access_token",
        "May allow API access as a user or service until expiry/revocation.",
        "Never ship long-lived tokens in static JS. Prefer short-lived tokens issued after login, stored in HttpOnly cookies.",
    ),
    (
        r"(?<![A-Za-z0-9])(AIza[0-9A-Za-z\-_]{20,})(?![A-Za-z0-9])",
        "high", "CWE-798", "Google API key embedded in JavaScript",
        "google_api_key",
        "Google API keys in frontend are common but must be restricted (HTTP referrer / API restrictions). Unrestricted keys can be abused for quota theft.",
        "In Google Cloud Console: restrict this key by HTTP referrer to your domains and lock APIs. Prefer server-side keys for sensitive APIs.",
    ),
    (
        r"(?<![A-Za-z0-9])(sk_(?:live|test)_[A-Za-z0-9]{16,})(?![A-Za-z0-9])",
        "critical", "CWE-798", "Stripe secret key in JavaScript",
        "stripe_secret",
        "Stripe sk_live/sk_test keys must never be in frontend code — they can move money / access the account.",
        "Revoke/rotate this key in Stripe Dashboard immediately. Only pk_ (publishable) keys belong in browser code.",
    ),
    (
        r"(?<![A-Za-z0-9])(pk_(?:live|test)_[A-Za-z0-9]{16,})(?![A-Za-z0-9])",
        "low", "CWE-798", "Stripe publishable key in JavaScript",
        "stripe_publishable",
        "Publishable keys are designed for browser use. Risk is lower but still restrict in Stripe settings.",
        "Confirm this is a pk_ key (not sk_). Restrict allowed domains in Stripe. No rotation urgency unless abused.",
    ),
    (
        r"(?<![A-Za-z0-9])(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})(?![A-Za-z0-9])",
        "critical", "CWE-798", "GitHub token in JavaScript",
        "github_token",
        "Can read/write repos and org resources depending on scopes.",
        "Revoke the token in GitHub settings now. Never embed GitHub PATs in frontend code.",
    ),
    (
        r"(?<![A-Za-z0-9])(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{8,})(?![A-Za-z0-9_\-])",
        "medium", "CWE-922", "JWT string embedded in JavaScript",
        "jwt",
        "JWTs in static bundles may be demo tokens, hard-coded sessions, or config. If valid, they can impersonate a subject until expiry.",
        "Decode the payload (jwt.io) without trusting it: check exp/sub/scope. Remove hard-coded JWTs; issue them from your auth API at runtime.",
    ),
    (
        r"(?i)(?:aws_access_key_id|accessKeyId)\s*[:=]\s*['\"]?(AKIA[0-9A-Z]{16})['\"]?",
        "critical", "CWE-798", "AWS access key id in JavaScript",
        "aws_key",
        "Together with a secret key this can control AWS resources.",
        "Deactivate the IAM key in AWS IAM immediately; use temporary credentials / Cognito for browser workloads.",
    ),
]

# Noise filters: values that look like placeholders / public config
_JS_SECRET_FALSE_POSITIVE = re.compile(
    r"(?i)^(null|undefined|true|false|test|todo|changeme|your[_-]?|xxx+|placeholder|example|"
    r"public|anonymous|pk_test_sample|process\.env)"
)

JS_SINKS = [
    (r"\beval\s*\(", "high", "CWE-95", "eval()", "Never use eval on untrusted data; use JSON.parse / safe parsers."),
    (r"new\s+Function\s*\(", "high", "CWE-95", "new Function()", "Avoid dynamic code generation from strings."),
    (r"\bdocument\.write\s*\(", "medium", "CWE-79", "document.write", "Avoid document.write; use safe DOM APIs."),
    (r"\.innerHTML\s*=", "medium", "CWE-79", "innerHTML assignment", "Use textContent or sanitize with a vetted library."),
    (r"\bdangerouslySetInnerHTML\b", "medium", "CWE-79", "dangerouslySetInnerHTML", "Sanitize HTML; prefer safe components."),
    (r"\blocalStorage\.setItem\s*\(", "low", "CWE-922", "localStorage write", "Do not store access tokens/secrets in localStorage."),
    (r"\bsessionStorage\.setItem\s*\(", "low", "CWE-922", "sessionStorage write", "Avoid storing sensitive tokens in sessionStorage."),
    (r"\bdocument\.cookie\s*=", "medium", "CWE-1004", "JS writes document.cookie", "Set session cookies server-side with HttpOnly."),
    (r"\.postMessage\s*\(", "low", "CWE-345", "postMessage", "Validate message origin on receivers."),
    (r"location\.(href|hash|search)\s*=", "medium", "CWE-601", "location assignment", "Avoid open redirects from untrusted input."),
]

JS_SOURCES = [
    r"location\.(href|hash|search)",
    r"document\.URL",
    r"document\.documentURI",
    r"window\.name",
    r"document\.referrer",
]

# API path namespaces used by real single-page applications.  This list used to
# be the single literal ``/api/``, which made every app serving its API under a
# different namespace invisible: OWASP Juice Shop (the canonical vulnerable-by-
# design target) serves its injectable endpoints at ``/rest/...``, GraphQL apps
# at ``/graphql``, and plenty of Express/Spring apps at ``/v1/``.  Those paths
# never entered the endpoint inventory, so they were never crawled and never
# probed -- the scanner reported 15 hints from a bundle that contained the whole
# vulnerable attack surface.
API_NAMESPACES = (
    "api", "rest", "graphql", "gql", "oauth", "auth", "services", "sockets",
    "socket\\.io", "ws", "rpc", "jsonrpc", "query",
)
_API_NS = "|".join(API_NAMESPACES)

# Characters that can appear inside an API path once it starts.
_API_PATH_CHARS = r"[a-zA-Z0-9_\-./{}:?&=]"

# Built by concatenation rather than an f-string because the regex is full of
# literal braces.  The shape, spelled out so the grouping is auditable:
#
#     (?<=[`'"}])            preceded by a quote or by `}` closing a template
#                            interpolation -- not only by a quote
#     (                      capture group 1 opens
#       /                    the leading slash
#       (?:NS)               an API namespace
#       (?![A-Za-z0-9_])     `/restaurant` is not `/rest`
#       (?:/[chars]*)?       the rest of the path, optional so `/graphql` matches
#     )                      capture group 1 closes
#
# The trailing `?` belongs to the path remainder only.  Attaching it to the
# whole capture group makes the regex match the empty string wherever the
# lookbehind succeeds, so `m.group(1)` is None and every hint is silently
# dropped.
_JS_API_PATH_PAT = (
    r"""(?<=[`'"}])"""
    r"""(/"""
    + "(?:" + _API_NS + ")"
    + r"""(?![A-Za-z0-9_])"""
    + r"""(?:/"""
    + _API_PATH_CHARS
    + r"""*)?"""
    + r""")"""
)

JS_ENDPOINT_PATS = [
    r"""['"`](https?://[^'"`\s]+)['"`]""",
    # A path whose first segment is one of the API namespaces.  The opening
    # delimiter is a lookbehind rather than a matched quote, because the paths
    # that matter most are not quoted on both sides: Juice Shop builds its
    # search URL as a template literal,
    #     `${this.hostServer}/rest/products/search?q=${t}`
    # where the path is preceded by `}` and followed by `$`.  Requiring a quote
    # on both sides silently dropped the single most injectable endpoint on the
    # target.  The trailing side has no delimiter requirement for the same
    # reason -- the character class stops naturally at `$`, `"`, and backtick.
    _JS_API_PATH_PAT,
    # A versioned path (/v1/..., /v2/...) -- the version segment is not itself a
    # namespace, but a path under one is still an API route.  The leading slash
    # is INSIDE the capture group: `_analyze_js` only keeps a candidate that
    # starts with "/", so a group that omits it loses every versioned path.
    (
        r"""(?<=[`'"}])"""
        r"""(/(?:v[0-9]+)/"""
        r"""[a-zA-Z0-9_\-./{}]+)"""
    ),
    r"""fetch\s*\(\s*['"`]([^'"`]+)['"`]""",
    r"""axios\.\w+\s*\(\s*['"`]([^'"`]+)['"`]""",
    r"""\.(?:get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]""",
]


@dataclass
class WebFinding:
    severity: str
    category: str
    title: str
    detail: str
    recommendation: str
    evidence: Optional[str] = None
    endpoint: Optional[str] = None
    cwe: Optional[str] = None
    confidence: str = "medium"  # high|medium|low


@dataclass
class WebScanResult:
    url: str
    final_url: str = ""
    status_code: int = 0
    findings: list[WebFinding] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    endpoints: list[dict] = field(default_factory=list)
    network: list[dict] = field(default_factory=list)
    cookies: list[dict] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    js_files: list[dict] = field(default_factory=list)
    api_hints: list[str] = field(default_factory=list)
    playbook: list[dict] = field(default_factory=list)
    score: float = 100.0
    grade: str = "A"
    summary: str = ""
    headers_sample: dict[str, str] = field(default_factory=dict)
    fixes: list[str] = field(default_factory=list)
    advisories: list = field(default_factory=list)
    relevance: list = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        c = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        return c

    def compute_score(self) -> None:
        # A statement that the scan could not assess something is coverage, not
        # a vulnerability (defect D67) -- it costs nothing, and an owner who is
        # told "medium" for a line that says "we could not check" learns to
        # distrust the true findings beside it.
        w = {"critical": 20, "high": 9, "medium": 4, "low": 1, "info": 0}
        # confidence weighting
        cw = {"high": 1.0, "medium": 0.75, "low": 0.45}
        penalty = 0.0
        for f in self.findings:
            penalty += w.get(f.severity, 3) * cw.get(f.confidence, 0.75)
        self.score = max(0.0, round(100.0 - min(penalty, 100.0), 1))

        # A scan that never reached the site has assessed nothing (defect D84).
        # The finding penalty then scores a single "Connection failed" at 91/100
        # and prints grade A: a pentester scanning a typo'd URL, or a site that
        # was down, filed a clean bill of health for a target no request ever
        # touched.  The number below describes findings, not the site, so the
        # grade says so instead of borrowing the A-F health vocabulary -- F would
        # be the opposite fabrication, and "A" is the one that gets filed.
        assessed = bool(self.network) or bool(self.endpoints) or bool(self.status_code)
        if not assessed:
            self.score = 0.0
            self.grade = "N"
        else:
            self.grade = (
                "A" if self.score >= 90 else "B" if self.score >= 75 else
                "C" if self.score >= 60 else "D" if self.score >= 40 else "F"
            )
        c = self.counts()
        if assessed:
            self.summary = (
                f"Security adviser score {self.score}/100 ({self.grade}). "
                f"{len(self.endpoints)} endpoints · {len(self.network)} HTTP traces · "
                f"{len(self.js_files)} JS · {len(self.cookies)} cookies · "
                f"findings {c['critical']}C/{c['high']}H/{c['medium']}M/{c['low']}L."
            )
        else:
            self.summary = (
                f"NOT ASSESSED - the target never answered a request "
                f"(0 endpoints, 0 HTTP traces, status {self.status_code}). "
                f"No grade is reported: the {c['high']}H/{c['medium']}M findings "
                f"describe the attempt, not the site."
            )
        # playbook: top issues with fix steps
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        play = []
        seen = set()
        for f in sorted(self.findings, key=lambda x: (order.get(x.severity, 9), x.title)):
            key = f.title
            if key in seen:
                continue
            seen.add(key)
            play.append({
                "priority": len(play) + 1,
                "severity": f.severity,
                "title": f.title,
                "cwe": f.cwe,
                "why": f.detail,
                "fix": f.recommendation,
                "where": f.endpoint or f.evidence or "",
            })
            if len(play) >= 15:
                break
        self.playbook = play
        self.fixes = [p["fix"] for p in play]

    def to_markdown(self) -> str:
        self.compute_score()
        c = self.counts()
        lines = [
            f"# Website Security Adviser — `{self.url}`",
            "",
            f"**Final URL:** {self.final_url or self.url}  ",
            f"**Status:** {self.status_code} · **Score:** {self.score}/100 ({self.grade})  ",
            f"**Surface:** endpoints={len(self.endpoints)} network={len(self.network)} "
            f"js={len(self.js_files)} cookies={len(self.cookies)} forms={len(self.forms)}  ",
            f"**Findings:** C={c['critical']} H={c['high']} M={c['medium']} L={c['low']}",
            "",
            self.summary,
            "",
        ]
        if self.playbook:
            lines.append("## Remediation playbook (do these first)")
            for p in self.playbook:
                cwe = f" · {p['cwe']}" if p.get("cwe") else ""
                lines += [
                    f"### P{p['priority']}. [{p['severity'].upper()}] {p['title']}{cwe}",
                    f"- Why: {p['why']}",
                    f"- Fix: {p['fix']}",
                ]
                if p.get("where"):
                    lines.append(f"- Where: `{p['where']}`")
                lines.append("")
        if self.technologies:
            lines += ["## Technology fingerprint", *[f"- {t}" for t in self.technologies], ""]
        if self.api_hints:
            lines += ["## Client-side API / URL hints", *[f"- `{h}`" for h in self.api_hints[:50]], ""]
        if self.cookies:
            lines.append("## Cookies")
            for ck in self.cookies[:25]:
                flags = []
                if ck.get("secure"):
                    flags.append("Secure")
                if ck.get("httponly"):
                    flags.append("HttpOnly")
                if ck.get("samesite"):
                    flags.append(f"SameSite={ck['samesite']}")
                lines.append(f"- `{ck.get('name')}` [{', '.join(flags) or 'weak flags'}]")
            lines.append("")
        if self.forms:
            lines.append("## Forms / inbound data")
            for fm in self.forms[:20]:
                lines.append(f"- `{fm.get('method')} {fm.get('action')}` inputs={fm.get('inputs')}")
            lines.append("")
        if self.js_files:
            lines.append("## JavaScript analyzed")
            for j in self.js_files[:20]:
                lines.append(f"- `{j.get('url')}` ({j.get('bytes')}B, signals={j.get('findings')})")
            lines.append("")
        if self.network:
            lines.append("## Network trace (sample)")
            for n in self.network[:30]:
                lines.append(
                    f"- `{n.get('method')} {n.get('url')}` → {n.get('status')} "
                    f"({n.get('bytes')}B, set-cookie={n.get('set_cookie_count')})"
                )
            lines.append("")
        if self.findings:
            lines.append("## Full findings")
            order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            for f in sorted(self.findings, key=lambda x: order.get(x.severity, 9)):
                cwe = f" · {f.cwe}" if f.cwe else ""
                lines += [
                    f"### [{f.severity.upper()}] {f.title}{cwe}",
                    f"- Category: {f.category} · Confidence: {f.confidence}",
                    f"- {f.detail}",
                    f"- **Fix:** {f.recommendation}",
                ]
                if f.endpoint:
                    lines.append(f"- Endpoint: `{f.endpoint}`")
                if f.evidence:
                    lines.append(f"- Evidence: `{str(f.evidence)[:200]}`")
                lines.append("")
        if getattr(self, "advisories", None):
            try:
                from .exploitdb import advisories_markdown
                lines.append(advisories_markdown(self.advisories))
                lines.append("")
            except Exception:
                pass
        if getattr(self, "relevance", None):
            try:
                from .exploit_relevance import relevance_markdown
                lines.append(relevance_markdown(self.relevance))
                lines.append("")
            except Exception:
                pass
        lines += [
            "---",
            "*TriageKit Security Adviser — authorized testing only. "
            "Safe active checks + static analysis; not a replacement for a full pentest.*",
        ]
        return "\n".join(lines)


class _HTMLAnalyzer(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[dict] = []
        self.comments: list[str] = []
        self.meta: list[tuple[str, str]] = []
        self._form: Optional[dict] = None
        self._in_script = False
        self._script_buf = ""
        self.inline_scripts: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        ad = dict(attrs)
        if tag in ("a", "link") and ad.get("href"):
            self.links.append(ad["href"])
        if tag == "script":
            if ad.get("src"):
                self.scripts.append(ad["src"])
                if not ad.get("integrity"):
                    self.links.append(f"__sri_missing__:{ad['src']}")
            else:
                self._in_script = True
                self._script_buf = ""
        if tag == "form":
            self._form = {
                "action": ad.get("action") or "",
                "method": (ad.get("method") or "GET").upper(),
                "inputs": [],
                "has_csrf": False,
            }
        if tag in ("input", "textarea", "select") and self._form is not None:
            name = ad.get("name") or ad.get("id") or tag
            typ = ad.get("type") or "text"
            self._form["inputs"].append(f"{name}:{typ}")
            nlow = (name or "").lower()
            if any(x in nlow for x in ("csrf", "_token", "authenticity_token", "__requestverificationtoken")):
                self._form["has_csrf"] = True
            if typ == "hidden" and any(x in nlow for x in ("csrf", "token")):
                self._form["has_csrf"] = True
        if tag == "meta":
            key = ad.get("name") or ad.get("property") or ""
            if key and ad.get("content"):
                self.meta.append((key, ad["content"]))

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None
        if tag == "script" and self._in_script:
            self.inline_scripts.append(self._script_buf)
            self._in_script = False
            self._script_buf = ""

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._script_buf += data

    def handle_comment(self, data: str) -> None:
        if data and len(data.strip()) > 3:
            self.comments.append(data.strip()[:400])


def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        raise ValueError("Empty URL")
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    if not urlparse(url).netloc:
        raise ValueError(f"Invalid URL: {url}")
    return url


def _same_host(base: str, other: str) -> bool:
    try:
        return urlparse(base).netloc.lower() == urlparse(other).netloc.lower()
    except Exception:
        return False



def _form_key(form: dict) -> tuple:
    """A stable identity for a form, so the same form is recorded once.

    D6: the home page was parsed twice (once for the initial fetch, once for the
    crawl) and the same form landed in the report twice, so the form count was
    double the truth.  Three dimensions decide identity -- action, method, and
    the set of inputs.  Attribute ORDER is deliberately excluded: the HTML
    parser emits attributes in document order, which carries no meaning, and two
    records of one form can arrive with their fields shuffled.
    """
    action = (form.get("action") or "").strip()
    method = (form.get("method") or "GET").strip().upper()
    inputs = tuple(sorted(
        (i or "").strip() for i in (form.get("inputs") or []) if i and i.strip()
    ))
    # A trailing slash on the action is the same endpoint, not a different one.
    return (action.rstrip("/"), method, inputs)


def _parse_set_cookie_headers(set_cookie_headers: list[str]) -> list[dict]:
    """Parse Set-Cookie headers into structured attributes.

    Uses attribute-token matching (not substring search on the whole header),
    so a cookie *value* containing the text "secure" does not count as the
    Secure attribute. Handles multiple Set-Cookie headers independently
    (does not split on commas inside Expires=).
    """
    out: list[dict] = []
    for header in set_cookie_headers:
        if not header or not header.strip():
            continue
        # RFC 6265: first pair is name=value; remainder are attributes
        segments = [s.strip() for s in header.split(";") if s.strip()]
        if not segments or "=" not in segments[0]:
            continue
        name, _, value = segments[0].partition("=")
        name = name.strip()
        value = value.strip()
        attrs: dict[str, str | bool] = {}
        for seg in segments[1:]:
            if "=" in seg:
                k, _, v = seg.partition("=")
                attrs[k.strip().lower()] = v.strip()
            else:
                attrs[seg.strip().lower()] = True
        out.append({
            "name": name,
            "value_preview": (value[:10] + "…") if len(value) > 10 else value,
            "secure": bool(attrs.get("secure")),
            "httponly": bool(attrs.get("httponly")),
            "samesite": (str(attrs["samesite"]) if attrs.get("samesite") not in (None, True) else None),
            "domain": str(attrs["domain"]) if attrs.get("domain") not in (None, True) else None,
            "path": str(attrs["path"]) if attrs.get("path") not in (None, True) else None,
            "raw_attrs": sorted(attrs.keys()),
        })
    return out


def _parse_set_cookie(header_val: str) -> list[dict]:
    """Backward-compatible wrapper for a single header string."""
    return _parse_set_cookie_headers([header_val] if header_val else [])


def _fingerprint(headers: dict, body: str, paths: list[str]) -> list[str]:
    """Label the stack from what the TARGET told us -- never from our own guesses.

    D5: a fingerprint is a claim about the target, so every label needs observed
    evidence.  Two rules make that true:

    (a) ``paths`` is accepted for signature compatibility and is DELIBERATELY
        NOT searched.  Every path a caller hands us is one this scanner asked
        for; a 404 on our own guess must never label the target.  The one thing
        that *is* independent evidence -- a URL the target itself linked --
        already appears in the body, so crawling is not needed to see it.
    (b) Needles are anchored regexes rather than bare substrings, so English
        prose cannot match.  ``"react"`` labelled every page that says "react";
        ``"vue."`` matched "revue." and "argue.".  Real framework markup is
        distinctive (``react-dom``, ``vue.runtime``, ``jquery-1.4.2.min.js``),
        so requiring it costs nothing and removes the false labels.

    ``Server``/``X-Powered-By`` are reported verbatim: the target volunteered
    them, which is exactly the standard of evidence the rest of this function
    is held to.
    """
    techs = []
    h = {str(k).lower(): v for k, v in headers.items()}
    if h.get("server"):
        techs.append(f"Server: {h['server']}")
    if h.get("x-powered-by"):
        techs.append(f"X-Powered-By: {h['x-powered-by']}")
    # Lowercased so the rules below can stay lowercase.  Only the body is
    # searched; see (a) in the docstring.
    blob = (body or "")[:100_000].lower()
    for pattern, label in (
        # WordPress: wp-content assets, the REST namespace, wp-includes.
        ("WordPress", r"wp-content|/wp-json|wp-includes"),
        # Spring Boot: the actuator path guarded by a boundary so a slug or a
        # prose "actuator" cannot match, plus the error page's own signature.
        ("Spring Boot", r"/actuator(?:/|[\"'\s?])|spring-boot|whitelabel error page"),
        ("Drupal", r"drupal\.settings|drupal\.js"),
        ("Next.js", r"_next/static|__next"),
        ("Django", r"csrfmiddlewaretoken"),
        ("Laravel", r"laravel_session"),
        ("Shopify", r"shopify"),
        # jQuery: the versioned filename, not the bare word.
        ("jQuery", r"jquery[-.]\d|jquery\.min\.js|/jquery"),
        # React: react-dom, the prod/dev marker, a versioned path, the internal
        # container id.  Not the English verb.
        ("React", r"react-dom|react\.production|react\.development|react@\d|__react|reactroot"),
        # Vue: a boundary-checked "vue" so "revue."/"argue." cannot match.
        ("Vue", r"(?<![a-z])vue(?:\.(?:runtime|min|js|esm|dev)|@\d)"),
        ("Angular", r"ng-app|angular(?:\.js|\.min\.js)|@angular/"),
        ("Cloudflare", r"cdnjs\.cloudflare\.com|cloudflare"),
        ("Nginx", r"nginx"),
    ):
        if re.search(label, blob) and pattern not in techs:
            techs.append(pattern)
    return techs[:20]



def _line_col(text: str, index: int) -> tuple[int, int]:
    line = text.count("\n", 0, index) + 1
    last_nl = text.rfind("\n", 0, index)
    col = index - last_nl
    return line, col


def _context_snippet(text: str, start: int, end: int, pad: int = 40) -> str:
    a = max(0, start - pad)
    b = min(len(text), end + pad)
    snip = text[a:b].replace("\n", " ").replace("\r", " ")
    if a > 0:
        snip = "…" + snip
    if b < len(text):
        snip = snip + "…"
    return snip[:220]


def _analyze_js(source: str, url: str, findings: list[WebFinding], api_hints: list[str]) -> int:
    signals = 0
    for pat in JS_ENDPOINT_PATS:
        for m in re.finditer(pat, source):
            cand = (m.group(1) if m.lastindex else m.group(0)).strip()
            if cand.startswith(("/", "http", "ws")) and cand not in api_hints:
                api_hints.append(cand[:300])
                signals += 1

    for rule in JS_SECRET_RULES:
        pat, sev, cwe, title, kind, how_used, fix = rule
        for m in re.finditer(pat, source):
            val = m.group(1) if m.lastindex else m.group(0)
            if _JS_SECRET_FALSE_POSITIVE.search(val or ""):
                continue
            # skip short / low-entropy-ish pure words
            if len(re.sub(r"[^A-Za-z0-9]", "", val)) < 12:
                continue
            line, col = _line_col(source, m.start())
            snip = _context_snippet(source, m.start(), m.end())
            # mask middle of secret in evidence
            if len(val) > 12:
                shown = val[:6] + "…" + val[-4:]
            else:
                shown = val[:2] + "…"
            detail = (
                f"File: {url}\n"
                f"Line {line}, column {col}\n"
                f"Type: {kind}\n"
                f"Matched value (redacted): {shown}\n"
                f"What this is: {how_used}\n"
                f"Code context: {snip}"
            )
            findings.append(WebFinding(
                sev, "js-secret", title,
                detail,
                fix + f" Search the bundle for line {line} or the redacted value prefix `{val[:6]}`.",
                evidence=f"L{line}: {snip}",
                endpoint=urlparse(url).path or url,
                cwe=cwe,
                confidence="medium" if kind in ("jwt", "api_key") else "high",
            ))
            signals += 1

    sink_hits = []
    for pat, sev, cwe, title, rec in JS_SINKS:
        for m in re.finditer(pat, source):
            line, col = _line_col(source, m.start())
            snip = _context_snippet(source, m.start(), m.end(), pad=30)
            sink_hits.append(title)
            findings.append(WebFinding(
                sev, "js-sink", f"Dangerous JS pattern: {title}",
                f"File: {url}\nLine {line}, column {col}\nCode context: {snip}",
                rec + f" Inspect line {line} in this script.",
                evidence=f"L{line}: {snip}",
                endpoint=urlparse(url).path or url,
                cwe=cwe,
                confidence="medium",
            ))
            signals += 1

    source_hits = []
    for p in JS_SOURCES:
        if re.search(p, source):
            source_hits.append(p)
    if source_hits and sink_hits:
        findings.append(WebFinding(
            "high", "js-domxss", "Possible DOM XSS source→sink pattern",
            f"File: {url}\nSources seen: {', '.join(source_hits[:4])}\nSinks seen: {', '.join(sorted(set(sink_hits))[:4])}\n"
            "This does not prove exploitability; it flags that URL/location data and HTML sinks both appear in the same file.",
            "Trace data flow from location/URL into sinks; encode/sanitize before DOM write; add CSP.",
            evidence=url,
            endpoint=urlparse(url).path or url,
            cwe="CWE-79",
            confidence="low",
        ))
        signals += 1
    return signals




# ---------------------------------------------------------------------------
# TLS attribution (defects D67, D69, D71, D74)
#
# One rule governs both probes below: the tool may assert a target-side defect
# only from evidence that is actually about the target.  A refusal, an error, or
# an incomplete trust store on the *scanning host* is a statement about the
# scanner, and it is disclosed as NOT_ASSESSED rather than converted into a
# severity the owner would act on.
#
# D67: the shipped expression was
#       "verification error" in blob or "verify return code" in blob and "0 (ok)" not in blob
#       which parses as A or (B and C).  ``openssl s_client -brief`` never prints
#       "Verify return code:" at all, so B was always False and C never
#       evaluated: the whole condition collapsed to A -- and A is exactly what
#       openssl prints for its OWN empty trust store (error 20, "unable to get
#       local issuer certificate").  A valid chain was therefore reported as a
#       MEDIUM CWE-295 defect telling the owner to repair a server that is fine.
#
# D69: the probe made one handshake at the client's default preference, which
#       negotiates the highest version both sides support.  A server still
#       accepting TLS 1.0/1.1 was invisible; the report said "TLS chain
#       verified".  A false negative of the same family D67 was a false
#       positive: the scan's silence read as "nothing wrong here".
#
# D71: _tls_floor_probe dispatched only on "completed", so a legacy version the
#       LOCAL library could not offer was dropped without a trace -- the floor
#       was reported as fully assessed when half of it had not been asked.
# ---------------------------------------------------------------------------

# openssl's own inability to offer a protocol -- a property of the local
# library, never of the target.  Kept as a module constant so a test can assert
# it is non-empty: with it empty, a local refusal is indistinguishable from the
# target refusing the protocol and the D69 discipline collapses.
_TLS_LOCAL_UNAVAILABLE = (
    "no protocols available",
    "no ciphers available",
    "unsupported protocol",
)

# The deprecated versions asked about by name.  Two entries, so the seam is
# called exactly twice per probe.  ``ssl.TLSVersion`` is what gets pinned.
_TLS_LEGACY_VERSIONS = (
    ("TLS 1.0", "tls1", ssl.TLSVersion.TLSv1),
    ("TLS 1.1", "tls1_1", ssl.TLSVersion.TLSv1_1),
)

# What openssl prints in "Protocol version:" when we pinned each one.  A
# handshake that reports anything else did NOT accept the legacy version.
_TLS_NEGOTIATED_TOKENS = {"TLS 1.0": "tlsv1", "TLS 1.1": "tlsv1.1"}

# Test seam.  ``None`` means "use the real _tls_floor_attempt".  Assigned only
# by tests and read only inside _tls_floor_probe, which is single-threaded
# within one scan.
_TLS_FLOOR_ATTEMPT = None

# Verification codes that describe the scanning host, not the target.  20 and 19
# are "cannot build a path"; 21 and 27 are "the root is not in my bundle".  All
# four fire on a machine with no CA bundle against a perfectly valid chain.
_TLS_LOCAL_VERIFY_CODES = frozenset({19, 20, 21, 27})

# Verification codes that ARE the target's fault.  10 expired, 62 hostname
# mismatch, 7/5 chain problems, 18 self-signed in chain served by the peer.
_TLS_PEER_VERIFY_CODES = frozenset({5, 7, 10, 18, 26, 62, 65, 68})


def _tls_verdict(blob: str) -> tuple[str, str]:
    """Classify an ``openssl s_client -brief`` blob.

    Returns ``(outcome, evidence)`` where outcome is one of::

        "verified"      the chain built and nothing was reported
        "peer_defect"   a numeric verification code that is the target's fault
        "cannot_verify" a local trust gap, or no numeric code to read

    The contract that makes D67 unreproducible: the answer must never depend on
    a ``Verify return code:`` line, because ``-brief`` does not print one.  Both
    the brief and the verbose form of the same handshake must classify
    identically, so every decision here comes from the ``verify
    error:num=N:`` / ``Verification error:`` lines that both formats emit.
    """
    text = blob or ""
    lowered = text.lower()

    # openssl's own summary line wins when it is present and affirmative.
    if "verification: ok" in lowered:
        return "verified", "openssl reported Verification: OK"

    codes: list[int] = []
    reason = ""
    for m in re.finditer(r"verify error:num=(\d+):([^\\\n]*)", lowered):
        try:
            codes.append(int(m.group(1)))
        except ValueError:  # pragma: no cover - regex guarantees digits
            continue
        reason = reason or m.group(2).strip()
    if not codes:
        for m in re.finditer(r"verification error:\s*([^\n]*)", lowered):
            reason = reason or m.group(1).strip()

    if not codes:
        # No numeric code at all.  An unparseable "Verification error: something
        # new" says nothing, and the tool must not guess a severity from it.
        if "verification error" in lowered:
            return "cannot_verify", reason or "verification error with no numeric code"
        return "cannot_verify", "no verification evidence in openssl output"

    if any(c in _TLS_LOCAL_VERIFY_CODES for c in codes):
        local = ", ".join(str(c) for c in codes if c in _TLS_LOCAL_VERIFY_CODES)
        return "cannot_verify", f"openssl verify error num={local}: {reason}"

    if any(c in _TLS_PEER_VERIFY_CODES for c in codes):
        peer = ", ".join(str(c) for c in codes if c in _TLS_PEER_VERIFY_CODES)
        return "peer_defect", f"openssl verify error num={peer}: {reason}"

    # A code we do not recognise.  Unknown evidence is not target evidence.
    return "cannot_verify", f"unrecognised openssl verify error num={codes[0]}: {reason}"


def _tls_floor_attempt(host: str, name: str, version) -> tuple[str, str]:
    """Offer exactly one TLS version to ``host:443`` and report what happened.

    Returns one of exactly three outcomes -- the whole vocabulary the probe's
    dispatch understands::

        "completed"    a handshake finished at this version: TARGET evidence
        "unavailable"  the LOCAL library declined to offer it: scanner evidence
        "refused"      the target declined: genuine negative target evidence

    The third distinction is the point of D69/D71.  A host whose openssl
    disables TLS 1.0 produces ``error:0A000042:SSL routines:no protocols
    available``; that is the scanning machine, and the target must be neither
    credited nor blamed for it.
    """
    import shutil
    import subprocess

    openssl = shutil.which("openssl")
    if not openssl:
        return "unavailable", "openssl is not installed on the scanning host"

    cmd = [openssl, "s_client", "-connect", f"{host}:443",
           "-servername", host, "-brief"]
    flag = dict((n, f) for n, f, _ in _TLS_LEGACY_VERSIONS).get(name)
    if flag:
        cmd.append(flag)
    try:
        proc = subprocess.run(cmd, input="", capture_output=True, text=True, timeout=8)
    except Exception as exc:
        return "unavailable", f"handshake could not be attempted: {exc}"

    blob = (proc.stdout or "") + (proc.stderr or "")
    low = blob.lower()
    if any(marker in low for marker in _TLS_LOCAL_UNAVAILABLE):
        return "unavailable", blob.strip()[:200]

    # A completed handshake is the only thing that licenses a finding -- and only
    # if it completed AT THE VERSION WE PINNED.  Asking for TLS 1.0 and getting
    # a TLS 1.3 session is a refusal, not an acceptance: without this check an
    # unpinned or stubbed handshake would be reported as a legacy floor on a
    # server that does not have one.
    expected = _TLS_NEGOTIATED_TOKENS.get(name)
    negotiated = ""
    m = re.search(r"(?im)^\s*Protocol version:\s*(\S+)", blob)
    if m:
        negotiated = m.group(1)

    if "connection established" in low or negotiated:
        if expected is not None and negotiated.lower() != expected:
            return "refused", (
                f"{name} not accepted; handshake completed at {negotiated or 'an unknown version'}"
            )
        suite = ""
        m = re.search(r"(?im)^\s*Ciphersuite:\s*(\S+)", blob)
        if m:
            suite = m.group(1)
        evidence = f"{name} accepted"
        if negotiated:
            evidence += f" (negotiated {negotiated}"
            evidence += f", {suite})" if suite else ")"
        return "completed", evidence

    return "refused", (blob.strip() or f"openssl exited {proc.returncode}")[:200]


def _tls_floor_probe(host: str) -> list[WebFinding]:
    """Ask the target which deprecated versions it still accepts.

    Asserts a finding ONLY where a handshake actually completed at the legacy
    version, and discloses every version the local library could not offer.
    D71: the "unavailable" arm used to be missing entirely, so a host that
    cannot offer TLS 1.0 reported a fully-assessed floor over half a question.
    """
    if not host:
        return []

    attempt = _TLS_FLOOR_ATTEMPT or _tls_floor_attempt
    accepted: list[tuple[str, str]] = []
    unavailable: list[tuple[str, str]] = []

    for label, _flag, version in _TLS_LEGACY_VERSIONS:
        try:
            outcome, evidence = attempt(host, label, version)
        except Exception as exc:
            # A callback that blows up is not a target refusal.  Treat it as an
            # unanswered question, which is what it is.
            outcome, evidence = "unavailable", f"probe raised: {exc}"
        if outcome == "completed":
            accepted.append((label, evidence))
        elif outcome == "unavailable":
            unavailable.append((label, evidence))
        # "refused" is a genuine negative and needs no disclosure.

    findings: list[WebFinding] = []
    for label, evidence in accepted:
        # TLS 1.0 is the worse of the two: it has no downgrade protection at all.
        sev = "high" if label == "TLS 1.0" else "medium"
        findings.append(WebFinding(
            sev, "tls",
            f"Server still accepts a deprecated protocol ({label})",
            f"A client pinned to {label} completed a full handshake with this "
            f"server. {label} is deprecated by RFC 8996 and disallowed by PCI "
            f"DSS, and it lacks the downgrade protection of modern versions. "
            f"Evidence: {evidence}",
            f"Raise the minimum TLS version to 1.2 on the edge: set the "
            f"protocol floor so {label} is refused, not negotiated. This is a "
            f"configuration change (Cloudflare: SSL/TLS -> Edge Certificates -> "
            f"Minimum TLS Version); it needs no application code.",
            endpoint=f"{host}:443",
            cwe="CWE-757",
            confidence="high",
            evidence=evidence,
        ))

    if unavailable:
        names = ", ".join(label for label, _ in unavailable)
        detail = "; ".join(ev for _l, ev in unavailable)
        findings.append(WebFinding(
            "info", "tls",
            "TLS protocol floor NOT_ASSESSED (local library cannot offer legacy versions)",
            f"The versions this server would accept below TLS 1.2 could not be "
            f"determined for: {names}. The scanning host's own TLS library "
            f"declined to offer them ({detail}), which says nothing about the "
            f"target. Run the scan on a host whose openssl is built with those "
            f"protocols enabled before drawing any conclusion.",
            "No server-side change is implied by this line. It records the limit "
            "of the assessment, not a defect.",
            endpoint=f"{host}:443",
            confidence="high",
            evidence=detail[:200],
        ))

    return findings


def _recon_host(host: str) -> list[WebFinding]:
    """Optional OS-level recon (openssl/dig) when tools exist — authorized use."""
    import shutil
    import subprocess
    findings: list[WebFinding] = []
    if not host:
        return findings
    # DNS
    dig = shutil.which("dig") or shutil.which("nslookup")
    if dig and "dig" in dig:
        try:
            out = subprocess.run(
                [dig, "+short", host], capture_output=True, text=True, timeout=5
            )
            ips = ",".join([ln.strip() for ln in (out.stdout or "").splitlines() if ln.strip()][:6])
            if ips:
                findings.append(WebFinding(
                    "low", "recon", "DNS resolution",
                    f"Host {host} resolves to: {ips}",
                    "Confirm expected infrastructure; monitor unexpected IP changes.",
                    evidence=ips, confidence="high",
                ))
        except Exception:
            pass
    # TLS cert via openssl
    openssl = shutil.which("openssl")
    if openssl:
        try:
            proc = subprocess.run(
                [openssl, "s_client", "-connect", f"{host}:443", "-servername", host, "-brief"],
                input="", capture_output=True, text=True, timeout=8,
            )
            blob = (proc.stdout or "") + (proc.stderr or "")
            if "Protocol" in blob or "Verification" in blob:
                outcome, evidence = _tls_verdict(blob)
                flat = blob[:400].replace("\n", " | ")
                if outcome == "peer_defect":
                    # A numeric verification code the target is responsible for.
                    findings.append(WebFinding(
                        "high", "tls",
                        f"TLS certificate defect: {evidence}",
                        f"openssl reported a verification failure that is the "
                        f"server's responsibility: {evidence}.\nHandshake probe: {flat}",
                        "Reissue or complete the certificate chain, fix the "
                        "hostname/SAN mismatch, or disable the deprecated "
                        "protocol on the edge.",
                        evidence=host, cwe="CWE-295", confidence="high",
                    ))
                elif outcome == "cannot_verify":
                    # D67: error 20/19/21/27, or no code at all.  A statement
                    # about this machine, not about the server.
                    findings.append(WebFinding(
                        "info", "tls",
                        "TLS chain NOT_ASSESSED (local trust store incomplete)",
                        f"The chain could not be verified from this host, so no "
                        f"conclusion about the server is offered: {evidence}. "
                        f"An incomplete local CA bundle produces this for every "
                        f"site, valid chain or not.\nHandshake probe: {flat}",
                        "No server-side change is implied. Point the scanner at "
                        "a populated CA bundle (certifi, or the OS trust store) "
                        "and re-run to obtain a verdict.",
                        evidence=host, confidence="high",
                    ))
                else:
                    findings.append(WebFinding(
                        "info", "tls", "TLS chain verified",
                        f"The certificate chain built successfully during the "
                        f"handshake.\nHandshake probe: {flat}",
                        "No certificate action required.",
                        evidence=host, confidence="high",
                    ))
        except Exception:
            pass

    # TLS protocol floor (D69/D71/D74).  The SSL context is built inside the
    # try: on some Python builds the context constructor itself is what raises
    # when a pinned version is unavailable locally (D74 -- TypeError: an integer
    # is required (got type NoneType)), and building it outside turned that into
    # a lost probe with no NOT_ASSESSED line at all.
    try:
        findings.extend(_tls_floor_probe(host))
    except Exception:
        pass
    return findings



# Safe, non-destructive probes only — unique markers / benign expressions.
# No reverse shells, no destructive SQL, no credential stuffing.
SAFE_PROBES = {
    "xss": [
        ("xss_plain", "<tkxss{cid}>", "If reflected raw, HTML injection may be possible."),
        ("xss_attr", '" tkxss={cid} ', "Attribute-break style marker."),
        ("xss_enc", "%3Ctkxss{cid}%3E", "URL-encoded marker reflection."),
    ],
    "sqli": [
        ("sqli_quote", "'", "Single quote — watch for DB error signatures."),
        ("sqli_dquote", "\"", "Double quote — watch for DB error signatures."),
        ("sqli_comment", "'--", "Comment marker — error/behavior change only."),
        ("sqli_logic", "' OR '1'='1", "Tautology pattern — compare response length/status only."),
    ],
    "ssti": [
        ("ssti_curly", "{{7*7}}", "If response contains 49, template injection may exist."),
        ("ssti_dollar", "${7*7}", "Alt template syntax probe."),
        ("ssti_hash", "#{7*7}", "Alt template syntax probe."),
    ],
    "path": [
        ("path_dot", "....//....//tkpath{cid}", "Traversal-style marker (non-existent resource)."),
        ("path_enc", "..%2f..%2ftkpath{cid}", "Encoded traversal marker."),
    ],
    "cmd_sep": [
        # separators only — no actual commands executed by us; we only look for odd errors
        ("sep_semi", "tkcmd{cid};", "Command-separator character in input."),
        ("sep_pipe", "tkcmd{cid}|", "Pipe character in input."),
        ("sep_back", "tkcmd{cid}`", "Backtick character in input."),
    ],
}

_SQL_ERRORS = re.compile(
    r"(?i)(sql syntax|mysql_fetch|mysqli_|pg_query|postgresql|ora-\d{5}|"
    r"sqlite3?\.|odbc|syntax error.*query|unclosed quotation mark|"
    r"you have an error in your sql|warning: mysql|sqlstate\[|jdbc\.sql)",
)

_SSTI_HIT = re.compile(r"(?<![0-9])49(?![0-9])")


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_CONF_RANK = {"high": 0, "medium": 1, "low": 2}


def _probe_parameter(
    client: httpx.Client,
    base_url: str,
    param: str,
    cid: str,
    record_fn,
    baseline: dict,
    *,
    timeout: float = 8.0,
) -> list[dict]:
    """Send the safe probe matrix at ONE query parameter and return MEASUREMENTS.

    This returns signals, not findings.  The measurement and the decision about
    how to report it are separated on purpose: one endpoint that echoes every
    query value used to produce one finding per parameter name tried, all of
    them the same sentence with a different name in it (defect D4).  The caller
    folds these signals with :func:`_fold_probe_signals`, which keeps every
    parameter in the evidence while emitting one line per defect.

    ``baseline`` is the caller's pre-measured response for this URL
    (``{"len", "status", "body"}``), so one endpoint costs one baseline request
    instead of one per parameter.
    """
    parsed = urlparse(base_url)
    endpoint = parsed.path or "/"
    baseline_q = dict(parse_qsl(parsed.query, keep_blank_values=True))
    base_body = baseline.get("body") or ""
    base_len = baseline.get("len") or 0
    base_status = baseline.get("status")
    signals: list[dict] = []

    def _emit(family, outcome, pid, severity, confidence, cwe, recommendation,
              headline, facts):
        signals.append({
            "family": family,
            "outcome": outcome,
            "endpoint": endpoint,
            "param": param,
            "probe": pid,
            "severity": severity,
            "confidence": confidence,
            "cwe": cwe,
            "recommendation": recommendation,
            "headline": headline,
            "meaning": meaning_by_probe.get(pid, ""),
            "facts": facts,
        })

    meaning_by_probe = {pid: m for _fam, probes in SAFE_PROBES.items()
                       for pid, _t, m in probes}

    for family, probes in SAFE_PROBES.items():
        for pid, payload_tmpl, meaning in probes:
            payload = payload_tmpl.replace("{cid}", cid)
            q = dict(baseline_q)
            q[param] = payload
            test_url = urlunparse(parsed._replace(query=urlencode(q, safe="")))
            try:
                tr = client.get(test_url, timeout=timeout)
                record_fn("GET", test_url, tr)
            except Exception:
                continue
            body = tr.text or ""
            status = tr.status_code
            length = len(tr.content or b"")

            # Reflection evidence must be something the marker actually put in
            # the payload.  ``"{{7*7}}".split("{")[0]`` is the empty string and
            # ``"" in body`` is always true, so an empty prefix is discarded
            # rather than counted as a match on every target.
            prefix = payload_tmpl.split("{")[0]
            reflected = (
                (payload and payload in body)
                or (cid and cid in body)
                or (bool(prefix) and prefix in body)
            )

            if family == "xss":
                if not reflected:
                    continue
                # One outcome for both cases: whether the marker came back
                # escaped changes HOW exploitable the reflection is, not WHETHER
                # the endpoint reflects.  Two outcomes would split one defect
                # into two lines at the same endpoint, and the fold's severity
                # rule already lifts the finding to HIGH when any position
                # produced a raw break.
                raw_hit = f"<tkxss{cid}>" in body or f"tkxss={cid}" in body
                _emit(family, "reflected", pid, "high" if raw_hit else "medium",
                      "medium" if raw_hit else "low", "CWE-79",
                      "Context-encode output (HTML/attr/JS). Prefer templating "
                      "auto-escape; add CSP.",
                      "Script-injection marker reflected",
                      [f"param {param} reflected the marker",
                       f"unescaped tag/attribute break: {raw_hit}",
                       f"status {status}"])
            elif family == "sqli":
                err = bool(_SQL_ERRORS.search(body)) and not _SQL_ERRORS.search(base_body)
                delta = abs(length - base_len) > max(80, int(base_len * 0.15))
                status_shift = status != base_status and status >= 500
                if err or status_shift:
                    _emit(family, "error_signal", pid, "high" if err else "medium",
                          "medium" if err else "low", "CWE-89",
                          "Use parameterized queries / prepared statements "
                          "everywhere; never concatenate SQL.",
                          "Database error text appeared after a SQL metacharacter",
                          [f"db error signature matched: {err}",
                           f"status {base_status} -> {status}",
                           f"length {base_len} -> {length}"])
                elif delta and reflected:
                    _emit(family, "behavioral_delta", pid, "low", "low", "CWE-89",
                          "Review query handling for this parameter; add tests "
                          "with hostile input in staging.",
                          "Response size changed with SQL-like input",
                          [f"length {base_len} -> {length}",
                           "no error text; not proof of exploit"])
            elif family == "ssti":
                evaluated = bool(_SSTI_HIT.search(body)) and not _SSTI_HIT.search(base_body)
                if evaluated:
                    _emit(family, "evaluated", pid, "high", "medium", "CWE-94",
                          "Do not render user input as a template; use strict "
                          "sandboxed templates or string escaping.",
                          "Template expression evaluated (probe returned 49)",
                          [f"{pid} evaluated to 49 on {endpoint}",
                           f"49 absent from the baseline: "
                           f"{not _SSTI_HIT.search(base_body)}"])
                elif reflected and "{{" in payload:
                    _emit(family, "reflected", pid, "low", "low", "CWE-94",
                          "Ensure template engines do not evaluate untrusted strings.",
                          "Template syntax reflected without evaluation",
                          ["marker reflected verbatim; no evaluation evidence"])
            elif family == "path":
                if status != base_status or abs(length - base_len) > 100:
                    _emit(family, "behavior_change", pid, "medium", "low", "CWE-22",
                          "Canonicalize and allowlist paths; reject .. and encoded "
                          "variants.",
                          "Traversal-style marker changed the response",
                          [f"status {base_status} -> {status}",
                           f"length {base_len} -> {length}"])
            elif family == "cmd_sep":
                errish = bool(re.search(r"(?i)(sh:|bash:|cmd\.exe|not recognized|syntax error)", body)) and not re.search(
                    r"(?i)(sh:|bash:|cmd\.exe)", base_body
                )
                if errish:
                    _emit(family, "error_signal", pid, "high", "medium", "CWE-78",
                          "Never pass user input to shell; use argument arrays / "
                          "library APIs.",
                          "Shell-like error text appeared after a separator probe",
                          [f"separator-only probe produced shell error text on {param}"])

    return signals


# Payloads for the JSON-body probe.  These are the same benign metacharacter
# and tautology markers the GET matrix uses -- a quote and a tautology.  No
# UNION, no stacked query, no time delay, no credential guessing: a login bypass
# is *visible* from a status-code and body-shape change, so nothing destructive
# is needed to see it.
_JSON_PROBE_PAYLOADS = (
    ("json_quote", "'", "Single quote in a JSON string field."),
    ("json_tautology", "' OR 1=1--", "Tautology marker in a JSON string field."),
)

# Field names worth trying in a JSON body.  Deliberately excludes "password":
# a probe that varies a password field is credential testing, which this scanner
# is not, and the field that matters (email/username) is what carries the
# injection in the first place.
_JSON_PROBE_FIELDS = ("email", "username", "user", "login", "q", "search", "id", "name")

# Substrings that mean the response carries a session, not an error page.
_JSON_SESSION_TOKENS = ("token", "jwt", "session", "authentication", "basket", "userId")

# Namespaces that carry a JSON API rather than an HTML page.  Used to decide
# whether a POST with a body is meaningful at all: POSTing JSON at a route that
# renders HTML is noise.
_API_NAMESPACE_PREFIXES = ("/api/", "/rest/", "/v1/", "/v2/", "/v3/",
                           "/graphql", "/gql", "/auth/", "/oauth/",
                           "/rpc", "/jsonrpc", "/services/", "/query")

# Path fragments that mark a credential endpoint.  The JSON-body probe is aimed
# at these preferentially: they are the routes where a tautology produces a
# session rather than an error page, which is the whole bypass class.
#
# Weighted, not a flat tuple, and the weight order is the fix.  A flat
# "any of these appears" rule put ``/rest/user/login`` BELOW
# ``/rest/user/change-password``, ``/rest/user/security-question`` and
# ``/api/v1/users`` on a live Juice Shop scan, because all four contain "user"
# and insertion order decided the rest -- so the login route still lost its slot
# and the bypass still went unmeasured.  A login endpoint is the class this
# probe exists for; it has to outrank an ordinary user route.
_JSON_AUTH_WEIGHTS: tuple[tuple[int, tuple[str, ...]], ...] = (
    (4, ("login", "signin", "sign-in", "log-in")),
    (3, ("password", "passwd", "register", "signup", "sign-up")),
    (2, ("auth", "token", "session", "oauth", "credential")),
    (1, ("user", "account", "me", "profile")),
)


def _auth_weight(path: str) -> int:
    """How strongly a path looks like the credential route the probe wants."""
    low = (path or "").lower()
    return sum(w for w, hints in _JSON_AUTH_WEIGHTS
               if any(h in low for h in hints))


def _is_api_path(path: str) -> bool:
    """True when a URL path looks like a JSON API route rather than a page."""
    low = (path or "").lower()
    return any(low.startswith(p) for p in _API_NAMESPACE_PREFIXES)


def _json_probe_candidates(targets: list[str], limit: int = 3) -> list[str]:
    """Endpoints worth a JSON-body probe, in priority order.

    The JSON probe has a DIFFERENT target profile from the GET matrix: the GET
    matrix wants endpoints that already carry a query string, and this wants the
    credential routes.  Reusing the matrix's first six meant the login route was
    never reached -- on a live Juice Shop scan, 53 API endpoints were extracted,
    ``/rest/user/login`` was among them, and the first six slots went to five
    other paths, so the one endpoint on the target that answers a tautology with
    an admin JWT was never sent a request.

    API routes are ranked by :func:`_auth_weight`, most credential-shaped first,
    then by their original position.  The sort is stable, so equal weights keep
    their input order and the run stays reproducible; the weight only moves a
    login route ahead of a user route, which is the one distinction that decides
    whether the bypass class is measured at all.
    """
    api = [t for t in targets if _is_api_path(urlparse(t).path)]
    ranked = sorted(
        api, key=lambda t: (-_auth_weight(urlparse(t).path), api.index(t))
    )
    return ranked[:limit]


def _probe_json_parameter(
    client: httpx.Client,
    base_url: str,
    field: str,
    cid: str,
    record_fn,
    baseline: dict,
    *,
    timeout: float = 8.0,
) -> list[dict]:
    """POST ``{"<field>": "<benign marker>"}`` and measure what comes back.

    Wall 3: :func:`_probe_parameter` can only express a query string, so the
    most common vulnerability class in JSON APIs is structurally unreachable.
    OWASP Juice Shop's signature bug is exactly this -- ``POST /rest/user/login``
    with ``{"email": "' OR 1=1--"}`` returns HTTP 200 and a valid admin JWT,
    while the honest baseline returns 401.  Nothing about that requires an
    exploit: the endpoint answers a tautology differently from a real address,
    which is a measurement.

    Safety: one baseline request plus one request per marker.  No credentials
    are ever sent, nothing is retried after a 2xx, and the payloads are limited
    to a quote and a tautology.  The function returns measurements, exactly like
    :func:`_probe_parameter`, so ``_fold_probe_signals`` reports one line per
    defect rather than one per field.
    """
    parsed = urlparse(base_url)
    endpoint = parsed.path or "/"
    base_body = baseline.get("body") or ""
    base_status = baseline.get("status")
    base_len = baseline.get("len") or 0
    signals: list[dict] = []

    def _emit(outcome, pid, severity, confidence, cwe, recommendation,
              headline, facts):
        signals.append({
            "family": "sqli",
            "outcome": outcome,
            "endpoint": endpoint,
            "param": field,
            "probe": pid,
            "severity": severity,
            "confidence": confidence,
            "cwe": cwe,
            "recommendation": recommendation,
            "headline": headline,
            "meaning": "JSON body field; measured against a POST baseline.",
            "facts": facts,
        })

    for pid, payload, _meaning in _JSON_PROBE_PAYLOADS:
        body = {field: payload}
        try:
            tr = client.post(base_url, json=body, timeout=timeout)
            record_fn("POST", base_url, tr)
        except Exception:
            continue
        text = tr.text or ""
        status = tr.status_code
        length = len(tr.content or b"")

        err = bool(_SQL_ERRORS.search(text)) and not _SQL_ERRORS.search(base_body)
        sessionish = any(t in text.lower() for t in _JSON_SESSION_TOKENS)

        # A baseline of 4xx and a probe of 2xx is the whole finding: the
        # endpoint accepted a tautology as a valid credential.  Requiring the
        # session marker as well keeps a 401-turned-200 that returns only an
        # empty object from being called an auth bypass.
        if base_status in (400, 401, 403, 404) and 200 <= status < 300:
            if sessionish or length > max(80, base_len):
                _emit("auth_bypass", pid, "critical", "medium", "CWE-89",
                      "Use parameterized queries / prepared statements for every "
                      "credential check; never build SQL by concatenation. Treat "
                      "this endpoint as compromised until the query is rewritten.",
                      "JSON API accepted a tautology as valid credentials",
                      [f"POST {endpoint} field '{field}'",
                       f"status {base_status} -> {status}",
                       f"session material in response: {sessionish}",
                       f"length {base_len} -> {length}"])
                # One confirmed bypass per endpoint is enough; a second payload
                # would only restate it, and each extra POST is traffic on the
                # target for no new information.
                return signals
            continue

        if err:
            _emit("error_signal", pid, "high", "medium", "CWE-89",
                  "Use parameterized queries / prepared statements; never "
                  "concatenate user input into SQL.",
                  "Database error text appeared after a JSON body marker",
                  [f"db error signature matched on field '{field}'",
                   f"status {base_status} -> {status}"])
        elif sessionish and 200 <= status < 300 and not (base_status and 200 <= base_status < 300):
            _emit("auth_bypass", pid, "high", "low", "CWE-89",
                  "Review credential handling for this field; parameterize the "
                  "lookup and fail closed on unexpected rows.",
                  "JSON API returned session material for a tautology marker",
                  [f"baseline status {base_status} had no session material",
                   f"probe status {status} carries a session token"])

    return signals


def _fold_probe_signals(signals: list[dict]) -> list[WebFinding]:
    """Collapse per-parameter probe measurements into one finding per defect.

    D4: ten parameter names on one echoing endpoint became ten identical
    findings.  Folding removes LINES, not facts -- every parameter that showed
    the defect stays in ``evidence`` and in the count, so a reader can still see
    how wide the exposure is.

    The grouping key is ``(endpoint, family, outcome)``.  Two endpoints are two
    defects, and "the marker came back" versus "the expression was evaluated"
    are two different facts about the same endpoint -- folding those would hide
    the worse one or invent a severity neither measurement supports.
    """
    groups: dict[tuple, list[dict]] = {}
    order: list[tuple] = []
    for sig in signals:
        key = (sig.get("endpoint") or "/", sig.get("family") or "?",
               sig.get("outcome") or "?")
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(sig)

    findings: list[WebFinding] = []
    for key in order:
        group = groups[key]
        endpoint, family, outcome = key
        params: list[str] = []
        probes: list[str] = []
        for sig in group:
            p = sig.get("param") or ""
            if p and p not in params:
                params.append(p)
            pr = sig.get("probe") or ""
            if pr and pr not in probes:
                probes.append(pr)
        # Worst measurement wins: folding must never soften a finding.
        severity = min((s.get("severity") or "low" for s in group),
                       key=lambda s: _SEV_RANK.get(s, 9))
        confidence = min((s.get("confidence") or "low" for s in group),
                         key=lambda c: _CONF_RANK.get(c, 9))
        first = group[0]
        headline = first.get("headline") or family

        if len(params) == 1:
            title = f"{headline} via ?{params[0]}="
        else:
            title = f"{headline} across {len(params)} parameter positions"

        facts: list[str] = []
        for sig in group:
            for fact in sig.get("facts") or []:
                if fact not in facts:
                    facts.append(fact)

        detail = (
            f"{len(group)} measurement(s) at {endpoint} across "
            f"{len(params)} parameter positions: {', '.join(params)}. "
            f"{first.get('meaning') or ''} "
            f"Outcome class: {outcome}."
        ).strip()
        if facts:
            detail += "\nObserved: " + "; ".join(facts) + "."

        findings.append(WebFinding(
            severity,
            f"probe-{family}",
            title,
            detail,
            first.get("recommendation") or "",
            endpoint=endpoint,
            cwe=first.get("cwe"),
            confidence=confidence,
            evidence=f"params={','.join(params)}; probes={','.join(probes)}",
        ))
    return findings


def scan_website(
    url: str,
    *,
    timeout: float = 30.0,
    check_sensitive_paths: bool = True,
    max_paths: int = 120,
    crawl: bool = True,
    max_crawl_pages: int = 25,
    max_js_files: int = 20,
    max_js_bytes: int = 1_800_000,
    active: bool = True,
) -> WebScanResult:
    url = _normalize_url(url)
    result = WebScanResult(url=url)
    findings: list[WebFinding] = []
    network: list[dict] = []
    cookies_map: dict[str, dict] = {}
    discovered: dict[str, dict] = {}
    api_hints: list[str] = []
    js_files: list[dict] = []
    forms: list[dict] = []
    body_404_hash: Optional[str] = None
    _seen_form_keys: set = set()

    def _add_form(item: dict) -> None:
        """Record a form once (defect D6).

        The home page is parsed for its own findings and again as the first page
        of the crawl, so every form on it arrived twice and the report's form
        count was double the truth.  Identity is ``_form_key`` -- action, method
        and the SET of inputs, never their order.
        """
        key = _form_key(item)
        if key in _seen_form_keys:
            return
        _seen_form_keys.add(key)
        forms.append(item)

    def add_cookie_findings(ck: dict, https: bool) -> None:
        name = ck.get("name") or "?"
        if https and not ck.get("secure"):
            findings.append(WebFinding(
                "high" if any(x in name.lower() for x in ("sess", "auth", "token", "jwt", "sid")) else "medium",
                "cookies", f"Cookie '{name}' missing Secure",
                "Cookie can be sent over HTTP if a mixed request occurs.",
                "Set Secure on all cookies; prefer __Host- / __Secure- prefixes for session cookies.",
                evidence=name, cwe="CWE-614", confidence="high",
            ))
        if not ck.get("httponly"):
            findings.append(WebFinding(
                "high" if any(x in name.lower() for x in ("sess", "auth", "token", "jwt", "sid")) else "medium",
                "cookies", f"Cookie '{name}' missing HttpOnly",
                "JavaScript can read this cookie if XSS exists (session theft risk).",
                "Set HttpOnly on session cookies so document.cookie cannot access them.",
                evidence=name, cwe="CWE-1004", confidence="high",
            ))
        if not ck.get("samesite"):
            findings.append(WebFinding(
                "medium", "cookies", f"Cookie '{name}' missing SameSite",
                "Without SameSite, cookies may be sent on cross-site requests (CSRF risk).",
                "Set SameSite=Lax or Strict (and CSRF tokens for state-changing requests).",
                evidence=name, cwe="CWE-352", confidence="high",
            ))

    def record(method: str, req_url: str, resp: httpx.Response) -> dict:
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        set_cookies: list[str] = []
        try:
            set_cookies = list(resp.headers.get_list("set-cookie"))  # type: ignore
        except Exception:
            # httpx: multiple may be combined incorrectly; prefer raw multi-header
            if resp.headers.get("set-cookie"):
                set_cookies = [resp.headers["set-cookie"]]
        https = urlparse(str(resp.url)).scheme == "https"
        for ck in _parse_set_cookie_headers(set_cookies):
            # keep strongest flags if same name seen twice
            prev = cookies_map.get(ck["name"])
            if prev:
                ck = {
                    **ck,
                    "secure": bool(prev.get("secure") or ck.get("secure")),
                    "httponly": bool(prev.get("httponly") or ck.get("httponly")),
                    "samesite": ck.get("samesite") or prev.get("samesite"),
                }
            cookies_map[ck["name"]] = ck
            add_cookie_findings(ck, https)
        entry = {
            "method": method,
            "url": str(resp.url),
            "status": resp.status_code,
            "content_type": hdrs.get("content-type", ""),
            "bytes": len(resp.content),
            "set_cookie_count": len(set_cookies),
            "redirect_chain": list(getattr(resp, "_tk_redirects", []) or []),
        }
        network.append(entry)
        return entry

    ua = {"User-Agent": "TriageKit-SecurityAdviser/4.0 (+authorized assessment)"}
    try:
        with httpx.Client(follow_redirects=True, timeout=timeout, headers=ua, verify=True) as client:
            # Baseline 404 for soft-404 detection
            if active:
                try:
                    token = uuid.uuid4().hex[:12]
                    r404 = client.get(urljoin(_normalize_url(url).rstrip("/") + "/", f"triagekit-notfound-{token}"))
                    record("GET", str(r404.url), r404)
                    body_404_hash = hashlib.sha256((r404.content or b"")[:50_000]).hexdigest()
                except Exception:
                    pass

            try:
                root = client.get(url)
            except (httpx.ConnectError, httpx.ConnectTimeout) as e:
                # Neither of these is a property of the site: no request ever
                # completed, so the finding below reports the attempt and
                # compute_score marks the run NOT ASSESSED (defect D84).
                findings.append(WebFinding("high", "availability", "Connection failed", str(e)[:240], "Verify DNS/TLS and allowlisting.", cwe="CWE-754", confidence="high"))
                result.findings = findings
                result.compute_score()
                return result

            record("GET", url, root)
            # Redirect chain from history
            try:
                chain = [str(u) for u in root.history] + [str(root.url)]
                if len(chain) > 1:
                    network[-1]["redirect_chain"] = chain
                    findings.append(WebFinding(
                        "low", "redirect", "Redirect chain observed",
                        " → ".join(chain[:8]),
                        "Ensure redirects terminate on HTTPS and do not bounce through untrusted hosts.",
                        confidence="high",
                    ))
                    # mixed redirect http->https is ok; https->http is bad
                    for u in chain:
                        if u.startswith("http://"):
                            findings.append(WebFinding(
                                "high", "transport", "HTTP hop in redirect chain",
                                u,
                                "Remove cleartext HTTP hops; redirect to HTTPS only.",
                                cwe="CWE-319", confidence="high", evidence=u,
                            ))
                            break
            except Exception:
                pass
            # OS recon
            try:
                findings.extend(_recon_host(urlparse(str(root.url)).hostname or ""))
            except Exception:
                pass
            result.status_code = root.status_code
            result.final_url = str(root.url)
            base = f"{urlparse(str(root.url)).scheme}://{urlparse(str(root.url)).netloc}"
            hdrs = {k.lower(): v for k, v in root.headers.items()}
            result.headers_sample = {k: hdrs[k] for k in list(hdrs)[:30]}
            body = root.text or ""

            # --- Transport / headers ---
            if urlparse(str(root.url)).scheme != "https":
                findings.append(WebFinding("critical", "transport", "Site not on HTTPS", f"Final URL {root.url}", "Terminate TLS and redirect all HTTP to HTTPS.", cwe="CWE-319", confidence="high", endpoint="/"))
            for hk, (title, sev, cwe, rec) in SECURITY_HEADERS.items():
                if hk == "x-xss-protection":
                    continue
                if hk not in hdrs or not str(hdrs[hk]).strip():
                    findings.append(WebFinding(sev, "headers", f"Missing security header: {title}", f"Home response lacks {title}.", rec, cwe=cwe, confidence="high", endpoint="/"))
            # CSP weak
            csp = hdrs.get("content-security-policy", "")
            if csp and ("unsafe-inline" in csp or "unsafe-eval" in csp):
                findings.append(WebFinding("medium", "headers", "CSP allows unsafe-inline/eval", csp[:160], "Remove 'unsafe-inline' and 'unsafe-eval'; use nonces/hashes.", cwe="CWE-79", confidence="high", endpoint="/"))
            for h in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
                if h in hdrs:
                    findings.append(WebFinding("low", "disclosure", f"Technology disclosure via {h}", hdrs[h], "Remove or genericize version banners.", evidence=hdrs[h][:80], cwe="CWE-200", confidence="high"))
            acao = hdrs.get("access-control-allow-origin", "")
            acac = (hdrs.get("access-control-allow-credentials") or "").lower()
            if acao == "*":
                findings.append(WebFinding("medium", "cors", "CORS reflects wildcard origin", "ACAO is *.", "Reflect only trusted origins.", cwe="CWE-942", confidence="high"))
            if acao == "*" and acac == "true":
                findings.append(WebFinding("high", "cors", "CORS wildcard + credentials", "Invalid/dangerous CORS combination.", "Never combine ACAO * with credentials.", cwe="CWE-942", confidence="high"))

            # --- HTML ---
            analyzer = _HTMLAnalyzer()
            try:
                analyzer.feed(body)
            except Exception:
                pass

            for fm in analyzer.forms:
                action = urljoin(str(root.url), fm.get("action") or "")
                item = {
                    "action": action,
                    "method": fm.get("method") or "GET",
                    "inputs": fm.get("inputs") or [],
                    "has_csrf": bool(fm.get("has_csrf")),
                }
                _add_form(item)
                path = urlparse(action).path or "/"
                if any("password" in (x or "").lower() for x in item["inputs"]):
                    if urlparse(action).scheme == "http":
                        findings.append(WebFinding("critical", "forms", "Password form over HTTP", action, "Serve auth forms only on HTTPS.", endpoint=path, cwe="CWE-319", confidence="high"))
                    if item["method"] == "GET":
                        findings.append(WebFinding("high", "forms", "Password form uses GET", action, "Use POST for credentials so they are not logged in URLs.", endpoint=path, cwe="CWE-598", confidence="high"))
                if item["method"] in ("POST", "PUT", "PATCH", "DELETE") and not item["has_csrf"]:
                    findings.append(WebFinding(
                        "medium", "csrf", "State-changing form without obvious CSRF token",
                        f"{item['method']} {action} inputs={item['inputs'][:8]}",
                        "Add anti-CSRF tokens synchronized with session; validate server-side.",
                        endpoint=path, cwe="CWE-352", confidence="low",
                    ))

            for c in analyzer.comments:
                if re.search(r"(?i)(password|api[_-]?key|secret|todo:|fixme|credentials|bearer )", c):
                    findings.append(WebFinding("medium", "html", "Sensitive HTML comment", c[:160], "Strip debug/secret comments from production HTML.", evidence=c[:120], cwe="CWE-615", confidence="medium"))

            for link in analyzer.links:
                if link.startswith("__sri_missing__:"):
                    src = link.split(":", 1)[-1]
                    if src.startswith("http") and not _same_host(base, src):
                        findings.append(WebFinding(
                            "medium", "supply-chain", "Third-party script without SRI",
                            src, "Add integrity= and crossorigin= on third-party scripts.",
                            evidence=src, cwe="CWE-353", confidence="medium",
                        ))

            for inline in analyzer.inline_scripts:
                _analyze_js(inline, str(root.url) + "#inline", findings, api_hints)

            # --- Discovery seeds ---
            paths: list[tuple[str, str]] = [("/", "root")]
            js_urls: list[str] = []
            for src in analyzer.scripts:
                abs_js = urljoin(str(root.url), src)
                if abs_js not in js_urls:
                    js_urls.append(abs_js)
            for href in analyzer.links:
                if href.startswith("__sri"):
                    continue
                abs_u = urljoin(str(root.url), href)
                if _same_host(base, abs_u):
                    paths.append((urlparse(abs_u).path or "/", "html"))

            # robots / sitemap
            try:
                rob = client.get(urljoin(base + "/", "robots.txt"))
                record("GET", str(rob.url), rob)
                if rob.status_code == 200:
                    for line in (rob.text or "").splitlines():
                        s = line.strip()
                        low = s.lower()
                        if low.startswith(("disallow:", "allow:")):
                            part = s.split(":", 1)[-1].strip()
                            if part and part != "/":
                                paths.append((part, "robots"))
                        if low.startswith("sitemap:"):
                            smu = s.split(":", 1)[-1].strip()
                            if smu.startswith("http"):
                                try:
                                    sm = client.get(smu)
                                    record("GET", smu, sm)
                                    for m in re.findall(r"<loc>\s*([^<]+)\s*</loc>", sm.text or "", re.I):
                                        if _same_host(base, m):
                                            paths.append((urlparse(m).path or "/", "sitemap"))
                                except Exception:
                                    pass
            except Exception:
                pass

            # crawl
            if crawl:
                q: deque[str] = deque([str(root.url)])
                seen = {str(root.url)}
                n = 0
                while q and n < max_crawl_pages:
                    page = q.popleft()
                    n += 1
                    try:
                        pr = client.get(page)
                        record("GET", page, pr)
                    except Exception:
                        continue
                    pa = _HTMLAnalyzer()
                    try:
                        pa.feed(pr.text or "")
                    except Exception:
                        pass
                    for src in pa.scripts:
                        u = urljoin(page, src)
                        if u not in js_urls:
                            js_urls.append(u)
                    for fm in pa.forms:
                        _add_form({
                            "action": urljoin(page, fm.get("action") or ""),
                            "method": fm.get("method") or "GET",
                            "inputs": fm.get("inputs") or [],
                            "has_csrf": bool(fm.get("has_csrf")),
                        })
                    for href in pa.links:
                        if href.startswith("__sri"):
                            continue
                        abs_u = urljoin(page, href)
                        if not _same_host(base, abs_u):
                            continue
                        paths.append((urlparse(abs_u).path or "/", "crawl"))
                        if abs_u not in seen and not re.search(
                            r"\.(css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|zip|pdf)(\?|$)", abs_u, re.I
                        ):
                            seen.add(abs_u)
                            q.append(abs_u)

            early_tech = _fingerprint(hdrs, body, [p for p, _ in paths[:40]])
            if check_sensitive_paths:
                for p in SENSITIVE_PATHS:
                    paths.append((p, "sensitive"))
                # backup guesses on home path
                for suf in BACKUP_SUFFIXES:
                    paths.append((f"/index.php{suf}", "backup"))
                    paths.append((f"/index.html{suf}", "backup"))
                tech_l = " ".join(early_tech).lower()
                for sk, plist in STACK_PATHS.items():
                    if sk in tech_l:
                        for p in plist:
                            paths.append((p, f"stack:{sk}"))

            # JS fetch + analyze
            for js_url in js_urls[:max_js_files]:
                try:
                    jr = client.get(js_url)
                    record("GET", js_url, jr)
                    if jr.status_code != 200 or len(jr.content) > max_js_bytes:
                        continue
                    text = jr.text or ""
                    sigs = _analyze_js(text, str(jr.url), findings, api_hints)
                    js_files.append({"url": str(jr.url), "bytes": len(jr.content), "findings": sigs})
                    for h in api_hints[-40:]:
                        if h.startswith("/"):
                            paths.append((urlparse(h).path or h, "js"))
                        elif h.startswith("http") and _same_host(base, h):
                            paths.append((urlparse(h).path or "/", "js"))
                except Exception:
                    continue

            # Unique path probe
            seen_p = set()
            ordered: list[tuple[str, str]] = []
            for path, src in paths:
                path = (path or "/").split("#")[0]
                if not path.startswith("/"):
                    path = "/" + path
                key = path.rstrip("/") or "/"
                if key in seen_p:
                    continue
                seen_p.add(key)
                ordered.append((path, src))
                if len(ordered) >= max_paths:
                    break

            for path, src in ordered:
                full = urljoin(base + "/", path.lstrip("/"))
                try:
                    pr = client.get(full, timeout=8.0)
                    record("GET", full, pr)
                except Exception:
                    continue
                content = pr.content or b""
                sample = (pr.text or "")[:3000]
                soft404 = False
                if body_404_hash and pr.status_code == 200:
                    hsh = hashlib.sha256(content[:50_000]).hexdigest()
                    if hsh == body_404_hash:
                        soft404 = True
                discovered[path] = {
                    "method": "GET", "path": path, "status": pr.status_code,
                    "source": src, "content_type": pr.headers.get("content-type"),
                }
                if soft404:
                    continue

                interesting_status = pr.status_code in (200, 401, 403, 500)
                if pr.status_code == 200 and any(
                    s in path.lower() for s in (
                        ".env", ".git", "backup", "phpinfo", "actuator", "heapdump",
                        "debug.log", "swagger", "openapi", "wp/v2/users", "id_rsa",
                        "composer.json", "package.json", "application.properties",
                    )
                ):
                    sev = "critical" if any(x in path.lower() for x in (".env", ".git", "heapdump", "backup", "id_rsa")) else "high"
                    findings.append(WebFinding(
                        sev, "exposure", f"Sensitive path accessible: {path}",
                        f"HTTP {pr.status_code}, size={len(content)}, source={src}",
                        "Block via server/WAF; rotate any credentials that may have leaked; audit access logs.",
                        evidence=sample[:120].replace("\n", " "), endpoint=path,
                        cwe="CWE-200", confidence="high",
                    ))
                for pat, sev, cwe, title in LEAK_BODY:
                    if re.search(pat, sample):
                        findings.append(WebFinding(
                            sev, "leak", title,
                            f"Pattern in response body of {path}",
                            "Remove secrets and verbose errors from client-visible responses; use generic error pages.",
                            endpoint=path, cwe=cwe, confidence="medium",
                        ))
                if pr.status_code == 200 and re.search(r"(?i)<title>index of|parent directory", sample):
                    findings.append(WebFinding("high", "exposure", f"Directory listing: {path}", "Autoindex-like response.", "Disable directory listing.", endpoint=path, cwe="CWE-548", confidence="medium"))
                if "graphql" in path.lower() and pr.status_code == 200:
                    findings.append(WebFinding("medium", "api", f"GraphQL endpoint exposed: {path}", "GraphQL HTTP 200.", "Disable introspection in production; require auth; limit query depth/cost.", endpoint=path, cwe="CWE-200", confidence="medium"))
                if "wp/v2/users" in path.lower() and pr.status_code == 200 and re.search(r"slug|name", sample):
                    findings.append(WebFinding("high", "wordpress", "WordPress user enumeration", path, "Disable public users REST endpoint or require auth.", endpoint=path, cwe="CWE-200", confidence="high"))
                if "actuator" in path.lower() and pr.status_code == 200:
                    sev = "critical" if any(x in path for x in ("env", "heapdump")) else "high"
                    findings.append(WebFinding(sev, "spring", f"Spring Actuator exposed: {path}", "Actuator returned 200.", "Protect actuator with auth + network policy; disable sensitive endpoints.", endpoint=path, cwe="CWE-200", confidence="high"))

            # --- Safe active checks ---
            canary = f"tk{uuid.uuid4().hex[:10]}"
            if active:
                # Reflection check on home with query params commonly used in XSS
                for param in ("q", "search", "s", "query", "keyword", "id", "page", "redirect", "url", "next", "return", "callback", "goto", "file", "path", "template", "lang"):
                    try:
                        parsed = urlparse(str(root.url))
                        q = dict(parse_qsl(parsed.query, keep_blank_values=True))
                        q[param] = canary
                        test_url = urlunparse(parsed._replace(query=urlencode(q)))
                        tr = client.get(test_url, timeout=8.0)
                        record("GET", test_url, tr)
                        if canary in (tr.text or ""):
                            findings.append(WebFinding(
                                "medium", "reflection", f"User input reflected via ?{param}=",
                                f"Canary reflected in response body for parameter '{param}'.",
                                "Contextual-encode all reflected input; apply CSP; avoid reflecting unsanitized params into HTML/JS.",
                                endpoint=parsed.path or "/", cwe="CWE-79", confidence="medium",
                                evidence=f"param={param}",
                            ))
                        # open redirect heuristic: redirect param to external without validation
                        if param in ("redirect", "url", "next", "return") and tr.status_code in (301, 302, 303, 307, 308):
                            loc = tr.headers.get("location", "")
                            if canary in loc:
                                findings.append(WebFinding(
                                    "high", "redirect", f"Possible open redirect via ?{param}=",
                                    f"Location header echoes canary for '{param}'.",
                                    "Allowlist redirect targets; never redirect to raw user input.",
                                    cwe="CWE-601", confidence="medium", evidence=loc[:120],
                                ))
                    except Exception:
                        continue


                # Deeper safe probes (passive markers only).
                #
                # The matrix is aimed at every endpoint that can receive a
                # query parameter, not just the root: a page whose form targets
                # /search?q= gets no probe at all when / itself reflects
                # nothing, which is the ordinary case, so the deep probes used
                # to miss essentially every real defect.  Per-parameter
                # measurements are collected first and folded afterwards, so one
                # echoing endpoint still costs one line per defect (D4).
                probe_params = ["q", "search", "s", "query", "id", "file", "path", "template", "name", "message"]
                for fm in forms[:8]:
                    for inp in (fm.get("inputs") or [])[:6]:
                        n = (inp.split(":")[0] if ":" in inp else inp).strip()
                        if n and n not in probe_params and n.lower() not in ("submit", "password", "csrf", "_token"):
                            probe_params.append(n)
                probe_params = probe_params[:10]

                # Same-host endpoints that can receive a query parameter.
                #
                # This list used to be the root plus the action of every form.
                # On a client-rendered SPA there are no <form> elements at all
                # (Juice Shop reports forms=0), so the list collapsed to exactly
                # one URL -- the homepage, which returns the same shell for any
                # query string -- and the deep probes found nothing.  Every
                # endpoint the target's own JavaScript named was sitting in the
                # report's "API hints" section while the probe layer fired its
                # whole matrix at "/".
                #
                # Now the crawled endpoints and the JS-extracted hints are
                # candidates too, same-host filtered, ranked so that endpoints
                # which already carry a query string come first: a URL the
                # target built with "?q=" is the target telling us it accepts a
                # parameter, which is precisely what the probe matrix needs.
                probe_targets: list[str] = [str(root.url)]

                def _add_probe_target(cand: str) -> None:
                    if not cand:
                        return
                    try:
                        u = urljoin(str(root.url), cand)
                    except Exception:
                        return
                    if _same_host(base, u) and u not in probe_targets:
                        probe_targets.append(u)

                # A form action is the strongest signal there is, so it stays first.
                for fm in forms[:12]:
                    _add_probe_target(fm.get("action") or "")
                # Endpoints discovered by crawling the target's own links.
                for path in list(discovered.keys())[:80]:
                    _add_probe_target(path)
                # Endpoints the target's own JavaScript referenced.
                for hint in api_hints[:80]:
                    _add_probe_target(hint)

                # Partition, do not sort: this keeps the ordering deterministic
                # (a sorted() on equal keys would still be stable, but an
                # explicit partition is obvious about intent) while moving the
                # endpoints that demonstrably accept a parameter to the front.
                _with_q = [u for u in probe_targets if "?" in u]
                _no_q = [u for u in probe_targets if "?" not in u]
                probe_targets = _with_q + _no_q

                probe_signals: list[dict] = []
                for target_url in probe_targets[:6]:
                    try:
                        br = client.get(target_url, timeout=8.0)
                        record("GET", target_url, br)
                        baseline = {
                            "len": len(br.content or b""),
                            "status": br.status_code,
                            "body": br.text or "",
                        }
                    except Exception:
                        continue
                    for param in probe_params:
                        try:
                            probe_signals.extend(_probe_parameter(
                                client, target_url, param, canary.replace("tk", ""),
                                record, baseline, timeout=timeout,
                            ))
                        except Exception:
                            continue

                # JSON-body probe, over its own ranked candidate list rather than
                # the GET matrix's first six.  It wants the credential routes; the
                # matrix wants the query-carrying ones, and spending both probes'
                # budget on the same six URLs is what left the login endpoint
                # unrequested.  Relative paths are resolved against the root so a
                # directly-scanned API route is always among its own candidates.
                json_targets = _json_probe_candidates(
                    [urljoin(str(root.url), t) for t in probe_targets], limit=3
                )
                for target_url in json_targets:
                    try:
                        pb = client.post(
                            target_url,
                            json={_JSON_PROBE_FIELDS[0]: ""},
                            timeout=8.0,
                        )
                        record("POST", target_url, pb)
                        pbaseline = {
                            "len": len(pb.content or b""),
                            "status": pb.status_code,
                            "body": pb.text or "",
                        }
                    except Exception:
                        pbaseline = None
                    if pbaseline is None:
                        continue
                    for field in _JSON_PROBE_FIELDS[:6]:
                        try:
                            probe_signals.extend(_probe_json_parameter(
                                client, target_url, field,
                                canary.replace("tk", ""), record,
                                pbaseline, timeout=8.0,
                            ))
                        except Exception:
                            continue
                    # One confirmed bypass on one endpoint is the finding.  The
                    # remaining candidates are the same class on the same target,
                    # so probing them adds requests to somebody else's server and
                    # nothing to the report.
                    if any(s.get("outcome") == "auth_bypass" for s in probe_signals):
                        break
                findings.extend(_fold_probe_signals(probe_signals))

                # OPTIONS on origin
                try:
                    opt = client.request("OPTIONS", base)
                    record("OPTIONS", base, opt)
                    allow = opt.headers.get("allow") or opt.headers.get("access-control-allow-methods") or ""
                    if allow:
                        findings.append(WebFinding(
                            "low", "methods", "HTTP methods advertised",
                            allow, "Disable unused methods (TRACE/TRACK); restrict CORS methods.",
                            cwe="CWE-749", confidence="medium", evidence=allow[:120],
                        ))
                        if re.search(r"TRACE|TRACK", allow, re.I):
                            findings.append(WebFinding(
                                "medium", "methods", "TRACE/TRACK enabled",
                                allow, "Disable TRACE/TRACK on the edge server.",
                                cwe="CWE-693", confidence="medium",
                            ))
                except Exception:
                    pass

            
            # Form-driven injection points (map only — safe canary on GET forms)
            for fm in forms[:12]:
                action = fm.get("action") or str(root.url)
                if not _same_host(base, action) and not action.startswith("/"):
                    continue
                method = (fm.get("method") or "GET").upper()
                inputs = fm.get("inputs") or []
                params = []
                for inp in inputs:
                    name = (inp.split(":")[0] if ":" in inp else inp).strip()
                    if name and name not in ("submit", "button"):
                        params.append(name)
                if not params:
                    continue
                findings.append(WebFinding(
                    "low", "injection-surface", "Input surface mapped from form",
                    f"{method} {action} fields={params[:12]}",
                    "Validate/encode every field server-side; use parameterized queries and CSRF tokens for state changes.",
                    endpoint=urlparse(urljoin(str(root.url), action)).path,
                    cwe="CWE-20", confidence="high",
                ))
                if method == "GET" and active:
                    try:
                        parsed = urlparse(urljoin(str(root.url), action))
                        q = dict(parse_qsl(parsed.query, keep_blank_values=True))
                        for name in params[:4]:
                            q[name] = canary
                        test_url = urlunparse(parsed._replace(query=urlencode(q)))
                        tr = client.get(test_url, timeout=8.0)
                        record("GET", test_url, tr)
                        if canary in (tr.text or ""):
                            findings.append(WebFinding(
                                "medium", "reflection", f"Form field reflected: {name}",
                                f"Canary from form field '{name}' reflected at {action}",
                                "Contextually encode output; never embed raw input into HTML/JS/SQL.",
                                endpoint=parsed.path or "/", cwe="CWE-79", confidence="medium",
                                evidence=f"field={name}",
                            ))
                    except Exception:
                        pass

            result.technologies = _fingerprint(hdrs, body, list(discovered.keys()))
            tech_l = " ".join(result.technologies).lower()
            if "wordpress" in tech_l:
                findings.append(WebFinding("low", "wordpress", "WordPress detected", "Stack fingerprint.", "Keep core/plugins updated; harden wp-admin; limit REST enumeration.", cwe="CWE-1104", confidence="medium"))
            if "spring" in tech_l:
                findings.append(WebFinding("low", "spring", "Spring detected", "Stack fingerprint.", "Lock down Actuator; review Spring Security configuration.", cwe="CWE-16", confidence="medium"))

    except httpx.TimeoutException:
        findings.append(WebFinding("medium", "availability", "Timeout", url, "Increase timeout or check WAF rate limits.", confidence="high"))
    except Exception as e:
        findings.append(WebFinding("high", "scanner", "Scan error", str(e)[:300], "Verify URL/network.", confidence="high"))

    seen = set()
    uniq = []
    for f in findings:
        key = (f.title, f.endpoint or "", f.severity)
        if key not in seen:
            seen.add(key)
            uniq.append(f)

    result.findings = uniq
    result.network = network[:250]
    result.cookies = list(cookies_map.values())
    result.forms = forms[:50]
    result.js_files = js_files
    result.api_hints = list(dict.fromkeys(api_hints))[:100]
    result.endpoints = sorted(
        [{"method": "GET", "path": v["path"], "status": v["status"], "source": v.get("source")}
         for v in discovered.values()],
        key=lambda x: x["path"],
    )[:250]
    try:
        from .exploitdb import lookup_advisories
        result.advisories = lookup_advisories(result.technologies or [])
    except Exception:
        result.advisories = []
    try:
        from .exploit_relevance import analyze_exploit_relevance
        result.relevance = analyze_exploit_relevance(
            list(result.technologies or []),
            list(result.findings or []),
            use_llm=True,
            fetch_edb_pages=True,
        )
    except Exception:
        result.relevance = []
    result.compute_score()
    return result
