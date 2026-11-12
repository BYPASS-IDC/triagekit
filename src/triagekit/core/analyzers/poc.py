"""Defensive exploit/PoC generation for TriageKit findings.

WHAT THIS MODULE IS FOR
-----------------------
A finding that says "SQL injection, CWE-89" tells a reader WHAT is wrong.  It
does not tell them how the attacker gets in, which is the only thing that makes a
severity rating defensible, and it does not tell them how to prove the fix
worked.  This module closes both gaps: for each defect class it produces a
mechanism narrative, a safe proof-of-concept, the impact, the fix, and a
verification step.

WHAT THIS MODULE IS NOT
-----------------------
It does not generate weaponized exploits.  Every PoC here is a *detection* PoC:
a marker that proves a defect exists and shows how it is reached, not a payload
that exfiltrates data, executes arbitrary code, or causes damage.  The reason is
not squeamishness -- it is that this output is handed to third parties helping
clients FIX issues, and a report that could itself be used as an attack toolkit
would be unusable in exactly the engagements that need it most.  Anything that
requires real exploitation is left as a described next step for an authorised
engagement, with the authorisation scope stated.

Every PoC is tied to a specific finding -- a category from the scanner, plus the
CWE it reported -- so nothing is generated speculatively for code that was not
observed to be vulnerable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

__all__ = [
    "PoC",
    "poc_for",
    "pocs_for_findings",
    "poc_markdown",
    "has_poc",
]


# ---------------------------------------------------------------------------
# The output shape
# ---------------------------------------------------------------------------

@dataclass
class PoC:
    """One defensive proof-of-concept for one finding.

    ``confidence`` states how much of this is measured rather than inferred:
    a class-level PoC says "this defect class works like this"; a finding-level
    one says "and here is the evidence your own scan produced".
    """

    category: str
    cwe: str
    title: str
    # How the defect is reached, in the order an attacker would take.
    mechanism: list[str]
    # A safe reproduction: what to send/run, and what proves the defect.
    poc_request: str
    poc_expected: str
    # What the attacker gets out of it.
    impact: list[str]
    # The fix, most decisive first.
    remediation: list[str]
    # How to prove the fix worked -- a PoC that cannot be falsified is theatre.
    verification: list[str]
    severity: str = "high"
    requires_authorisation: bool = True
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "cwe": self.cwe,
            "title": self.title,
            "severity": self.severity,
            "mechanism": list(self.mechanism),
            "poc_request": self.poc_request,
            "poc_expected": self.poc_expected,
            "impact": list(self.impact),
            "remediation": list(self.remediation),
            "verification": list(self.verification),
            "requires_authorisation": self.requires_authorisation,
            "notes": list(self.notes),
        }


# ---------------------------------------------------------------------------
# The defect-class table
# ---------------------------------------------------------------------------

def _template_injection_poc() -> "PoC":
    """SSTI: evaluation of template syntax the attacker controls."""
    return PoC(
        category="template-injection",
        cwe="CWE-1336",
        title="Server-Side Template Injection",
        severity="critical",
        mechanism=[
            "The application renders a string that the attacker controls as a TEMPLATE,"
            " rather than as a VALUE.  Rendering a string evaluates any expression in it,"
            " so {{7*7}} becomes 49 and {{...}} becomes whatever the expression returns.",
            "Start with a harmless arithmetic probe: if {{7*7}} returns 49 the template"
            " engine is evaluating input, which is the whole vulnerability.",
            "Escalate by walking the object graph from the template context outward:"
            " Jinja2 reaches the template globals, then the request object, then the"
            " interpreter's own module/class helpers that read files or spawn processes.",
            "Reaching those helpers converts a reflected-expression bug into file read"
            " and, on most stacks, into arbitrary code execution.",
        ],
        poc_request=(
            "Benign evaluation probe, safe against any target:\n"
            "  GET /search?q={{7*7}}\n"
            "Expect the response to contain 49.\n"
            "\n"
            "Detection only -- no payload is sent that touches the filesystem or spawns"
            " a process."
        ),
        poc_expected="The literal marker '{{7*7}}' does not appear; '49' does.",
        impact=[
            "Read of arbitrary files reachable by the server process (configuration,"
            " credentials, source).",
            "On stacks where the template context exposes import/module helpers,"
            " arbitrary code execution as the application user.",
            "Full compromise of the application tier, typically without any credential.",
        ],
        remediation=[
            "Never pass user input to a template engine as the template SOURCE.  Render"
            " data as a value: render_template('page.html', name=user_input), not"
            " render_template_string(user_input) or Template(user_input).",
            "If a template must be built at runtime, use a logic-less engine renderer on a"
            " strict allowlist of field names, never on free-form input.",
            "Run the application as an unprivileged user with a read-only filesystem and no"
            " network egress, so reaching an import helper does not yield code execution.",
        ],
        verification=[
            "Re-send the {{7*7}} probe: the response must contain the literal '{{7*7}}'."
            " A 49 anywhere in the body means the fix did not take.",
            "Run the same probe through the scanner: the probe-ssti finding for this"
            " endpoint must be gone.",
        ],
        notes=[
            "A marker reflected VERBATIM (the literal {{7*7}} visible in the page) is"
            " reflection, not evaluation -- it is a lower-severity finding and the two"
            " must not be conflated in the report.",
        ],
    )


def _sql_injection_poc() -> "PoC":
    return PoC(
        category="sql-injection",
        cwe="CWE-89",
        title="SQL Injection",
        severity="critical",
        mechanism=[
            "User input is concatenated into a SQL statement, so it changes the statement's"
            " grammar rather than only its data.  A quote closes the string literal early,"
            " and the rest of the input is parsed as SQL.",
            "Confirm with a quote: a syntax error, a stack trace, or an empty result set"
            " where a row is expected shows the input reached the parser.",
            "Confirm control with a tautology (OR 1=1) or with a UNION whose column count"
            " is walked until the shape matches -- that is the point the query becomes a"
            " read primitive for another table.",
            "Time-based confirmation avoids the need for any visible error.",
        ],
        poc_request=(
            "Quote probe (safe, changes no data):\n"
            "  GET /search?q='\n"
            "  GET /search?q=abc'\n"
            "Compare with a normal request: an error, a traceback, or a 500 shows the input"
            " reached the SQL parser.\n"
            "\n"
            "Tautology probe (safe, read-only):\n"
            "  GET /search?q=' OR '1'='1\n"
            "If the result set grows to include rows that the term should not match, the"
            " injection controls the WHERE clause."
        ),
        poc_expected="A DB error signature, a status change to 5xx, or a result set that differs from the term's true matches.",
        impact=[
            "Read of every table the application's database user can reach, including"
            " credentials and other tenants' data.",
            "With a write-capable statement and no parameter binding, INSERT/UPDATE/DELETE"
            " on the same tables.",
            "On stacks with stacked queries or INTO OUTFILE, file write and code execution.",
        ],
        remediation=[
            "Use parameterized queries / prepared statements for every statement that"
            " includes user input.  Never build SQL with string concatenation, f-strings,"
            " '%s' substitution, or an ORM's raw-string escape hatch.",
            "Where SQL fragments must be dynamic (ORDER BY, IN lists), map them through a"
            " strict allowlist of literal values -- identifiers cannot be parameterized.",
            "Run the application's DB user with the least privilege that still serves the"
            " feature: no DDL, no FILE privilege, read-only where possible.",
        ],
        verification=[
            "Re-send the quote and tautology probes: the response must be identical to the"
            " baseline.  Any new error text or changed result set means injection remains.",
            "Grep the codebase for concatenated SQL (the repo scanner's sql-injection rule"
            " covers f-string, %, and .format shapes) and confirm each hit is either"
            " parameterized or allowlisted.",
        ],
    )


def _command_injection_poc() -> "PoC":
    return PoC(
        category="command-injection",
        cwe="CWE-78",
        title="OS Command Injection",
        severity="critical",
        mechanism=[
            "Input reaches an OS command.  If it is passed through a shell, shell"
            " metacharacters (; | && ` $()) start new commands the developer never wrote.",
            "A separator-only probe (a trailing semicolon or pipe) is enough to confirm"
            " reachability: a shell error message appears where the input was echoed.",
            "Once confirmed, the command's output is usually returned to the attacker, so"
            " the injection is both an execution primitive and an oracle.",
            "An argument list (subprocess.run with a list) blocks the whole class because"
            " no shell parses the string.",
        ],
        poc_request=(
            "Separator probe (no command is executed by this probe; only the error shape"
            " is observed):\n"
            "  GET /cmd?c=echo;\n"
            "  GET /cmd?c=echo|\n"
            "A shell diagnostic (sh:, bash:, not recognized) in the response shows the input"
            " reached a shell.\n"
            "\n"
            "Detection only.  Do not send commands that read credentials or modify state."
        ),
        poc_expected="Shell-like error text appears in the response when a separator is appended.",
        impact=[
            "Arbitrary command execution as the server process user.",
            "Read of every file and environment variable that user can read, including"
            " credentials held in the environment.",
            "Lateral movement and persistence on the host.",
        ],
        remediation=[
            "Never pass user input to a shell.  Use an argument list and no interpreter:"
            " subprocess.run([\"convert\", filename]) -- not subprocess.run(f\"convert"
            " {filename}\", shell=True).",
            "If a shell is genuinely required, quote every interpolated value with"
            " shlex.quote and validate it against an allowlist first.",
            "Prefer library APIs over subprocesses entirely (e.g. PIL for image work),"
            " which removes the sink rather than guarding it.",
        ],
        verification=[
            "Re-send the separator probe: no shell diagnostic may appear.",
            "Search the codebase for shell=True and for os.system/popen and confirm every"
            " remaining call passes an argument list.",
        ],
    )


def _xss_poc(family: str = "reflected") -> "PoC":
    if family == "dom":
        return PoC(
            category="xss-dom",
            cwe="CWE-79",
            title="DOM-based Cross-Site Scripting",
            severity="high",
            mechanism=[
                "The page reads attacker-controllable data from the DOM -- location.hash,"
                " location.search, document.referrer -- and writes it into an HTML sink"
                " such as innerHTML, document.write, or an element attribute.",
                "No server round-trip is needed, so server-side filtering does not apply"
                " and the payload lives entirely in the URL fragment or query string.",
                "document.write and innerHTML both parse their input as HTML, so a"
                " <script> or onerror attribute in the fragment executes.",
                "The executed script runs in the victim's authenticated session on the"
                " origin, which is what makes it a session-compromise bug.",
            ],
            poc_request=(
                "Marker probe (defensive, no exfiltration):\n"
                "  http://target/#<img src=x onerror=alert(1)>\n"
                "  http://target/?q=<script>alert(1)</script>\n"
                "A harmless dialog or a created element proves the sink parsed HTML."
            ),
            poc_expected="The injected element executes in the page instead of rendering as literal text.",
            impact=[
                "Theft of session cookies and tokens for the origin, when they are not"
                " HttpOnly.",
                "Actions performed in the victim's authenticated session without their"
                " knowledge.",
                "Credential harvesting via an injected overlay on a real page.",
            ],
            remediation=[
                "Never write DOM-derived data into an HTML sink.  Use textContent or"
                " innerText, which do not parse markup.",
                "Where HTML must be inserted, sanitize with a maintained library"
                " (DOMPurify) on the way in, and encode contextually on the way out.",
                "Set cookies HttpOnly and SameSite, and add a CSP that disallows inline"
                " script -- both limit what an injected payload can do.",
            ],
            verification=[
                "Re-load the page with the marker in the fragment: nothing must execute."
                " The literal text may render as text; that is the correct behaviour.",
                "Run the scanner against the page: the js-domxss finding must be gone.",
            ],
        )
    return PoC(
        category="xss-eval",
        cwe="CWE-79",
        title="Cross-Site Scripting (reflected)",
        severity="high",
        mechanism=[
            "User input from a request is written into the HTML response without"
            " contextual encoding, so markup in the input is parsed by the browser.",
            "Reflected means the input comes straight from the current request: the"
            " attacker must get the victim to follow a crafted URL.",
            "Context decides the payload shape: inside an attribute, a quote breaks out"
            " into an event handler; inside an element, a tag is enough; inside a"
            " <script> block, the input is already code.",
            "The payload executes with the victim's privileges on this origin.",
        ],
        poc_request=(
            "Marker probe (defensive, no exfiltration):\n"
            "  GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E\n"
            "  GET /search?q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E\n"
            "A harmless dialog proves the response parsed the injected markup."
        ),
        poc_expected="The injected element executes in the page instead of rendering as literal text.",
        impact=[
            "Theft of session cookies and tokens for the origin, when they are not"
            " HttpOnly.",
            "Actions performed in the victim's authenticated session without their"
            " knowledge.",
            "Credential harvesting via an injected overlay on a real page.",
        ],
        remediation=[
            "Encode output contextually: HTML-encode element content, attribute-encode"
            " attribute values, JS-encode script contexts.  One encoder is not enough for"
            " all three.",
            "Prefer a template engine with context-aware autoescaping, so encoding is not"
            " per-developer.",
            "Add a Content-Security-Policy that disallows inline script, and set cookies"
            " HttpOnly and SameSite.",
        ],
        verification=[
            "Re-send the marker: it must render as literal text, not execute.",
            "Run the scanner against the endpoint: the probe-xss and js-domxss findings"
            " must be gone.",
        ],
    )


def _path_traversal_poc() -> "PoC":
    return PoC(
        category="path-traversal",
        cwe="CWE-22",
        title="Path Traversal",
        severity="high",
        mechanism=[
            "A filename is built from user input and used to read or write a file, so"
            " '../' sequences climb out of the intended directory.",
            "A non-existent resource marker shows whether the traversal reached outside"
            " the web root: a 404 from a path that should exist means it climbed.",
            "Encoding variants (%2e%2e%2f, ....//) and null-byte or wrapper tricks bypass"
            " filters that only match the literal '../'.",
            "The reachable set is everything the process user can read.",
        ],
        poc_request=(
            "Traversal probe (safe, non-existent resource):\n"
            "  GET /download?file=....//....//etc/passwd\n"
            "  GET /download?file=..%2f..%2f..%2fetc%2fpasswd\n"
            "Compare status and length with a request for a file that does not exist:"
            " a hit means the traversal succeeded."
        ),
        poc_expected="The response differs from the baseline for a non-existent path, or file contents outside the web root are returned.",
        impact=[
            "Read of any file the process can open: configuration, private keys, source,"
            " /etc/passwd.",
            "Where the path is used for a write, overwrite of application code or"
            " configuration, which is often code execution.",
        ],
        remediation=[
            "Never join user input into a filesystem path.  Map allowed resources through"
            " a dict of identifiers to server-side paths.",
            "Resolve the final path with the real path and confirm it is still inside the"
            " intended root directory; reject anything outside it.",
            "Strip basenames with a real basename call or secure_filename, and run the"
            " process with no access outside its own data directory.",
        ],
        verification=[
            "Re-send both traversal probes: both must behave exactly like a request for a"
            " non-existent file.",
            "Run the scanner: the probe-path finding for this endpoint must be gone.",
        ],
    )


def _ssrf_poc() -> "PoC":
    return PoC(
        category="ssrf",
        cwe="CWE-918",
        title="Server-Side Request Forgery",
        severity="high",
        mechanism=[
            "The server fetches a URL that the attacker supplies, so the request is made"
            " from inside the network with the server's own privileges.",
            "Pointing it at a loopback or link-local address reaches services that are"
            " firewalled from the internet but not from the application host.",
            "Cloud metadata endpoints (169.254.169.254) return instance credentials to"
            " anything on the host that asks, which makes SSRF a direct credential leak",
            "Error text and timing disclose which hosts and ports exist, mapping the"
            " internal network even when the response body is not returned.",
        ],
        poc_request=(
            "Detection probe (targets your own service, not a third party):\n"
            "  GET /fetch?url=http://127.0.0.1:<a port your own service listens on>/\n"
            "  GET /fetch?url=http://169.254.169.254/latest/meta-data/\n"
            "A response that differs from the baseline shows the server made the request."
        ),
        poc_expected="The response reflects content or timing from the requested internal endpoint.",
        impact=[
            "Read of internal services not exposed to the internet, including admin"
            " panels and databases bound to loopback.",
            "Leak of cloud instance credentials via the metadata endpoint, leading to"
            " control of the cloud account.",
            "Port and host discovery of the internal network.",
        ],
        remediation=[
            "Never fetch a caller-supplied URL.  Fetch a caller-supplied IDENTIFIER that"
            " is resolved to a server-side allowlisted URL.",
            "Where a full URL is unavoidable, parse it and require an allowlisted scheme"
            " and host, resolve the host and reject private/loopback/link-local ranges"
            " before connecting, and block redirects to unvalidated hosts.",
            "Run with no route to the metadata service (IMDSv2 with a hop limit, or a"
            " firewall rule), so a bypass is not immediately fatal.",
        ],
        verification=[
            "Re-send the probe: the server must refuse to fetch an address outside the"
            " allowlist, and must not follow a redirect to one.",
            "Run the scanner: the ssrf finding must be gone.",
        ],
    )


def _weak_hash_poc() -> "PoC":
    return PoC(
        category="weak-hash",
        cwe="CWE-327",
        title="Weak hash or cipher",
        severity="high",
        mechanism=[
            "The algorithm is fast and unsalted, so precomputed tables and commodity"
            " hardware reverse the stored value, and identical inputs produce identical"
            " digests.",
            "Breaking one digest does not require attacking the application at all: the"
            " digest is matched against a public table.",
            "Because the algorithm is fast, brute force over the whole candidate space"
            " is measured in hours on a single GPU.",
        ],
        poc_request=(
            "Offline check only, against data you already hold:\n"
            "  Compare a stored digest against a rainbow table or a hashcat run with the"
            "  relevant algorithm.  No request to the application is involved."
        ),
        poc_expected="A candidate plaintext is recovered for the digest in seconds to hours.",
        impact=[
            "Recovery of the original secret from a stored digest.",
            "Credential reuse across accounts, because the recovered value is the"
            " user's actual password.",
            "For integrity uses, forgery of the signed content.",
        ],
        remediation=[
            "For passwords, use a memory-hard password hash (argon2id, scrypt, bcrypt)"
            " with a per-user salt -- never a general-purpose digest.",
            "For integrity and signatures, use SHA-256 or better with HMAC, or an AEAD"
            " construction.",
            "For anything still security-relevant, retire MD5, SHA-1, DES, RC4, and ECB"
            " mode entirely; do not merely add a salt.",
        ],
        verification=[
            "Confirm no MD5/SHA-1/DES/RC4/ECB use remains in the codebase; the scanner's"
            " weak-hash and weak-cipher rules must return nothing.",
            "For passwords, confirm the stored format is a password-hash algorithm with a"
            " per-record salt and a work factor.",
        ],
    )


def _secret_poc() -> "PoC":
    return PoC(
        category="hardcoded-secret",
        cwe="CWE-798",
        title="Hardcoded credential in source",
        severity="critical",
        mechanism=[
            "A credential is embedded in source, so anyone with read access to the"
            " repository has it, and the repository's history keeps it after removal.",
            "The credential works from any network path that accepts it -- it is not"
            " tied to a location or a session.",
            "Removing the line does not remove the credential: it stays in git history,"
            " in forks, and in any build artifact already shipped.",
        ],
        poc_request=(
            "Confirm exposure scope without using the credential:\n"
            "  git log -p -- <file>   # does the value exist in history?\n"
            "  Scan build artifacts and container images for the same value prefix.\n"
            "Then ROTATE the credential; do not test it from production."
        ),
        poc_expected="The credential is found in history or in an artifact, confirming it must be treated as compromised.",
        impact=[
            "Direct authentication to whatever the credential protects, from anywhere.",
            "Persistence after the code is fixed, because the value is still valid.",
            "Compromise of every environment that shares the credential.",
        ],
        remediation=[
            "Rotate the credential first, then remove it from source -- in that order, or"
            " the window between the two leaves it valid.",
            "Load secrets from the environment or a secrets manager, never from source or"
            " a committed config file.",
            "Purge history (git filter-repo or BFG) and force-rotate anything the value"
            " could have reached, including downstream consumers.",
        ],
        verification=[
            "The scanner's secret rules return nothing for the file.",
            "git log -p finds no occurrence of the value in history.",
            "The credential is confirmed revoked at the provider.",
        ],
    )


def _auth_poc() -> "PoC":
    return PoC(
        category="jwt-verify-off",
        cwe="CWE-347",
        title="Missing authentication or verification",
        severity="critical",
        mechanism=[
            "A verification step that should reject an untrusted token, signature, or"
            " TLS certificate is disabled or skipped, so the check always passes.",
            "The attacker supplies a token they crafted: any signature, an expired"
            " expiry, or the 'none' algorithm all satisfy the disabled check.",
            "The application then treats the forged token as authentic.",
        ],
        poc_request=(
            "Detection probe with a deliberately INVALID token (no real credentials used):\n"
            "  Send a token whose signature is replaced with garbage, or whose 'alg' is"
            "  'none'.  A 200 response means verification is not happening."
        ),
        poc_expected="The application accepts a token it should have rejected.",
        impact=[
            "Complete authentication bypass: any identity, any privilege claim.",
            "For TLS verification disabled, interception of traffic to a trusted service.",
        ],
        remediation=[
            "Verify the signature on every token, and reject the 'none' algorithm"
            " explicitly by pinning the accepted algorithm list.",
            "Verify expiry and audience, and fail closed on any error -- never fall"
            " through to accepting.",
            "For TLS connections, keep verification enabled; supply the CA bundle if the"
            " error is a trust-root problem rather than a security one.",
        ],
        verification=[
            "Re-send the invalid token: it must be rejected with 401/403.",
            "Run the scanner: the verification-disabled finding must be gone.",
        ],
    )


def _info_disclosure_poc() -> "PoC":
    return PoC(
        category="disclosure",
        cwe="CWE-209",
        title="Information disclosure",
        severity="medium",
        mechanism=[
            "Verbose output reaches the client: a stack trace, a framework banner, or a"
            " server header that names exact versions.",
            "The disclosed versions map directly to public vulnerability databases,"
            " which turns a generic scan into a targeted one.",
            "Traces also reveal internal paths, framework names, and query shapes.",
        ],
        poc_request=(
            "Compare a normal response's headers and body against a request that triggers"
            " an error:\n"
            "  GET /debug\n"
            "  GET /nonexistent-page-to-trigger-404-or-500\n"
            "Inspect the Server, X-Powered-By, and X-AspNet-Version headers and any"
            " traceback in the body."
        ),
        poc_expected="Version banners or a traceback appear in the response.",
        impact=[
            "Version-specific attacks become straightforward, cutting reconnaissance time"
            " to zero.",
            "Internal structure disclosure helps an attacker target the weak component.",
        ],
        remediation=[
            "Return generic error pages to clients; log the detail server-side only.",
            "Remove or genericize version banners (Server, X-Powered-By) at the edge.",
            "Run with debug disabled in every deployed environment, and verify the"
            " deployment config, not just the code default.",
        ],
        verification=[
            "Re-send the error-triggering requests: no traceback and no version banner"
            " may appear.",
            "Run the scanner: the disclosure and technology-disclosure findings must be"
            " gone.",
        ],
    )


def _unsafe_deserialization_poc() -> "PoC":
    return PoC(
        category="unsafe-deserialization",
        cwe="CWE-502",
        title="Unsafe deserialization",
        severity="critical",
        mechanism=[
            "Untrusted data is passed to a serializer that reconstructs objects by NAME,"
            " so the input chooses which classes are instantiated and with what arguments.",
            "A gadget chain -- a sequence of ordinary-looking methods -- reaches a call"
            " that executes a command or writes a file, with no injected code involved.",
            "The whole payload is data, so no signature or length check detects it.",
        ],
        poc_request=(
            "No exploit payload is generated here.  Confirmation is static: the code path"
            " passes request data to pickle.loads, yaml.load without SafeLoader,"
            " ObjectInputStream, or Marshal.load.\n"
            "A runtime confirmation requires a gadget-chain PoC and is authorised-engagement"
            " work; the static evidence is sufficient to fix."
        ),
        poc_expected="Untrusted input reaches an unsafe deserializer in the source path.",
        impact=[
            "Arbitrary code execution during deserialization, before any validation runs.",
            "Full compromise of the process.",
        ],
        remediation=[
            "Do not deserialize untrusted input.  Use a format that carries data only --"
            " JSON, protobuf, or a typed schema -- instead of a pickle-style format.",
            "Where the format is unavoidable, restrict the loader (yaml.safe_load,"
            " pickle with an explicit Unpickler allowlist) and validate against a schema"
            " before use.",
            "Run the process unprivileged, so exploitation of the sink is not immediate"
            " system compromise.",
        ],
        verification=[
            "Confirm every deserialization call on an untrusted path uses a safe loader or"
            " a data-only format.",
            "Run the scanner: the unsafe-deserialization finding must be gone.",
        ],
        notes=["Class-level PoC only: runtime confirmation needs an authorised engagement."],
    )


def _injection_surface_poc() -> "PoC":
    return PoC(
        category="injection-surface",
        cwe="CWE-20",
        title="Unmapped input surface",
        severity="medium",
        mechanism=[
            "The application accepts parameters that were never enumerated, so validation"
            " coverage is unknown for them.",
            "Unmapped input is where injection classes hide: the parameter works, but no"
            " one ever decided what it is allowed to contain.",
            "Mapping the surface is the prerequisite for any of the injection fixes above.",
        ],
        poc_request=(
            "Enumerate the surface and compare against the documented contract:\n"
            "  Submit each form with an unexpected extra parameter and observe whether it"
            "  changes behaviour.\n"
            "  Review the parameter list against the API specification."
        ),
        poc_expected="Parameters exist that are not in the documented API contract.",
        impact=[
            "Injection defects in parameters no reviewer examined.",
            "Mass-assignment style writes through undocumented fields.",
        ],
        remediation=[
            "Define an explicit allowlist of accepted parameters per endpoint and reject"
            " unknown ones.",
            "Validate every accepted parameter against a schema (type, length, format,"
            " range) server-side.",
            "Add contract tests so a new parameter fails CI until it is documented and"
            " validated.",
        ],
        verification=[
            "Re-scan: the injection-surface findings should enumerate only documented"
            " parameters.",
        ],
    )


# ---------------------------------------------------------------------------
# Category resolution
# ---------------------------------------------------------------------------

# Canonical scanner category / finding-type -> PoC builder.  Keyed on the
# category strings the scanners actually emit, with the public "-risk" aliases
# included so a finding from the heuristic layer resolves the same way.
_POC_BUILDERS = {
    "template-injection": _template_injection_poc,
    "template-injection-risk": _template_injection_poc,
    "sql-injection": _sql_injection_poc,
    "sql-injection-risk": _sql_injection_poc,
    "command-injection": _command_injection_poc,
    "command-injection-risk": _command_injection_poc,
    "shell-injection": _command_injection_poc,
    "shell-injection-risk": _command_injection_poc,
    "xss-eval": _xss_poc,
    "xss-eval-risk": _xss_poc,
    "xss-dom": _xss_poc,
    "xss-domxss": _xss_poc,
    "xss-framework": _xss_poc,
    "path-traversal": _path_traversal_poc,
    "path-traversal-risk": _path_traversal_poc,
    "ssrf": _ssrf_poc,
    "ssrf-risk": _ssrf_poc,
    "weak-hash": _weak_hash_poc,
    "weak-hash-md5": _weak_hash_poc,
    "weak-hash-sha1": _weak_hash_poc,
    "weak-cipher": _weak_hash_poc,
    "hardcoded-secret": _secret_poc,
    "private-key": _secret_poc,
    "bearer-token-literal": _secret_poc,
    "jwt-verify-off": _auth_poc,
    "plaintext-password-compare": _auth_poc,
    "tls-verify-off": _auth_poc,
    "disclosure": _info_disclosure_poc,
    "unsafe-deserialization": _unsafe_deserialization_poc,
    "injection-surface": _injection_surface_poc,
    "js-domxss": _xss_poc,
    "probe-xss": _xss_poc,
    "probe-ssti": _template_injection_poc,
    "probe-sqli": _sql_injection_poc,
    "probe-cmd": _command_injection_poc,
    "probe-path": _path_traversal_poc,
    # The repository scanner's own public category names (``repo_scan`` emits
    # ``category='sql'`` with ``cwe='CWE-89'``).  Registering them keeps
    # category-based resolution working directly instead of leaning on the CWE
    # fallback, which would otherwise be the only route for the most common
    # findings in the tool.
    "sql": _sql_injection_poc,
    "command": _command_injection_poc,
    "shell": _command_injection_poc,
    "path": _path_traversal_poc,
    "ssrf": _ssrf_poc,
    "template": _template_injection_poc,
    "xss": _xss_poc,
    "domxss": _xss_poc,
    "weak": _weak_hash_poc,
    "weak-hash": _weak_hash_poc,
    "secret": _secret_poc,
    "hardcoded": _secret_poc,
    "unsafe": _unsafe_deserialization_poc,
    "deserialization": _unsafe_deserialization_poc,
}

# CWE fallback, for a finding whose category the table does not name directly.
_CWE_BUILDERS = {
    "CWE-1336": _template_injection_poc,
    "CWE-94": _template_injection_poc,
    "CWE-89": _sql_injection_poc,
    "CWE-78": _command_injection_poc,
    "CWE-79": _xss_poc,
    "CWE-22": _path_traversal_poc,
    "CWE-918": _ssrf_poc,
    "CWE-327": _weak_hash_poc,
    "CWE-328": _weak_hash_poc,
    "CWE-798": _secret_poc,
    "CWE-347": _auth_poc,
    "CWE-287": _auth_poc,
    "CWE-209": _info_disclosure_poc,
    "CWE-200": _info_disclosure_poc,
    "CWE-502": _unsafe_deserialization_poc,
    "CWE-20": _injection_surface_poc,
}

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _first_cwe(cwe_ids: Iterable[Any]) -> Optional[str]:
    """First non-empty CWE id, accepting either a list or a single scalar string.

    A bare string is iterable CHARACTER BY CHARACTER, so iterating it directly
    yields "C", "W", "E" and the lookup fails -- a caller passing the scanner's
    single ``cwe`` field rather than a list would silently get no PoC at all.
    """
    if isinstance(cwe_ids, str):
        cleaned = cwe_ids.strip()
        return cleaned or None
    for cwe in cwe_ids or ():
        if cwe:
            return str(cwe)
    return None


def has_poc(category: str, cwe_ids: Iterable[Any] = ()) -> bool:
    """True when a defensive PoC exists for this category or CWE."""
    if (category or "") in _POC_BUILDERS:
        return True
    return _first_cwe(cwe_ids) in _CWE_BUILDERS


def poc_for(
    category: str = "",
    cwe_ids: Iterable[Any] = (),
    severity: str = "",
    language: str = "",
    title: str = "",
    endpoint: str = "",
    evidence: str = "",
) -> Optional[PoC]:
    """Build the defensive PoC for one finding, or return None.

    Category wins over CWE when both are available and both resolve: the
    category carries the concrete defect (``path-traversal``), while a CWE is a
    broader class that may cover several.

    ``language`` only sharpens the wording where it changes the mechanism (the
    SSTI PoC names the template engine's escalation path); every builder here is
    language-agnostic by design, because the mechanism and the fix do not change
    between Python and Go for these classes.
    """
    cat = (category or "").strip()
    builder = _POC_BUILDERS.get(cat)
    if builder is None:
        builder = _CWE_BUILDERS.get(_first_cwe(cwe_ids))
    if builder is None:
        return None

    poc = builder()
    if language and cat in ("template-injection", "probe-ssti", "template-injection-risk"):
        poc.notes.append(f"Template engine to confirm on the target stack: {language}")
    if endpoint:
        poc.notes.append(f"Observed at: {endpoint}")
    if evidence:
        # Evidence is what makes this a finding-level PoC rather than a class
        # description: quote what the scanner actually saw.
        snippet = re.sub(r"\s+", " ", str(evidence)).strip()[:160]
        if snippet:
            poc.notes.append(f"Scanner evidence: {snippet}")
    if title:
        poc.notes.append(f"Reported as: {title}")
    if severity and severity in _SEVERITY_ORDER:
        if _SEVERITY_ORDER[severity] > _SEVERITY_ORDER.get(poc.severity, 0):
            poc.severity = severity
        elif _SEVERITY_ORDER[severity] < _SEVERITY_ORDER.get(poc.severity, 0):
            poc.notes.append(
                f"Reported severity '{severity}' is lower than the class default"
                f" '{poc.severity}'; confirm the exposure before downgrading."
            )
    return poc


def _finding_fields(finding: Any) -> dict[str, Any]:
    """Pull (category, cwe_ids, severity, ...) out of a scanner finding.

    Works for the web scanner's ``WebFinding`` and for ``UnifiedFinding`` without
    importing either, so this module stays independent of the scanner layer.
    """
    category = getattr(finding, "category", None) or ""
    cwe_ids = getattr(finding, "cwe_ids", None) or getattr(finding, "cwe", None) or ()
    if isinstance(cwe_ids, str):
        cwe_ids = (cwe_ids,)
    severity = getattr(finding, "severity", "") or ""
    if hasattr(severity, "value"):
        severity = str(severity.value)
    return {
        "category": str(category),
        "cwe_ids": list(cwe_ids),
        "severity": str(severity).lower(),
        "language": str(getattr(finding, "language", "") or ""),
        "title": str(getattr(finding, "title", "") or ""),
        "endpoint": str(getattr(finding, "endpoint", "") or getattr(finding, "file_path", "") or ""),
        "evidence": str(getattr(finding, "evidence", "") or ""),
    }


def pocs_for_findings(findings: Iterable[Any]) -> list[PoC]:
    """PoCs for every finding that has one, ordered by severity.

    A finding with no PoC entry is skipped rather than given a generic one: an
    invented mechanism would be worse than no mechanism.
    """
    out: list[PoC] = []
    for finding in findings:
        fields = _finding_fields(finding)
        poc = poc_for(**fields)
        if poc is not None:
            out.append(poc)
    out.sort(key=lambda p: -_SEVERITY_ORDER.get(p.severity, 0))
    return out


def poc_markdown(pocs: Iterable[PoC]) -> str:
    """Render PoCs as the 'how it is exploited / how to fix it' report section."""
    lines: list[str] = ["## Proof-of-concept, impact, and remediation", ""]
    any_written = False
    for poc in pocs:
        any_written = True
        lines.append(f"### {poc.title} ({poc.category}, {poc.cwe}) - {poc.severity}")
        lines.append("")
        lines.append("**How it works**")
        lines.append("")
        for step in poc.mechanism:
            lines.append(f"{step}")
            lines.append("")
        lines.append("**Safe detection PoC**")
        lines.append("")
        lines.append("```")
        lines.append(poc.poc_request.strip("\n"))
        lines.append("```")
        lines.append("")
        lines.append(f"**What proves it**: {poc.poc_expected}")
        lines.append("")
        if poc.impact:
            lines.append("**What an attacker gains**")
            lines.append("")
            for item in poc.impact:
                lines.append(f"- {item}")
            lines.append("")
        if poc.remediation:
            lines.append("**Fix**")
            lines.append("")
            for item in poc.remediation:
                lines.append(f"- {item}")
            lines.append("")
        if poc.verification:
            lines.append("**How to prove the fix worked**")
            lines.append("")
            for item in poc.verification:
                lines.append(f"- {item}")
            lines.append("")
        if poc.notes:
            lines.append("**Context**")
            lines.append("")
            for note in poc.notes:
                lines.append(f"- {note}")
            lines.append("")
    if not any_written:
        lines.append("_No defect class in this scan has a defensive proof-of-concept._")
        lines.append("")
    return "\n".join(lines)
