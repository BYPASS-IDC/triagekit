"""Source, Sink, and Sanitizer registry for taint analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .models import Sanitizer, SanitizerAction, Sink, Source, TaintKind


# ─────────────────────────────────────────────────────────────────────────────
# BUILT-IN SOURCES
# ─────────────────────────────────────────────────────────────────────────────

PYTHON_SOURCES = [
    Source(
        name="http-request-get",
        category="http-request",
        description="Flask/Django request.GET parameters",
        pattern=r"request\.(GET|args|query_params|query)\[",
        languages=["python"],
        confidence=0.95,
        cwe_ids=["CWE-20"],
        tags=["web", "input"],
    ),
    Source(
        name="http-request-post",
        category="http-request",
        description="Flask/Django request.POST/form data",
        pattern=r"request\.(POST|form|data|json|body)\[",
        languages=["python"],
        confidence=0.95,
        cwe_ids=["CWE-20"],
        tags=["web", "input"],
    ),
    Source(
        name="http-request-cookies",
        category="http-request",
        description="HTTP cookies",
        pattern=r"request\.cookies\[",
        languages=["python"],
        confidence=0.9,
        cwe_ids=["CWE-20"],
        tags=["web", "input"],
    ),
    Source(
        name="http-request-headers",
        category="http-request",
        description="HTTP headers",
        pattern=r"request\.headers\[",
        languages=["python"],
        confidence=0.9,
        cwe_ids=["CWE-20"],
        tags=["web", "input"],
    ),
    Source(
        name="django-request",
        category="http-request",
        description="Django HttpRequest GET/POST",
        pattern=r"request\.(GET|POST|REQUEST|FILES)\[",
        languages=["python"],
        confidence=0.95,
        cwe_ids=["CWE-20"],
        tags=["web", "input", "django"],
    ),
    Source(
        name="flask-request",
        category="http-request",
        description="Flask request object access",
        # Bare ``request.args``/``request.data`` is just as attacker-controlled
        # as the subscripted form, and ``request.get_data()`` is the raw body
        # read as a call.  Requiring a trailing "[" missed both, so a whole
        # class of body- and query-reading handlers produced no finding.
        pattern=r"request\.(values|args|form|json|files|data)\b",
        languages=["python"],
        confidence=0.95,
        cwe_ids=["CWE-20"],
        tags=["web", "input", "flask"],
    ),
    Source(
        name="flask-request-methods",
        category="http-request",
        description="Flask request getter methods (body/stream)",
        pattern=r"request\.(get_data|get_json|read|stream)\s*\(",
        languages=["python"],
        confidence=0.95,
        cwe_ids=["CWE-20"],
        tags=["web", "input", "flask"],
    ),
    Source(
        name="fastapi-request",
        category="http-request",
        description="FastAPI request parameters",
        pattern=r"(query_params|path_params|form_data|body|cookies|headers)\[",
        languages=["python"],
        confidence=0.95,
        cwe_ids=["CWE-20"],
        tags=["web", "input", "fastapi"],
    ),
    Source(
        name="stdlib-input",
        category="user-input",
        description="Python built-in input() function",
        pattern=r"^input$",
        languages=["python"],
        confidence=0.9,
        cwe_ids=["CWE-20"],
        tags=["cli", "input"],
    ),
    Source(
        name="sys-argv",
        category="user-input",
        description="Command line arguments via sys.argv",
        pattern=r"sys\.argv\[",
        languages=["python"],
        confidence=0.9,
        cwe_ids=["CWE-20"],
        tags=["cli", "input"],
    ),
    Source(
        name="os-environ",
        category="environment",
        description="Environment variables via os.environ",
        pattern=r"os\.environ\[|os\.getenv\s*\(",
        languages=["python"],
        confidence=0.85,
        cwe_ids=["CWE-20"],
        tags=["config", "input"],
    ),
    Source(
        name="file-read",
        category="file",
        description="File read operations",
        pattern=r"(open\s*\(|read\s*\(|readline\s*\(|readlines\s*\()",
        languages=["python"],
        confidence=0.7,
        cwe_ids=["CWE-20"],
        tags=["file", "input"],
    ),
    Source(
        name="sqlite-fetch",
        category="database",
        description="SQLite fetch results",
        pattern=r"\.(fetchall|fetchone|fetchmany)\s*\(",
        languages=["python"],
        confidence=0.8,
        cwe_ids=["CWE-20"],
        tags=["database", "input"],
    ),
    Source(
        name="psycopg2-fetch",
        category="database",
        description="Psycopg2 fetch results",
        pattern=r"\.(fetchall|fetchone|fetchmany)\s*\(",
        languages=["python"],
        confidence=0.8,
        cwe_ids=["CWE-20"],
        tags=["database", "input", "postgresql"],
    ),
    Source(
        name="sqlalchemy-result",
        category="database",
        description="SQLAlchemy result fetch",
        pattern=r"\.(fetchall|fetchone|first|all|scalar)\s*\(",
        languages=["python"],
        confidence=0.8,
        cwe_ids=["CWE-20"],
        tags=["database", "input", "sqlalchemy"],
    ),
    Source(
        name="redis-get",
        category="database",
        description="Redis GET operations",
        pattern=r"redis\.(get|mget|hget|hgetall|lrange)\s*\(",
        languages=["python"],
        confidence=0.8,
        cwe_ids=["CWE-20"],
        tags=["database", "input", "redis"],
    ),
    Source(
        name="requests-response",
        category="http-response",
        description="HTTP response data from requests library",
        pattern=r"\.json\s*\(|\.text|\.content",
        languages=["python"],
        confidence=0.7,
        cwe_ids=["CWE-20"],
        tags=["http", "input"],
    ),
    Source(
        name="subprocess-output",
        category="process-output",
        description="Subprocess stdout/stderr",
        pattern=r"\.(stdout|stderr|communicate\s*\(|check_output\s*\()",
        languages=["python"],
        confidence=0.75,
        cwe_ids=["CWE-20"],
        tags=["process", "input"],
    ),
    Source(
        name="yaml-load",
        category="deserialization",
        description="YAML deserialization (unsafe)",
        pattern=r"yaml\.(load|unsafe_load)\s*\(",
        languages=["python"],
        confidence=0.9,
        cwe_ids=["CWE-502"],
        tags=["deserialization", "input"],
    ),
    Source(
        name="pickle-load",
        category="deserialization",
        description="Pickle deserialization (unsafe)",
        pattern=r"pickle\.(load|loads)\s*\(",
        languages=["python"],
        confidence=0.95,
        cwe_ids=["CWE-502"],
        tags=["deserialization", "input"],
    ),
    Source(
        name="json-loads",
        category="deserialization",
        description="JSON deserialization",
        pattern=r"json\.loads\s*\(",
        languages=["python"],
        confidence=0.6,
        cwe_ids=["CWE-20"],
        tags=["deserialization", "input"],
    ),
    Source(
        name="eval-exec",
        category="code-execution",
        description="eval/exec with user input",
        pattern=r"\b(eval|exec)\s*\(",
        languages=["python"],
        confidence=0.95,
        cwe_ids=["CWE-95"],
        tags=["code-execution", "input"],
    ),
]


JAVASCRIPT_SOURCES = [
    Source(
        name="express-req-query",
        category="http-request",
        description="Express.js req.query parameters",
        pattern=r"req\.query\[|\.query\.",
        languages=["javascript", "typescript"],
        confidence=0.95,
        cwe_ids=["CWE-20"],
        tags=["web", "input", "express"],
    ),
    Source(
        name="express-req-body",
        category="http-request",
        description="Express.js req.body",
        pattern=r"req\.body\[|\.body\.",
        languages=["javascript", "typescript"],
        confidence=0.95,
        cwe_ids=["CWE-20"],
        tags=["web", "input", "express"],
    ),
    Source(
        name="express-req-params",
        category="http-request",
        description="Express.js req.params",
        pattern=r"req\.params\[|\.params\.",
        languages=["javascript", "typescript"],
        confidence=0.95,
        cwe_ids=["CWE-20"],
        tags=["web", "input", "express"],
    ),
    Source(
        name="express-req-headers",
        category="http-request",
        description="Express.js req.headers",
        pattern=r"req\.headers\[|\.headers\.",
        languages=["javascript", "typescript"],
        confidence=0.9,
        cwe_ids=["CWE-20"],
        tags=["web", "input", "express"],
    ),
    Source(
        name="express-req-cookies",
        category="http-request",
        description="Express.js req.cookies",
        pattern=r"req\.cookies\[|\.cookies\.",
        languages=["javascript", "typescript"],
        confidence=0.9,
        cwe_ids=["CWE-20"],
        tags=["web", "input", "express"],
    ),
    Source(
        name="koa-ctx-request",
        category="http-request",
        description="Koa context request",
        pattern=r"ctx\.request\.(query|body|params|headers)\[",
        languages=["javascript", "typescript"],
        confidence=0.95,
        cwe_ids=["CWE-20"],
        tags=["web", "input", "koa"],
    ),
    Source(
        name="fastify-request",
        category="http-request",
        description="Fastify request",
        pattern=r"request\.(query|body|params|headers)\[",
        languages=["javascript", "typescript"],
        confidence=0.95,
        cwe_ids=["CWE-20"],
        tags=["web", "input", "fastify"],
    ),
    Source(
        name="nextjs-request",
        category="http-request",
        description="Next.js request (App Router)",
        pattern=r"(searchParams|params)\[",
        languages=["javascript", "typescript"],
        confidence=0.95,
        cwe_ids=["CWE-20"],
        tags=["web", "input", "nextjs"],
    ),
    Source(
        name="browser-url-search",
        category="http-request",
        description="Browser URLSearchParams",
        pattern=r"(URLSearchParams|window\.location\.search|location\.search)",
        languages=["javascript", "typescript"],
        confidence=0.85,
        cwe_ids=["CWE-20"],
        tags=["web", "input", "browser"],
    ),
    # ``location.hash`` is the single most common DOM-XSS source and the only
    # reason it was absent is that the original entry listed ``location.search``
    # alone.  ``document.referrer`` and ``window.name`` are the two other
    # attacker-settable browser values, so they belong in the same class.
    Source(
        name="browser-location",
        category="http-request",
        description="Browser location / document URL (hash, href, pathname, referrer)",
        pattern=r"(?:location|window\s*\.\s*location)\s*\.\s*(?:hash|href|search|pathname|host|hostname|origin|port)"
        r"|document\s*\.\s*(?:referrer|URL|documentURI|baseURI)|window\s*\.\s*name",
        languages=["javascript", "typescript"],
        confidence=0.85,
        cwe_ids=["CWE-20", "CWE-79"],
        tags=["web", "input", "browser", "dom-xss"],
    ),
    # Parsing untrusted JSON is the entry point for prototype pollution and for
    # every "object with attacker-controlled keys" bug.  A literal argument is
    # still matched, which is why confidence is deliberately low.
    Source(
        name="json-parse",
        category="deserialization",
        description="JSON.parse of untrusted data",
        pattern=r"JSON\s*\.\s*parse\s*\(",
        languages=["javascript", "typescript"],
        confidence=0.7,
        cwe_ids=["CWE-502", "CWE-1321"],
        tags=["deserialization", "input", "json"],
    ),
    Source(
        name="fetch-response",
        category="http-response",
        description="Fetch API response",
        pattern=r"\.json\s*\(|\.text\s*\(|\.blob\s*\(",
        languages=["javascript", "typescript"],
        confidence=0.7,
        cwe_ids=["CWE-20"],
        tags=["http", "input"],
    ),
    Source(
        name="axios-response",
        category="http-response",
        description="Axios response data",
        pattern=r"response\.data|axios\.(get|post|put|delete)\s*\(",
        languages=["javascript", "typescript"],
        confidence=0.7,
        cwe_ids=["CWE-20"],
        tags=["http", "input"],
    ),
    Source(
        name="node-process-argv",
        category="user-input",
        description="Node.js process.argv",
        pattern=r"process\.argv\[",
        languages=["javascript", "typescript"],
        confidence=0.9,
        cwe_ids=["CWE-20"],
        tags=["cli", "input"],
    ),
    Source(
        name="node-process-env",
        category="environment",
        description="Node.js process.env",
        pattern=r"process\.env\.",
        languages=["javascript", "typescript"],
        confidence=0.85,
        cwe_ids=["CWE-20"],
        tags=["config", "input"],
    ),
    Source(
        name="fs-read",
        category="file",
        description="Node.js fs read operations",
        pattern=r"fs\.(readFile|readFileSync|read)\s*\(",
        languages=["javascript", "typescript"],
        confidence=0.7,
        cwe_ids=["CWE-20"],
        tags=["file", "input"],
    ),
    Source(
        name="eval-function",
        category="code-execution",
        description="JavaScript eval/Function constructor",
        pattern=r"\b(eval|new Function)\s*\(",
        languages=["javascript", "typescript"],
        confidence=0.95,
        cwe_ids=["CWE-95"],
        tags=["code-execution", "input"],
    ),
    Source(
        name="innerHTML-sink",
        category="dom-xss",
        description="DOM XSS via innerHTML",
        pattern=r"\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(",
        languages=["javascript", "typescript"],
        confidence=0.9,
        cwe_ids=["CWE-79"],
        tags=["dom", "xss", "sink-as-source"],
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# BUILT-IN SINKS
# ─────────────────────────────────────────────────────────────────────────────

PYTHON_SINKS = [
    Sink(
        name="sql-execute",
        category="sql-execution",
        description="SQL execution with string formatting",
        pattern=r"(cursor\.execute|execute|executemany|raw_query|\.query\s*\()",
        vulnerable_param=0,
        languages=["python"],
        confidence=0.95,
        cwe_ids=["CWE-89"],
        severity="critical",
        tags=["sql", "injection"],
    ),
    Sink(
        name="sql-format",
        category="sql-execution",
        description="SQL string formatting",
        pattern=r"(f\".*SELECT|f\".*INSERT|f\".*UPDATE|f\".*DELETE|\.format)",
        vulnerable_param=0,
        languages=["python"],
        confidence=0.9,
        cwe_ids=["CWE-89"],
        severity="critical",
        tags=["sql", "injection"],
    ),
    Sink(
        name="sqlite3-execute",
        category="sql-execution",
        description="sqlite3 execute",
        pattern=r"sqlite3\.(execute|executemany|executescript)\s*\(",
        vulnerable_param=0,
        languages=["python"],
        confidence=0.95,
        cwe_ids=["CWE-89"],
        severity="critical",
        tags=["sql", "injection", "sqlite"],
    ),
    Sink(
        name="psycopg2-execute",
        category="sql-execution",
        description="psycopg2 execute",
        pattern=r"\.(execute|executemany|callproc)\s*\(",
        vulnerable_param=0,
        languages=["python"],
        confidence=0.95,
        cwe_ids=["CWE-89"],
        severity="critical",
        tags=["sql", "injection", "postgresql"],
    ),
    Sink(
        name="sqlalchemy-execute",
        category="sql-execution",
        description="SQLAlchemy execute/text",
        pattern=r"(session\.execute|conn\.execute|text\s*\()",
        vulnerable_param=0,
        languages=["python"],
        confidence=0.9,
        cwe_ids=["CWE-89"],
        severity="critical",
        tags=["sql", "injection", "sqlalchemy"],
    ),
    Sink(
        name="django-raw-sql",
        category="sql-execution",
        description="Django raw SQL",
        pattern=r"(raw\s*\(|extra\s*\(|cursor\.execute)",
        vulnerable_param=0,
        languages=["python"],
        confidence=0.95,
        cwe_ids=["CWE-89"],
        severity="critical",
        tags=["sql", "injection", "django"],
    ),
    Sink(
        name="command-execution",
        category="command-execution",
        description="OS command execution",
        pattern=r"(os\.system|subprocess\.(call|run|Popen|check_output)|commands\.getstatusoutput|popen\s*\()",
        vulnerable_param=0,
        languages=["python"],
        confidence=0.95,
        cwe_ids=["CWE-78"],
        severity="critical",
        tags=["command", "injection", "rce"],
    ),
    Sink(
        name="shell-command",
        category="command-execution",
        description="Shell command with shell=True",
        pattern=r"shell\s*=\s*True",
        vulnerable_param=0,
        languages=["python"],
        confidence=0.9,
        cwe_ids=["CWE-78"],
        severity="critical",
        tags=["command", "injection", "shell"],
    ),
    Sink(
        name="os-popen",
        category="command-execution",
        description="os.popen / subprocess.getoutput shell execution",
        pattern=r"(os\.popen|subprocess\.getoutput|subprocess\.getstatusoutput|commands\.getoutput)\s*\(",
        vulnerable_param=0,
        languages=["python"],
        confidence=0.95,
        cwe_ids=["CWE-78"],
        severity="critical",
        tags=["command", "injection", "rce"],
    ),
    Sink(
        name="ssrf-http-request",
        category="ssrf",
        description="Outbound HTTP request with user-controlled URL",
        pattern=r"(requests\.(get|post|put|delete|head|patch|request)|httpx\.(get|post|put|delete|head|patch|request|stream)|urllib\.request\.urlopen|urlopen\s*\(|http\.client\.(HTTPConnection|HTTPSConnection))",
        vulnerable_param=0,
        languages=["python"],
        confidence=0.9,
        cwe_ids=["CWE-918"],
        severity="high",
        tags=["ssrf", "injection", "network"],
    ),
    Sink(
        name="ssrf-request-object",
        category="ssrf",
        description="urllib.request.Request with user-controlled URL",
        pattern=r"urllib\.request\.Request\s*\(",
        vulnerable_param=0,
        languages=["python"],
        confidence=0.85,
        cwe_ids=["CWE-918"],
        severity="high",
        tags=["ssrf", "injection", "network"],
    ),
    Sink(
        name="weak-hash",
        category="weak-cryptography",
        description="Weak hash algorithm (MD5/SHA1) on attacker-reachable data",
        pattern=r"(hashlib\.(md5|sha1)|Crypto\.Hash\.(MD5|SHA1)|cryptography\.hazmat\.primitives\.hashes\.(MD5|SHA1))\s*\(",
        vulnerable_param=0,
        languages=["python"],
        confidence=0.8,
        cwe_ids=["CWE-327", "CWE-328"],
        severity="medium",
        tags=["crypto", "weak-hash"],
    ),
    Sink(
        name="xxe-parse",
        category="xxe",
        description="XML parser processing attacker-controlled documents",
        pattern=r"(xml\.etree\.ElementTree\.(parse|fromstring)|xml\.dom\.minidom\.parse|xml\.sax\.parse|lxml\.etree\.(parse|fromstring|XMLParser))\s*\(",
        vulnerable_param=0,
        languages=["python"],
        confidence=0.85,
        cwe_ids=["CWE-611"],
        severity="high",
        tags=["xxe", "xml", "injection"],
    ),
    Sink(
        name="archive-extract",
        category="path-traversal",
        description="Archive extraction without member validation (zip-slip)",
        pattern=r"(zipfile\.ZipFile\s*\([^)]*\)\.extract(all|member)|tarfile\.open\s*\([^)]*\)\.extract(all)?|ZipFile\.extractall|TarFile\.extractall)\s*\(",
        vulnerable_param=0,
        languages=["python"],
        confidence=0.75,
        cwe_ids=["CWE-22"],
        severity="high",
        tags=["path", "traversal", "archive"],
    ),
    Sink(
        name="eval-exec-sink",
        category="code-execution",
        description="eval/exec sink",
        pattern=r"\b(eval|exec|compile)\s*\(",
        vulnerable_param=0,
        languages=["python"],
        confidence=0.95,
        cwe_ids=["CWE-95"],
        severity="critical",
        tags=["code-execution", "rce"],
    ),
    Sink(
        name="pickle-load-sink",
        category="deserialization",
        description="Pickle load sink",
        pattern=r"pickle\.(load|loads)\s*\(",
        vulnerable_param=0,
        languages=["python"],
        confidence=0.95,
        cwe_ids=["CWE-502"],
        severity="critical",
        tags=["deserialization", "rce"],
    ),
    Sink(
        name="yaml-load-sink",
        category="deserialization",
        description="YAML load sink",
        pattern=r"yaml\.(load|unsafe_load)\s*\(",
        vulnerable_param=0,
        languages=["python"],
        confidence=0.9,
        cwe_ids=["CWE-502"],
        severity="high",
        tags=["deserialization"],
    ),
    Sink(
        name="template-render",
        category="template-injection",
        description="Template rendering with user input",
        # ``from jinja2 import Environment`` then ``Environment()`` is the common
        # form, and ``.from_string()`` compiles a template from user text -- both
        # were absent, so an SSTI written either way produced no finding.
        pattern=(
            r"(render_template|render_template_string|jinja2\.Environment|"
            r"from_string\s*\(|\bEnvironment\s*\(|Template\s*\()"
        ),
        vulnerable_param=0,
        languages=["python"],
        confidence=0.85,
        cwe_ids=["CWE-94"],
        severity="high",
        tags=["template", "injection", "ssti"],
    ),
    Sink(
        name="path-traversal",
        category="path-traversal",
        description="Path traversal via user input",
        pattern=r"(open\s*\(|os\.path\.join|pathlib\.Path|send_file|send_from_directory|safe_join)",
        vulnerable_param=0,
        languages=["python"],
        confidence=0.85,
        cwe_ids=["CWE-22"],
        severity="high",
        tags=["path", "traversal", "file-access"],
    ),
    Sink(
        name="redirect",
        category="open-redirect",
        description="HTTP redirect with user input",
        pattern=r"(redirect\s*\(|HttpResponseRedirect|redirect_to\s*=)",
        vulnerable_param=0,
        languages=["python"],
        confidence=0.8,
        cwe_ids=["CWE-601"],
        severity="medium",
        tags=["redirect", "open-redirect"],
    ),
    Sink(
        name="html-response",
        category="xss",
        description="Direct HTML response",
        pattern=r"(HttpResponse\s*\(|Response\s*\(|make_response\s*\()",
        vulnerable_param=0,
        languages=["python"],
        confidence=0.7,
        cwe_ids=["CWE-79"],
        severity="high",
        tags=["xss", "html"],
    ),
    Sink(
        name="log-injection",
        category="log-injection",
        description="Logging user input without sanitization",
        # ``log``, ``LOG``, ``logger``, ``logging``, ``self.log`` and
        # ``self.logger`` are all common spellings of the same object; matching
        # only ``logger.``/``logging.`` silently skipped the most frequent alias
        # in real code and every bare ``print()`` of a request value.
        pattern=r"((^|[.\w])(logger|log|LOG|logging|_logger|_log)[.\w]*\.(info|warning|warn|error|debug|critical|exception|log)\s*\(|print\s*\()",
        vulnerable_param=0,
        languages=["python"],
        confidence=0.6,
        cwe_ids=["CWE-117"],
        severity="low",
        tags=["log", "injection"],
    ),
    Sink(
        name="ldap-query",
        category="ldap-injection",
        description="LDAP query with user input",
        pattern=r"ldap\.(search|bind|add|modify|delete)\s*\(",
        vulnerable_param=0,
        languages=["python"],
        confidence=0.85,
        cwe_ids=["CWE-90"],
        severity="high",
        tags=["ldap", "injection"],
    ),
    Sink(
        name="xpath-query",
        category="xpath-injection",
        description="XPath query with user input",
        pattern=r"(xpath|etree\.XPath|lxml\.etree\.XPath)\s*\(",
        vulnerable_param=0,
        languages=["python"],
        confidence=0.85,
        cwe_ids=["CWE-643"],
        severity="high",
        tags=["xpath", "injection"],
    ),
    Sink(
        name="regex-dos",
        category="regex-dos",
        description="User input used as a regex pattern (ReDoS)",
        # The dangerous position is the PATTERN argument (index 0), not the
        # subject.  The old pattern required a literal ``+`` in the rendered
        # call text, so ``re.match(request.args["p"], subject)`` -- the actual
        # vulnerability -- never matched.
        pattern=r"(re\.(search|match|fullmatch|findall|finditer|sub|subn|split|compile)\s*\(|regex\.(search|match|compile)\s*\()",
        vulnerable_param=0,
        languages=["python"],
        confidence=0.7,
        cwe_ids=["CWE-1333"],
        severity="medium",
        tags=["regex", "dos"],
    ),
]


JAVASCRIPT_SINKS = [
    Sink(
        name="sql-template",
        category="sql-execution",
        description="SQL template literal",
        pattern=r"(db\.query|db\.execute|pool\.query|client\.query|knex\.raw|sequelize\.query)\s*\([\s\S]*`",
        vulnerable_param=0,
        languages=["javascript", "typescript"],
        confidence=0.9,
        cwe_ids=["CWE-89"],
        severity="critical",
        tags=["sql", "injection"],
    ),
    Sink(
        name="sql-concat",
        category="sql-execution",
        description="SQL string concatenation",
        pattern=r"(query|execute|raw)\s*\([^)]*\+",
        vulnerable_param=0,
        languages=["javascript", "typescript"],
        confidence=0.85,
        cwe_ids=["CWE-89"],
        severity="critical",
        tags=["sql", "injection"],
    ),
    Sink(
        name="mongoose-query",
        category="sql-execution",
        description="Mongoose query with user input",
        pattern=r"\.(find|findOne|findById|update|delete)\s*\([^)]*req\.",
        vulnerable_param=0,
        languages=["javascript", "typescript"],
        confidence=0.8,
        cwe_ids=["CWE-89"],
        severity="high",
        tags=["sql", "injection", "mongodb"],
    ),
    Sink(
        name="child-process",
        category="command-execution",
        description="Node.js child_process execution",
        pattern=r"child_process\.(exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\(",
        vulnerable_param=0,
        languages=["javascript", "typescript"],
        confidence=0.95,
        cwe_ids=["CWE-78"],
        severity="critical",
        tags=["command", "injection", "rce"],
    ),
    Sink(
        name="eval-sink",
        category="code-execution",
        description="JavaScript eval/Function",
        pattern=r"\b(eval|new Function|setTimeout|setInterval)\s*\(",
        vulnerable_param=0,
        languages=["javascript", "typescript"],
        confidence=0.95,
        cwe_ids=["CWE-95"],
        severity="critical",
        tags=["code-execution", "rce"],
    ),
    Sink(
        name="innerHTML-sink",
        category="xss",
        description="DOM XSS via innerHTML",
        pattern=r"\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|\.insertAdjacentHTML\s*\(",
        vulnerable_param=0,
        languages=["javascript", "typescript"],
        confidence=0.9,
        cwe_ids=["CWE-79"],
        severity="high",
        tags=["xss", "dom"],
    ),
    Sink(
        name="react-dangerously",
        category="xss",
        description="React dangerouslySetInnerHTML",
        pattern=r"dangerouslySetInnerHTML\s*=",
        vulnerable_param=0,
        languages=["javascript", "typescript"],
        confidence=0.95,
        cwe_ids=["CWE-79"],
        severity="high",
        tags=["xss", "react"],
    ),
    Sink(
        name="vue-v-html",
        category="xss",
        description="Vue v-html directive",
        pattern=r"v-html\s*=",
        vulnerable_param=0,
        languages=["javascript", "typescript"],
        confidence=0.95,
        cwe_ids=["CWE-79"],
        severity="high",
        tags=["xss", "vue"],
    ),
    Sink(
        name="angular-bypass",
        category="xss",
        description="Angular bypassSecurityTrustHtml",
        pattern=r"bypassSecurityTrustHtml|bypassSecurityTrustUrl|bypassSecurityTrustScript",
        vulnerable_param=0,
        languages=["javascript", "typescript"],
        confidence=0.9,
        cwe_ids=["CWE-79"],
        severity="high",
        tags=["xss", "angular"],
    ),
    Sink(
        name="path-traversal-fs",
        category="path-traversal",
        description="Path traversal in fs operations",
        pattern=r"fs\.(readFile|writeFile|open|createReadStream|createWriteStream|unlink|mkdir|rmdir)\s*\(",
        vulnerable_param=0,
        languages=["javascript", "typescript"],
        confidence=0.8,
        cwe_ids=["CWE-22"],
        severity="high",
        tags=["path", "traversal", "file-access"],
    ),
    Sink(
        name="redirect-express",
        category="open-redirect",
        description="Express redirect",
        pattern=r"res\.redirect\s*\(",
        vulnerable_param=0,
        languages=["javascript", "typescript"],
        confidence=0.8,
        cwe_ids=["CWE-601"],
        severity="medium",
        tags=["redirect", "open-redirect"],
    ),
    Sink(
        name="response-send",
        category="xss",
        description="Express res.send with user input",
        pattern=r"res\.(send|json|sendFile)\s*\(",
        vulnerable_param=0,
        languages=["javascript", "typescript"],
        confidence=0.6,
        cwe_ids=["CWE-79"],
        severity="medium",
        tags=["xss", "response"],
    ),
    # -------------------------------------------------------------------------
    # Sinks that only exist in real code once a module is *destructured*.
    #
    # ``const { exec } = require('child_process')`` is the idiom in virtually
    # every Express codebase, and ``child-process`` above requires the literal
    # ``child_process.`` prefix -- so the most common command-execution shape in
    # Node.js matched nothing at all.  The same applies to ``const fs =
    # require('fs')`` followed by ``readFileSync(...)``, and to ``db.query``
    # whose SQL is assembled on a previous line, which is why ``sql-concat``
    # (it requires the ``+`` inside the call) misses it too.
    # -------------------------------------------------------------------------
    Sink(
        name="child-process-shell",
        category="command-execution",
        description="Shell command execution (exec/execSync, incl. destructured child_process)",
        # execFile/spawn with an argv array are deliberately excluded: they do
        # not interpret the string.  The analyzer additionally requires either
        # ``shell: true`` or an interpolated first argument for them.
        pattern=r"\b(exec|execSync)\s*\(",
        vulnerable_param=0,
        languages=["javascript", "typescript"],
        confidence=0.9,
        cwe_ids=["CWE-78"],
        severity="critical",
        tags=["command", "injection", "rce"],
    ),
    Sink(
        name="sql-query-generic",
        category="sql-execution",
        description="Database query/execute call (receiver-agnostic)",
        pattern=r"\.(query|execute)\s*\(",
        vulnerable_param=0,
        languages=["javascript", "typescript"],
        confidence=0.85,
        cwe_ids=["CWE-89"],
        severity="critical",
        tags=["sql", "injection"],
    ),
    Sink(
        name="fs-destructured",
        category="path-traversal",
        description="fs operation via destructured import",
        pattern=r"\b(readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync"
        r"|createReadStream|createWriteStream|unlink|unlinkSync|rmdir|rmdirSync"
        r"|mkdir|mkdirSync)\s*\(",
        vulnerable_param=0,
        languages=["javascript", "typescript"],
        confidence=0.8,
        cwe_ids=["CWE-22"],
        severity="high",
        tags=["path", "traversal", "file-access"],
    ),
    Sink(
        name="prototype-pollution",
        category="prototype-pollution",
        description="Object merge/extend fed with untrusted data",
        pattern=r"\b(Object\s*\.\s*assign|deepMerge|deepExtend|mergeDeep|defaultsDeep"
        r"|_\s*\.\s*(?:merge|defaultsDeep)|merge)\s*\(",
        vulnerable_param=1,
        languages=["javascript", "typescript"],
        confidence=0.75,
        cwe_ids=["CWE-1321"],
        severity="high",
        tags=["prototype-pollution", "object-injection"],
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# BUILT-IN SANITIZERS
# ─────────────────────────────────────────────────────────────────────────────

PYTHON_SANITIZERS = [
    Sanitizer(
        name="sql-parameterize",
        category="sql-parametrize",
        description="SQL parameterized queries",
        pattern=r"(execute|executemany)\s*\([^,]+,\s*[\(\[]",
        action=SanitizerAction.REMOVE,
        handles_kinds=[TaintKind.DIRECT, TaintKind.INTERPROCEDURAL],
        languages=["python"],
        confidence=0.95,
        cwe_ids=["CWE-89"],
        is_strong=True,
        tags=["sql", "sanitization"],
    ),
    Sanitizer(
        name="django-orm",
        category="sql-parametrize",
        description="Django ORM (safe)",
        pattern=r"\.(filter|exclude|get|create|update|delete|all|first|last)\s*\(",
        action=SanitizerAction.REMOVE,
        handles_kinds=[TaintKind.DIRECT],
        languages=["python"],
        confidence=0.9,
        cwe_ids=["CWE-89"],
        is_strong=True,
        tags=["sql", "sanitization", "django"],
    ),
    Sanitizer(
        name="sqlalchemy-orm",
        category="sql-parametrize",
        description="SQLAlchemy ORM (safe)",
        pattern=r"(session\.query|select\s*\(|insert\s*\(|update\s*\(|delete\s*\()",
        action=SanitizerAction.REMOVE,
        handles_kinds=[TaintKind.DIRECT],
        languages=["python"],
        confidence=0.9,
        cwe_ids=["CWE-89"],
        is_strong=True,
        tags=["sql", "sanitization", "sqlalchemy"],
    ),
    Sanitizer(
        name="html-escape",
        category="html-escape",
        description="HTML escaping",
        pattern=r"(escape|escape_html|html_escape|Markup\.escape|markupsafe\.escape)\s*\(",
        action=SanitizerAction.ESCAPE,
        handles_kinds=[TaintKind.DIRECT],
        languages=["python"],
        confidence=0.9,
        cwe_ids=["CWE-79"],
        is_strong=True,
        tags=["xss", "sanitization"],
    ),
    Sanitizer(
        name="jinja2-autoescape",
        category="html-escape",
        description="Jinja2 autoescape",
        pattern=r"autoescape\s*=\s*True|Environment\s*\(\s*autoescape",
        action=SanitizerAction.ESCAPE,
        handles_kinds=[TaintKind.DIRECT],
        languages=["python"],
        confidence=0.85,
        cwe_ids=["CWE-79"],
        is_strong=True,
        tags=["xss", "sanitization", "jinja2"],
    ),
    Sanitizer(
        name="django-template-autoescape",
        category="html-escape",
        description="Django template autoescape",
        pattern=r"autoescape|safe\s*filter",
        action=SanitizerAction.ESCAPE,
        handles_kinds=[TaintKind.DIRECT],
        languages=["python"],
        confidence=0.85,
        cwe_ids=["CWE-79"],
        is_strong=True,
        tags=["xss", "sanitization", "django"],
    ),
    Sanitizer(
        name="path-normalize",
        category="path-normalize",
        description="Path normalization",
        pattern=r"(os\.path\.normpath|pathlib\.Path\.resolve|os\.path\.realpath|secure_filename)\s*\(",
        action=SanitizerAction.TRANSFORM,
        handles_kinds=[TaintKind.DIRECT],
        languages=["python"],
        confidence=0.8,
        cwe_ids=["CWE-22"],
        is_strong=False,
        tags=["path", "sanitization"],
    ),
    Sanitizer(
        name="path-basename",
        category="path-normalize",
        description="Strip every directory component from a path (basename)",
        # basename returns the final component only, so any "../" in the input is
        # discarded rather than preserved.  That makes it a genuine neutralizer
        # for path traversal, unlike normpath, which keeps ".." and therefore
        # only transforms.  Without this entry, open(dirname, basename(user)) --
        # the standard safe idiom -- was reported as traversal.
        pattern=r"os\.path\.basename\s*\(",
        action=SanitizerAction.REMOVE,
        handles_kinds=[TaintKind.DIRECT],
        languages=["python"],
        confidence=0.95,
        cwe_ids=["CWE-22"],
        is_strong=True,
        tags=["path", "sanitization", "traversal"],
    ),
    Sanitizer(
        name="path-join-safe",
        category="path-normalize",
        description="Safe path join with base directory check",
        pattern=r"(os\.path\.join|pathlib\.Path)\s*\(",
        action=SanitizerAction.VALIDATE,
        handles_kinds=[TaintKind.DIRECT],
        languages=["python"],
        confidence=0.7,
        cwe_ids=["CWE-22"],
        is_strong=False,
        tags=["path", "sanitization"],
    ),
    Sanitizer(
        name="subprocess-argv",
        category="command-sanitize",
        description="Subprocess with argv list (no shell)",
        # The argv itself may contain commas -- ``run(["ping", "-c", "1", host],
        # shell=False)`` -- so ``[^,]+`` never matched a real multi-element
        # argument list and the one genuinely safe spelling was reported as
        # command injection.
        pattern=r"subprocess\.(run|Popen|call|check_output|check_call)\s*\(.*,\s*shell\s*=\s*False",
        action=SanitizerAction.REMOVE,
        handles_kinds=[TaintKind.DIRECT],
        languages=["python"],
        confidence=0.9,
        cwe_ids=["CWE-78"],
        is_strong=True,
        tags=["command", "sanitization"],
    ),
    Sanitizer(
        name="shlex-quote",
        category="command-sanitize",
        description="shlex.quote for shell arguments",
        pattern=r"shlex\.quote\s*\(",
        action=SanitizerAction.ESCAPE,
        handles_kinds=[TaintKind.DIRECT],
        languages=["python"],
        confidence=0.85,
        cwe_ids=["CWE-78"],
        is_strong=True,
        tags=["command", "sanitization"],
    ),
    Sanitizer(
        name="yaml-safe-load",
        category="deserialization-sanitize",
        description="YAML safe_load",
        pattern=r"yaml\.safe_load\s*\(",
        action=SanitizerAction.REMOVE,
        handles_kinds=[TaintKind.DIRECT],
        languages=["python"],
        confidence=0.95,
        cwe_ids=["CWE-502"],
        is_strong=True,
        tags=["deserialization", "sanitization"],
    ),
    Sanitizer(
        name="json-loads-safe",
        category="deserialization-sanitize",
        description="JSON loads (safe for data)",
        pattern=r"json\.loads\s*\(",
        action=SanitizerAction.REMOVE,
        handles_kinds=[TaintKind.DIRECT],
        languages=["python"],
        confidence=0.8,
        cwe_ids=["CWE-502"],
        is_strong=True,
        tags=["deserialization", "sanitization"],
    ),
    Sanitizer(
        name="url-validate",
        category="url-validate",
        description="URL validation",
        pattern=r"(validators\.url|urlparse|urllib\.parse\.urlparse)\s*\(",
        action=SanitizerAction.VALIDATE,
        handles_kinds=[TaintKind.DIRECT],
        languages=["python"],
        confidence=0.75,
        cwe_ids=["CWE-601"],
        is_strong=False,
        tags=["url", "sanitization"],
    ),
    Sanitizer(
        name="regex-escape",
        category="regex-sanitize",
        description="Regex escape",
        pattern=r"re\.escape\s*\(",
        action=SanitizerAction.ESCAPE,
        handles_kinds=[TaintKind.DIRECT],
        languages=["python"],
        confidence=0.9,
        cwe_ids=["CWE-1333"],
        is_strong=True,
        tags=["regex", "sanitization"],
    ),
]


JAVASCRIPT_SANITIZERS = [
    Sanitizer(
        name="parameterized-query",
        category="sql-parametrize",
        description="Parameterized SQL query",
        pattern=r"(query|execute)\s*\([^,]+,\s*\[",
        action=SanitizerAction.REMOVE,
        handles_kinds=[TaintKind.DIRECT],
        languages=["javascript", "typescript"],
        confidence=0.9,
        cwe_ids=["CWE-89"],
        is_strong=True,
        tags=["sql", "sanitization"],
    ),
    Sanitizer(
        name="sequelize-orm",
        category="sql-parametrize",
        description="Sequelize ORM (safe)",
        pattern=r"\.(findAll|findOne|findByPk|create|update|destroy)\s*\(",
        action=SanitizerAction.REMOVE,
        handles_kinds=[TaintKind.DIRECT],
        languages=["javascript", "typescript"],
        confidence=0.85,
        cwe_ids=["CWE-89"],
        is_strong=True,
        tags=["sql", "sanitization", "sequelize"],
    ),
    Sanitizer(
        name="knex-parameterize",
        category="sql-parametrize",
        description="Knex parameterized query",
        pattern=r"knex\s*\([^)]+\)\.(where|insert|update|delete)\s*\(",
        action=SanitizerAction.REMOVE,
        handles_kinds=[TaintKind.DIRECT],
        languages=["javascript", "typescript"],
        confidence=0.85,
        cwe_ids=["CWE-89"],
        is_strong=True,
        tags=["sql", "sanitization", "knex"],
    ),
    Sanitizer(
        name="html-escape-js",
        category="html-escape",
        description="HTML escaping libraries",
        pattern=r"(escapeHtml|he\.escape|escape\.html|DOMPurify\.sanitize)\s*\(",
        action=SanitizerAction.ESCAPE,
        handles_kinds=[TaintKind.DIRECT],
        languages=["javascript", "typescript"],
        confidence=0.9,
        cwe_ids=["CWE-79"],
        is_strong=True,
        tags=["xss", "sanitization"],
    ),
    Sanitizer(
        name="react-autoescape",
        category="html-escape",
        description="React auto-escapes by default",
        pattern=r"\{[^}]+\}",  # JSX expressions are auto-escaped
        action=SanitizerAction.ESCAPE,
        handles_kinds=[TaintKind.DIRECT],
        languages=["javascript", "typescript"],
        confidence=0.95,
        cwe_ids=["CWE-79"],
        is_strong=True,
        tags=["xss", "sanitization", "react"],
    ),
    Sanitizer(
        name="path-join",
        category="path-normalize",
        description="Path join with validation",
        pattern=r"path\.(join|resolve|normalize)\s*\(",
        action=SanitizerAction.VALIDATE,
        handles_kinds=[TaintKind.DIRECT],
        languages=["javascript", "typescript"],
        confidence=0.7,
        cwe_ids=["CWE-22"],
        is_strong=False,
        tags=["path", "sanitization"],
    ),
    # The JS counterpart of the Python ``path-basename`` entry.  ``basename``
    # returns the final component only, so every ``../`` in the input is
    # discarded rather than preserved -- a genuine neutralizer, unlike
    # ``path.join`` above (VALIDATE), which keeps an absolute path that escapes
    # the base intact.  Without this entry,
    # ``sendFile(path.join(DIR, path.basename(req.query.f)))`` -- the standard
    # safe idiom -- was reported as path traversal.
    Sanitizer(
        name="path-basename-js",
        category="path-normalize",
        description="Strip every directory component from a path (basename)",
        pattern=r"(?:path\s*\.\s*)?basename\s*\(",
        action=SanitizerAction.REMOVE,
        handles_kinds=[TaintKind.DIRECT],
        languages=["javascript", "typescript"],
        confidence=0.95,
        cwe_ids=["CWE-22"],
        is_strong=True,
        tags=["path", "sanitization", "traversal"],
    ),
    Sanitizer(
        name="shell-escape",
        category="command-sanitize",
        description="Shell escape for arguments",
        pattern=r"(shellescape|shell-escape|shlex\.quote)\s*\(",
        action=SanitizerAction.ESCAPE,
        handles_kinds=[TaintKind.DIRECT],
        languages=["javascript", "typescript"],
        confidence=0.85,
        cwe_ids=["CWE-78"],
        is_strong=True,
        tags=["command", "sanitization"],
    ),
    Sanitizer(
        name="url-validate-js",
        category="url-validate",
        description="URL validation",
        pattern=r"(new URL\(|valid-url|is-url|validator\.isURL)\s*\(",
        action=SanitizerAction.VALIDATE,
        handles_kinds=[TaintKind.DIRECT],
        languages=["javascript", "typescript"],
        confidence=0.75,
        cwe_ids=["CWE-601"],
        is_strong=False,
        tags=["url", "sanitization"],
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# REGISTRY CLASS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class TaintRegistry:
    """Registry for sources, sinks, and sanitizers."""

    sources: list[Source] = field(default_factory=list)
    sinks: list[Sink] = field(default_factory=list)
    sanitizers: list[Sanitizer] = field(default_factory=list)

    def __post_init__(self):
        """Initialize with built-in rules."""
        self.load_builtins()

    def load_builtins(self) -> None:
        """Load built-in sources, sinks, and sanitizers."""
        self.sources.extend(PYTHON_SOURCES)
        self.sources.extend(JAVASCRIPT_SOURCES)
        self.sinks.extend(PYTHON_SINKS)
        self.sinks.extend(JAVASCRIPT_SINKS)
        self.sanitizers.extend(PYTHON_SANITIZERS)
        self.sanitizers.extend(JAVASCRIPT_SANITIZERS)

    def add_source(self, source: Source) -> None:
        """Add a custom source."""
        self.sources.append(source)

    def add_sink(self, sink: Sink) -> None:
        """Add a custom sink."""
        self.sinks.append(sink)

    def add_sanitizer(self, sanitizer: Sanitizer) -> None:
        """Add a custom sanitizer."""
        self.sanitizers.append(sanitizer)

    def get_sources(self, language: Optional[str] = None) -> list[Source]:
        """Get sources, optionally filtered by language."""
        if language:
            return [s for s in self.sources if not s.languages or language in s.languages]
        return self.sources

    def get_sinks(self, language: Optional[str] = None) -> list[Sink]:
        """Get sinks, optionally filtered by language."""
        if language:
            return [s for s in self.sinks if not s.languages or language in s.languages]
        return self.sinks

    def get_sanitizers(self, language: Optional[str] = None) -> list[Sanitizer]:
        """Get sanitizers, optionally filtered by language."""
        if language:
            return [s for s in self.sanitizers if not s.languages or language in s.languages]
        return self.sanitizers

    def find_sources(self, node_name: str, language: str) -> list[Source]:
        """Find sources matching a node name."""
        return [s for s in self.get_sources(language) if s.matches(node_name, language)]

    def find_sinks(self, node_name: str, language: str) -> list[Sink]:
        """Find sinks matching a node name."""
        return [s for s in self.get_sinks(language) if s.matches(node_name, language)]

    def find_sanitizers(self, node_name: str, language: str) -> list[Sanitizer]:
        """Find sanitizers matching a node name."""
        return [s for s in self.get_sanitizers(language) if s.matches(node_name, language)]

    def get_stats(self) -> dict[str, int]:
        """Get registry statistics."""
        return {
            "sources": len(self.sources),
            "sinks": len(self.sinks),
            "sanitizers": len(self.sanitizers),
            "python_sources": len([s for s in self.sources if "python" in s.languages]),
            "javascript_sources": len([s for s in self.sources if "javascript" in s.languages]),
            "python_sinks": len([s for s in self.sinks if "python" in s.languages]),
            "javascript_sinks": len([s for s in self.sinks if "javascript" in s.languages]),
            "python_sanitizers": len([s for s in self.sanitizers if "python" in s.languages]),
            "javascript_sanitizers": len([s for s in self.sanitizers if "javascript" in s.languages]),
        }


# Global registry instance
_default_registry: TaintRegistry | None = None


def get_registry() -> TaintRegistry:
    """Get or create the default taint registry."""
    global _default_registry
    if _default_registry is None:
        _default_registry = TaintRegistry()
    return _default_registry