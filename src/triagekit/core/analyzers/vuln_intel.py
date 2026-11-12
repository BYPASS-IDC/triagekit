"""Vulnerability and exploit intelligence enrichment.

OSV already returns a CVSS v4.0 vector string, GHSA/CVE aliases, CWE ids and
reference URLs.  The dependency scanner kept only id/summary/severity/fixed, so
every one of those arrived and was thrown away.  This module recovers them.

Deliberate scope limits, both measured:

* **No numeric CVSS is ever computed here.**  CVSS v4.0 is scored by a lookup
  table on FIRST.org, not a formula, so any locally-derived score would be a
  guess presented as a measurement.  Where OSV supplies a vector it is passed
  through verbatim and a calculator link is emitted; where it does not, a
  vector is *derived from the finding's own evidence* using a documented rule
  table and flagged as derived.  Both paths always surface the FIRST.org
  calculator link, which is where the number comes from.
* **No exploit code is downloaded or executed.**  Only public metadata:
  advisory identifiers, reference URLs, searchsploit results when the tool is
  installed locally, and a Metasploit *module index* mapping.  Every record
  carries its provenance so a consumer can tell measured data from a curated
  cross-reference.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional
from urllib.parse import quote_plus

# ── CVSS v4.0 ────────────────────────────────────────────────────────────
# Metric values accepted per metric, used only to validate a vector we are
# about to pass through or link to.  Nothing here scores anything.
_CVSS_V4_BASE_ORDER = [
    "AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA",
]
_CVSS_V4_VALUES = {
    "AV": ("N", "A", "L", "P"),
    "AC": ("L", "H"),
    "AT": ("N", "P"),
    "PR": ("N", "L", "H"),
    "UI": ("N", "P", "A"),
    "VC": ("H", "L", "N"),
    "VI": ("H", "L", "N"),
    "VA": ("H", "L", "N"),
    "SC": ("H", "L", "N"),
    "SI": ("H", "L", "N"),
    "SA": ("H", "L", "N"),
}
_CVSS_CALCULATOR = "https://www.first.org/cvss/calculator/4.0"
_CVSS_VECTOR_RE = re.compile(r"CVSS:4\.0/([A-Z]{2}:[NALHP][A-Za-z:/]*)")
# Any CVSS versioned vector.  Used to recognise one an advisory supplies in a
# version this build does not score.
_CVSS_ANY_VERSION_RE = re.compile(r"CVSS:(3\.[01]|4\.0)/\S+")
_CVSS_CALCULATORS = {
    "3.1": "https://www.first.org/cvss/calculator/3.1",
    "3.0": "https://www.first.org/cvss/calculator/3.0",
    "4.0": _CVSS_CALCULATOR,
}


def cvss_version(vector: Optional[str]) -> Optional[str]:
    """The CVSS version a vector string declares, or None if it is not one.

    ``CVSS:3.1/AV:N/...`` and ``CVSS:4.0/AV:N/...`` are different scoring
    systems: the v4.0 metrics (AT, VC/VI/VA/SC/SI/SA) do not exist in 3.1 and
    ``Scope`` does not exist in 4.0.  A vector is only meaningful next to the
    version it belongs to, so the version is tracked rather than assumed.
    """
    match = _CVSS_ANY_VERSION_RE.search(str(vector or ""))
    return match.group(1) if match else None


def parse_cvss_vector(vector: str) -> dict[str, str] | None:
    """Extract and validate the base metrics of a CVSS v4.0 vector string."""
    match = _CVSS_VECTOR_RE.search(str(vector or ""))
    if not match:
        return None
    metrics: dict[str, str] = {}
    for part in match.group(1).split("/"):
        if ":" not in part:
            continue
        key, _, value = part.partition(":")
        if key in _CVSS_V4_VALUES and value in _CVSS_V4_VALUES[key]:
            metrics[key] = value
    return metrics or None


def calculator_link(vector: str) -> str:
    """FIRST.org calculator link with the vector pre-applied."""
    return f"{_CVSS_CALCULATOR}#{vector}"


# A CVSS vector derived from a vulnerability class, used only when the upstream
# advisory supplies none.  Every row names the attack surface the (single) taint
# source that reaches the sink actually gives an attacker, which is what the
# exploitability metrics measure.  Rows are deliberately conservative: impact is
# never set to High without the evidence for it.
_CLASS_VECTORS: dict[str, str] = {
    # SQL injection: network, no privileges, no interaction; read+modify the
    # application's own data, no downstream system impact.
    "sql-execution": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    # Command injection: full integrity loss in the vulnerable system.
    "command-execution": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "code-execution": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    # XSS: the victim's browser is a subsequent system.
    "xss": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N",
    "dom-xss": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N",
    # Path traversal: read files, limited modification.
    "path-traversal": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
    # Unsafe deserialization typically yields code execution.
    "deserialization": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    # SSRF: the vulnerable app reaches an internal target on the attacker's
    # behalf; confidential data of the app is exposed, not the target's.
    "ssrf": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "template-injection": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "open-redirect": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:N/SC:L/SI:L/SA:N",
    "xxe": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "log-injection": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:L/SC:N/SI:N/SA:N",
    "ldap-injection": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "xpath-injection": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "regex-dos": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
}


# ── CWE ──────────────────────────────────────────────────────────────────
# CWE -> (short label, what it means, what fixes it).  Keyed by the ids the
# taint registry and OSV actually emit, so an unknown id degrades to a generic
# row instead of being dropped.
_CWE_GUIDANCE: dict[str, tuple[str, str, str]] = {
    "CWE-78": ("OS Command Injection", "Attacker-supplied text becomes part of a command line executed by a shell.", "Pass an argument array to subprocess without shell=True; never build a command string."),
    "CWE-79": ("Cross-site Scripting (XSS)", "Untrusted input is emitted into a page without contextual output encoding.", "Contextually encode on output; enable a strict CSP; use framework autoescaping."),
    "CWE-89": ("SQL Injection", "Untrusted input alters the structure of a SQL statement.", "Use parameterized statements / an ORM; never concatenate or interpolate into SQL."),
    "CWE-22": ("Path Traversal", "A path built from untrusted input escapes its intended directory.", "Resolve and verify the result stays under an allowlisted root; reject '..' and absolute paths."),
    "CWE-502": ("Deserialization of Untrusted Data", "Data from an untrusted source is turned back into live objects.", "Use json / ast.literal_eval; never unpickle or yaml.load untrusted input."),
    "CWE-94": ("Code Injection", "Untrusted input is evaluated as code or as a template.", "Never eval/exec untrusted input; never render user input as template source."),
    "CWE-611": ("XML External Entity (XXE)", "An XML parser resolves external entities from untrusted documents.", "Use defusedxml or disable entity/DTD resolution in the parser."),
    "CWE-918": ("Server-Side Request Forgery", "The server fetches an attacker-supplied URL, reaching internal services.", "Allowlist destinations and schemes; block link-local and metadata ranges."),
    "CWE-601": ("Open Redirect", "An unvalidated target sends users to an attacker-chosen site.", "Redirect only to an allowlisted set of paths; never to raw user input."),
    "CWE-352": ("Cross-Site Request Forgery", "A state-changing request is triggered by another site.", "Require an anti-CSRF token and verify Origin on state-changing methods."),
    "CWE-287": ("Improper Authentication", "Authentication is missing, bypassable, or applied inconsistently.", "Enforce authentication at the trust boundary; verify on the server, not the client."),
    "CWE-798": ("Hardcoded Credentials", "A secret is embedded in source or configuration.", "Load secrets from the environment or a secret manager; rotate anything committed."),
    "CWE-327": ("Broken Cryptographic Algorithm", "A weak or broken primitive is used.", "Use SHA-256+ for digests, AES-GCM/ChaCha20 for encryption, and a vetted password KDF."),
    "CWE-328": ("Weak Password Hash", "A fast, unsalted or trivially cracked digest stores passwords.", "Use argon2id, scrypt or bcrypt with per-credential salt."),
    "CWE-330": ("Insufficient Randomness", "A non-cryptographic PRNG produces a security-relevant token.", "Use secrets / os.urandom for anything an attacker must not predict."),
    "CWE-312": ("Cleartext Storage", "Sensitive data is stored without protection.", "Encrypt at rest and restrict access to the store."),
    "CWE-319": ("Cleartext Transmission", "Data travels without transport protection.", "Serve HTTPS only, enable HSTS, and refuse plaintext."),
    "CWE-200": ("Information Exposure", "Internal detail is disclosed to an attacker.", "Remove version banners, debug output and stack traces from responses."),
    "CWE-400": ("Uncontrolled Resource Consumption", "Unbounded work allows denial of service.", "Bound sizes/timeouts/rates and fail fast."),
    "CWE-1333": ("Inefficient Regular Expression", "A pattern with catastrophic backtracking stalls on crafted input.", "Avoid user input in patterns; use linear-time matchers or a timeout."),
    "CWE-1204": ("UI Redressing / Clickjacking", "The page is framed by an attacker.", "Set X-Frame-Options or CSP frame-ancestors."),
    "CWE-693": ("Protection Mechanism Failure", "A defensive control is missing or misconfigured.", "Enable and verify the control; add nosniff and a tight CSP."),
    "CWE-1021": ("Improper Restriction of Rendering in a Frame", "The page can be embedded by a third party.", "Set frame-ancestors or X-Frame-Options."),
    "CWE-1104": ("Use of Unmaintained Third Party Components", "A dependency is unmaintained or exposed.", "Upgrade or replace the component; track advisories."),
    "CWE-16": ("Configuration", "An insecure default or setting is in effect.", "Harden the configuration and fail closed."),
    "CWE-250": ("Execution with Unnecessary Privileges", "Code runs with more privilege than it needs.", "Drop privileges and scope permissions to the minimum."),
    "CWE-754": ("Improper Check for Unusual Conditions", "An error condition is not handled and breaks the flow.", "Handle and log the exceptional path explicitly."),
    "CWE-20": ("Improper Input Validation", "Input is trusted without validating shape or range.", "Validate against an allowlist at the trust boundary."),
    "CWE-117": ("Log Injection", "Unvalidated input is written into a log record.", "Encode newlines and control characters before logging."),
    "CWE-524": ("Use of Cache Containing Sensitive Information", "Sensitive data is placed in a cache.", "Mark sensitive responses no-store and scope cache keys."),
}


# ── Vulnerability-class vocabulary ───────────────────────────────────────
# Maps a vulnerability *class* to the words a reviewer types when looking for
# how that class is attacked in practice.  This is a search-term table, not
# exploit content: it lets a report hand the reader a working query into the
# public module/exploit databases.  Nothing here is downloaded, executed, or
# pointed at a target.
#
# These TERMS, not module paths: the earlier table held Metasploit-style paths
# such as "auxiliary/scanner/http/" and an invented
# "exploits/*/sqlmap_style_param_probes".  Passing those to the public search
# box as the query searched for the path string itself and matched nothing, so
# the Metasploit/ExploitDB capability was reachable but useless.  A public
# search is done on the vulnerable product plus the class of weakness.
_CLASS_SEARCH_TERMS: dict[str, str] = {
    "sql-execution": "SQL injection",
    "command-execution": "command execution",
    "code-execution": "remote code execution",
    "xss": "cross-site scripting",
    "deserialization": "deserialization remote code execution",
    "path-traversal": "path traversal",
    "ssrf": "server-side request forgery",
    "open-redirect": "open redirect",
    "xxe": "XML external entity",
    "template-injection": "template injection",
    "log-injection": "log injection",
    "regex-dos": "regular expression denial of service",
}
# Deliberately no "default" entry: for an unknown or absent CWE the class is
# simply not known, and inventing "remote code execution" as the search term
# would assert an impact nobody measured.  Those searches fall back to the
# bare product name.
_METASPLOIT_SEARCH = "https://www.rapid7.com/db/?q="
_EDB_SEARCH = "https://www.exploit-db.com/search?q="
_NVD_SEARCH = "https://nvd.nist.gov/vuln/search?query="


def _dedupe_terms(items: Iterable[Any]) -> list[str]:
    """Drop blanks and case-insensitive duplicates, preserving order."""
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        term = str(item or "").strip()
        if term and term.lower() not in seen:
            seen.add(term.lower())
            out.append(term)
    return out


def _product_terms(package: str, version: Optional[str]) -> list[str]:
    """The bare product terms a reviewer would type into an exploit database."""
    product = str(package or "").strip()
    if not product:
        return []
    ver = str(version or "").strip()
    return [f"{product} {ver}"] if ver else [product]


def _identifier_terms(cve_ids: Iterable[Any], aliases: Iterable[Any]) -> list[str]:
    """CVE and advisory aliases, most precise first (these are indexed)."""
    return _dedupe_terms(list(cve_ids or []) + list(aliases or []))


def exploitdb_terms(intel: "VulnIntel") -> list[str]:
    """Ranked ExploitDB search terms.

    ExploitDB indexes by CVE and by the affected product *version*, so the
    versioned product name is the most useful fallback when no CVE exists.
    """
    return (_identifier_terms(intel.cve_ids, intel.aliases)
            + _product_terms(intel.package, intel.version))[:6]


def _class_term(category: Optional[str]) -> Optional[str]:
    """The class phrase for a known category, or None when it is not known."""
    if not category:
        return None
    return _CLASS_SEARCH_TERMS.get(category)


def metasploit_terms(intel: "VulnIntel") -> list[str]:
    """Ranked Rapid7 module-DB search terms.

    Rapid7's database names modules by the target product and the action the
    module performs ("Apache Log4j", "Exchange Server", ...), so the product
    plus the vulnerability class is the most useful term there -- it is what a
    reviewer types when looking for how this class is actually attacked.  When
    the class is unknown, the bare product is used rather than a term that
    claims an impact nobody measured.
    """
    product = str(intel.package or "").strip()
    class_term = _class_term(_category_from_cwes(intel.cwe_ids))
    combo = " ".join(part for part in (product, class_term) if part)
    return _dedupe_terms([combo] + _identifier_terms(intel.cve_ids, intel.aliases))[:4]


@dataclass
class VulnIntel:
    """Everything public intelligence can add to one dependency advisory.

    ``__post_init__`` fills the derived fields so the object is self-consistent
    on *every* construction path.  Only ``enrich_osv_vuln`` used to populate
    them, which meant an intel built directly -- in a test, in a report, in a
    caller that has the advisory fields already -- silently lost its exploit
    references and its CVSS link.
    """

    package: str
    version: Optional[str]
    ecosystem: str
    advisory_id: Optional[str] = None
    aliases: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    summary: str = ""
    severity: str = "medium"
    fixed: Optional[str] = None
    cvss_vector: Optional[str] = None
    cvss_source: str = "none"  # advisory | derived | none
    cvss_link: Optional[str] = None
    # A vector the advisory supplies in a CVSS version this build does not
    # score (3.1 or 3.0).  It is real severity information, so it is kept and
    # linked to its own calculator -- never rewritten as a v4.0 vector, which
    # would mislabel it and send it to a calculator that cannot read it.
    cvss_other_vector: Optional[str] = None
    references: list[str] = field(default_factory=list)
    metasploit_queries: list[str] = field(default_factory=list)
    exploitdb_queries: list[str] = field(default_factory=list)
    provenance: str = "osv"

    def __post_init__(self) -> None:
        if not self.exploitdb_queries:
            self.exploitdb_queries = exploitdb_terms(self)
        if not self.metasploit_queries:
            self.metasploit_queries = metasploit_terms(self)
        # Derive a class vector only when the advisory supplied none at all.
        # The class table is a stand-in for missing data, not an addition to
        # data that exists: placing a derived (explicitly unmeasured) v4.0
        # vector next to the advisory's own measurement invites the reader to
        # prefer the invented one.
        if not self.cvss_link and not self.cvss_other_vector:
            _cvss_vector_for(self)

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "advisory_id": self.advisory_id,
            "aliases": self.aliases,
            "cve_ids": self.cve_ids,
            "cwe_ids": self.cwe_ids,
            "summary": self.summary,
            "severity": self.severity,
            "fixed": self.fixed,
            "cvss_vector": self.cvss_vector,
            "cvss_source": self.cvss_source,
            "cvss_link": self.cvss_link,
            "cvss_other_vector": self.cvss_other_vector,
            "references": self.references,
            "metasploit_queries": self.metasploit_queries,
            "exploitdb_queries": self.exploitdb_queries,
            "provenance": self.provenance,
        }


def _cvss_vector_for(intel: "VulnIntel", category_hint: Optional[str] = None) -> None:
    """Attach a CVSS vector, preferring the advisory's own.

    The advisory vector is authoritative, so it is used verbatim.  Only when
    there is none does the class table supply one, and that is recorded as
    ``derived`` so a reader knows it was not measured.
    """
    if intel.cvss_vector:
        intel.cvss_link = calculator_link(intel.cvss_vector)
        return
    key = category_hint or _category_from_cwes(intel.cwe_ids)
    vector = _CLASS_VECTORS.get(key)
    if not vector:
        return
    intel.cvss_vector = vector
    intel.cvss_source = "derived"
    intel.cvss_link = calculator_link(vector)


def _category_from_cwes(cwe_ids: Iterable[str]) -> Optional[str]:
    """Best-effort CWE -> our taint-sink category vocabulary."""
    table = {
        "CWE-89": "sql-execution",
        "CWE-78": "command-execution",
        "CWE-79": "xss",
        "CWE-22": "path-traversal",
        "CWE-502": "deserialization",
        "CWE-94": "code-execution",
        "CWE-918": "ssrf",
        "CWE-601": "open-redirect",
        "CWE-611": "xxe",
        "CWE-1333": "regex-dos",
        "CWE-117": "log-injection",
    }
    for cwe in cwe_ids:
        if cwe in table:
            return table[cwe]
    return None


def _reference_kind(url: str) -> str:
    """Classify a reference URL by host so consumers can weight it."""
    low = url.lower()
    if "exploit-db" in low:
        return "exploitdb"
    if "rapid7" in low or "metasploit" in low:
        return "metasploit"
    if "nvd.nist.gov" in low:
        return "nvd"
    if "github.com" in low and "advisories" in low:
        return "ghsa"
    if "github.com" in low:
        return "github"
    if "packetstorm" in low or "seebug" in low:
        return "exploitdb-mirror"
    return "other"


def enrich_osv_record(record: dict[str, Any]) -> VulnIntel:
    """Turn one dependency-scan advisory record into an enriched VulnIntel.

    ``record`` is the shape :func:`triagekit.core.analyzers.cve.query_osv`
    returns: package, version and ecosystem are read from the record itself
    rather than passed separately, so the advisory can never be enriched under
    a package name the caller made up.

    A raw OSV response object is accepted too (``database_specific`` and the
    nested ``affected[].ranges[]`` form), which is what a caller gets straight
    from the OSV API; the two shapes are normalised here so neither consumer
    has to know the difference.
    """
    raw = "database_specific" in record or "affected" in record
    db_specific = record.get("database_specific") or {}
    if not isinstance(db_specific, dict):
        db_specific = {}

    aliases = [str(a) for a in (record.get("aliases") or []) if a]
    if not aliases and not raw:
        # A flat record without aliases carries nothing else to derive them
        # from, so there is nothing to guess.
        aliases = []

    cve_ids = [a for a in aliases if a.upper().startswith("CVE-")]
    if not cve_ids and not raw:
        # GHSA-style ids are aliases, never CVE ids; do not promote them.
        cve_ids = []

    cwe_ids = [
        str(c).upper() for c in (record.get("cwes") or db_specific.get("cwe_ids") or [])
        if str(c).upper().startswith("CWE-")
    ]
    if not cwe_ids:
        cwe_ids = [c.upper() for c in re.findall(
            r"CWE-\d{1,4}", json.dumps(record.get("severity") or "")
        )]

    references: list[str] = []
    for ref in record.get("references") or []:
        url = str(ref.get("url")) if isinstance(ref, dict) else str(ref or "")
        if url.startswith("http") and url not in references:
            references.append(url)

    fixed = record.get("fixed")
    if fixed is None:
        # Raw form: the fixed version lives in the nested event list.
        for affected in record.get("affected") or []:
            if not isinstance(affected, dict):
                continue
            for rng in affected.get("ranges") or []:
                if not isinstance(rng, dict):
                    continue
                for event in rng.get("events") or []:
                    if isinstance(event, dict) and event.get("fixed"):
                        fixed = str(event["fixed"])
                        break
    fixed = str(fixed) if fixed is not None else None

    cvss_vector = record.get("cvss_vector") or _raw_cvss_vector(record)
    cvss_other_vector = None
    if cvss_vector is not None:
        version = cvss_version(cvss_vector)
        if version == "4.0":
            cvss_vector = str(cvss_vector).strip() or None
        else:
            # Not a v4.0 vector.  Keep it separately so it cannot be labelled
            # v4.0 or fed to the v4.0 calculator.
            cvss_other_vector = str(cvss_vector).strip() or None
            cvss_vector = None
    # Coerce only what is actually present.  str(None) is the four-character
    # string "None", which is truthy: a record with no CVSS field used to come
    # out of here carrying cvss_vector="None", which then produced a report
    # link of ".../calculator/4.0#None" labelled as advisory-supplied.

    severity = str(
        record.get("severity") if isinstance(record.get("severity"), str)
        else db_specific.get("severity") or ""
    ).lower().strip() or None
    if severity not in ("critical", "high", "medium", "low"):
        severity = _severity_from_vector(parse_cvss_vector(cvss_vector or ""))

    summary = str(record.get("summary") or "").strip()
    if not summary:
        summary = str(record.get("details") or "")
    summary = re.sub(r"\s+", " ", summary).strip()[:400]

    return VulnIntel(
        package=str(record.get("package") or ""),
        version=(str(record["version"]) if record.get("version") else None),
        ecosystem=str(record.get("ecosystem") or ""),
        advisory_id=str(record.get("id") or "") or None,
        aliases=aliases,
        cve_ids=cve_ids,
        cwe_ids=list(dict.fromkeys(cwe_ids)),
        summary=summary,
        severity=severity or "medium",
        fixed=fixed,
        cvss_vector=cvss_vector,
        cvss_source="advisory" if cvss_vector else "none",
        cvss_other_vector=cvss_other_vector,
        references=references,
    )


# The name the rest of the codebase used before the record shape settled.
enrich_osv_vuln = enrich_osv_record


def _raw_cvss_vector(record: dict[str, Any]) -> Optional[str]:
    """The CVSS vector in a raw OSV response object, if it has one."""
    for entry in record.get("severity") or []:
        if not isinstance(entry, dict):
            continue
        score = str(entry.get("score") or "").strip()
        if _CVSS_ANY_VERSION_RE.search(score):
            return score
    return None


def _severity_from_vector(metrics: Optional[dict[str, str]]) -> str:
    """Coarse severity from CVSS metrics *only* when nothing better is given.

    This is a band label, not a CVSS score: it never claims to be one and is
    used purely so a finding without an explicit severity still sorts.
    """
    if not metrics:
        return "medium"
    if metrics.get("AV") == "N" and metrics.get("PR") == "N" and metrics.get("UI") == "N":
        if (metrics.get("VC") == "H" or metrics.get("VI") == "H"
                or metrics.get("VA") == "H"):
            return "critical"
        return "high"
    if metrics.get("VC") == "H" or metrics.get("VI") == "H":
        return "medium"
    return "low"


def cwe_guidance(cwe_ids: Iterable[str]) -> list[dict[str, str]]:
    """Human guidance for each CWE id, with a generic fallback per unknown id."""
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw in cwe_ids:
        cwe = str(raw).upper()
        if cwe in seen:
            continue
        seen.add(cwe)
        label, meaning, fix = _CWE_GUIDANCE.get(
            cwe,
            (
                cwe,
                "A recorded weakness with no local description. Look the id up in the MITRE CWE list.",
                "Apply the vendor advisory's remediation; verify the control at the trust boundary.",
            ),
        )
        out.append({
            "cwe": cwe,
            "label": label,
            "what_it_means": meaning,
            "how_to_fix": fix,
            "url": f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[-1]}.html",
        })
    return out


def reference_links(intel: VulnIntel) -> list[dict[str, str]]:
    """Public reference links for one advisory, classified by kind."""
    out: list[dict[str, str]] = []
    for url in intel.references:
        kind = _reference_kind(url)
        if kind == "other":
            continue
        out.append({"kind": kind, "url": url})
    for cve in intel.cve_ids:
        # Only offer an NVD search link when no NVD URL came back with the
        # advisory; otherwise this duplicates a reference already listed.
        if any(_reference_kind(url) == "nvd" for url in intel.references):
            continue
        out.append({"kind": "nvd-search", "url": f"{_NVD_SEARCH}{quote_plus(cve)}"})
    return out


def metasploit_links(intel: VulnIntel) -> list[dict[str, str]]:
    """Public Metasploit / ExploitDB search links for this advisory.

    These are search URLs, never module content: TriageKit tells a reviewer
    where public attack tooling for the class can be studied, and does not
    fetch or run it.
    """
    out: list[dict[str, str]] = []
    # Two Rapid7 links is enough: the product+class search and the first
    # advisory identifier.  One link per stored query is noise in a report.
    for query in intel.metasploit_queries[:2]:
        out.append({
            "source": "rapid7-db",
            "query": query,
            "url": f"{_METASPLOIT_SEARCH}{quote_plus(query)}",
        })
    if intel.exploitdb_queries:
        out.append({
            "source": "exploit-db",
            "query": " ".join(intel.exploitdb_queries[:3]),
            "url": f"{_EDB_SEARCH}{quote_plus(intel.exploitdb_queries[0])}",
        })
    return out


def intel_markdown(items: Iterable[VulnIntel]) -> str:
    """Render enriched advisories for a report."""
    lines = ["## Vulnerability and exploit intelligence", ""]
    any_items = False
    for i in items:
        any_items = True
        target = f"{i.package}" + (f" {i.version}" if i.version else "")
        lines.append(f"### {target} — {i.advisory_id or 'advisory'}")
        if i.aliases:
            lines.append(f"- **Identifiers:** {', '.join(i.aliases)}")
        if i.cwe_ids:
            lines.append(f"- **CWE:** {', '.join(i.cwe_ids)}")
        lines.append(f"- **Severity band:** {i.severity}")
        if i.fixed:
            lines.append(f"- **Fixed in:** {i.fixed}")
        if i.cvss_vector:
            src = ("advisory-supplied" if i.cvss_source == "advisory"
                   else "derived from the vulnerability class (not measured)")
            lines.append(f"- **CVSS v4.0 vector** ({src}): `{i.cvss_vector}`")
            if i.cvss_link:
                lines.append(f"  - Score at the FIRST.org calculator: {i.cvss_link}")
        if i.cvss_other_vector:
            # Kept and linked on its own terms.  Rewriting a 3.1 vector as 4.0
            # would assert a mapping this build does not do; dropping it would
            # throw away an advisory-supplied measurement.
            version = cvss_version(i.cvss_other_vector) or "?"
            base = _CVSS_CALCULATORS.get(version, _CVSS_CALCULATOR)
            lines.append(
                f"- **CVSS v{version} vector (advisory-supplied, not scored by this "
                f"build):** `{i.cvss_other_vector}`"
            )
            lines.append(f"  - Score it at the FIRST.org v{version} calculator: {base}#{i.cvss_other_vector}")
        if i.summary:
            lines.append(f"- **Summary:** {i.summary}")
        for guide in cwe_guidance(i.cwe_ids):
            lines.append(
                f"  - {guide['cwe']} ({guide['label']}): {guide['what_it_means']} "
                f"**Fix:** {guide['how_to_fix']} ({guide['url']})"
            )
        links = metasploit_links(i)
        if links:
            lines.append("- **Public attack reference (search only, not executed):**")
            for link in links:
                lines.append(f"  - {link['source']}: {link['url']}")
        lines.append("")
    if not any_items:
        return ""
    lines.append(
        "*Reference metadata only — TriageKit does not download, weaponise or "
        "execute exploit code, and does not score CVSS numerically; the "
        "calculator link is where the score comes from.*"
    )
    return "\n".join(lines)
