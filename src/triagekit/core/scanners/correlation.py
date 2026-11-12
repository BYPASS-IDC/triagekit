"""Cross-scanner correlation and deduplication engine."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from .base import ScanResult, ScanType, Severity, UnifiedFinding


# ---------------------------------------------------------------------------
# Advisory identity (defect D64)
# ---------------------------------------------------------------------------
# A dependency finding is identified by its advisory, not by where it was
# found.  Twenty advisories for one package share the package, share the
# manifest, and share a line number of 0 -- because a manifest is a list and
# neither dependency scanner records a position in it.  Any rule that decides
# "duplicate" from file and line therefore held for every pair of them, and a
# scan of a repository pinning flask==0.12.2 and requests==2.19.1 reported 1
# vulnerable dependency where it had found 12.  The report was eleven
# vulnerabilities cleaner than the code.

_DEPENDENCY_CATEGORY = "vulnerable-dependency"

# An advisory identifier, so a title can be read as one.  OSV answers with
# GHSA-, CVE-, PYSEC- and GSD- ids.  The leading segment of a prose title
# ("Vulnerable dependency") is NOT an identifier: matching it would make every
# advisory for a package compare equal on the words before the colon, which is
# the very thing this gate exists to stop.
_ADVISORY_ID_RE = re.compile(
    r"^(?:GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}"
    r"|CVE-\d{4}-\d{3,9}"
    r"|PYSEC-[\w.\-]+"
    r"|GSD-[\w.\-]+"
    r"|OSV-[\w.\-]+)",
    re.IGNORECASE,
)


def advisory_id(finding: UnifiedFinding) -> Optional[str]:
    """The advisory a finding names, or None when it names none.

    ``scanner_metadata["advisory_id"]`` is the authoritative source and both
    dependency scanners set it.  The title is read as a fallback so that a
    finding which lost its metadata still separates from its neighbours, but
    only when the leading segment really is an identifier.
    """
    meta = getattr(finding, "scanner_metadata", None) or {}
    value = str(meta.get("advisory_id") or "").strip()
    if value:
        return value
    title = str(getattr(finding, "title", "") or "").strip()
    if not title:
        return None
    head = title.split(":", 1)[0].strip()
    return head if _ADVISORY_ID_RE.match(head) else None


@dataclass
class CorrelationRule:
    """Rule for correlating findings across scanners."""

    name: str
    description: str
    primary_types: list[ScanType]
    related_types: list[ScanType]
    match_fields: list[str]  # Fields to match for correlation
    severity_boost: dict[str, str] = field(default_factory=dict)  # Finding type -> boosted severity
    confidence_threshold: float = 0.7


@dataclass
class CorrelatedGroup:
    """A group of correlated findings from multiple scanners."""

    id: str
    primary_finding: UnifiedFinding
    related_findings: list[UnifiedFinding] = field(default_factory=list)
    scan_types: set[ScanType] = field(default_factory=set)
    combined_severity: Severity = Severity.MEDIUM
    combined_confidence: float = 0.5
    attack_path: list[str] = field(default_factory=list)
    remediation_priority: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


class FindingDeduplicator:
    """Deduplicates findings within and across scan results."""

    def __init__(
        self,
        fingerprint_weight: float = 0.8,
        fuzzy_match_threshold: float = 0.85,
    ):
        self.fingerprint_weight = fingerprint_weight
        self.fuzzy_match_threshold = fuzzy_match_threshold
        self._seen_fingerprints: dict[str, UnifiedFinding] = {}
        self._fuzzy_cache: dict[str, list[UnifiedFinding]] = {}

    def deduplicate(self, findings: list[UnifiedFinding]) -> list[UnifiedFinding]:
        """Deduplicate a list of findings using fingerprint and fuzzy matching."""
        unique: list[UnifiedFinding] = []
        fingerprint_map: dict[str, list[UnifiedFinding]] = defaultdict(list)

        # Group by fingerprint
        for finding in findings:
            fp = finding.fingerprint or finding.compute_fingerprint()
            fingerprint_map[fp].append(finding)

        # Process each fingerprint group
        for fp, group in fingerprint_map.items():
            if len(group) == 1:
                unique.append(group[0])
                self._seen_fingerprints[fp] = group[0]
            else:
                # Merge duplicates in the same fingerprint group
                merged = self._merge_duplicates(group)
                unique.append(merged)
                self._seen_fingerprints[fp] = merged

        # Fuzzy matching for near-duplicates across different fingerprints
        unique = self._fuzzy_deduplicate(unique)

        return unique

    def _merge_duplicates(self, duplicates: list[UnifiedFinding]) -> UnifiedFinding:
        """Merge multiple duplicate findings into one."""
        if not duplicates:
            raise ValueError("Cannot merge empty list")

        # Sort by severity (critical first) and confidence
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFORMATIONAL: 4,
        }
        duplicates.sort(key=lambda f: (severity_order.get(f.severity, 5), -hash(f.fingerprint)))

        primary = duplicates[0]
        primary.correlated_findings = [d.id for d in duplicates[1:]]

        # Mark others as duplicates
        for dup in duplicates[1:]:
            dup.is_duplicate = True
            dup.duplicate_of = primary.id

        # Merge evidence and metadata
        all_evidence = [d.evidence for d in duplicates if d.evidence]
        if all_evidence:
            primary.evidence = "; ".join(all_evidence[:3])  # Limit to 3

        all_snippets = [d.snippet for d in duplicates if d.snippet]
        if all_snippets:
            primary.snippet = all_snippets[0]

        # Merge CWE IDs
        cwe_set = set()
        for d in duplicates:
            cwe_set.update(d.cwe_ids)
        primary.cwe_ids = list(cwe_set)

        # Merge MITRE ATT&CK IDs
        mitre_set = set()
        for d in duplicates:
            mitre_set.update(d.mitre_attack_ids)
        primary.mitre_attack_ids = list(mitre_set)

        # Merge tags
        tag_set = set()
        for d in duplicates:
            tag_set.update(d.tags)
        primary.tags = list(tag_set)

        # Update scanner metadata to track all sources
        for d in duplicates[1:]:
            primary.scanner_metadata[f"duplicate_from_{d.scanner_name}"] = {
                "scanner": d.scanner_name,
                "original_id": d.id,
                "original_severity": d.severity.value,
            }

        return primary

    def _fuzzy_deduplicate(self, findings: list[UnifiedFinding]) -> list[UnifiedFinding]:
        """Fuzzy deduplication based on title/location similarity."""
        if len(findings) <= 1:
            return findings

        unique: list[UnifiedFinding] = []
        processed: set[int] = set()

        for i, f1 in enumerate(findings):
            if i in processed:
                continue

            matches = [f1]
            for j, f2 in enumerate(findings[i + 1:], i + 1):
                if j in processed:
                    continue

                if self._are_similar(f1, f2):
                    matches.append(f2)
                    processed.add(j)

            if len(matches) > 1:
                merged = self._merge_duplicates(matches)
                unique.append(merged)
            else:
                unique.append(f1)

            processed.add(i)

        return unique

    def _are_similar(self, f1: UnifiedFinding, f2: UnifiedFinding) -> bool:
        """Check if two findings are similar enough to be duplicates."""
        # Different categories = not similar
        if f1.category != f2.category:
            return False

        # Different scanners = not similar (preserve cross-scanner correlation)
        if f1.scanner_name != f2.scanner_name:
            return False

        # Two different advisories are two different vulnerabilities, whatever
        # else they share (defect D64).  Checked before the location rules
        # below, because for a manifest the location is identical for all of
        # them and would otherwise answer "duplicate" for every pair.
        id1 = advisory_id(f1)
        id2 = advisory_id(f2)
        if id1 and id2 and id1 != id2:
            return False

        # A dependency manifest is a list, not a line.  Every entry in
        # requirements.txt shares one file_path and a line number of 0, so
        # "same file and line" is true for every advisory in the file and
        # decides nothing.  For an identified finding the advisory id is the
        # answer; for an unidentified one fall through and let the title
        # comparison decide, which a genuine duplicate satisfies.
        if f1.category == _DEPENDENCY_CATEGORY:
            if id1 and id2:
                return id1 == id2
        elif f1.file_path and f2.file_path:
            # Same file and line = likely duplicate
            if f1.file_path == f2.file_path and f1.line_number == f2.line_number:
                return True

        # Same URL and parameter = likely duplicate
        if f1.url and f2.url:
            if f1.url == f2.url and f1.parameter == f2.parameter:
                return True

        # Title similarity (Jaccard on words)
        title1_words = set(f1.title.lower().split())
        title2_words = set(f2.title.lower().split())
        if title1_words and title2_words:
            intersection = len(title1_words & title2_words)
            union = len(title1_words | title2_words)
            if union > 0:
                jaccard = intersection / union
                if jaccard >= self.fuzzy_match_threshold:
                    return True

        return False

    def deduplicate_across_results(self, results: list[ScanResult]) -> list[ScanResult]:
        """Deduplicate findings across multiple scan results."""
        all_findings: list[UnifiedFinding] = []
        for result in results:
            all_findings.extend(result.findings)

        deduplicated = self.deduplicate(all_findings)

        # Redistribute back to results (keeping original result structure)
        # For now, return a new combined result
        combined = ScanResult(
            scanner_name="correlated",
            scanner_version="1.0",
            scan_type=ScanType.STATIC_ANALYSIS,
            target="correlated",
            status=results[0].status if results else None,
            findings=deduplicated,
        )
        return [combined]


# ---------------------------------------------------------------------------
# Cross-layer precedence (defect D39)
# ---------------------------------------------------------------------------
# Two layers can report the same line for the same defect: the regex layer
# matches a shape, the taint layer proves data reaches it.  Both are real
# evidence, but they are not equal, and a report that shows them as two
# unrelated findings -- with no statement of which to trust -- invites the reader
# to believe whichever one they happened to read first.
#
# The precedence is: TAINT beats REGEX at the same location, because a taint
# finding carries a source, a trace, and a sink while the regex finding carries
# only a pattern.  The weaker finding is not discarded: it is folded into the
# surviving one as corroboration, and the surviving one records that a second,
# independent layer agreed.

_LAYER_RANK = {"taint": 3, "probe": 3, "regex": 2, "dependency": 2, "intel": 1, "risk": 0}

# A regex finding in one of these categories describes the same defect as a
# taint finding whose sink category matches.  Keyed by the regex rule id / category.
#
# Both spellings are listed: the tree-walking repository scanner reports the
# canonical rule id (``command-injection``) while the diff scanner reports the
# public alias (``command-injection-risk``).  Since the diff layer now derives
# its rules from the same table as the tree walker, every language-specific rule
# family appears here too -- otherwise a Java SQL injection in a pull request
# would be reported twice instead of once, corroborated.
def _sink_map() -> dict[str, set[str]]:
    m: dict[str, set[str]] = {
        "command-injection": {"command-execution"},
        "shell-injection": {"command-execution"},
        "sql-injection": {"sql-execution"},
        "xss-eval": {"xss", "dom-xss"},
        "xss-framework": {"xss", "dom-xss"},
        "path-traversal": {"path-traversal"},
        "open-redirect": {"open-redirect"},
        "unsafe-deserialization": {"deserialization"},
        "template-injection": {"template-injection"},
        "ssrf": {"ssrf"},
        "prototype-pollution": {"prototype-pollution"},
        # Language packs: the same defect, the same sink, another syntax.
        "py-os-system": {"command-execution"},
        "py-shell-true": {"command-execution"},
        "py-eval-exec": {"code-execution", "command-execution"},
        "py-sqli": {"sql-execution"},
        "py-xss-safe": {"xss", "dom-xss"},
        "py-yaml-load": {"deserialization"},
        "py-pickle": {"deserialization"},
        "cs-process": {"command-execution"},
        "cs-sqli": {"sql-execution"},
        "cs-xss": {"xss", "dom-xss"},
        "cs-deser": {"deserialization"},
        "java-exec": {"command-execution"},
        "java-sqli": {"sql-execution"},
        "java-deser": {"deserialization"},
        "java-script-engine": {"code-execution"},
        "rs-shell-command": {"command-execution"},
        "rs-cmd-format": {"command-execution"},
        "rs-deser": {"deserialization"},
        "swift-process": {"command-execution"},
        "cpp-system": {"command-execution"},
        "cpp-std-system": {"command-execution"},
        "php-sqli": {"sql-execution"},
        "php-xss": {"xss", "dom-xss"},
    }
    # Every canonical id also answers to its public "-risk" alias.
    for canonical, sinks in list(m.items()):
        m.setdefault(canonical + "-risk", set(sinks))
    m.setdefault("command-injection-risk", {"command-execution"})
    m.setdefault("sql-injection-risk", {"sql-execution"})
    m.setdefault("xss-eval-risk", {"xss", "dom-xss"})
    return m


_REGEX_TO_SINK_CATEGORY = _sink_map()

CROSS_LAYER_PRECEDENCE_NOTE = (
    "Cross-layer precedence: where a taint (data-flow) finding and a regex "
    "(pattern-shape) finding describe the same defect at the same location, the "
    "taint finding is authoritative -- it proves a source reaches the sink -- and "
    "the regex finding is recorded on it as corroboration. A regex finding with no "
    "taint counterpart is still reported, but it means the pattern matched and no "
    "flow was proven, which is a weaker claim."
)


def _norm_path(path: str) -> str:
    """POSIX-normalised path with any leading ``./`` removed."""
    return (path or "").replace("\\", "/").lstrip("./")


def _paths_agree(a: str, b: str) -> bool:
    """True when two paths refer to the same file.

    The repository and heuristic scanners report paths *relative to the scan
    root* ("src/app.js") while the taint scanner reports the path its analyzer
    produced, which is *absolute*.  Comparing them for equality therefore never
    matches, and every cross-layer rule silently fails.  Accept either equality
    or a suffix relationship, which is the only relationship these two
    conventions can have.
    """
    a, b = _norm_path(a), _norm_path(b)
    if not a or not b:
        return False
    if a.lower() == b.lower():
        return True
    return a.lower().endswith("/" + b.lower()) or b.lower().endswith("/" + a.lower())


def _same_defect(regex_finding: UnifiedFinding, taint_finding: UnifiedFinding) -> bool:
    """True when two findings from different layers describe the same defect."""
    if not _paths_agree(regex_finding.file_path, taint_finding.file_path):
        return False
    if regex_finding.line_number and taint_finding.line_number:
        # A taint sink is reported at the sink line; the regex that matched is
        # usually the same line or the one that built the value.
        if abs(regex_finding.line_number - taint_finding.line_number) > 2:
            return False
    sink_cat = str(taint_finding.scanner_metadata.get("sink_category") or "")
    if not sink_cat:
        sink_cat = (taint_finding.category or "").removeprefix("taint-")
    # The rule id lives in ``category`` for the heuristic scanner and in
    # ``scanner_metadata["rule_id"]`` for the repository scanner.  There is no
    # ``rule_id`` field on UnifiedFinding -- reaching for one raised
    # AttributeError the first time a regex finding's category missed this table,
    # which is a crash, not a "no match".
    expected = _REGEX_TO_SINK_CATEGORY.get(regex_finding.category or "")
    if expected is None:
        expected = _REGEX_TO_SINK_CATEGORY.get(
            str(regex_finding.scanner_metadata.get("rule_id") or "")
        )
    return bool(expected) and sink_cat in expected


class CrossLayerResolver:
    """Merges findings that different layers report for the same defect."""

    def __init__(self, weaker_layers: tuple[str, ...] = ("regex",)):
        self.weaker_layers = weaker_layers

    def resolve(self, findings: list[UnifiedFinding]) -> tuple[list[UnifiedFinding], list[dict[str, Any]]]:
        """Fold weaker-layer findings into the strongest layer's for the same defect.

        Returns ``(surviving, merges)`` where ``merges`` describes each fold so the
        report can state, per defect, which layers agreed.
        """
        authoritative = [f for f in findings if _LAYER_RANK.get(f.layer, 1) >= 3]
        weaker = [f for f in findings if f.layer in self.weaker_layers and _LAYER_RANK.get(f.layer, 1) < 3]

        merges: list[dict[str, Any]] = []
        consumed: set[str] = set()
        for w in weaker:
            for s in authoritative:
                if not _same_defect(w, s):
                    continue
                corroborated_by = list(s.scanner_metadata.get("corroborated_by") or [])
                if w.scanner_name not in corroborated_by:
                    corroborated_by.append(w.scanner_name)
                    s.scanner_metadata["corroborated_by"] = corroborated_by
                    s.layer_authority = s.layer
                    s.tags = sorted(set(s.tags) | {"cross-layer-confirmed"})
                merges.append({
                    "file": w.file_path,
                    "line": w.line_number,
                    "defect": w.category,
                    "authoritative": {"layer": s.layer, "scanner": s.scanner_name, "id": s.id},
                    "corroborating": {"layer": w.layer, "scanner": w.scanner_name, "id": w.id},
                })
                consumed.add(w.id)
                break

        return [f for f in findings if f.id not in consumed], merges


class FindingCorrelator:
    """Correlates findings across different scanner types to identify attack paths."""

    DEFAULT_RULES = [
        CorrelationRule(
            name="injection_chain",
            description="Correlate injection findings across static analysis, heuristic, and active probes",
            primary_types=[ScanType.STATIC_ANALYSIS, ScanType.HEURISTIC_SECURITY],
            related_types=[ScanType.WEB_SCAN, ScanType.ACTIVE_PROBING, ScanType.DATA_FLOW],
            match_fields=["category", "file_path", "url", "parameter"],
            severity_boost={
                "sql-injection": "critical",
                "command-injection": "critical",
                "xss": "high",
            },
        ),
        CorrelationRule(
            name="secret_exposure_chain",
            description="Correlate hardcoded secrets in code with leaked secrets in web responses",
            primary_types=[ScanType.STATIC_ANALYSIS, ScanType.REPOSITORY_SCAN],
            related_types=[ScanType.WEB_SCAN, ScanType.DEPENDENCY_SCAN],
            match_fields=["category", "cwe_ids"],
            severity_boost={
                "hardcoded-secret": "critical",
                "private-key": "critical",
                "aws-access-key": "critical",
            },
        ),
        CorrelationRule(
            name="crypto_weakness_chain",
            description="Correlate weak crypto in code with TLS issues in web scan",
            primary_types=[ScanType.STATIC_ANALYSIS, ScanType.REPOSITORY_SCAN],
            related_types=[ScanType.WEB_SCAN],
            match_fields=["category", "cwe_ids"],
            severity_boost={
                "weak-hash": "high",
                "tls-verify-off": "high",
                "weak-cipher": "high",
            },
        ),
        CorrelationRule(
            name="auth_bypass_chain",
            description="Correlate auth issues in code with exposed endpoints in web scan",
            primary_types=[ScanType.STATIC_ANALYSIS, ScanType.HEURISTIC_SECURITY],
            related_types=[ScanType.WEB_SCAN, ScanType.ACTIVE_PROBING],
            match_fields=["category", "file_path", "url"],
            severity_boost={
                "jwt-verify-off": "critical",
                "password-form-http": "critical",
                "missing-csrf": "high",
            },
        ),
        CorrelationRule(
            name="dependency_vuln_chain",
            description="Correlate vulnerable dependencies with exploitable code patterns",
            primary_types=[ScanType.DEPENDENCY_SCAN, ScanType.CVE_LOOKUP],
            related_types=[ScanType.REPOSITORY_SCAN, ScanType.EXPLOIT_RELEVANCE],
            match_fields=["category", "cwe_ids"],
            severity_boost={},
        ),
        CorrelationRule(
            name="path_traversal_chain",
            description="Correlate path traversal patterns in code with accessible sensitive paths",
            primary_types=[ScanType.STATIC_ANALYSIS, ScanType.HEURISTIC_SECURITY],
            related_types=[ScanType.WEB_SCAN, ScanType.ACTIVE_PROBING],
            match_fields=["category", "file_path", "url", "parameter"],
            severity_boost={
                "path-traversal": "high",
                "sensitive-path-accessible": "critical",
            },
        ),
    ]

    def __init__(self, rules: list[CorrelationRule] | None = None):
        self.rules = rules or self.DEFAULT_RULES
        self._correlated_groups: list[CorrelatedGroup] = []

    def correlate(self, results: list[ScanResult]) -> list[CorrelatedGroup]:
        """Correlate findings across scan results using defined rules."""
        # Build index of findings by scan type
        findings_by_type: dict[ScanType, list[UnifiedFinding]] = defaultdict(list)
        for result in results:
            findings_by_type[result.scan_type].extend(result.findings)

        self._correlated_groups = []

        for rule in self.rules:
            self._apply_rule(rule, findings_by_type)

        # Also find cross-type correlations not covered by rules
        self._find_cross_type_correlations(findings_by_type)

        return self._correlated_groups

    def _apply_rule(
        self, rule: CorrelationRule, findings_by_type: dict[ScanType, list[UnifiedFinding]]
    ) -> None:
        """Apply a single correlation rule."""
        # Get primary findings
        primary_findings: list[UnifiedFinding] = []
        for st in rule.primary_types:
            primary_findings.extend(findings_by_type.get(st, []))

        # Get related findings
        related_findings: list[UnifiedFinding] = []
        for st in rule.related_types:
            related_findings.extend(findings_by_type.get(st, []))

        if not primary_findings:
            return

        # Match primary to related
        for primary in primary_findings:
            matched_related = self._find_matches(primary, related_findings, rule.match_fields)

            if matched_related:
                group = CorrelatedGroup(
                    id=f"CORR-{hashlib.md5(f'{primary.id}:{rule.name}'.encode()).hexdigest()[:8]}",
                    primary_finding=primary,
                    related_findings=matched_related,
                    scan_types={primary.scan_type} | {f.scan_type for f in matched_related},
                )

                # Calculate combined severity
                group.combined_severity = self._calculate_combined_severity(
                    [primary] + matched_related, rule.severity_boost
                )

                # Calculate combined confidence
                group.combined_confidence = self._calculate_combined_confidence(
                    [primary] + matched_related
                )

                # Build attack path hint
                group.attack_path = self._build_attack_path(group)

                # Calculate remediation priority
                group.remediation_priority = self._calculate_priority(group)

                self._correlated_groups.append(group)

    def _find_matches(
        self, primary: UnifiedFinding, candidates: list[UnifiedFinding], match_fields: list[str]
    ) -> list[UnifiedFinding]:
        """Find candidate findings that match the primary on specified fields."""
        matches = []

        for candidate in candidates:
            if candidate.id == primary.id:
                continue
            if candidate.scanner_name == primary.scanner_name:
                continue  # Same scanner, already deduplicated

            score = 0
            total_fields = len(match_fields)

            for field in match_fields:
                primary_val = getattr(primary, field, None)
                candidate_val = getattr(candidate, field, None)

                if primary_val and candidate_val:
                    if primary_val == candidate_val:
                        score += 1
                    elif isinstance(primary_val, str) and isinstance(candidate_val, str):
                        # Fuzzy string match
                        if self._string_similarity(primary_val, candidate_val) > 0.7:
                            score += 0.5

                # Special handling for cwe_ids (list)
                if field == "cwe_ids" and primary.cwe_ids and candidate.cwe_ids:
                    if set(primary.cwe_ids) & set(candidate.cwe_ids):
                        score += 1

            if score >= max(1, total_fields * 0.5):
                matches.append(candidate)

        return matches

    def _string_similarity(self, s1: str, s2: str) -> float:
        """Simple string similarity (Jaccard on words)."""
        w1 = set(s1.lower().split())
        w2 = set(s2.lower().split())
        if not w1 or not w2:
            return 0.0
        return len(w1 & w2) / len(w1 | w2)

    def _calculate_combined_severity(
        self, findings: list[UnifiedFinding], severity_boost: dict[str, str]
    ) -> Severity:
        """Calculate combined severity from multiple findings."""
        severity_order = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFORMATIONAL: 0,
        }

        max_severity = Severity.INFORMATIONAL
        max_score = 0

        for f in findings:
            score = severity_order.get(f.severity, 0)

            # Apply severity boost if applicable
            for category, boosted in severity_boost.items():
                if category in f.category or category in f.title.lower():
                    boosted_severity = Severity(boosted)
                    score = max(score, severity_order.get(boosted_severity, 0))

            if score > max_score:
                max_score = score
                max_severity = f.severity

        return max_severity

    def _calculate_combined_confidence(self, findings: list[UnifiedFinding]) -> float:
        """Calculate combined confidence from multiple findings."""
        if not findings:
            return 0.0

        confidence_map = {
            "high": 0.9,
            "medium": 0.6,
            "low": 0.3,
        }

        scores = [confidence_map.get(f.confidence.value, 0.5) for f in findings]

        # Weighted average with bonus for multiple independent confirmations
        base = sum(scores) / len(scores)
        bonus = min(0.3, (len(findings) - 1) * 0.1)

        return min(1.0, base + bonus)

    def _build_attack_path(self, group: CorrelatedGroup) -> list[str]:
        """Build an attack path description from correlated findings."""
        path = []

        # Start with primary finding
        path.append(f"1. {group.primary_finding.title} ({group.primary_finding.scan_type.value})")

        # Add related findings in order
        for i, related in enumerate(group.related_findings, 2):
            path.append(
                f"{i}. {related.title} ({related.scan_type.value}) - "
                f"via {related.category}"
            )

        return path

    def _calculate_priority(self, group: CorrelatedGroup) -> int:
        """Calculate remediation priority (lower = higher priority)."""
        severity_weight = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 10,
            Severity.MEDIUM: 20,
            Severity.LOW: 30,
            Severity.INFORMATIONAL: 40,
        }

        base = severity_weight.get(group.combined_severity, 50)

        # Boost for more correlated scanners
        scanner_bonus = len(group.scan_types) * 2

        # Boost for attack path length
        path_bonus = len(group.attack_path) * 3

        return base - scanner_bonus - path_bonus

    def _find_cross_type_correlations(
        self, findings_by_type: dict[ScanType, list[UnifiedFinding]]
    ) -> None:
        """Find correlations not covered by explicit rules."""
        all_findings = []
        for findings in findings_by_type.values():
            all_findings.extend(findings)

        # Group by CWE ID
        cwe_groups: dict[str, list[UnifiedFinding]] = defaultdict(list)
        for f in all_findings:
            for cwe in f.cwe_ids:
                cwe_groups[cwe].append(f)

        # Create correlated groups for CWEs found in multiple scan types
        for cwe, findings in cwe_groups.items():
            scan_types = {f.scan_type for f in findings}
            if len(scan_types) >= 2:
                # Find the highest severity finding as primary
                severity_order = {
                    Severity.CRITICAL: 0,
                    Severity.HIGH: 1,
                    Severity.MEDIUM: 2,
                    Severity.LOW: 3,
                    Severity.INFORMATIONAL: 4,
                }
                findings.sort(key=lambda f: severity_order.get(f.severity, 5))
                primary = findings[0]
                related = findings[1:]

                group = CorrelatedGroup(
                    id=f"CORR-CWE-{cwe.replace('-', '')}",
                    primary_finding=primary,
                    related_findings=related,
                    scan_types=scan_types,
                    combined_severity=primary.severity,
                    combined_confidence=self._calculate_combined_confidence(findings),
                )
                group.attack_path = [f"CWE {cwe} found across {len(scan_types)} scan types"]
                group.metadata["cwe"] = cwe
                group.remediation_priority = self._calculate_priority(group)

                self._correlated_groups.append(group)


class CorrelationEngine:
    """Main correlation engine combining deduplication and correlation."""

    def __init__(
        self,
        deduplicator: FindingDeduplicator | None = None,
        correlator: FindingCorrelator | None = None,
        cross_layer: CrossLayerResolver | None = None,
    ):
        self.deduplicator = deduplicator or FindingDeduplicator()
        self.correlator = correlator or FindingCorrelator()
        self.cross_layer = cross_layer or CrossLayerResolver()

    def _fold_duplicate_advisories(self, findings: list[UnifiedFinding]) -> set[str]:
        """Fold the same advisory reported by more than one scanner.

        repository_scanner and dependency_scanner both query OSV and both emit
        one finding per advisory.  ``FindingDeduplicator.deduplicate`` only runs
        inside a single ScanResult, and ``_are_similar`` refuses to compare
        across scanner names by design, so nothing ever reconciled the two: a
        repository with 12 advisories produced 24 findings and the payload
        advertised 24 CVEs where there were 12 (defect D65).

        This is corroboration, not a discard.  The surviving finding records
        every other scanner that found the same advisory, so the report can
        state that the dedicated SCA scanner and the god-mode repo scanner
        agree on it.

        Returns the ids of the findings the caller should drop.
        """
        groups: dict[tuple[str, str], list[UnifiedFinding]] = defaultdict(list)
        for f in findings:
            if f.category != _DEPENDENCY_CATEGORY:
                continue
            aid = advisory_id(f)
            if not aid:
                # An advisory with no id cannot be shown to be a duplicate of
                # anything.  Folding it on a package name alone would assert a
                # fact nobody established.
                continue
            package = str(f.scanner_metadata.get("package") or "").strip().lower()
            groups[(aid, package)].append(f)

        folded: set[str] = set()
        for group in groups.values():
            if len(group) < 2:
                continue
            # A deterministic winner: most references, then most metadata, then
            # scanner name, then id.  Any tie broken by iteration order would
            # leave a different finding surviving on each run, which makes the
            # report non-reproducible for no reason.
            group.sort(key=lambda f: (
                -len(f.references or []),
                -len(f.scanner_metadata or {}),
                f.scanner_name,
                f.id,
            ))
            primary = group[0]
            confirms = list(primary.scanner_metadata.get("corroborated_by") or [])
            for dup in group[1:]:
                dup.is_duplicate = True
                dup.duplicate_of = primary.id
                folded.add(dup.id)
                if dup.scanner_name not in confirms:
                    confirms.append(dup.scanner_name)
            if confirms:
                primary.scanner_metadata["corroborated_by"] = confirms
                primary.tags = sorted(set(primary.tags) | {"cross-scanner-confirmed"})
        return folded

    def process(self, results: list[ScanResult]) -> dict[str, Any]:
        """Process scan results through deduplication and correlation."""
        # Deduplicate within each result first
        for result in results:
            result.findings = self.deduplicator.deduplicate(result.findings)
            # counts were maintained incrementally by add_finding and describe
            # the pre-dedup list; recompute them so the summary matches reality.
            result.recount()

        # Cross-layer precedence: several layers can report one defect.  Fold the
        # weaker layers into the strongest rather than emitting N findings for
        # N layers (defect D39).
        flat: list[UnifiedFinding] = []
        for result in results:
            flat.extend(result.findings)
        # The same rule applies to advisories found by two scanners (defect D65):
        # deduplication above runs *within* each ScanResult, so nothing has yet
        # compared a repository_scanner advisory with the dependency_scanner's.
        advisory_folded = self._fold_duplicate_advisories(flat)
        surviving, layer_merges = self.cross_layer.resolve(flat)
        folded = advisory_folded | {m["corroborating"]["id"] for m in layer_merges}
        for result in results:
            result.findings = [f for f in result.findings if f.id not in folded]
            result.recount()
            for f in result.findings:
                confirms = (f.scanner_metadata or {}).get("corroborated_by")
                if confirms:
                    result.metadata.setdefault("cross_layer_confirmations", []).append({
                        "finding": f.title,
                        "file": f.file_path,
                        "line": f.line_number,
                        "confirmed_by": confirms,
                    })

        # Correlate across results
        correlated_groups = self.correlator.correlate(results)

        # Build summary
        total_findings = sum(len(r.findings) for r in results)
        critical_correlations = sum(
            1 for g in correlated_groups if g.combined_severity == Severity.CRITICAL
        )

        return {
            "results": results,
            "correlated_groups": correlated_groups,
            "cross_layer": {
                "note": CROSS_LAYER_PRECEDENCE_NOTE,
                "merges": layer_merges,
                "folded_findings": len(folded),
            },
            "summary": {
                "total_findings": total_findings,
                "total_results": len(results),
                "correlated_groups": len(correlated_groups),
                "critical_correlations": critical_correlations,
                "cross_layer_folded": len(folded),
                "layers_represented": sorted({f.layer for f in surviving}),
                "scan_types_covered": list({r.scan_type for r in results}),
            },
        }

    def get_attack_paths(self) -> list[dict[str, Any]]:
        """Extract attack paths from correlated groups."""
        paths = []
        for group in self.correlator._correlated_groups:
            if group.attack_path:
                paths.append({
                    "group_id": group.id,
                    "severity": group.combined_severity.value,
                    "confidence": group.combined_confidence,
                    "primary": group.primary_finding.title,
                    "path": group.attack_path,
                    "remediation_priority": group.remediation_priority,
                    "scan_types": [st.value for st in group.scan_types],
                })
        # Sort by priority (lower = higher priority)
        paths.sort(key=lambda p: p["remediation_priority"])
        return paths

    def get_prioritized_findings(self) -> list[UnifiedFinding]:
        """Get all findings prioritized by correlation and severity."""
        all_findings: list[UnifiedFinding] = []
        for group in self.correlator._correlated_groups:
            all_findings.append(group.primary_finding)
            all_findings.extend(group.related_findings)

        # Deduplicate
        seen = set()
        unique = []
        for f in all_findings:
            if f.id not in seen:
                seen.add(f.id)
                unique.append(f)

        # Sort by severity and correlation count
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFORMATIONAL: 4,
        }

        confidence_order = {
            "high": 3,
            "medium": 2,
            "low": 1,
        }

        unique.sort(
            key=lambda f: (
                severity_order.get(f.severity, 5),
                -len(f.correlated_findings),
                -confidence_order.get(f.confidence.value, 0),
            )
        )

        return unique