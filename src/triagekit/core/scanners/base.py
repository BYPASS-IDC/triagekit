"""Scanner foundation: BaseScanner ABC, ScannerRegistry, UnifiedFinding model, and factory registry."""

from __future__ import annotations

import threading
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Generic, Optional, TypeVar, Union

from pydantic import BaseModel, Field


# Scanner factory registry to avoid circular imports
_scanner_factories: dict[str, Callable[[dict[str, Any]], "BaseScanner"]] = {}


def register_scanner_factory(name: str, factory: Callable[[dict[str, Any]], "BaseScanner"]) -> None:
    """Register a scanner factory function.

    This avoids circular imports by allowing scanners to register their
    factory functions without importing the registry_init module.
    """
    if name in _scanner_factories:
        raise ValueError(f"Scanner factory '{name}' already registered")
    _scanner_factories[name] = factory


def get_scanner_factory(name: str) -> Callable[[dict[str, Any]], "BaseScanner"] | None:
    """Get a scanner factory by name."""
    return _scanner_factories.get(name)


def list_scanner_factories() -> list[str]:
    """List all registered scanner factory names."""
    return list(_scanner_factories.keys())


class ScanType(str, Enum):
    """Types of scans supported by the scanner framework."""

    STATIC_ANALYSIS = "static_analysis"
    HEURISTIC_SECURITY = "heuristic_security"
    REPOSITORY_SCAN = "repository_scan"
    WEB_SCAN = "web_scan"
    DEPENDENCY_SCAN = "dependency_scan"
    CVE_LOOKUP = "cve_lookup"
    EXPLOIT_RELEVANCE = "exploit_relevance"
    DATA_FLOW = "data_flow"
    TAINT_ANALYSIS = "taint_analysis"
    ACTIVE_PROBING = "active_probing"
    ATTACK_PATH = "attack_path"
    REMEDIATION = "remediation"


class Severity(str, Enum):
    """Standardized severity levels across all scanners."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class Confidence(str, Enum):
    """Confidence levels for findings."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ScannerStatus(str, Enum):
    """Scanner execution status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


T = TypeVar("T", bound="ScanResult")


@dataclass
class ScannerMetadata:
    """Metadata about a scanner's capabilities and requirements."""

    name: str
    version: str
    scan_type: ScanType
    description: str
    supported_languages: list[str] = field(default_factory=list)
    required_tools: list[str] = field(default_factory=list)
    requires_network: bool = False
    requires_auth: bool = False
    is_intrusive: bool = False
    estimated_duration_seconds: int = 30
    tags: list[str] = field(default_factory=list)


@dataclass
class ScanContext:
    """Context passed to scanners during execution."""

    target: str  # Path, URL, or identifier
    config: dict[str, Any] = field(default_factory=dict)
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    previous_results: dict[str, "ScanResult"] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    dry_run: bool = False
    timeout_seconds: int = 300


class UnifiedFinding(BaseModel):
    """Unified finding model for cross-scanner correlation and deduplication.

    This model standardizes findings across all scanner types, enabling
    correlation, deduplication, and unified reporting.
    """

    # Core identification
    id: str = Field(default_factory=lambda: f"TKF-{uuid.uuid4().hex[:12]}")
    scanner_name: str
    scanner_version: str
    scan_type: ScanType

    # Finding details
    title: str
    description: str
    severity: Severity
    confidence: Confidence = Confidence.MEDIUM
    category: str  # e.g., "injection", "secret", "crypto", "misconfiguration"

    # Location information
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    function_name: Optional[str] = None
    url: Optional[str] = None
    parameter: Optional[str] = None

    # Evidence and context
    evidence: Optional[str] = None
    snippet: Optional[str] = None
    raw_data: dict[str, Any] = Field(default_factory=dict)

    # Remediation
    recommendation: str = ""
    fix_example: Optional[str] = None
    effort_estimate: Optional[str] = None  # "low", "medium", "high"
    references: list[str] = Field(default_factory=list)

    # Classification
    cwe_ids: list[str] = Field(default_factory=list)
    cvss_vector: Optional[str] = None
    cvss_score: Optional[float] = None
    owasp_categories: list[str] = Field(default_factory=list)
    mitre_attack_ids: list[str] = Field(default_factory=list)

    # Correlation and deduplication
    fingerprint: str = ""  # Hash for deduplication
    correlated_findings: list[str] = Field(default_factory=list)  # Other finding IDs
    is_duplicate: bool = False
    duplicate_of: Optional[str] = None
    suppressed: bool = False
    suppression_reason: Optional[str] = None

    # Temporal
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    status: str = "open"  # open, fixed, false_positive, accepted_risk, suppressed

    # Metadata
    tags: list[str] = Field(default_factory=list)
    scanner_metadata: dict[str, Any] = Field(default_factory=dict)

    # Which analysis produced this finding.  When two layers report the same
    # line, the reader must be told which one to believe -- a report that shows
    # a regex hit and a taint flow as two unrelated findings, with no statement
    # of precedence, invites the reader to trust whichever one they saw first
    # (defect D39).
    #
    #   "taint"      -- data flow proven from a source to this sink
    #   "regex"      -- pattern shape matched at this line, no flow proven
    #   "probe"      -- an active request was sent and the response observed
    #   "dependency" -- a manifest/CVE fact, not code
    #   "intel"      -- an external advisory reference
    #   "risk"       -- a scoring/aggregation result, not a defect
    layer: str = "regex"
    layer_authority: Optional[str] = None  # set when a stronger layer confirmed this one

    def compute_fingerprint(self) -> str:
        """Compute a deterministic fingerprint for deduplication.

        Uses: scanner_type + category + normalized_location + normalized_title
        """
        import hashlib

        parts = [
            self.scan_type.value,
            self.category.lower(),
            (self.file_path or "").lower(),
            str(self.line_number or 0),
            (self.url or "").lower(),
            (self.parameter or "").lower(),
            self.title.lower().strip(),
        ]
        # Normalize: remove non-alphanumeric from title for fuzzy matching
        normalized_title = "".join(c for c in self.title.lower() if c.isalnum() or c.isspace())
        parts[-1] = normalized_title
        fp = hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]
        self.fingerprint = fp
        return fp

    def model_post_init(self, __context: Any) -> None:
        if not self.fingerprint:
            self.compute_fingerprint()


class ScanResult(BaseModel, Generic[T]):
    """Standardized result container for all scanners."""

    scanner_name: str
    scanner_version: str
    scan_type: ScanType
    target: str
    status: ScannerStatus = ScannerStatus.PENDING
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0

    findings: list[UnifiedFinding] = Field(default_factory=list)
    summary: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    # Aggregated counts
    counts: dict[str, int] = Field(default_factory=lambda: {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0
    })

    def add_finding(self, finding: UnifiedFinding) -> None:
        """Add a finding and update counts."""
        self.findings.append(finding)
        self.counts[finding.severity.value] = self.counts.get(finding.severity.value, 0) + 1

    def recount(self) -> dict[str, int]:
        """Recompute ``counts`` from the findings actually present.

        ``add_finding`` maintains the counts incrementally, so anything that
        replaces ``findings`` in place -- deduplication, a filter, a merge --
        leaves the counts describing a list that no longer exists.  The summary
        then reported 28 findings for a 13-finding scan.  Call this after any
        wholesale rewrite of ``findings``.
        """
        fresh = {k: 0 for k in ("critical", "high", "medium", "low", "informational")}
        for finding in self.findings:
            key = finding.severity.value
            fresh[key] = fresh.get(key, 0) + 1
        self.counts = fresh
        return fresh

    def complete(self, status: ScannerStatus = ScannerStatus.COMPLETED) -> None:
        """Mark scan as complete."""
        self.status = status
        self.completed_at = datetime.utcnow()
        if self.started_at:
            self.duration_seconds = (self.completed_at - self.started_at).total_seconds()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "scanner_name": self.scanner_name,
            "scanner_version": self.scanner_version,
            "scan_type": self.scan_type.value,
            "target": self.target,
            "status": self.status.value,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "findings_count": len(self.findings),
            "counts": self.counts,
            "summary": self.summary,
            "metadata": self.metadata,
            "errors": self.errors,
            "warnings": self.warnings,
        }


class BaseScanner(ABC, Generic[T]):
    """Abstract base class for all scanners.

    All scanner implementations must inherit from this class and implement
    the required methods. The framework provides common functionality for
    lifecycle management, error handling, and result standardization.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self._metadata = self._get_metadata()
        self._result: ScanResult | None = None

    @abstractmethod
    def _get_metadata(self) -> ScannerMetadata:
        """Return scanner metadata. Must be implemented by subclass."""
        pass

    @abstractmethod
    async def _scan(self, context: ScanContext) -> ScanResult:
        """Execute the scan logic. Must be implemented by subclass."""
        pass

    @property
    def metadata(self) -> ScannerMetadata:
        return self._metadata

    @property
    def name(self) -> str:
        return self._metadata.name

    @property
    def version(self) -> str:
        return self._metadata.version

    @property
    def scan_type(self) -> ScanType:
        return self._metadata.scan_type

    async def scan(self, context: ScanContext) -> ScanResult:
        """Public scan method with lifecycle management."""
        # A scanner is constructed with its config (register_all_scanners passes
        # scanner_configs to the constructor), but _scan() reads context.config.
        # The orchestrator never copies one into the other, so context.config
        # stayed empty and every configured value silently fell back to its
        # hardcoded default -- max_packages=40, max_files, timeouts, everything.
        # Merge the two: the scanner's own config is the base, a caller-supplied
        # context wins on conflict.  replace() gives each scanner its own copy,
        # so scanner A's keys cannot leak into scanner B via a shared dict.
        if self.config:
            merged = dict(self.config)
            merged.update(context.config or {})
            context = replace(context, config=merged)

        self._result = ScanResult(
            scanner_name=self.name,
            scanner_version=self.version,
            scan_type=self.scan_type,
            target=context.target,
            status=ScannerStatus.RUNNING,
        )

        try:
            self._result = await self._scan(context)
            self._result.complete(ScannerStatus.COMPLETED)
        except Exception as e:
            self._result.errors.append(f"Scan failed: {type(e).__name__}: {e}")
            self._result.complete(ScannerStatus.FAILED)

        return self._result

    def validate_config(self) -> list[str]:
        """Validate scanner configuration. Override in subclass."""
        return []

    def get_supported_targets(self) -> list[str]:
        """Return list of target patterns this scanner supports."""
        return ["*"]

    def can_scan(self, target: str) -> bool:
        """Check if this scanner can handle the given target."""
        import fnmatch
        for pattern in self.get_supported_targets():
            if fnmatch.fnmatch(target.lower(), pattern.lower()):
                return True
        return False


class ScannerRegistry:
    """Registry for managing and discovering scanners."""

    def __init__(self):
        self._scanners: dict[str, BaseScanner] = {}
        self._metadata_index: dict[str, ScannerMetadata] = {}
        self._type_index: dict[ScanType, list[str]] = {}
        # The registry is a process-wide global, so two concurrent scans in a
        # server can interleave a register with an unregister and leave it
        # half-populated.  Reentrant: register() calls unregister().
        self._lock = threading.RLock()

    def register(self, scanner: BaseScanner, *, replace: bool = False) -> None:
        """Register a scanner instance.

        ``replace=True`` drops any instance already registered under the same
        name.  This is the only mode a long-lived process can use: the registry
        is a module-level global, but each ``ScannerOrchestrator`` instance has
        its own ``_initialized`` flag, so without it the SECOND scan in a server
        process raises ``Scanner 'static_analysis' already registered`` -- the
        repo scan works exactly once, then every subsequent request fails.  The
        CLI never hit this because it scans once per process.

        Replacing is also the correct semantics, not just the convenient one: a
        scanner's config is bound to its instance, so a request that asked for
        ``max_files=500`` must not be served by the ``max_files=8000`` instance
        the first request registered.
        """
        name = scanner.name
        with self._lock:
            if name in self._scanners:
                if not replace:
                    raise ValueError(f"Scanner '{name}' already registered")
                self.unregister(name)

            self._scanners[name] = scanner
            self._metadata_index[name] = scanner.metadata

            # Index by scan type
            st = scanner.scan_type
            if st not in self._type_index:
                self._type_index[st] = []
            self._type_index[st].append(name)

    def unregister(self, name: str) -> bool:
        """Unregister a scanner by name."""
        with self._lock:
            if name not in self._scanners:
                return False

            scanner = self._scanners.pop(name)
            self._metadata_index.pop(name, None)

            # Remove from type index
            st = scanner.scan_type
            if st in self._type_index:
                self._type_index[st] = [n for n in self._type_index[st] if n != name]
                if not self._type_index[st]:
                    del self._type_index[st]

            return True

    def get(self, name: str) -> BaseScanner | None:
        """Get a scanner by name."""
        return self._scanners.get(name)

    def get_by_type(self, scan_type: ScanType) -> list[BaseScanner]:
        """Get all scanners of a specific type."""
        names = self._type_index.get(scan_type, [])
        return [self._scanners[n] for n in names if n in self._scanners]

    def get_for_target(self, target: str) -> list[BaseScanner]:
        """Get all scanners that can handle the given target."""
        return [s for s in self._scanners.values() if s.can_scan(target)]

    def list_all(self) -> list[ScannerMetadata]:
        """List all registered scanner metadata."""
        return list(self._metadata_index.values())

    def list_names(self) -> list[str]:
        """List all registered scanner names."""
        return list(self._scanners.keys())

    def get_metadata(self, name: str) -> ScannerMetadata | None:
        """Get metadata for a scanner by name."""
        return self._metadata_index.get(name)

    def clear(self) -> None:
        """Clear all registered scanners."""
        with self._lock:
            self._scanners.clear()
            self._metadata_index.clear()
            self._type_index.clear()


# Global registry instance
_scanner_registry: ScannerRegistry | None = None
_registry_lock = threading.Lock()


def get_scanner_registry() -> ScannerRegistry:
    """Get or create the global scanner registry."""
    global _scanner_registry
    # Unguarded, two threads could both see None, both build a registry, and one
    # of them would register into an instance that is then discarded -- the
    # scanners "registered" but unreachable, which is the same half-populated
    # end state the registry lock prevents inside a single registry.
    if _scanner_registry is None:
        with _registry_lock:
            if _scanner_registry is None:
                _scanner_registry = ScannerRegistry()
    return _scanner_registry


def register_scanner(scanner: BaseScanner, *, replace: bool = False) -> None:
    """Register a scanner in the global registry."""
    get_scanner_registry().register(scanner, replace=replace)