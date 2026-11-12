"""Scanner framework for TriageKit.

Provides a unified interface for all security scanners with:
- BaseScanner ABC for consistent scanner implementation
- ScannerRegistry for discovery and management
- UnifiedFinding model for cross-scanner correlation
- FindingDeduplicator and FindingCorrelator for analysis
- Concrete scanners: StaticAnalysis, HeuristicSecurity, Repository, Web, Dependency
- Orchestrator for multi-scanner execution with correlation
"""

from .base import (
    BaseScanner,
    Confidence,
    ScanContext,
    ScanResult,
    ScanType,
    ScannerMetadata,
    ScannerRegistry,
    ScannerStatus,
    Severity,
    UnifiedFinding,
    get_scanner_registry,
    register_scanner,
)
from .correlation import (
    CorrelationEngine,
    CorrelationRule,
    CorrelatedGroup,
    FindingCorrelator,
    FindingDeduplicator,
)
from .orchestrator import (
    OrchestrationResult,
    OrchestratorConfig,
    ScannerOrchestrator,
    create_orchestrator,
)
from .registry_init import (
    get_default_scanner_config,
    register_all_scanners,
    create_scanner_pipeline,
)
from .taint_scanner import create_taint_scanner

# Concrete scanners (lazy import to avoid circular deps)
def __getattr__(name: str):
    if name == "StaticAnalysisScanner":
        from .static_scanner import StaticAnalysisScanner
        return StaticAnalysisScanner
    if name == "HeuristicSecurityScanner":
        from .heuristic_scanner import HeuristicSecurityScanner
        return HeuristicSecurityScanner
    if name == "RepositoryScanner":
        from .repo_scanner import RepositoryScanner
        return RepositoryScanner
    if name == "WebScanner":
        from .web_scanner import WebScanner
        return WebScanner
    if name == "DependencyScanner":
        from .dependency_scanner import DependencyScanner
        return DependencyScanner
    if name == "TaintAnalysisScanner":
        from .taint_scanner import TaintAnalysisScanner
        return TaintAnalysisScanner
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    # Base types
    "BaseScanner",
    "ScannerRegistry",
    "ScannerMetadata",
    "ScanContext",
    "ScanResult",
    "ScanType",
    "ScannerStatus",
    "Severity",
    "Confidence",
    "UnifiedFinding",
    "get_scanner_registry",
    "register_scanner",
    # Correlation
    "FindingDeduplicator",
    "FindingCorrelator",
    "CorrelationEngine",
    "CorrelationRule",
    "CorrelatedGroup",
    # Orchestrator
    "ScannerOrchestrator",
    "OrchestratorConfig",
    "OrchestrationResult",
    "create_orchestrator",
    # Registry init
    "get_default_scanner_config",
    "register_all_scanners",
    "create_scanner_pipeline",
    # Factory functions
    "create_taint_scanner",
    # Concrete scanners (via __getattr__)
    "StaticAnalysisScanner",
    "HeuristicSecurityScanner",
    "RepositoryScanner",
    "WebScanner",
    "DependencyScanner",
    "TaintAnalysisScanner",
]