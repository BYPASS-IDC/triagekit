"""Initialize and register all built-in scanners."""

from __future__ import annotations

from typing import Any

from .base import (
    get_scanner_registry,
    register_scanner,
    get_scanner_factory,
    register_scanner_factory,
)
from .static_scanner import StaticAnalysisScanner, create_static_scanner
from .heuristic_scanner import HeuristicSecurityScanner, create_heuristic_scanner
from .repo_scanner import RepositoryScanner, create_repo_scanner
from .web_scanner import WebScanner, create_web_scanner
from .dependency_scanner import DependencyScanner, create_dependency_scanner
from .taint_scanner import TaintAnalysisScanner, create_taint_scanner


def register_all_scanners(config: dict[str, Any] | None = None) -> None:
    """Register all built-in scanners with the global registry.

    Args:
        config: Optional configuration dict with per-scanner settings.
                Format: {"scanner_name": {...config...}}

    Idempotent by replacement, and serialised by a lock: the registry is global,
    but the config is per-call, and two concurrent requests must not interleave
    a register with an unregister and leave the registry half-populated.
    """
    registry = get_scanner_registry()
    config = config or {}

    # Register scanner factories (avoids circular imports)
    # Use get_scanner_factory to check first - idempotent registration
    factories = [
        ("static_analysis", create_static_scanner),
        ("heuristic_security", create_heuristic_scanner),
        ("repository_scanner", create_repo_scanner),
        ("web_scanner", create_web_scanner),
        ("dependency_scanner", create_dependency_scanner),
        ("taint_analysis", create_taint_scanner),
    ]
    for name, factory in factories:
        if get_scanner_factory(name) is None:
            register_scanner_factory(name, factory)

    # Static Analysis Scanner
    static_config = config.get("static_analysis", {})
    registry.register(StaticAnalysisScanner(static_config), replace=True)

    # Heuristic Security Scanner
    heuristic_config = config.get("heuristic_security", {})
    registry.register(HeuristicSecurityScanner(heuristic_config), replace=True)

    # Repository Scanner
    repo_config = config.get("repository_scanner", {})
    registry.register(RepositoryScanner(repo_config), replace=True)

    # Web Scanner
    web_config = config.get("web_scanner", {})
    registry.register(WebScanner(web_config), replace=True)

    # Dependency Scanner
    dep_config = config.get("dependency_scanner", {})
    registry.register(DependencyScanner(dep_config), replace=True)

    # Taint Analysis Scanner
    taint_config = config.get("taint_analysis", {})
    registry.register(TaintAnalysisScanner(taint_config), replace=True)


def get_default_scanner_config() -> dict[str, Any]:
    """Get default configuration for all scanners."""
    return {
        "static_analysis": {},
        "heuristic_security": {},
        "repository_scanner": {
            "max_files": 8000,
        },
        "web_scanner": {
            "timeout": 30.0,
            "check_sensitive_paths": True,
            "max_paths": 120,
            "crawl": True,
            "max_crawl_pages": 25,
            "max_js_files": 20,
            "max_js_bytes": 1_800_000,
            "active": True,
        },
        "dependency_scanner": {
            "max_packages": 40,
        },
        "taint_analysis": {
            "max_files": 1000,
            "languages": None,  # auto-detect
        },
    }


def create_scanner_pipeline(
    scan_types: list[str] | None = None,
    config: dict[str, Any] | None = None,
) -> list:
    """Create a list of scanner instances for a pipeline.

    Args:
        scan_types: List of scan type names to include. If None, includes all.
        config: Optional configuration overrides.

    Returns:
        List of initialized scanner instances.
    """
    all_scanners = {
        "static_analysis": StaticAnalysisScanner,
        "heuristic_security": HeuristicSecurityScanner,
        "repository_scanner": RepositoryScanner,
        "web_scanner": WebScanner,
        "dependency_scanner": DependencyScanner,
        "taint_analysis": TaintAnalysisScanner,
    }

    config = config or get_default_scanner_config()
    types = scan_types or list(all_scanners.keys())

    scanners = []
    for scan_type in types:
        if scan_type in all_scanners:
            scanner_config = config.get(scan_type, {})
            scanners.append(all_scanners[scan_type](scanner_config))

    return scanners