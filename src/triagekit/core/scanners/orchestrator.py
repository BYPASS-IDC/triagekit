"""Scanner Orchestrator - runs multiple scanners and correlates results."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

from .base import (
    BaseScanner,
    ScanContext,
    ScanResult,
    ScanType,
    ScannerRegistry,
    get_scanner_registry,
)
from .correlation import CorrelationEngine
from .registry_init import get_default_scanner_config, register_all_scanners


@dataclass
class OrchestratorConfig:
    """Configuration for the scanner orchestrator."""

    max_concurrent_scans: int = 3
    default_timeout: float = 300.0
    enable_correlation: bool = True
    enable_deduplication: bool = True
    scanner_configs: dict[str, dict[str, Any]] = field(default_factory=dict)
    enabled_scanners: list[str] | None = None  # None = all


@dataclass
class OrchestrationResult:
    """Result of running multiple scanners."""

    scan_results: list[ScanResult]
    correlated_groups: list[Any] = field(default_factory=list)
    attack_paths: list[dict[str, Any]] = field(default_factory=list)
    prioritized_findings: list[Any] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    total_duration: float = 0.0
    errors: list[str] = field(default_factory=list)


class ScannerOrchestrator:
    """Orchestrates multiple scanners with correlation and deduplication."""

    def __init__(self, config: OrchestratorConfig | None = None):
        self.config = config or OrchestratorConfig()
        self.registry = get_scanner_registry()
        self.correlation_engine = CorrelationEngine()
        self._initialized = False

    def initialize(self) -> None:
        """Initialize the registry with all scanners."""
        if not self._initialized:
            register_all_scanners(self.config.scanner_configs)
            self._initialized = True

    def get_enabled_scanners(self) -> list[BaseScanner]:
        """Get list of enabled scanners."""
        all_scanners = list(self.registry._scanners.values())

        if self.config.enabled_scanners:
            enabled_names = set(self.config.enabled_scanners)
            return [s for s in all_scanners if s.name in enabled_names]

        return all_scanners

    def filter_scanners_for_target(self, target: str) -> list[BaseScanner]:
        """Filter scanners that can handle the given target."""
        return [s for s in self.get_enabled_scanners() if s.can_scan(target)]

    async def run_scan(
        self,
        target: str,
        context: ScanContext | None = None,
        scanners: list[BaseScanner] | None = None,
    ) -> OrchestrationResult:
        """Run selected scanners on a target and correlate results."""
        start_time = time.time()

        if not self._initialized:
            self.initialize()

        # Use provided scanners or filter for target
        if scanners is None:
            scanners = self.filter_scanners_for_target(target)

        if not scanners:
            return OrchestrationResult(
                scan_results=[],
                errors=[f"No scanners available for target: {target}"],
                total_duration=time.time() - start_time,
            )

        # Create scan context
        if context is None:
            context = ScanContext(target=target)
        else:
            context.target = target

        # Apply defaults
        if context.timeout_seconds == 300:  # default
            context.timeout_seconds = int(self.config.default_timeout)

        # Run scanners with concurrency control
        semaphore = asyncio.Semaphore(self.config.max_concurrent_scans)

        async def run_with_semaphore(scanner: BaseScanner) -> ScanResult:
            async with semaphore:
                try:
                    return await asyncio.wait_for(
                        scanner.scan(context),
                        timeout=context.timeout_seconds,
                    )
                except asyncio.TimeoutError:
                    result = ScanResult(
                        scanner_name=scanner.name,
                        scanner_version=scanner.version,
                        scan_type=scanner.scan_type,
                        target=target,
                    )
                    result.errors.append(f"Scan timed out after {context.timeout_seconds}s")
                    result.complete()
                    return result
                except Exception as e:
                    result = ScanResult(
                        scanner_name=scanner.name,
                        scanner_version=scanner.version,
                        scan_type=scanner.scan_type,
                        target=target,
                    )
                    result.errors.append(f"Scan failed: {type(e).__name__}: {e}")
                    result.complete()
                    return result

        # Execute all scans
        tasks = [run_with_semaphore(s) for s in scanners]
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Handle exceptions
        final_results: list[ScanResult] = []
        for i, result in enumerate(scan_results):
            if isinstance(result, Exception):
                scanner = scanners[i]
                error_result = ScanResult(
                    scanner_name=scanner.name,
                    scanner_version=scanner.version,
                    scan_type=scanner.scan_type,
                    target=target,
                )
                error_result.errors.append(f"Scan exception: {type(result).__name__}: {result}")
                error_result.complete()
                final_results.append(error_result)
            else:
                final_results.append(result)

        # Correlate and deduplicate
        if self.config.enable_correlation or self.config.enable_deduplication:
            correlation_result = self.correlation_engine.process(final_results)
            final_results = correlation_result["results"]
            correlated_groups = correlation_result["correlated_groups"]
            attack_paths = self.correlation_engine.get_attack_paths()
            prioritized_findings = self.correlation_engine.get_prioritized_findings()
            cross_layer = correlation_result.get("cross_layer") or {}
        else:
            correlated_groups = []
            attack_paths = []
            prioritized_findings = []
            cross_layer = {}

        # Build summary
        total_findings = sum(len(r.findings) for r in final_results)
        scanners_run = len(final_results)
        scanners_failed = sum(1 for r in final_results if r.status.value == "failed")
        scanners_completed = sum(1 for r in final_results if r.status.value == "completed")

        summary = {
            "target": target,
            "scanners_run": scanners_run,
            "scanners_completed": scanners_completed,
            "scanners_failed": scanners_failed,
            "total_findings": total_findings,
            "correlated_groups": len(correlated_groups),
            "attack_paths": len(attack_paths),
            # Which layers produced the surviving findings, and how many weaker
            # layer findings were folded into a stronger one for the same defect.
            "layers_represented": correlation_result["summary"].get("layers_represented", []),
            "cross_layer_folded": cross_layer.get("folded_findings", 0),
            "cross_layer_note": cross_layer.get("note", ""),
            "by_severity": self._aggregate_counts(final_results),
            "by_scanner": {
                r.scanner_name: {
                    "status": r.status.value,
                    "findings": len(r.findings),
                    "duration": r.duration_seconds,
                }
                for r in final_results
            },
        }

        total_duration = time.time() - start_time

        return OrchestrationResult(
            scan_results=final_results,
            correlated_groups=correlated_groups,
            attack_paths=attack_paths,
            prioritized_findings=prioritized_findings,
            summary=summary,
            total_duration=total_duration,
            errors=[e for r in final_results for e in r.errors],
        )

    def _aggregate_counts(self, results: list[ScanResult]) -> dict[str, int]:
        """Aggregate finding counts by severity across all results."""
        total = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        for r in results:
            for sev, count in r.counts.items():
                total[sev] = total.get(sev, 0) + count
        return total

    def run_sync(
        self,
        target: str,
        context: ScanContext | None = None,
        scanners: list[BaseScanner] | None = None,
    ) -> OrchestrationResult:
        """Synchronous wrapper for run_scan."""
        return asyncio.run(self.run_scan(target, context, scanners))


def create_orchestrator(
    config: OrchestratorConfig | None = None,
) -> ScannerOrchestrator:
    """Factory function to create a ScannerOrchestrator."""
    return ScannerOrchestrator(config)