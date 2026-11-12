"""Taint Analysis Scanner - integrates taint analysis with the scanner framework."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ..taint.analyzer import PythonTaintAnalyzer, analyze_python_directory
from ..taint.js_analyzer import JSTaintAnalyzer, analyze_js_directory
from ..taint.models import TaintPath
from ..taint.registry import get_registry
from .base import (
    BaseScanner,
    Confidence,
    ScanContext,
    ScanResult,
    ScanType,
    ScannerMetadata,
    Severity,
    UnifiedFinding,
)


class TaintAnalysisScanner(BaseScanner[ScanResult]):
    """Taint analysis scanner for source-to-sink vulnerability detection.

    Performs interprocedural data flow analysis to track tainted data from
    sources (user input, HTTP requests, etc.) to sinks (SQL execution, command
    execution, XSS, etc.) across function boundaries.
    """

    def _get_metadata(self) -> ScannerMetadata:
        return ScannerMetadata(
            name="taint_analysis",
            version="1.0.0",
            scan_type=ScanType.TAINT_ANALYSIS,
            description="Interprocedural taint analysis for source-to-sink vulnerability detection",
            supported_languages=["python", "javascript", "typescript"],
            required_tools=[],
            estimated_duration_seconds=60,
            tags=["taint-analysis", "data-flow", "sast", "interprocedural", "source-to-sink"],
        )

    async def _scan(self, context: ScanContext) -> ScanResult:
        result = ScanResult(
            scanner_name=self.name,
            scanner_version=self.version,
            scan_type=self.scan_type,
            target=context.target,
        )

        target_path = self._resolve_target(context.target)
        if not target_path:
            result.errors.append(f"Could not resolve target path: {context.target}")
            result.complete()
            return result

        max_files = context.config.get("max_files", 1000)
        languages = context.config.get("languages", None)  # None = auto-detect
        dry_run = context.dry_run

        if dry_run:
            result.warnings.append("Dry run mode - skipping actual taint analysis")
            result.summary = f"Dry run: would analyze {target_path} for taint flows"
            result.complete()
            return result

        try:
            # Detect languages if not specified
            if languages is None:
                languages = self._detect_languages(target_path)

            all_taint_paths: list[TaintPath] = []

            # Analyze Python files
            if "python" in languages:
                python_paths = analyze_python_directory(target_path, max_files)
                all_taint_paths.extend(python_paths)

            # Analyze JavaScript/TypeScript files
            if "javascript" in languages or "typescript" in languages:
                js_paths = analyze_js_directory(target_path, max_files)
                all_taint_paths.extend(js_paths)

            # Convert taint paths to unified findings
            for path in all_taint_paths:
                finding = self._taint_path_to_finding(path)
                result.add_finding(finding)

            # Summary
            result.summary = (
                f"Taint analysis complete: {len(all_taint_paths)} taint paths found "
                f"({result.counts['critical']} critical, {result.counts['high']} high, "
                f"{result.counts['medium']} medium, {result.counts['low']} low)"
            )
            result.metadata.update({
                "languages_analyzed": languages,
                "files_analyzed": self._count_files(target_path, languages),
                "taint_paths": len(all_taint_paths),
                "registry_stats": get_registry().get_stats(),
                "layer": "taint",
            })

        except Exception as e:
            # Never print a traceback from here: this runs inside a command whose
            # stdout is a JSON or SARIF document, and a traceback interleaved into
            # that stream is corrupt output (defect D2).  The message goes to the
            # result, which every output path already knows how to render.
            result.errors.append(f"Taint analysis failed: {type(e).__name__}: {e}")

        result.complete()
        return result

    def _detect_languages(self, path: Path) -> list[str]:
        """Detect which languages are present in the target."""
        languages = set()
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in {
                "node_modules", "venv", ".venv", "__pycache__", "dist", "build"
            }]
            for file in files:
                ext = Path(file).suffix.lower()
                if ext == ".py":
                    languages.add("python")
                elif ext in (".js", ".jsx", ".ts", ".tsx"):
                    languages.add("javascript" if ext in (".js", ".jsx") else "typescript")
        return list(languages)

    def _count_files(self, path: Path, languages: list[str]) -> int:
        """Count files to be analyzed."""
        count = 0
        exts = set()
        if "python" in languages:
            exts.add(".py")
        if "javascript" in languages:
            exts.update([".js", ".jsx"])
        if "typescript" in languages:
            exts.update([".ts", ".tsx"])

        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in {
                "node_modules", "venv", ".venv", "__pycache__", "dist", "build"
            }]
            for file in files:
                if Path(file).suffix.lower() in exts:
                    count += 1
        return count

    def _taint_path_to_finding(self, path: TaintPath) -> UnifiedFinding:
        """Convert a taint path to a unified finding."""
        # Map severity string to Severity enum
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }

        # Map confidence float to Confidence enum
        def confidence_to_enum(conf: float) -> Confidence:
            if conf >= 0.8:
                return Confidence.HIGH
            elif conf >= 0.5:
                return Confidence.MEDIUM
            return Confidence.LOW

        finding = UnifiedFinding(
            scanner_name=self.name,
            scanner_version=self.version,
            scan_type=self.scan_type,
            title=f"Taint Flow: {path.source.category} -> {path.sink.category}",
            description=path.attack_vector or f"Tainted data from {path.source.name} flows to {path.sink.name}",
            severity=severity_map.get(path.severity, Severity.HIGH),
            confidence=confidence_to_enum(path.confidence),
            category=f"taint-{path.sink.category}",
            file_path=path.sink_file,
            line_number=path.sink_line,
            snippet=path.traces[-1].snippet if path.traces else "",
            recommendation=path.remediation,
            cwe_ids=path.cwe_ids,
            evidence=" -> ".join([t.description for t in path.traces]),
            tags=["taint-analysis", "data-flow", "source-to-sink"] + path.source.tags + path.sink.tags,
            layer="taint",
            scanner_metadata={
                "source_name": path.source.name,
                "source_category": path.source.category,
                "sink_name": path.sink.name,
                "sink_category": path.sink.category,
                "is_sanitized": path.is_sanitized,
                "sanitizers_encountered": [s.name for s in path.sanitizers_encountered],
                "breaking_sanitizer": path.breaking_sanitizer.name if path.breaking_sanitizer else None,
                "trace_count": len(path.traces),
                "trace_details": [
                    {
                        "step": t.step_number,
                        "file": t.file_path,
                        "line": t.line_number,
                        "function": t.function_name,
                        "variable": t.tainted_variable,
                        "description": t.description,
                        "kind": t.kind.value,
                    }
                    for t in path.traces
                ],
            },
        )
        return finding

    def _resolve_target(self, target: str) -> Path | None:
        """Resolve target to a local path."""
        # Handle GitHub URLs (would need github_client to download)
        if target.startswith("https://github.com/"):
            return None

        # Local path
        path = Path(target).expanduser().resolve()
        if path.exists():
            return path

        # Try relative to cwd
        cwd_path = Path.cwd() / target
        if cwd_path.exists():
            return cwd_path.resolve()

        return None

    def validate_config(self) -> list[str]:
        errors = []
        if "max_files" in self.config:
            try:
                max_files = int(self.config["max_files"])
                if max_files < 1 or max_files > 10000:
                    errors.append("max_files must be between 1 and 10000")
            except ValueError:
                errors.append("max_files must be an integer")
        if "languages" in self.config:
            langs = self.config["languages"]
            if isinstance(langs, str):
                langs = [langs]
            valid = {"python", "javascript", "typescript"}
            for lang in langs:
                if lang not in valid:
                    errors.append(f"Invalid language: {lang}. Valid: {valid}")
        return errors

    def get_supported_targets(self) -> list[str]:
        return ["*", "repo:*", "path:*", "github:*"]


def create_taint_scanner(config: dict[str, Any] | None = None) -> TaintAnalysisScanner:
    """Factory function to create a TaintAnalysisScanner."""
    return TaintAnalysisScanner(config)