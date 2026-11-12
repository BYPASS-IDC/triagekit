"""Taint Analysis Engine for Source-to-Sink Vulnerability Detection.

This module provides interprocedural taint analysis capabilities for detecting
vulnerabilities where untrusted data flows from sources to dangerous sinks.

Key Components:
- models: Core data structures (Source, Sink, Sanitizer, TaintPath, TaintTrace)
- registry: Built-in and extensible registry of sources, sinks, and sanitizers
- analyzer: Python AST-based taint analyzer
- js_analyzer: JavaScript/TypeScript regex-based taint analyzer
"""

from .analyzer import PythonTaintAnalyzer, analyze_python_file, analyze_python_directory
from .js_analyzer import JSTaintAnalyzer, analyze_js_file, analyze_js_directory
from .models import (
    CallGraph,
    CallGraphNode,
    FunctionSummary,
    Sanitizer,
    SanitizerAction,
    Sink,
    Source,
    TaintKind,
    TaintPath,
    TaintTrace,
)
from .registry import (
    TaintRegistry,
    get_registry,
)

__all__ = [
    # Models
    "Source",
    "Sink",
    "Sanitizer",
    "SanitizerAction",
    "TaintKind",
    "TaintTrace",
    "TaintPath",
    "FunctionSummary",
    "CallGraphNode",
    "CallGraph",
    # Registry
    "TaintRegistry",
    "get_registry",
    # Analyzers
    "PythonTaintAnalyzer",
    "analyze_python_file",
    "analyze_python_directory",
    "JSTaintAnalyzer",
    "analyze_js_file",
    "analyze_js_directory",
]