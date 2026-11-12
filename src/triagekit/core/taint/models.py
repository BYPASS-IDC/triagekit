"""Core data structures for taint analysis."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional, Union

from pydantic import BaseModel, Field


class TaintKind(str, Enum):
    """Type of taint propagation."""

    DIRECT = "direct"  # Direct assignment/call
    INDIRECT = "indirect"  # Through data structures, attributes
    INTERPROCEDURAL = "interprocedural"  # Across function boundaries
    FIELD = "field"  # Object field taint
    RETURN = "return"  # Function return value taint
    PARAMETER = "parameter"  # Function parameter taint


class SanitizerAction(str, Enum):
    """Action taken by a sanitizer."""

    REMOVE = "remove"  # Completely removes taint
    TRANSFORM = "transform"  # Transforms tainted data (may still be dangerous)
    ESCAPE = "escape"  # Escapes dangerous characters
    VALIDATE = "validate"  # Validates but doesn't modify


@dataclass
class Source:
    """A taint source - where untrusted data enters the system."""

    name: str
    category: str  # e.g., "user-input", "http-request", "database", "file"
    description: str
    # Pattern to match the source (function name, variable pattern, etc.)
    pattern: str
    # Language-specific patterns
    languages: list[str] = field(default_factory=list)
    # Confidence that this is a real source (0-1)
    confidence: float = 0.9
    # CWE IDs associated with this source
    cwe_ids: list[str] = field(default_factory=list)
    # Whether this source requires sanitization before use
    requires_sanitization: bool = True
    # Tags for categorization
    tags: list[str] = field(default_factory=list)
    # Metadata
    metadata: dict[str, Any] = field(default_factory=dict)

    def matches(self, node_name: str, language: str) -> bool:
        """Check if a node matches this source pattern."""
        import re
        if self.languages and language not in self.languages:
            return False
        return bool(re.search(self.pattern, node_name, re.IGNORECASE))


@dataclass
class Sink:
    """A taint sink - where tainted data can cause harm."""

    name: str
    category: str  # e.g., "sql-execution", "command-execution", "html-output"
    description: str
    # Pattern to match the sink (function name, method, etc.)
    pattern: str
    # The argument index/name that is the vulnerable parameter
    vulnerable_param: Union[str, int] = 0
    # Language-specific patterns
    languages: list[str] = field(default_factory=list)
    # Confidence that this is a real sink (0-1)
    confidence: float = 0.9
    # CWE IDs associated with this sink
    cwe_ids: list[str] = field(default_factory=list)
    # Severity if tainted data reaches this sink
    severity: str = "high"
    # Whether sanitization can make this safe
    sanitizable: bool = True
    # Tags for categorization
    tags: list[str] = field(default_factory=list)
    # Metadata
    metadata: dict[str, Any] = field(default_factory=dict)

    def matches(self, node_name: str, language: str) -> bool:
        """Check if a node matches this sink pattern."""
        import re
        if self.languages and language not in self.languages:
            return False
        return bool(re.search(self.pattern, node_name, re.IGNORECASE))


@dataclass
class Sanitizer:
    """A sanitizer - function that removes or transforms taint."""

    name: str
    category: str  # e.g., "html-escape", "sql-parametrize", "path-normalize"
    description: str
    # Pattern to match the sanitizer function
    pattern: str
    # Action taken by this sanitizer
    action: SanitizerAction = SanitizerAction.REMOVE
    # Taint kinds this sanitizer handles
    handles_kinds: list[TaintKind] = field(default_factory=lambda: [TaintKind.DIRECT])
    # Language-specific patterns
    languages: list[str] = field(default_factory=list)
    # Confidence that this is a real sanitizer (0-1)
    confidence: float = 0.8
    # CWE IDs this sanitizer mitigates
    cwe_ids: list[str] = field(default_factory=list)
    # Whether this sanitizer is considered "strong" (complete removal)
    is_strong: bool = False
    # Tags for categorization
    tags: list[str] = field(default_factory=list)
    # Metadata
    metadata: dict[str, Any] = field(default_factory=dict)

    def matches(self, node_name: str, language: str) -> bool:
        """Check if a node matches this sanitizer pattern."""
        import re
        if self.languages and language not in self.languages:
            return False
        return bool(re.search(self.pattern, node_name, re.IGNORECASE))


class TaintTrace(BaseModel):
    """A single step in a taint trace."""

    id: str = Field(default_factory=lambda: f"TRC-{uuid.uuid4().hex[:8]}")
    step_number: int
    kind: TaintKind
    # Source code location
    file_path: str
    line_number: int
    column_number: Optional[int] = None
    function_name: Optional[str] = None
    # The code snippet
    snippet: str
    # What variable/expression is tainted at this point
    tainted_variable: str
    # Description of what happens at this step
    description: str
    # Confidence in this step (0-1)
    confidence: float = 1.0
    # Related source/sink/sanitizer
    source_id: Optional[str] = None
    sink_id: Optional[str] = None
    sanitizer_id: Optional[str] = None
    # Metadata
    metadata: dict[str, Any] = Field(default_factory=dict)


class TaintPath(BaseModel):
    """A complete taint path from source to sink."""

    id: str = Field(default_factory=lambda: f"TP-{uuid.uuid4().hex[:12]}")
    # The source that introduced taint
    source: Source
    # The sink that was reached
    sink: Sink
    # The sequence of taint trace steps
    traces: list[TaintTrace] = Field(default_factory=list)
    # Sanitizers encountered along the path
    sanitizers_encountered: list[Sanitizer] = Field(default_factory=list)
    # Whether the path was sanitized (broken)
    is_sanitized: bool = False
    # The sanitizer that broke the path (if any)
    breaking_sanitizer: Optional[Sanitizer] = None
    # Overall confidence of the path (0-1)
    confidence: float = 1.0
    # Severity inherited from sink
    severity: str = "high"
    # CWE IDs (union of source and sink)
    cwe_ids: list[str] = Field(default_factory=list)
    # Attack vector description
    attack_vector: str = ""
    # Remediation guidance
    remediation: str = ""
    # File where the sink is located
    sink_file: str = ""
    sink_line: int = 0
    # Discovery metadata
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def compute_confidence(self) -> float:
        """Compute overall confidence from trace steps."""
        if not self.traces:
            return 0.0
        # Base confidence from trace steps
        trace_conf = sum(t.confidence for t in self.traces) / len(self.traces)
        # Reduce for each sanitizer encountered (but not breaking)
        sanitizer_penalty = len([s for s in self.sanitizers_encountered if s != self.breaking_sanitizer]) * 0.1
        return max(0.1, trace_conf - sanitizer_penalty)

    def to_finding_dict(self) -> dict[str, Any]:
        """Convert to a dictionary suitable for UnifiedFinding."""
        return {
            "title": f"Taint Flow: {self.source.category} → {self.sink.category}",
            "description": self.attack_vector or f"Tainted data from {self.source.name} flows to {self.sink.name}",
            "severity": self.severity,
            "confidence": self.confidence,
            "category": f"taint-{self.sink.category}",
            "file_path": self.sink_file,
            "line_number": self.sink_line,
            "snippet": self.traces[-1].snippet if self.traces else "",
            "recommendation": self.remediation,
            "cwe_ids": self.cwe_ids,
            "evidence": " → ".join([t.description for t in self.traces]),
            "tags": ["taint-analysis", "data-flow"] + self.source.tags + self.sink.tags,
        }


@dataclass
class FunctionSummary:
    """Summary of taint behavior for a function."""

    name: str
    file_path: str
    line_number: int
    # Parameters that can be tainted
    tainted_params: list[int] = field(default_factory=list)  # indices
    # Whether return value can be tainted
    returns_taint: bool = False
    # Which parameters taint the return value
    return_tainted_by: list[int] = field(default_factory=list)
    # Sanitizers called within
    sanitizers_called: list[str] = field(default_factory=list)
    # Sinks called within
    sinks_called: list[str] = field(default_factory=list)
    # Sources called within
    sources_called: list[str] = field(default_factory=list)
    # Whether this function propagates taint
    propagates_taint: bool = False
    # Confidence in this summary
    confidence: float = 0.8


@dataclass
class CallGraphNode:
    """Node in the call graph."""

    function_name: str
    file_path: str
    line_number: int
    # Called functions (edges)
    calls: list["CallGraphNode"] = field(default_factory=list)
    # Calling functions (reverse edges)
    called_by: list["CallGraphNode"] = field(default_factory=list)
    # Function summary for taint analysis
    summary: FunctionSummary | None = None
    # Whether this node has been analyzed
    analyzed: bool = False


@dataclass
class CallGraph:
    """Call graph for interprocedural analysis."""

    nodes: dict[str, CallGraphNode] = field(default_factory=dict)  # qualified_name -> node
    entry_points: list[str] = field(default_factory=list)

    def add_node(self, node: CallGraphNode) -> None:
        key = f"{node.file_path}:{node.function_name}:{node.line_number}"
        self.nodes[key] = node

    def get_node(self, qualified_name: str) -> CallGraphNode | None:
        return self.nodes.get(qualified_name)

    def add_edge(self, caller: str, callee: str) -> None:
        caller_node = self.get_node(caller)
        callee_node = self.get_node(callee)
        if caller_node and callee_node:
            if callee_node not in caller_node.calls:
                caller_node.calls.append(callee_node)
            if caller_node not in callee_node.called_by:
                callee_node.called_by.append(caller_node)