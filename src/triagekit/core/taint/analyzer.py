"""Python AST-based taint analyzer."""

from __future__ import annotations

import ast
import os
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Union

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
from .registry import get_registry

# ast.Match (structural pattern matching) only exists on Python 3.10+.  Guarded
# so the analyzer still imports and runs on 3.9 without an AttributeError.
_MATCH_NODE = getattr(ast, "Match", None)

# Bounds for call-site-sensitive interprocedural propagation.  They exist so
# that recursive or mutually recursive call chains terminate: the active-call
# signature set stops direct re-entry, and these bounds stop the exponential
# blow-up a diamond-shaped call graph would otherwise cause.
_MAX_CALL_DEPTH = 16
_MAX_INTERPROCEDURAL_SYNTHESES = 500


@dataclass
class TaintState:
    """Tracks taint state for a variable during analysis."""

    variable: str
    is_tainted: bool = False
    source: Optional[Source] = None
    taint_kind: TaintKind = TaintKind.DIRECT
    traces: list[TaintTrace] = field(default_factory=list)
    sanitized: bool = False
    sanitizer: Optional[Sanitizer] = None
    # Every sanitizer applied to this value, innermost first.  A single
    # ``sanitizer`` field silently loses the earlier ones when calls nest:
    # ``open(os.path.join(base, os.path.basename(name)))`` sets the state to
    # os.path.join (weak) and forgets the basename (strong) that is the reason
    # the expression is safe, so the flow was reported anyway.
    sanitizer_chain: list[Sanitizer] = field(default_factory=list)
    confidence: float = 1.0


@dataclass
class FunctionContext:
    """Context for analyzing a single function."""

    name: str
    file_path: str
    node: Union[ast.FunctionDef, ast.AsyncFunctionDef]
    # Taint state for variables in this function
    taint_state: dict[str, TaintState] = field(default_factory=dict)
    # Parameters that are sources
    tainted_params: set[int] = field(default_factory=set)
    # Whether return value is tainted
    return_tainted: bool = False
    # Which parameters taint the return
    return_tainted_by: set[int] = field(default_factory=set)
    # Taint states observed at return statements, in source order.  Used by the
    # interprocedural engine to decide what a call expression evaluates to
    # without re-walking (and re-reporting) the callee body.
    return_taints: list[TaintState] = field(default_factory=list)
    # Called functions
    calls: list[str] = field(default_factory=list)
    # Sources/sinks/sanitizers found
    sources_found: list[Source] = field(default_factory=list)
    sinks_found: list[Sink] = field(default_factory=list)
    sanitizers_found: list[Sanitizer] = field(default_factory=list)
    # Line number
    line_number: int = 0


class PythonTaintAnalyzer:
    """AST-based taint analyzer for Python code."""

    def __init__(self, registry: Optional[Any] = None):
        self.registry = registry or get_registry()
        self.function_contexts: dict[str, FunctionContext] = {}
        self.call_graph = CallGraph()
        self.taint_paths: list[TaintPath] = []
        self._current_function: FunctionContext | None = None
        self._source_code: str = ""
        self._file_path: str = ""
        # Flows that a sanitizer genuinely neutralised.  Kept out of
        # taint_paths (they are not findings) but retained so the decision is
        # auditable rather than silently dropped.
        self.sanitized_flows: list[TaintPath] = []
        # Interprocedural engine state (see _propagate_into_callee).
        self._callee_index: dict[str, list[FunctionContext]] = {}
        self._interprocedural_depth = 0
        self._synthesis_budget = _MAX_INTERPROCEDURAL_SYNTHESES
        self._active_syntheses: set[tuple[int, int, int]] = set()

    def _reset_state(self) -> None:
        """Clear all per-analysis state so analyses cannot contaminate each other.

        ``analyze_file`` and ``analyze_directory`` may be called repeatedly on
        the same instance.  Without this reset, findings from one file leak into
        the next (safe files appear vulnerable, vulnerable files disappear, and
        the list returned by an earlier call is mutated by a later one).
        """
        self.function_contexts = {}
        self.call_graph = CallGraph()
        self.taint_paths = []
        self.sanitized_flows = []
        self._current_function = None
        self._source_code = ""
        self._file_path = ""
        self._callee_index = {}
        self._interprocedural_depth = 0
        self._synthesis_budget = _MAX_INTERPROCEDURAL_SYNTHESES
        self._active_syntheses = set()

    def analyze_file(self, file_path: str) -> list[TaintPath]:
        """Analyze a single Python file for taint flows."""
        self._reset_state()
        self._file_path = file_path
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                self._source_code = f.read()
        except Exception:
            return []

        try:
            tree = ast.parse(self._source_code, filename=file_path)
        except SyntaxError:
            return []

        # First pass: build function contexts and call graph
        self._build_function_contexts(tree)

        # Second pass: analyze each function for taint flows
        for ctx in self.function_contexts.values():
            self._analyze_function(ctx)

        # Analyze module-level statements (code not inside functions)
        self._analyze_module_level(tree)

        # Third pass: interprocedural analysis
        self._interprocedural_analysis()

        # Extract taint paths
        self._extract_taint_paths()

        # Return a copy: callers must never observe the analyzer's internal
        # list, otherwise a later analysis mutates results they already hold.
        return list(self.taint_paths)

    def analyze_directory(self, dir_path: str, max_files: int = 1000) -> list[TaintPath]:
        """Analyze all Python files in a directory."""
        all_paths = []
        count = 0

        for root, dirs, files in os.walk(dir_path):
            # Skip common ignore directories
            dirs[:] = [d for d in dirs if d not in {
                ".git", "node_modules", "venv", ".venv", "env", "__pycache__",
                ".mypy_cache", ".pytest_cache", "dist", "build", "target"
            }]

            for file in files:
                if file.endswith(".py"):
                    file_path = os.path.join(root, file)
                    paths = self.analyze_file(file_path)
                    all_paths.extend(paths)
                    count += 1
                    if count >= max_files:
                        break

            if count >= max_files:
                break

        # Sort for deterministic output regardless of os.walk enumeration
        # order, so a directory's findings never depend on the order the
        # filesystem happens to return files in.
        all_paths.sort(key=lambda p: (os.path.basename(p.sink_file), p.sink_line, p.sink.name))
        return all_paths

    def _build_function_contexts(self, tree: ast.AST) -> None:
        """Build function contexts and call graph from AST."""
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                ctx = FunctionContext(
                    name=node.name,
                    file_path=self._file_path,
                    node=node,
                    line_number=node.lineno,
                )
                # Check parameters for sources
                for i, arg in enumerate(node.args.args):
                    # Check if parameter name matches any source pattern
                    for source in self.registry.find_sources(arg.arg, "python"):
                        ctx.tainted_params.add(i)
                        ctx.sources_found.append(source)

                qualified_name = f"{self._file_path}:{node.name}:{node.lineno}"
                self.function_contexts[qualified_name] = ctx

                # Add to call graph
                cg_node = CallGraphNode(
                    function_name=node.name,
                    file_path=self._file_path,
                    line_number=node.lineno,
                )
                self.call_graph.add_node(cg_node)

    def _analyze_function(self, ctx: FunctionContext) -> None:
        """Analyze a single function for taint flows."""
        self._current_function = ctx

        # Initialize taint state for parameters
        for i in ctx.tainted_params:
            if i < len(ctx.node.args.args):
                param_name = ctx.node.args.args[i].arg
                source = ctx.sources_found[i] if i < len(ctx.sources_found) else None
                ctx.taint_state[param_name] = TaintState(
                    variable=param_name,
                    is_tainted=True,
                    source=source,
                    taint_kind=TaintKind.PARAMETER,
                    confidence=source.confidence if source else 0.8,
                )

        # Visit all statements in the function
        for stmt in ctx.node.body:
            self._visit_statement(stmt, ctx)

        # Check if return value is tainted
        for ret in self._get_return_nodes(ctx.node):
            if isinstance(ret.value, ast.Name):
                var_name = ret.value.id
                if var_name in ctx.taint_state and ctx.taint_state[var_name].is_tainted:
                    ctx.return_tainted = True
                    # Find which parameters taint this return
                    for param_idx, param in enumerate(ctx.node.args.args):
                        if param.arg in ctx.taint_state and ctx.taint_state[param.arg].is_tainted:
                            ctx.return_tainted_by.add(param_idx)

    def _visit_statement(self, node: ast.AST, ctx: FunctionContext) -> None:
        """Visit a statement node."""
        if isinstance(node, ast.Assign):
            self._visit_assign(node, ctx)
        elif isinstance(node, ast.AnnAssign):
            # ``cmd: str = request.args["c"]`` -- the annotation is part of the
            # statement, so it must not hide the assignment from taint tracking.
            if node.value is not None:
                value_taint = self._visit_expression(node.value, ctx)
                dotted = self._dotted_path(node.target)
                if dotted:
                    self._bind_taint(ctx, dotted, value_taint, node)
        elif isinstance(node, ast.AugAssign):
            self._visit_aug_assign(node, ctx)
        elif isinstance(node, ast.Call):
            self._visit_call(node, ctx)
        elif isinstance(node, ast.Return):
            self._visit_return(node, ctx)
        elif isinstance(node, (ast.If, ast.While, ast.For)):
            # Visit body
            for stmt in node.body:
                self._visit_statement(stmt, ctx)
            # Visit else/orelse
            for stmt in getattr(node, "orelse", []):
                self._visit_statement(stmt, ctx)
        elif isinstance(node, ast.Try):
            for stmt in node.body:
                self._visit_statement(stmt, ctx)
            for handler in node.handlers:
                for stmt in handler.body:
                    self._visit_statement(stmt, ctx)
            for stmt in node.finalbody:
                self._visit_statement(stmt, ctx)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            # with open(filename) as f:  -- the context expression is itself a
            # call that may be a sink.
            for item in node.items:
                self._visit_expression(item.context_expr, ctx)
            for stmt in node.body:
                self._visit_statement(stmt, ctx)
        elif _MATCH_NODE is not None and isinstance(node, _MATCH_NODE):
            for case in node.cases:
                for stmt in case.body:
                    self._visit_statement(stmt, ctx)
        elif isinstance(node, ast.Expr):
            self._visit_expression(node.value, ctx)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            # Nested definitions are analyzed through their own context.
            return
        else:
            # Generic fallback: visit any expression sitting directly on this
            # statement so sinks inside constructs we do not model explicitly
            # (assert, raise, delete, with-items, ...) are still evaluated
            # rather than silently skipped.
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.expr):
                    self._visit_expression(child, ctx)

    def _make_source_state(self, source: Source, node: ast.AST, ctx: FunctionContext) -> TaintState:
        """Build a taint state for a freshly observed source expression."""
        return TaintState(
            variable=self._describe_node(node),
            is_tainted=True,
            source=source,
            taint_kind=TaintKind.DIRECT,
            traces=[self._create_trace(node, ctx, self._describe_node(node), f"source: {source.name}")],
            confidence=source.confidence,
        )

    def _describe_node(self, node: ast.AST) -> str:
        """Short human-readable label for a node, used as the taint variable."""
        dotted = self._dotted_path(node)
        if dotted:
            return dotted
        return type(node).__name__.lower()

    def _visit_expression(self, node: ast.AST, ctx: FunctionContext) -> TaintState | None:
        """Visit an expression and return its taint state."""
        if isinstance(node, ast.Name):
            return ctx.taint_state.get(node.id)
        elif isinstance(node, ast.Call):
            return self._visit_call(node, ctx)
        elif isinstance(node, ast.BinOp):
            left = self._visit_expression(node.left, ctx)
            right = self._visit_expression(node.right, ctx)
            if left and left.is_tainted:
                return left
            if right and right.is_tainted:
                return right
        elif isinstance(node, ast.BoolOp):
            # ``a or b`` evaluates to one of the operands, so either being
            # tainted taints the result.
            for value in node.values:
                taint = self._visit_expression(value, ctx)
                if taint and taint.is_tainted:
                    return taint
        elif isinstance(node, ast.IfExp):
            # ``redirect(url if url in ALLOWED else "/")``: the tainted branch is
            # reached only when the value passed an allowlist membership test,
            # and the other branch is a constant.  That is the standard safe
            # idiom for an open-redirect guard, so the expression as a whole is
            # validated.  Reporting it punished the recommended fix.
            if self._is_allowlist_guard(node):
                return None
            for branch in (node.body, node.orelse):
                taint = self._visit_expression(branch, ctx)
                if taint and taint.is_tainted:
                    return taint
        elif isinstance(node, ast.JoinedStr):  # f-string
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    taint = self._visit_expression(value.value, ctx)
                    if taint and taint.is_tainted:
                        return taint
        elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            # A container literal is tainted when any element is tainted:
            # ``subprocess.run(["sh", "-c", user])`` passes user to the child.
            for element in node.elts:
                taint = self._visit_expression(element, ctx)
                if taint and taint.is_tainted:
                    return taint
        elif isinstance(node, ast.Dict):
            # ``{"cmd": user}`` builds attacker-controlled data that is later
            # read back with ``payload["cmd"]``.
            for key, value in zip(node.keys, node.values):
                for element in (key, value):
                    if element is None:
                        continue
                    taint = self._visit_expression(element, ctx)
                    if taint and taint.is_tainted:
                        return taint
        elif isinstance(node, ast.Starred):
            return self._visit_expression(node.value, ctx)
        elif isinstance(node, ast.Await):
            return self._visit_expression(node.value, ctx)
        elif isinstance(node, ast.NamedExpr):  # walrus :=
            taint = self._visit_expression(node.value, ctx)
            if taint and taint.is_tainted and isinstance(node.target, ast.Name):
                ctx.taint_state[node.target.id] = taint
            return taint
        elif isinstance(node, ast.Attribute):
            # Handle attribute access (e.g., obj.attr)
            sources = self._match_sources(node)
            if sources:
                return self._make_source_state(sources[0], node, ctx)
            dotted = self._dotted_path(node)
            if dotted:
                stored = ctx.taint_state.get(dotted)
                if stored is not None:
                    return stored
            value_taint = self._visit_expression(node.value, ctx)
            if value_taint and value_taint.is_tainted:
                return value_taint
        elif isinstance(node, ast.Subscript):
            # Handle subscript access (e.g., arr[i], sys.argv[1], request.args['q'])
            sources = self._match_sources(node)
            if sources:
                return self._make_source_state(sources[0], node, ctx)
            dotted = self._dotted_path(node.value)
            if dotted:
                stored = ctx.taint_state.get(dotted)
                if stored is not None:
                    return stored
            value_taint = self._visit_expression(node.value, ctx)
            if value_taint and value_taint.is_tainted:
                return value_taint
        return None

    def _visit_assign(self, node: ast.Assign, ctx: FunctionContext) -> None:
        """Visit an assignment statement."""
        # Get taint from the value
        value_taint = self._visit_expression(node.value, ctx)

        for target in node.targets:
            if isinstance(target, (ast.Tuple, ast.List)):
                # ``a, b = ...``: unpacking binds each element.  Without knowing
                # the runtime structure, the conservative and sound choice is to
                # taint every name in the target list.
                for element in target.elts:
                    if isinstance(element, ast.Name):
                        self._bind_taint(ctx, element.id, value_taint, node)
                continue
            # ``self.cmd = tainted`` / ``store["cmd"] = tainted``: the value is
            # reachable later through the same attribute or subscript, so it is
            # recorded under the dotted path the read will use.
            dotted = self._dotted_path(target)
            if dotted:
                self._bind_taint(ctx, dotted, value_taint, node)

    def _bind_taint(
        self,
        ctx: FunctionContext,
        var_name: str,
        value_taint: Optional[TaintState],
        node: ast.AST,
    ) -> None:
        """Bind ``value_taint`` to ``var_name``, or clear its taint."""
        if value_taint and value_taint.is_tainted:
            # Propagate taint.  ``sanitizer``/``sanitized`` are carried
            # across the binding so a sanitizer already applied stays
            # visible for the rest of the flow: a reviewer must be able
            # to see that os.path.join() was used and judge whether it
            # was the right defence for the sink the value reaches.
            ctx.taint_state[var_name] = TaintState(
                variable=var_name,
                is_tainted=True,
                source=value_taint.source,
                taint_kind=TaintKind.DIRECT,
                traces=value_taint.traces + [self._create_trace(node, ctx, var_name, "assignment")],
                confidence=value_taint.confidence * 0.95,
                sanitized=value_taint.sanitized,
                sanitizer=value_taint.sanitizer,
                # The whole chain must survive the binding, or a value that was
                # basenamed before being joined loses the reason it is safe as
                # soon as it is stored in a variable.
                sanitizer_chain=list(value_taint.sanitizer_chain),
            )
        else:
            # Clear taint if assigning clean value
            if var_name in ctx.taint_state:
                ctx.taint_state[var_name].is_tainted = False

    def _visit_aug_assign(self, node: ast.AugAssign, ctx: FunctionContext) -> None:
        """Visit an augmented assignment (e.g., +=)."""
        if isinstance(node.target, ast.Name):
            var_name = node.target.id
            value_taint = self._visit_expression(node.value, ctx)
            existing = ctx.taint_state.get(var_name)

            if value_taint and value_taint.is_tainted:
                if existing and existing.is_tainted:
                    # Merge traces
                    existing.traces.append(self._create_trace(node, ctx, var_name, "augmented assignment"))
                    existing.confidence *= 0.95
                else:
                    ctx.taint_state[var_name] = TaintState(
                        variable=var_name,
                        is_tainted=True,
                        source=value_taint.source,
                        taint_kind=TaintKind.DIRECT,
                        traces=value_taint.traces + [self._create_trace(node, ctx, var_name, "augmented assignment")],
                        confidence=value_taint.confidence * 0.95,
                        sanitized=value_taint.sanitized,
                        sanitizer=value_taint.sanitizer,
                    )

    def _visit_call(self, node: ast.Call, ctx: FunctionContext) -> TaintState | None:
        """Visit a function call."""
        func_name = self._get_call_name(node)
        method_name = node.func.attr if isinstance(node.func, ast.Attribute) else None
        if not func_name:
            # The callee is not a plain name or attribute chain, so the full
            # dotted name cannot be reconstructed.  The callee expression is
            # usually itself a call -- ``open(path).read()``,
            # ``conn.cursor().execute(q)``, ``Repo().find(id)`` -- and BOTH the
            # inner call and the terminal method are places a sink can live, so
            # the receiver calls must still be visited and the terminal method
            # name must still be matched.  Skipping it silently dropped every
            # sink reached through a call-valued receiver, which is the normal
            # spelling of ``cursor().execute()`` and ``session.execute()``.
            self._visit_receiver_calls(node, ctx)

        # ``func_name`` is the fully qualified chain when it resolves to a
        # plain name (``os.system``); ``method_name`` is the terminal attribute
        # (``execute``) and is used only when the chain does not resolve, so a
        # pattern is still matched against a name the source actually contains
        # rather than against a name synthesised from an unresolvable chain.
        match_name = func_name or method_name

        # Record the call
        ctx.calls.append(match_name or "<dynamic>")

        # Add edge to call graph
        caller_key = f"{self._file_path}:{ctx.name}:{ctx.line_number}"
        # Try to find callee in current file
        callee_key = f"{self._file_path}:{func_name}:0"  # line 0 = unknown
        self.call_graph.add_edge(caller_key, callee_key)

        # Check if this is a source.  Sinks are evaluated first: a single call
        # can be both a source and a sink (open() is a file-read source AND a
        # path-traversal sink), and returning early on the source taint would
        # hide the vulnerability in the same expression.
        sources = self._match_sources(node)

        # Check if this is a sanitizer.  Taint is NOT removed here: whether a
        # sanitizer actually protects anything depends on the sink the value
        # eventually reaches, and that is not known yet.  html.escape() removes
        # an XSS but does nothing about os.system(); os.path.join() does nothing
        # about open().  The call is recorded on the taint state for diagnostics
        # and evaluated per-sink by _neutralizing_sanitizer().
        sanitizers = self._match_sanitizers(node, match_name)
        sanitizer_result: Optional[TaintState] = None
        # Which argument expression each sanitizer covers.  ``subprocess.run(cmd,
        # shell=False)`` is both a sink and a sanitizer for its own argument, so
        # the sink check must see the sanitizer that was applied to the very
        # expression it is evaluating -- not a copy of it that lost the mark.
        sanitizer_by_argument: dict[ast.AST, Sanitizer] = {}
        if sanitizers:
            for sanitizer in sanitizers:
                ctx.sanitizers_found.append(sanitizer)
                for arg in self._sanitizable_arguments(node, sanitizer):
                    arg_taint = self._visit_expression(arg, ctx)
                    if arg_taint and arg_taint.is_tainted:
                        if sanitizer_result is None:
                            sanitizer_result = self._derive_taint(
                                arg_taint, node, ctx,
                                "sanitizer %s applied" % sanitizer.name,
                            )
                            sanitizer_result.sanitizer = sanitizer
                        # Record the whole chain, innermost first, so an outer
                        # weak sanitizer cannot hide an inner strong one.
                        if sanitizer not in sanitizer_result.sanitizer_chain:
                            sanitizer_result.sanitizer_chain.append(sanitizer)
                        sanitizer_by_argument.setdefault(arg, sanitizer)

        # Check if this is a sink
        sinks = self._match_sinks(node, match_name)
        if sinks:
            for sink in sinks:
                ctx.sinks_found.append(sink)
                # Check the vulnerable parameter
                vuln_param = sink.vulnerable_param
                if isinstance(vuln_param, int) and vuln_param < len(node.args):
                    arg = node.args[vuln_param]
                    arg_taint = self._argument_state(
                        arg, sanitizer_by_argument, node, ctx
                    )
                    if arg_taint and arg_taint.is_tainted:
                        self._report_sink_hit(arg_taint, sink, node, ctx)

                # Unsafe dynamic SQL is always reported.  A tuple of bound
                # parameters passed alongside an interpolated statement does
                # NOT make it safe: the statement text is still
                # attacker-controlled, so this must not be suppressed.
                if sink.category == "sql-execution":
                    sql_text = self._sql_text_argument(node)
                    if sql_text is not None:
                        sql_taint = self._argument_state(
                            sql_text, sanitizer_by_argument, node, ctx
                        )
                        if sql_taint and sql_taint.is_tainted:
                            self._report_sink_hit(sql_taint, sink, node, ctx)
                        # The statement text alone decides whether a SQL sink
                        # is dangerous.  Bound parameters (args[1:], params=)
                        # travel out of band and cannot alter query structure,
                        # so they are deliberately not checked here.
                        continue

        if sources:
            for source in sources:
                ctx.sources_found.append(source)
                # If the call result is assigned, it's tainted
                return self._make_source_state(source, node, ctx)

        # Call-site-sensitive interprocedural propagation.  If the callee is
        # defined in this file and a tainted argument is bound to one of its
        # parameters, analyse the callee body with that parameter tainted so
        # sinks inside it are reported at their own call site.
        callee_state = self._propagate_into_callee(node, ctx)
        if callee_state is not None:
            if sanitizer_result is not None and callee_state.sanitizer is None:
                # A sanitizer wrapped around a call into this file still applies
                # to the value it returns, so keep it visible for the sink.
                callee_state.sanitizer = sanitizer_result.sanitizer
                callee_state.traces = sanitizer_result.traces + callee_state.traces
            return callee_state

        # A sanitizer call evaluates to a (possibly still dangerous) value
        # carrying the sanitizer that was applied.  Returning it here -- rather
        # than dropping the taint -- is what lets ``str(escape(x))`` keep the
        # ``escape`` step visible at the sink and be judged per sink instead of
        # being silently discarded.
        if sanitizer_result is not None:
            return sanitizer_result

        # A call that is not a source, sink or sanitizer still passes taint
        # from its arguments through to its result: str(user), user.strip()
        # and os.path.join(base, user) all evaluate to attacker-controlled
        # data even though none of them is a sanitizer.
        return self._propagate_through_call(node, ctx)

    def _argument_state(
        self,
        arg: ast.expr,
        sanitizer_by_argument: dict[ast.AST, Sanitizer],
        node: ast.Call,
        ctx: FunctionContext,
    ) -> TaintState | None:
        """Taint state of a sink argument, honouring a sanitizer on that argument.

        The sanitizer map is keyed by the argument *expression node*, so a
        sanitizer recorded against ``cmd`` is only ever applied to ``cmd`` and
        never to a different argument that happens to be tainted.
        """
        taint = self._visit_expression(arg, ctx)
        if not (taint and taint.is_tainted):
            return taint
        sanitizer = sanitizer_by_argument.get(arg)
        if sanitizer is None or taint.sanitizer is not None:
            return taint
        marked = self._derive_taint(
            taint, node, ctx, "sanitizer %s applied" % sanitizer.name
        )
        marked.sanitizer = sanitizer
        return marked

    def _visit_receiver_calls(self, node: ast.Call, ctx: FunctionContext) -> None:
        """Visit calls hiding in the callee expression of ``node``.

        ``node.func`` is a strict subtree of ``node``, so this terminates and
        cannot re-enter the call that dispatched here.
        """
        for child in ast.walk(node.func):
            if isinstance(child, ast.Call):
                self._visit_call(child, ctx)

    def _visit_return(self, node: ast.Return, ctx: FunctionContext) -> None:
        """Visit a return statement."""
        if node.value:
            ret_taint = self._visit_expression(node.value, ctx)
            if ret_taint and ret_taint.is_tainted:
                ctx.return_tainted = True
                ctx.return_taints.append(ret_taint)

    # ------------------------------------------------------------------
    # Call-site-sensitive interprocedural propagation
    # ------------------------------------------------------------------

    def _resolve_callees(self, func_name: str | None) -> list[FunctionContext]:
        """Return every function defined in this file with the given name."""
        if not func_name:
            return []
        if not self._callee_index:
            index: dict[str, list[FunctionContext]] = {}
            for ctx in sorted(self.function_contexts.values(), key=lambda c: c.line_number):
                index.setdefault(ctx.name, []).append(ctx)
            self._callee_index = index
        return self._callee_index.get(func_name, [])

    def _callee_parameters(self, callee_ctx: FunctionContext) -> list[tuple[int, str]]:
        """(index, name) for the callee's bindable positional parameters."""
        args = callee_ctx.node.args
        positional = list(getattr(args, "posonlyargs", []) or []) + list(args.args)
        return [(i, a.arg) for i, a in enumerate(positional)]

    def _bind_arguments(self, node: ast.Call, callee_ctx: FunctionContext) -> list[tuple[int, str, ast.expr]]:
        """Map a call site's arguments onto the callee's parameter names.

        Handles positional arguments at ANY index, keyword arguments matched by
        name, ``*args``/``**kwargs`` catch-alls, and gives up (rather than
        guessing) when an unpacked ``*seq``/``**mapping`` makes the positional
        mapping unknowable.
        """
        positional = self._callee_parameters(callee_ctx)
        by_name = {name: index for index, name in positional}
        signature = callee_ctx.node.args
        vararg = signature.vararg.arg if signature.vararg else None
        kwarg = signature.kwarg.arg if signature.kwarg else None

        # ``obj.method(x)`` binds x to the SECOND parameter of a method, not the
        # first: the receiver is passed implicitly and occupies ``self``/``cls``.
        # Skipping it is what makes ``self.run(cmd)`` taint ``cmd`` rather than
        # ``self``.  The skip only applies to attribute calls on a callee whose
        # first parameter is actually the receiver, so plain functions and
        # free functions assigned to attributes are unaffected.
        receiver_slots = 0
        if (
            isinstance(node.func, ast.Attribute)
            and positional
            and positional[0][1] in ("self", "cls")
        ):
            receiver_slots = 1
        by_name = {name: index for index, name in positional}
        positional = positional[receiver_slots:]

        bindings: list[tuple[int, str, ast.expr]] = []
        slot = 0
        for arg in node.args:
            if isinstance(arg, ast.Starred):
                # ``f(*seq)``: which parameter each element lands in depends on
                # the runtime length of seq, so the mapping is unknowable.
                break
            if slot < len(positional):
                index, name = positional[slot]
                bindings.append((index, name, arg))
            elif vararg:
                bindings.append((slot + receiver_slots, vararg, arg))
            slot += 1

        for kw in node.keywords:
            if kw.arg is not None and kw.arg in by_name:
                bindings.append((by_name[kw.arg], kw.arg, kw.value))
            elif kwarg:
                # Unmatched keyword or ``**mapping``: the whole expression
                # lands in the catch-all parameter.
                bindings.append((slot + receiver_slots, kwarg, kw.value))

        return bindings

    def _argument_taint(self, arg: ast.expr, ctx: FunctionContext) -> TaintState | None:
        """Taint state of a call argument, or None when it is clean."""
        taint = self._visit_expression(arg, ctx)
        if taint and taint.is_tainted and not taint.sanitized:
            return taint
        return None

    def _propagate_into_callee(self, node: ast.Call, caller_ctx: FunctionContext) -> TaintState | None:
        """Analyse the callee of ``node`` with the call's tainted arguments bound.

        Returns the callee's return-value taint state (so ``x = helper(user)``
        marks ``x`` tainted), or None when the callee is unknown or no
        argument is tainted.
        """
        func_name = self._get_call_name(node)
        candidates = self._resolve_callees(func_name)
        if not candidates and func_name and "." in func_name:
            # obj.method() -> a method defined in this file
            candidates = self._resolve_callees(func_name.rsplit(".", 1)[-1])
        if not candidates and isinstance(node.func, ast.Attribute):
            # The receiver is not a plain name -- ``Repo().find(id)``,
            # ``get_session().execute(q)`` -- so the chain cannot be resolved,
            # but the terminal method is still a method of this file.
            candidates = self._resolve_callees(node.func.attr)
        if not candidates:
            return None

        chosen = None
        for callee_ctx in candidates:
            bindings = self._bind_arguments(node, callee_ctx)
            tainted = [b for b in bindings if self._argument_taint(b[2], caller_ctx)]
            if tainted:
                chosen = (callee_ctx, tainted)
                break
        if chosen is None:
            return None
        callee_ctx, tainted = chosen

        # Re-entrancy and resource guards.
        signature = (id(callee_ctx.node), node.lineno, getattr(node, "col_offset", 0))
        if signature in self._active_syntheses:
            return None
        if self._interprocedural_depth >= _MAX_CALL_DEPTH:
            return None
        if self._synthesis_budget <= 0:
            return None

        self._active_syntheses.add(signature)
        self._synthesis_budget -= 1
        self._interprocedural_depth += 1
        try:
            return self._synthesize_callee(node, caller_ctx, callee_ctx, tainted)
        finally:
            self._interprocedural_depth -= 1
            self._active_syntheses.discard(signature)

    def _synthesize_callee(
        self,
        node: ast.Call,
        caller_ctx: FunctionContext,
        callee_ctx: FunctionContext,
        tainted: list[tuple[int, str, ast.expr]],
    ) -> TaintState | None:
        """Walk the callee body with its tainted parameters seeded.

        A throwaway FunctionContext is used so the callee's own per-function
        state is never polluted by one particular call site.
        """
        synthetic = FunctionContext(
            name=callee_ctx.name,
            file_path=self._file_path,
            node=callee_ctx.node,
            line_number=callee_ctx.node.lineno,
        )

        # A parameter whose own name matches a source pattern stays a source,
        # matching the seeding done by _analyze_function.
        for index in callee_ctx.tainted_params:
            if index >= len(callee_ctx.node.args.args):
                continue
            param_name = callee_ctx.node.args.args[index].arg
            source = callee_ctx.sources_found[index] if index < len(callee_ctx.sources_found) else None
            synthetic.tainted_params.add(index)
            if param_name not in synthetic.taint_state:
                synthetic.taint_state[param_name] = TaintState(
                    variable=param_name,
                    is_tainted=True,
                    source=source,
                    taint_kind=TaintKind.PARAMETER,
                    traces=[],
                    confidence=source.confidence if source else 0.8,
                )

        for _, param_name, arg in tainted:
            arg_taint = self._argument_taint(arg, caller_ctx)
            if arg_taint is None:
                continue
            synthetic.taint_state[param_name] = self._derive_taint(
                arg_taint,
                node,
                caller_ctx,
                "interprocedural: tainted argument reaches parameter '%s' of %s()"
                % (param_name, callee_ctx.name),
            )

        for stmt in callee_ctx.node.body:
            self._visit_statement(stmt, synthetic)

        for state in synthetic.return_taints:
            if state.is_tainted and not state.sanitized:
                return state
        return None

    def _propagate_through_call(self, node: ast.Call, ctx: FunctionContext) -> TaintState | None:
        """Taint survives a call that is neither a source, sink nor sanitizer."""
        expressions = list(node.args) + [kw.value for kw in node.keywords]
        for expression in expressions:
            taint = self._visit_expression(expression, ctx)
            if taint and taint.is_tainted and not taint.sanitized:
                callee = self._get_call_name(node) or "call"
                return TaintState(
                    variable=taint.variable,
                    is_tainted=True,
                    source=taint.source,
                    taint_kind=TaintKind.INDIRECT,
                    traces=taint.traces + [
                        self._create_trace(node, ctx, taint.variable, f"passed through {callee}()")
                    ],
                    confidence=max(0.7, taint.confidence * 0.95),
                    sanitized=taint.sanitized,
                    sanitizer=taint.sanitizer,
                )

        # A method call on a tainted receiver returns data derived from it:
        # ``user.encode()``, ``user.strip()``, ``",".join(parts)`` and
        # ``hashlib.md5(user.encode())`` all evaluate to attacker-controlled
        # bytes even though nothing was passed as an argument.  Skipping the
        # receiver dropped the flow one hop before the sink, which is the normal
        # spelling for encoding a hash input or normalising a header value.
        if isinstance(node.func, ast.Attribute):
            receiver = self._visit_expression(node.func.value, ctx)
            if receiver and receiver.is_tainted and not receiver.sanitized:
                callee = self._get_call_name(node) or node.func.attr or "method"
                return TaintState(
                    variable=receiver.variable,
                    is_tainted=True,
                    source=receiver.source,
                    taint_kind=TaintKind.INDIRECT,
                    traces=receiver.traces + [
                        self._create_trace(
                            node, ctx, receiver.variable,
                            f"passed through method {callee}()",
                        )
                    ],
                    confidence=max(0.7, receiver.confidence * 0.95),
                    sanitized=receiver.sanitized,
                    sanitizer=receiver.sanitizer,
                )
        return None

    def _derive_taint(
        self, base: TaintState, node: ast.AST, ctx: FunctionContext, description: str
    ) -> TaintState:
        """Carry an existing taint state across a call boundary."""
        return TaintState(
            variable=base.variable,
            is_tainted=True,
            source=base.source,
            taint_kind=TaintKind.INTERPROCEDURAL,
            traces=base.traces + [self._create_trace(node, ctx, base.variable, description)],
            confidence=max(0.7, base.confidence * 0.95),
            sanitized=base.sanitized,
            sanitizer=base.sanitizer,
            sanitizer_chain=list(base.sanitizer_chain),
        )

    def _create_trace(self, node: ast.AST, ctx: FunctionContext, variable: str, description: str) -> TaintTrace:
        """Create a taint trace step from an AST node."""
        snippet = self._get_snippet(node)
        return TaintTrace(
            step_number=len(ctx.taint_state.get(variable, TaintState(variable="")).traces) + 1,
            kind=TaintKind.DIRECT,
            file_path=self._file_path,
            line_number=getattr(node, "lineno", ctx.line_number),
            column_number=getattr(node, "col_offset", None),
            function_name=ctx.name,
            snippet=snippet,
            tainted_variable=variable,
            description=description,
            confidence=0.9,
        )

    def _get_snippet(self, node: ast.AST) -> str:
        """Get source code snippet for an AST node."""
        try:
            lines = self._source_code.splitlines()
            start = getattr(node, "lineno", 1) - 1
            end = getattr(node, "end_lineno", start + 1)
            return "\n".join(lines[start:end])
        except Exception:
            return ""

    def _get_call_name(self, node: ast.Call) -> str | None:
        """Get the name of a called function."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            # Handle method calls like obj.method()
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
                return ".".join(reversed(parts))
            # The chain does not bottom out in a plain name -- ``open(p).read()``
            # or ``argv[0].strip()``.  Reporting a bare terminal attribute such
            # as "read" as the call name would let a pattern match a name the
            # source never wrote, so there is no name to report here.
            return None
        return None

    # ------------------------------------------------------------------
    # AST-aware expression matching
    # ------------------------------------------------------------------

    def _dotted_path(self, node: ast.AST) -> str | None:
        """Return the dotted name of an attribute/name chain, else None.

        ``request.args`` -> "request.args"; ``sys.argv`` -> "sys.argv";
        ``foo()`` -> None (a call is not a name chain).
        """
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._dotted_path(node.value)
            if base:
                return "%s.%s" % (base, node.attr)
        return None

    def _accessor_attrs(self) -> set[str]:
        """Attribute names that read a value out of a container object.

        ``request.args.get('q')`` reads from ``request.args``, so the accessor
        itself must not hide the container from source matching.
        """
        return {
            "get", "getlist", "getall", "get_one", "pop", "setdefault",
            "getvalue", "getfirst", "read", "readline", "readlines",
            "json", "values", "items", "keys", "first", "all", "scalar",
            "fetchall", "fetchone", "fetchmany",
        }

    def _source_candidates(self, node: ast.AST) -> list[str]:
        """Build the candidate strings a source pattern may match against.

        Registry patterns are written against several concrete syntaxes
        (``sys.argv[``, ``os.environ[``, ``request.args[``, ``request.args.get(``).
        Rather than guess which one applies, the analyzer derives every
        structurally valid spelling of the expression from the AST, so a
        pattern matches whichever form it was written for.

        Returns candidates in priority order (most specific first).
        """
        candidates: list[str] = []

        def add(value: str | None) -> None:
            if value and value not in candidates:
                candidates.append(value)

        if isinstance(node, ast.Call):
            dotted = self._dotted_path(node.func)
            add(dotted)
            if dotted and "." in dotted:
                head, _, tail = dotted.rpartition(".")
                if tail in self._accessor_attrs():
                    # request.args.get(...) reads from request.args
                    add(head)
                    add(head + "[")
                add(dotted + "(")
            # A call on a subscript, e.g. os.environ.get('X')
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Subscript):
                inner = self._dotted_path(node.func.value.value)
                add(inner)
                add((inner or "") + "[")
        elif isinstance(node, ast.Subscript):
            dotted = self._dotted_path(node.value)
            add(dotted)
            add((dotted or "") + "[")
            # os.environ['X'] / sys.argv[1]
            if isinstance(node.value, ast.Attribute) and node.value.attr == "environ":
                add("os.environ.get(")
        elif isinstance(node, ast.Attribute):
            dotted = self._dotted_path(node)
            add(dotted)
            add((dotted or "") + "[")
            if node.attr == "environ":
                add("os.environ[")

        return candidates

    def _match_sources(self, node: ast.AST, language: str = "python") -> list[Source]:
        """Find registered sources matching an expression node, AST-aware."""
        for candidate in self._source_candidates(node):
            found = self.registry.find_sources(candidate, language)
            if found:
                return found
        return []

    def _render_arg(self, node: ast.AST, limit: int = 80) -> str:
        """Render an argument node back to a single line of source text."""
        try:
            text = ast.unparse(node)
        except Exception:
            return ""
        return text.splitlines()[0][:limit] if text else ""

    def _call_candidates(self, node: ast.Call, func_name: str | None) -> list[str]:
        """Candidate strings for sink/sanitizer patterns on a call site.

        Retained for compatibility: the concatenation of the name candidates and
        the anchored argument candidates.  Prefer ``_name_candidates`` /
        ``_argument_candidates`` directly -- see ``_match_sinks``.
        """
        return self._name_candidates(node, func_name) + self._argument_candidates(node, func_name)

    def _name_candidates(self, node: ast.Call, func_name: str | None) -> list[str]:
        """Candidates that name the callee itself.

        Patterns matched against these describe *what is called* -- ``os.system``,
        ``cursor.execute``, ``request.args[`` -- so a match anywhere in the
        string is meaningful.
        """
        candidates: list[str] = []

        def add(value: str | None) -> None:
            if value and value not in candidates:
                candidates.append(value)

        add(func_name)
        if func_name:
            add(func_name + "(")
        for candidate in self._source_candidates(node):
            add(candidate)
        return candidates

    def _argument_candidates(self, node: ast.Call, func_name: str | None) -> list[str]:
        """Candidates that include the rendered argument list.

        A handful of patterns describe the *shape of the call*, notably the
        sql-parameterize sanitizer ``(execute|executemany)\\s*\\([^,]+,\\s*[\\(\\[]``
        and the subprocess-argv sanitizer
        ``subprocess\\.(run|Popen|call)\\s*\\([^,]+,\\s*shell\\s*=\\s*False``.

        Every spelling emitted here is one the source actually contains.
        Synthesising ``func(arg0, (`` for a call that has no second argument
        would make ``conn.execute(query)`` look parameterized and silently strip
        a real injection, so the comma form is only produced when the AST really
        has a second argument.

        Crucially these candidates are matched ANCHORED (the pattern must match
        from position 0).  Without that, a pattern such as ``\\.(get)\\s*\\(`` --
        the Django ORM sanitizer -- matches the text of an inner call:
        ``str(escape(request.args.get('n')`` contains ``.get(`` and would be
        mistaken for a sanitizer applied by ``str()``, discarding the real
        ``escape()`` defence on the value.
        """
        candidates: list[str] = []
        if not func_name:
            return candidates

        parts = self._render_arguments(node)
        if not parts:
            return candidates

        head = parts[0]
        for count in range(1, len(parts) + 1):
            candidates.append("%s(%s" % (func_name, ", ".join(parts[:count])))
        if self._binds_query_parameters(node):
            candidates.append("%s(%s, (" % (func_name, head))
        return candidates

    @staticmethod
    def _anchored_match(pattern: str, text: str) -> bool:
        """True when ``pattern`` matches ``text`` starting at position 0."""
        import re

        try:
            match = re.search(pattern, text, re.IGNORECASE)
        except re.error:
            return False
        return match is not None and match.start() == 0

    def _find_anchored(self, kind: str, candidate: str, language: str) -> list:
        """Registry lookup restricted to patterns that match from position 0."""
        finder = {
            "sources": self.registry.find_sources,
            "sinks": self.registry.find_sinks,
            "sanitizers": self.registry.find_sanitizers,
        }.get(kind)
        if finder is None:
            return []
        return [
            item for item in finder(candidate, language)
            if self._anchored_match(item.pattern, candidate)
        ]

    def _render_arguments(self, node: ast.Call) -> list[str]:
        """Render each argument of a call, in source order, one per element."""
        parts: list[str] = []
        for arg in node.args:
            parts.append("*" if isinstance(arg, ast.Starred) else self._render_arg(arg))
        for kw in node.keywords:
            if kw.arg:
                parts.append("%s=%s" % (kw.arg, self._render_arg(kw.value)))
            else:
                parts.append("**%s" % self._render_arg(kw.value))
        return [part for part in parts if part]

    def _binds_query_parameters(self, node: ast.Call) -> bool:
        """True when the call binds query parameters as a sequence.

        ``execute(sql, (a, b))`` and ``execute(sql, params=[a, b])`` both move
        the values out of the statement text, which is what makes them safe.
        """
        if len(node.args) >= 2 and isinstance(node.args[1], (ast.Tuple, ast.List)):
            return True
        return any(
            kw.arg in self._SQL_PARAM_KEYWORDS and isinstance(kw.value, (ast.Tuple, ast.List))
            for kw in node.keywords
        )

    # Sanitizer categories whose protection is positional: they protect the
    # values that travel BESIDE an expression, never the expression itself.
    _PARAMETER_BINDING_CATEGORIES = frozenset({"sql-parametrize"})

    def _sanitizable_arguments(self, node: ast.Call, sanitizer: Sanitizer) -> list[ast.expr]:
        """Argument expressions a sanitizer may be recorded against.

        A sanitizer transforms the value it is applied to, so the attachment has
        to describe the value the sanitizer actually receives.  Parameter
        binding is the exception: in ``execute(sql, params)`` the values travel
        beside the statement text and never enter it, so recording a
        parameterization sanitizer against interpolated statement text would
        claim a protection it never provided and hide a real SQL injection.
        """
        arguments = list(node.args) + [kw.value for kw in node.keywords]
        if sanitizer.category not in self._PARAMETER_BINDING_CATEGORIES:
            return arguments
        if not self._binds_query_parameters(node):
            return arguments
        statement = self._sql_text_argument(node)
        if statement is None:
            return arguments
        return [arg for arg in arguments if arg is not statement]

    def _match_sinks(self, node: ast.Call, func_name: str | None) -> list[Sink]:
        """Find registered sinks matching a call site, AST-aware."""
        for candidate in self._name_candidates(node, func_name):
            found = self.registry.find_sinks(candidate, "python")
            if found:
                return found
        # Argument-shape patterns must describe the call from its first token,
        # otherwise a pattern written for one call matches inside another.
        for candidate in self._argument_candidates(node, func_name):
            found = self._find_anchored("sinks", candidate, "python")
            if found:
                return found
        return []

    def _match_sanitizers(self, node: ast.Call, func_name: str | None) -> list[Sanitizer]:
        """Find registered sanitizers matching a call site, AST-aware."""
        for candidate in self._name_candidates(node, func_name):
            found = self.registry.find_sanitizers(candidate, "python")
            if found:
                return found
        for candidate in self._argument_candidates(node, func_name):
            found = self._find_anchored("sanitizers", candidate, "python")
            if found:
                return found
        return []

    # ------------------------------------------------------------------
    # SQL execution analysis
    # ------------------------------------------------------------------

    _SQL_TEXT_KEYWORDS = ("sql", "query", "statement", "operation", "command")
    _SQL_PARAM_KEYWORDS = ("parameters", "params", "vars", "args", "seq", "param")

    def _sql_text_argument(self, node: ast.Call) -> ast.expr | None:
        """Return the expression holding the SQL statement text.

        This is the argument that becomes part of the executed statement, so
        it is the one that must be free of taint for a query to be safe.
        """
        if node.args:
            return node.args[0]
        for kw in node.keywords:
            if kw.arg in self._SQL_TEXT_KEYWORDS:
                return kw.value
        return None

    def _interpolates_taint(self, expr: ast.expr, ctx: "FunctionContext") -> bool:
        """True when tainted data is built INTO the given expression."""
        taint = self._visit_expression(expr, ctx)
        return bool(taint and taint.is_tainted)

    def _get_return_nodes(self, node: ast.FunctionDef) -> list[ast.Return]:
        """Get all return nodes in a function."""
        returns = []
        for n in ast.walk(node):
            if isinstance(n, ast.Return):
                returns.append(n)
        return returns

    def _record_taint_path(
        self,
        taint_state: TaintState,
        sink: Sink,
        node: ast.Call,
        ctx: FunctionContext,
        destination: Optional[list[TaintPath]] = None,
        breaking_sanitizer: Optional[Sanitizer] = None,
    ) -> None:
        """Record a discovered taint path from source to sink.

        ``destination`` is where the path is filed (reported findings by
        default).  ``breaking_sanitizer`` is set when a sanitizer genuinely
        neutralised this sink, in which case the path is filed as an auditable
        record rather than a finding.
        """
        if not taint_state.source:
            return

        traces = taint_state.traces + [self._create_trace(node, ctx, taint_state.variable, f"sink: {sink.name}")]
        self._number_traces(traces)

        broken = breaking_sanitizer is not None
        path = TaintPath(
            source=taint_state.source,
            sink=sink,
            traces=traces,
            # A sanitizer that does not break the flow is still reported, so a
            # reviewer can see that html.escape() was applied and judge it.
            sanitizers_encountered=(
                taint_state.sanitizer_chain
                or ([taint_state.sanitizer] if taint_state.sanitizer else [])
            ),
            is_sanitized=broken,
            breaking_sanitizer=breaking_sanitizer,
            severity=sink.severity,
            cwe_ids=list(set(taint_state.source.cwe_ids + sink.cwe_ids)),
            sink_file=self._file_path,
            # The sink call site, not the enclosing function's definition.
            sink_line=getattr(node, "lineno", ctx.line_number),
            attack_vector=f"Tainted data from {taint_state.source.name} flows to {sink.name} without proper sanitization",
            remediation=self._get_remediation(sink),
        )
        path.confidence = path.compute_confidence()
        if broken:
            path.metadata["sanitizer_verdict"] = (
                "%s neutralizes %s (%s)"
                % (breaking_sanitizer.name, sink.category, ",".join(sink.cwe_ids))
            )
        (self.taint_paths if destination is None else destination).append(path)

    @staticmethod
    def _number_traces(traces: list[TaintTrace]) -> None:
        """Renumber a trace 1..N in list order.

        ``_create_trace`` derives its provisional number from how many traces
        the tainted variable already carries, which repeats and skips once a
        variable flows through several steps.  A consumer must be able to order
        a trace deterministically, so the sequence is normalised here.
        """
        for index, trace in enumerate(traces):
            trace.step_number = index + 1

    # ------------------------------------------------------------------
    # Sanitizer effectiveness against a specific sink
    # ------------------------------------------------------------------

    # A sanitizer that only validates or merely reshapes its input does not
    # remove the dangerous characters, so it never breaks a flow.
    _NEUTRALIZING_ACTIONS = frozenset(
        {SanitizerAction.REMOVE, SanitizerAction.ESCAPE}
    )

    # Secondary cross-check between the sanitizer's own category vocabulary and
    # the sink's.  A sanitizer may only ever narrow this set: it is consulted
    # only when the sanitizer category is listed, and only to refuse a
    # neutralization, so an unlisted (novel) category cannot suppress anything.
    _SANITIZER_CATEGORY_PROTECTS = {
        "sql-parametrize": frozenset({"sql-execution"}),
        "html-escape": frozenset({"xss"}),
        "deserialization-sanitize": frozenset({"deserialization"}),
        "command-sanitize": frozenset({"command-execution"}),
        "path-normalize": frozenset({"path-traversal"}),
        "url-validate": frozenset({"open-redirect"}),
        "regex-sanitize": frozenset({"regex-dos"}),
    }

    def _kind_is_handled(self, sanitizer: Sanitizer, kind: TaintKind) -> bool:
        """Is the flow's taint kind inside the sanitizer's declared scope?"""
        handled = sanitizer.handles_kinds
        if not handled:
            # Unscoped: claims to handle every kind.
            return True
        if kind in handled:
            return True
        # A sanitizer is applied to the value itself at the call site.  Every
        # propagation kind (parameter, interprocedural, indirect, return, field)
        # describes how the value travelled, not a separate sanitization step,
        # so a sanitizer that handles DIRECT covers them.  A sanitizer that
        # declares only INTERPROCEDURAL is genuinely narrower and is respected.
        return TaintKind.DIRECT in handled

    def _cwe_overlap(self, sanitizer: Sanitizer, sink: Sink) -> bool:
        """True when the sanitizer and sink name the same weakness."""
        if not sanitizer.cwe_ids or not sink.cwe_ids:
            # Missing CWE metadata is not evidence of protection.
            return False
        return bool(set(sanitizer.cwe_ids) & set(sink.cwe_ids))

    def _category_allows(self, sanitizer: Sanitizer, sink: Sink) -> bool:
        """Secondary guard: the sink must be one this sanitizer class protects."""
        protected = self._SANITIZER_CATEGORY_PROTECTS.get(sanitizer.category)
        if protected is None:
            # Novel/unknown sanitizer category: no claim is made either way.
            return True
        return sink.category in protected

    def _neutralizing_sanitizer(self, taint_state: TaintState, sink: Sink) -> Optional[Sanitizer]:
        """Return the sanitizer that genuinely breaks this flow, else None.

        Effectiveness is decided per sink, from the sanitizer's own metadata:
        it must be strong, take a neutralizing action, declare this flow's taint
        kind in scope, name the same CWE as the sink, and belong to a sanitizer
        class that covers the sink's category.  Anything else leaves the flow
        intact and reported.

        Every sanitizer in the chain is tested, not just the last one: in
        ``open(os.path.join(base, os.path.basename(name)))`` the outer join is
        merely a transform, but the inner basename removes every directory
        component, so the traversal cannot happen regardless of the join.
        """
        if taint_state.sanitized:
            return None
        chain = taint_state.sanitizer_chain or (
            [taint_state.sanitizer] if taint_state.sanitizer else []
        )
        for sanitizer in chain:
            if sanitizer is None:
                continue
            if not sanitizer.is_strong:
                continue
            if sanitizer.action not in self._NEUTRALIZING_ACTIONS:
                continue
            if not self._kind_is_handled(sanitizer, taint_state.taint_kind):
                continue
            if not self._cwe_overlap(sanitizer, sink):
                continue
            if not self._category_allows(sanitizer, sink):
                continue
            return sanitizer
        return None

    @staticmethod
    def _has_shell_true(node: ast.Call) -> bool:
        """True when the call passes shell=True (explicitly or via a truthy name)."""
        for kw in node.keywords:
            if kw.arg != "shell":
                continue
            value = kw.value
            if isinstance(value, ast.Constant):
                return bool(value.value)
            return True  # shell=some_variable: assume the worst
        return False

    def _argv_list_exempt(self, node: ast.Call, sink: Sink) -> bool:
        """True when a command sink receives an argv list with no shell.

        ``subprocess.run(["ping", "-c", "1", host])`` hands ``host`` to execve
        as one argv element; no shell parses it, so ``; rm -rf /`` is an inert
        argument.  Reporting it as command injection is a false positive that
        made the safe corpus look compromised.

        Two cases stay dangerous even as a list: ``shell=True`` (the first
        element becomes a shell command line) and a tainted element 0 (the
        program name itself runs an arbitrary binary).
        """
        if sink.category != "command-execution" or not node.args:
            return False
        first = node.args[0]
        if not isinstance(first, (ast.List, ast.Tuple)) or not first.elts:
            return False
        if self._has_shell_true(node):
            return False
        # The program must be a literal, not a variable that may itself be tainted.
        return isinstance(first.elts[0], ast.Constant)

    @staticmethod
    def _is_allowlist_guard(node: ast.IfExp) -> bool:
        """True for ``value if value in ALLOWED else <safe default>``.

        The guard has to do three things, or it is not a guard:
          * the tested variable is the same one the tainted branch returns
            (``x if y in allowed else ...`` guards y, not x);
          * the other branch is a constant, so a failed test cannot return
            attacker-controlled data;
          * the membership is positive (``in``, not ``not in``) -- ``not in``
            inverts the check rather than validating the value.
        """
        test = node.test
        if not isinstance(test, ast.Compare):
            return False
        if len(test.ops) != 1 or not isinstance(test.ops[0], ast.In):
            return False
        guarded = test.left
        if not isinstance(guarded, ast.Name) or not isinstance(node.body, ast.Name):
            return False
        if guarded.id != node.body.id:
            return False
        # An allowlist the analyzer can see: a set/list/tuple literal, or a Name
        # that was assigned one.  A Name to an unknown collection is still the
        # documented safe idiom, so it is accepted; the audit trail records it.
        comparator = test.comparators[0]
        if isinstance(comparator, (ast.Set, ast.List, ast.Tuple)):
            return True
        return isinstance(comparator, ast.Name) and not isinstance(node.orelse, ast.Name)

    def _report_sink_hit(
        self, taint_state: TaintState, sink: Sink, node: ast.Call, ctx: FunctionContext
    ) -> None:
        """Record a tainted value reaching a sink, honouring real sanitization.

        A flow that a sanitizer genuinely protects against this specific sink is
        kept out of the reported findings but preserved in ``sanitized_flows``
        so the decision is auditable rather than silently dropped.
        """
        if not taint_state.is_tainted:
            return
        if self._argv_list_exempt(node, sink):
            # Keep the path as an auditable record, not a finding: the argv-list
            # form is the recommended fix and reporting it punishes correct code.
            self._record_taint_path(
                taint_state, sink, node, ctx, destination=self.sanitized_flows
            )
            return
        breaking = self._neutralizing_sanitizer(taint_state, sink)
        if breaking is not None:
            self._record_taint_path(
                taint_state, sink, node, ctx,
                destination=self.sanitized_flows, breaking_sanitizer=breaking,
            )
            return
        self._record_taint_path(taint_state, sink, node, ctx)

    def _get_remediation(self, sink: Sink) -> str:
        """Get remediation advice for a sink."""
        remediation_map = {
            "sql-execution": "Use parameterized queries / prepared statements. Never concatenate user input into SQL strings.",
            "command-execution": "Avoid shell=True. Use argument arrays (argv) with subprocess. Allowlist commands.",
            "code-execution": "Never use eval/exec on untrusted input. Use safe parsers (json.loads, ast.literal_eval).",
            "deserialization": "Use safe deserialization (yaml.safe_load, json.loads). Never deserialize untrusted pickle/yaml.",
            "template-injection": "Use template engines with autoescaping. Never render user input as template code.",
            "path-traversal": "Normalize paths (os.path.normpath), resolve (pathlib.Path.resolve), and validate against allowlist.",
            "open-redirect": "Validate redirect targets against an allowlist. Never redirect to raw user input.",
            "xss": "Use contextual output encoding. Enable CSP. Use safe APIs (textContent, framework bindings).",
            "ldap-injection": "Use parameterized LDAP queries. Escape user input with ldap3.utils.conv.escape_filter_chars.",
            "xpath-injection": "Use parameterized XPath or escape user input.",
            "regex-dos": "Avoid user input in regex patterns. Use timeout on regex operations.",
            "log-injection": "Sanitize newlines and control characters before logging.",
        }
        return remediation_map.get(sink.category, "Validate and sanitize all user input before use.")

    def _interprocedural_analysis(self) -> None:
        """Build per-function summaries and attach them to the call graph.

        The propagation itself happens at each call site while the body that
        contains it is visited (``_visit_call`` -> ``_propagate_into_callee``),
        which is call-site sensitive, keyword-aware, depth-bounded and reports
        sinks at their own line.  Replaying it here from summaries alone would
        lose the argument-to-parameter binding, which is exactly what made the
        old single-level pass report parameterized queries as injection and
        point at callee definition lines.
        """
        for key, ctx in self.function_contexts.items():
            summary = FunctionSummary(
                name=ctx.name,
                file_path=ctx.file_path,
                line_number=ctx.line_number,
                tainted_params=list(ctx.tainted_params),
                returns_taint=ctx.return_tainted,
                return_tainted_by=list(ctx.return_tainted_by),
                sanitizers_called=[s.name for s in ctx.sanitizers_found],
                sinks_called=[s.name for s in ctx.sinks_found],
                sources_called=[s.name for s in ctx.sources_found],
                propagates_taint=ctx.return_tainted and len(ctx.tainted_params) > 0,
            )
            # Update call graph node
            cg_node = self.call_graph.get_node(key)
            if cg_node:
                cg_node.summary = summary

    def _analyze_module_level(self, tree: ast.AST) -> None:
        """Analyze module-level statements for taint flows."""
        # Create a pseudo-function context for module-level code
        module_ctx = FunctionContext(
            name="<module>",
            file_path=self._file_path,
            node=tree,  # Use the module as the node
            line_number=0,
        )
        # Store in function_contexts for later interprocedural analysis
        qualified_name = f"{self._file_path}:<module>:0"
        self.function_contexts[qualified_name] = module_ctx
        self._current_function = module_ctx

        # Visit all module-level statements
        for stmt in tree.body:
            if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self._visit_statement(stmt, module_ctx)

    def _extract_taint_paths(self) -> None:
        """Extract and deduplicate taint paths."""
        # Deduplicate by source+sink+file+line
        seen = set()
        unique_paths = []
        for path in self.taint_paths:
            key = (path.source.name, path.sink.name, path.sink_file, path.sink_line)
            if key not in seen:
                seen.add(key)
                unique_paths.append(path)
        self.taint_paths = unique_paths


def analyze_python_file(file_path: str) -> list[TaintPath]:
    """Convenience function to analyze a single Python file."""
    analyzer = PythonTaintAnalyzer()
    return analyzer.analyze_file(file_path)


def analyze_python_directory(dir_path: str, max_files: int = 1000) -> list[TaintPath]:
    """Convenience function to analyze a Python directory."""
    analyzer = PythonTaintAnalyzer()
    return analyzer.analyze_directory(dir_path, max_files)