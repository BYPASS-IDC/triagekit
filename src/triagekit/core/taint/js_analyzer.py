"""JavaScript/TypeScript taint analyzer.

Regex/heuristic-based by design: there is no JS parser in this build, and a
hand-rolled one would be worse than an honest approximation.  What this module
does is approximate the *four* things a taint analysis needs, and be explicit
about what it cannot see:

1. **Function boundaries** -- named declarations, named and anonymous arrows,
   object/class methods, and (the case that produced zero findings before)
   anonymous callbacks passed directly to a call, which is how every Express
   handler is written.
2. **Sources** -- registry patterns matched against whole expressions, so
   ``req.query.host`` and ``location.hash`` are recognised inline rather than
   only through a parameter name.
3. **Propagation** -- assignment, reassignment, ``+`` concatenation, template
   literals, and pass-through calls.
4. **Sinks** -- registry patterns matched against the call/assignment text, with
   the vulnerable argument checked for taint and a sanitizer gate in front.

The registry's JS rules are *line-shaped* (``child_process\\.exec\\s*\\(``), while
the analyzer used to pass bare callee names (``exec``) to ``find_sinks``.  That
mismatch is why a file of nine vulnerabilities returned nothing: the patterns
were written for text they never received.  Matching is now done against the
call text with the additional constraint that the match must *begin inside the
callee span*, which keeps a pattern from matching something that merely appears
in an argument.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Union

from .models import (
    CallGraph,
    CallGraphNode,
    FunctionSummary,
    Sanitizer,
    Sink,
    Source,
    TaintKind,
    TaintPath,
    TaintTrace,
)
from .registry import get_registry


@dataclass
class JSTaintState:
    """Tracks taint state for a variable during JS analysis."""

    variable: str
    is_tainted: bool = False
    source: Optional[Source] = None
    taint_kind: TaintKind = TaintKind.DIRECT
    traces: list[TaintTrace] = field(default_factory=list)
    sanitized: bool = False
    sanitizer: Optional[Sanitizer] = None
    confidence: float = 1.0


@dataclass
class JSFunctionContext:
    """Context for analyzing a single JS function."""

    name: str
    file_path: str
    start_line: int
    end_line: int
    code: str
    # Taint state for variables in this function
    taint_state: dict[str, JSTaintState] = field(default_factory=dict)
    # Parameters that are sources
    tainted_params: set[int] = field(default_factory=set)
    # Parameter names in declaration order (index -> name).  Re-deriving these
    # from ``code`` fails for single-parameter arrows (``x => ...``), which have
    # no parentheses at all, and for handlers whose first parentheses in the
    # extracted text belong to something other than the parameter list.
    param_names: list[str] = field(default_factory=list)
    # Parameter index -> the source that taints it
    param_sources: dict[int, Source] = field(default_factory=dict)
    # Whether return value is tainted
    return_tainted: bool = False
    # Which parameters taint the return
    return_tainted_by: set[int] = field(default_factory=set)
    # Called functions
    calls: list[str] = field(default_factory=list)
    # Sources/sinks/sanitizers found
    sources_found: list[Source] = field(default_factory=list)
    sinks_found: list[Sink] = field(default_factory=list)
    sanitizers_found: list[Sanitizer] = field(default_factory=list)
    # Real 1-based line numbers for each line of ``code``.  ``code`` is not
    # always contiguous -- the synthetic module context holds the lines no
    # function owns -- so line numbers cannot be recovered by counting.
    line_map: Optional[list[int]] = None

    def line_for(self, index: int, default: int) -> int:
        """Map a 0-based index into ``code`` onto its real source line."""
        if self.line_map is not None and 0 <= index < len(self.line_map):
            return self.line_map[index]
        return self.start_line + index


class JSTaintAnalyzer:
    """Regex-based taint analyzer for JavaScript/TypeScript code."""

    # Patterns for parsing JS/TS code
    FUNCTION_PATTERN = re.compile(
        r"(?:(?:async\s+)?function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?function\s*\([^)]*\))",
        re.MULTILINE
    )
    ARROW_FUNCTION_PATTERN = re.compile(
        r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>",
        re.MULTILINE
    )
    METHOD_PATTERN = re.compile(
        r"(\w+)\s*:\s*(?:async\s*)?function\s*\(([^)]*)\)",
        re.MULTILINE
    )
    CLASS_METHOD_PATTERN = re.compile(
        r"(?:async\s+)?(\w+)\s*\(([^)]*)\)\s*\{",
        re.MULTILINE
    )
    # An inline function literal used as a call argument.  The dominant Node.js
    # shape -- ``app.get('/ping', (req, res) => { ... })`` -- was invisible to
    # every pattern above, because none of them match an *anonymous* function.
    # With no function extracted there is no context, and with no context there
    # is no analysis: the file yielded zero findings.  See D10.
    FUNCTION_LITERAL_PATTERN = re.compile(
        r"(?P<prefix>[A-Za-z_$][\w$.]*(?:\s*[:,]\s*|\s+)?)?"
        r"\((?P<params>[^()]*)\)"
        r"\s*(?:=>\s*)?\{",
        re.MULTILINE,
    )
    # A single unparenthesised arrow parameter: ``x => {``.
    ARROW_SINGLE_PATTERN = re.compile(
        r"(?<![\w$.])(?P<param>[A-Za-z_$][\w$]*)\s*=>\s*\{", re.MULTILINE)
    # A concise-body arrow: ``(req, res) => res.redirect(req.query.to)``.  No
    # brace, so every pattern above skips it -- and ``res.redirect`` handlers are
    # usually written exactly this way, so the sink was invisible too.
    ARROW_CONCISE_PATTERN = re.compile(
        r"\((?P<params>[^()]*)\)\s*=>\s*(?P<body>[^{\n]+)",
        re.MULTILINE,
    )
    # Words that introduce a brace block without being a function.  A pattern
    # alone cannot tell ``if (x) {`` from ``cb(x) {``, so they are filtered here
    # rather than argued with in the regex.
    _NON_FUNCTION_PREFIXES = frozenset({
        "if", "for", "while", "switch", "catch", "else", "return", "typeof",
        "new", "await", "delete", "void", "in", "of", "do", "try", "finally",
        "function", "require", "=>",
    })
    CALL_PATTERN = re.compile(
        r"(\w+(?:\.\w+)*)\s*\(",
        re.MULTILINE
    )
    ASSIGNMENT_PATTERN = re.compile(
        r"(?:const|let|var)\s+(\w+)\s*=\s*([^;\n]+);?",
        re.MULTILINE
    )
    RETURN_PATTERN = re.compile(
        r"return\s+([^;]+);",
        re.MULTILINE
    )
    # ``obj.prop = <expr>`` -- the shape every DOM-XSS sink in the registry
    # actually has (``el.innerHTML = ...``).  A plain ``\w+ =`` pattern never
    # matches it, so those sinks were unreachable.  Call segments are allowed in
    # the target because ``document.getElementById('out').innerHTML = x`` is the
    # form real code uses.
    MEMBER_ASSIGN_PATTERN = re.compile(
        r"^(?P<target>[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*|\s*\(\s*[^()]*\s*\))+)"
        r"\s*=\s*(?P<value>[^=].*?);?$",
    )
    # Parameter names whose whole value is attacker-controlled.  Express's
    # ``req`` (and Koa's ``ctx``) are the request object: ``req.query.host`` is
    # user input, and marking the *parameter* tainted is what lets the member
    # expression propagate.  Without this, a request object passed by value
    # carries no taint into the callback body.
    REQUEST_PARAM_NAMES = frozenset({"req", "request", "ctx"})

    # Synthetic context name for statements outside any function.  Python's
    # analyzer has module-level analysis; JS did not, so a flow that lives at
    # top level -- a config read from ``process.argv`` feeding an exported
    # handler -- was invisible.  See D12.
    MODULE_CONTEXT_NAME = "<module>"

    # The request object is a source by virtue of being the request object, not
    # by matching a call pattern.  Without this, ``exec('x ' + req.query.host)``
    # only works when the request value happens to be spelled exactly as a
    # registry pattern; ``ctx.state.user`` or ``request.params.id`` in Koa do not.
    _REQUEST_OBJECT_SOURCE = Source(
        name="js-request-object",
        category="http-request",
        description="Request object parameter (Express req / Koa ctx)",
        pattern=r"^(req|request|ctx)$",
        languages=["javascript", "typescript"],
        confidence=0.9,
        cwe_ids=["CWE-20"],
        tags=["web", "input", "request"],
    )

    # Calls that spawn a process but only interpret a shell when asked to.  An
    # argv array (``execFile('ping', ['-c','1',host])``) is the *safe* idiom and
    # must not fire; ``execFile('ping -c 1 ' + host)`` and ``{shell: true}`` do.
    _ARGV_CALLS = frozenset({
        "execFile", "execFileSync", "spawn", "spawnSync", "fork",
    })

    # A sanitizer only neutralises the sink classes it is defined for, and only
    # when it removes/escapes rather than validates.  ``path.join`` and
    # ``new URL()`` are VALIDATE in the registry and do not belong here:
    # ``path.join('/base', '/etc/passwd')`` still escapes the base.
    _SANITIZER_BLOCKS: dict[str, frozenset[str]] = {
        "sql-parametrize": frozenset({"sql-execution"}),
        "html-escape": frozenset({"xss", "dom-xss"}),
        "command-sanitize": frozenset({"command-execution"}),
    }

    # Which source categories count as attacker-controlled.  A sink only fires
    # when the data reaching it came from an attacker, so this is the gate that
    # separates a finding from a style note.
    #
    # ``environment`` is the deliberate exclusion.  ``process.env.API_TOKEN`` is
    # deployment configuration: it is server-side data the operator chose, and
    # letting it propagate made every derived value tainted -- an HMAC built
    # from it, a log line, a feature flag.  Reporting those as injection
    # findings is how a scanner loses its audience.  The remaining categories
    # are all data an attacker can influence: a request value, CLI input, a DOM
    # location, a remote response, a file the attacker supplied, or a payload
    # parsed from one.
    _ATTACKER_CONTROLLED_CATEGORIES = frozenset({
        "http-request", "user-input", "dom-xss", "code-execution",
        "deserialization", "http-response", "file",
    })

    # Identifiers that are language keywords or very common locals and must not
    # be mistaken for a tainted variable during expression scanning.
    _NON_TAINT_WORDS = frozenset({
        "const", "let", "var", "function", "return", "if", "else", "for",
        "while", "switch", "case", "break", "continue", "new", "typeof",
        "await", "async", "true", "false", "null", "undefined", "this",
        "require", "module", "exports", "default", "class", "extends", "import",
        "from", "export", "try", "catch", "finally", "throw", "of", "in", "do",
        "delete", "void", "instanceof", "yield", "static", "get", "set",
    })

    # Calls whose result carries the taint of their receiver or arguments.  The
    # default for a call is the opposite -- see ``_get_taint_from_expression``.
    _TRANSPARENT_CALLS = frozenset({
        "trim", "trimStart", "trimEnd", "toLowerCase", "toUpperCase",
        "toLocaleLowerCase", "toLocaleUpperCase", "toString", "valueOf",
        "split", "slice", "substring", "substr", "replace", "replaceAll",
        "padStart", "padEnd", "repeat", "normalize", "concat", "at", "charAt",
        "charCodeAt", "indexOf", "includes", "startsWith", "endsWith", "match",
        "join", "map", "filter", "find", "findIndex", "forEach", "reduce",
        "flat", "flatMap", "String", "Number", "Boolean", "Array", "Object",
        "parseInt", "parseFloat", "encodeURIComponent", "decodeURIComponent",
        "escape", "unescape", "JSON", "Promise", "then", "catch", "await",
        "resolves", "rejects",
    })

    _IDENT_CHAIN = re.compile(r"[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*")
    _OPENERS = {"(": ")", "[": "]", "{": "}"}
    _CLOSERS = {")", "]", "}"}

    def __init__(self, registry: Optional[Any] = None):
        self.registry = registry or get_registry()
        self.function_contexts: dict[str, JSFunctionContext] = {}
        self.call_graph = CallGraph()
        self.taint_paths: list[TaintPath] = []
        self._file_path: str = ""
        self._source_code: str = ""
        self._lines: list[str] = []
        self._module_ctx: Optional[JSFunctionContext] = None

    # ------------------------------------------------------------------
    # entry points
    # ------------------------------------------------------------------

    def analyze_file(self, file_path: str) -> list[TaintPath]:
        """Analyze a single JS/TS file for taint flows."""
        self._reset_state()
        self._file_path = file_path
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                self._source_code = f.read()
        except Exception:
            return []

        self._lines = self._source_code.splitlines()

        # Extract functions
        self._extract_functions()

        # Analyze each function
        for ctx in self.function_contexts.values():
            self._analyze_function(ctx)

        # Statements outside any function (Python's analyzer has this; JS did
        # not, so top-level flows were silently invisible -- D12).
        module_ctx = self._build_module_context()
        if module_ctx is not None:
            self._module_ctx = module_ctx
            self._analyze_function(module_ctx)

        # Interprocedural analysis (simplified)
        self._interprocedural_analysis()

        self._deduplicate_paths()

        return self.taint_paths

    def _reset_state(self) -> None:
        """Clear per-file state.

        ``analyze_directory`` reuses one analyzer instance across files, and
        every accumulator below survived between calls, so results depended on
        file order: a flow found in file 3 was attributed to the file processed
        first, and ``taint_paths`` grew monotonically.  See D11.
        """
        self.function_contexts = {}
        self.call_graph = CallGraph()
        self.taint_paths = []
        self._source_code = ""
        self._lines = []
        self._module_ctx = None

    def analyze_directory(self, dir_path: str, max_files: int = 1000) -> list[TaintPath]:
        """Analyze all JS/TS files in a directory."""
        all_paths = []
        count = 0

        for root, dirs, files in os.walk(dir_path):
            # Skip common ignore directories
            dirs[:] = [d for d in dirs if d not in {
                ".git", "node_modules", "venv", ".venv", "env", "__pycache__",
                ".mypy_cache", ".pytest_cache", "dist", "build", "target", "coverage",
                ".next", "out", ".turbo"
            }]

            for file in files:
                if file.endswith((".js", ".jsx", ".ts", ".tsx")) and not file.endswith((".min.js", ".min.ts", ".d.ts")):
                    file_path = os.path.join(root, file)
                    paths = self.analyze_file(file_path)
                    all_paths.extend(paths)
                    count += 1
                    if count >= max_files:
                        break

            if count >= max_files:
                break

        return all_paths

    # ------------------------------------------------------------------
    # function extraction
    # ------------------------------------------------------------------

    def _extract_functions(self) -> None:
        """Extract function definitions from source code."""
        # Find function declarations
        for match in self.FUNCTION_PATTERN.finditer(self._source_code):
            name = match.group(1) or match.group(2) or match.group(3)
            if name:
                start_line = self._source_code[:match.start()].count("\n") + 1
                # Find function end (simplified - find matching brace)
                end_line = self._find_function_end(match.end())
                code = "\n".join(self._lines[start_line - 1:end_line])

                ctx = JSFunctionContext(
                    name=name,
                    file_path=self._file_path,
                    start_line=start_line,
                    end_line=end_line,
                    code=code,
                )
                # Extract parameters
                self._extract_params(match.group(0), ctx)

                qualified_name = f"{self._file_path}:{name}:{start_line}"
                self.function_contexts[qualified_name] = ctx

                # Add to call graph
                cg_node = CallGraphNode(
                    function_name=name,
                    file_path=self._file_path,
                    line_number=start_line,
                )
                self.call_graph.add_node(cg_node)

        # Find arrow functions
        for match in self.ARROW_FUNCTION_PATTERN.finditer(self._source_code):
            name = match.group(1)
            params_str = match.group(2)
            start_line = self._source_code[:match.start()].count("\n") + 1
            end_line = self._find_function_end(match.end())
            code = "\n".join(self._lines[start_line - 1:end_line])

            ctx = JSFunctionContext(
                name=name,
                file_path=self._file_path,
                start_line=start_line,
                end_line=end_line,
                code=code,
            )
            self._extract_params_from_str(params_str, ctx)

            qualified_name = f"{self._file_path}:{name}:{start_line}"
            self.function_contexts[qualified_name] = ctx

        # Inline function literals in call arguments.  This is the shape every
        # Express/Connect/Koa handler takes, and it was the reason a file full
        # of vulnerabilities produced no findings at all (D10).
        self._extract_inline_functions()

    def _extract_inline_functions(self) -> None:
        """Extract anonymous and concise-body function literals.

        ``app.get('/ping', (req, res) => {...})`` has no binding name, so the
        named-declaration patterns cannot see it.  A generic
        ``(...)  => {`` / ``(...) {`` pattern can, once the brace blocks that are
        not functions (``if``, ``for``, ``while``, ``switch``, ``catch``, ...)
        are filtered out by the preceding word.
        """
        # Line ranges already owned by an extracted function.  The generic
        # literal patterns match named functions, object methods and nested
        # callbacks too, and analysing them twice would duplicate every finding.
        owned: set[int] = set()
        for existing in self.function_contexts.values():
            owned.update(range(existing.start_line, existing.end_line + 1))

        def _owns(start: int, end: int) -> bool:
            return any(line in owned for line in range(start, end + 1))

        patterns = (
            (self.FUNCTION_LITERAL_PATTERN, "brace"),
            (self.ARROW_SINGLE_PATTERN, "brace"),
            (self.ARROW_CONCISE_PATTERN, "concise"),
        )

        for pattern, kind in patterns:
            for match in pattern.finditer(self._source_code):
                start_line = self._source_code[:match.start()].count("\n") + 1

                if kind == "concise":
                    params_str = match.group("params") or ""
                    body = (match.group("body") or "").strip().rstrip(";,").rstrip()
                    # A concise body is one expression; it is analysed as a
                    # one-line context whose code is that expression.
                    if not body:
                        continue
                    end_line = start_line
                    code = body
                    name = "<anonymous>"
                else:
                    if pattern is self.FUNCTION_LITERAL_PATTERN:
                        prefix = (match.group("prefix") or "").strip()
                        prefix_word = re.split(r"[\s:,.]", prefix.strip())[-1] if prefix else ""
                        if prefix_word in self._NON_FUNCTION_PREFIXES:
                            continue
                        name = prefix_word or self._nearest_callable(match.start())
                        params_str = match.group("params") or ""
                    else:
                        name = self._nearest_callable(match.start())
                        params_str = match.group("param") or ""

                    # The match ends just past the opening brace, so the body
                    # starts at match.end().  _find_function_end expects to
                    # *begin* on the brace, hence the -1.
                    body_start = match.end() - 1
                    if body_start < 0 or body_start >= len(self._source_code):
                        continue
                    if self._source_code[body_start] != "{":
                        continue

                    end_line = self._find_function_end(body_start)
                    if end_line < start_line:
                        continue
                    code = "\n".join(self._lines[start_line - 1:end_line])

                if _owns(start_line, end_line):
                    continue

                ctx = JSFunctionContext(
                    name=name,
                    file_path=self._file_path,
                    start_line=start_line,
                    end_line=end_line,
                    code=code,
                )
                self._extract_params_from_str(params_str, ctx)

                qualified_name = f"{self._file_path}:{name}:{start_line}:inline"
                if qualified_name in self.function_contexts:
                    continue
                self.function_contexts[qualified_name] = ctx
                owned.update(range(start_line, end_line + 1))

    def _nearest_callable(self, pos: int) -> str:
        """Name an anonymous function after the call it is an argument of.

        ``app.get('/ping', (req, res) => {...})`` is far more useful in a report
        as ``app.get`` than as ``<anonymous>``, and the cost is a short backward
        scan for an identifier chain immediately followed by the opening paren.
        """
        i = pos - 1
        while i >= 0 and self._source_code[i] in " \t\r\n,":
            i -= 1
        if i < 0 or self._source_code[i] != "(":
            return "<anonymous>"
        j = i - 1
        while j >= 0 and self._source_code[j] in " \t":
            j -= 1
        end = j + 1
        while j >= 0 and (self._source_code[j].isalnum() or self._source_code[j] in "_$."):
            j -= 1
        name = self._source_code[j + 1:end].strip()
        return name or "<anonymous>"

    def _build_module_context(self) -> Optional[JSFunctionContext]:
        """Build a synthetic context covering statements outside any function.

        A top-level ``const token = process.argv[2]`` feeding an exported
        handler is a real flow, and nothing in the per-function pass sees it.
        The context spans the lines no extracted function owns, and carries an
        explicit line map because those lines are not contiguous.
        """
        owned: set[int] = set()
        for ctx in self.function_contexts.values():
            owned.update(range(ctx.start_line, ctx.end_line + 1))

        free = [i for i in range(1, len(self._lines) + 1) if i not in owned]
        if not free:
            return None

        code = "\n".join(self._lines[i - 1] for i in free)
        ctx = JSFunctionContext(
            name=self.MODULE_CONTEXT_NAME,
            file_path=self._file_path,
            start_line=min(free),
            end_line=max(free),
            code=code,
            line_map=list(free),
        )
        # Module scope has no request object, so nothing is tainted by default;
        # sources are still matched per line, which is what matters here.
        return ctx

    # ------------------------------------------------------------------
    # parameters
    # ------------------------------------------------------------------

    def _extract_params(self, func_decl: str, ctx: JSFunctionContext) -> None:
        """Extract parameters from a function declaration."""
        param_match = re.search(r"\(([^)]*)\)", func_decl)
        if param_match:
            self._extract_params_from_str(param_match.group(1), ctx)

    def _extract_params_from_str(self, params_str: str, ctx: JSFunctionContext) -> None:
        """Extract parameters from a parameter string."""
        params = [p.strip() for p in params_str.split(",") if p.strip()]
        for i, param in enumerate(params):
            # Remove default values, destructuring, etc.
            param_name = param.split("=")[0].strip()
            param_name = param_name.split(":")[0].strip()  # TypeScript types
            param_name = re.sub(r"[\{\}\[\]\.\.\.]", "", param_name).strip()

            if not param_name:
                continue

            ctx.param_names.append(param_name)
            index = len(ctx.param_names) - 1

            # The request object is a source in its own right.
            if param_name in self.REQUEST_PARAM_NAMES:
                ctx.tainted_params.add(index)
                ctx.param_sources[index] = self._REQUEST_OBJECT_SOURCE
                ctx.sources_found.append(self._REQUEST_OBJECT_SOURCE)
                continue

            # Check if parameter matches any source
            for source in self.registry.find_sources(param_name, "javascript"):
                ctx.tainted_params.add(index)
                ctx.param_sources[index] = source
                ctx.sources_found.append(source)

    def _find_function_end(self, start_pos: int) -> int:
        """Find the end line of a function (matching braces)."""
        brace_count = 0
        in_string = False
        string_char = None
        escaped = False

        for i, char in enumerate(self._source_code[start_pos:], start_pos):
            if escaped:
                escaped = False
                continue

            if char == "\\":
                escaped = True
                continue

            if not in_string and char in "\"'`":
                in_string = True
                string_char = char
            elif in_string and char == string_char:
                in_string = False
                string_char = None
            elif not in_string:
                if char == "{":
                    brace_count += 1
                elif char == "}":
                    brace_count -= 1
                    if brace_count == 0:
                        return self._source_code[:i + 1].count("\n") + 1

        return len(self._lines)

    # ------------------------------------------------------------------
    # per-line analysis
    # ------------------------------------------------------------------

    def _analyze_function(self, ctx: JSFunctionContext) -> None:
        """Analyze a single function for taint flows."""
        lines = ctx.code.splitlines()

        # Initialize taint state for parameters
        for index in sorted(ctx.tainted_params):
            param_name = ctx.param_names[index] if index < len(ctx.param_names) else None
            if not param_name:
                continue
            source = ctx.param_sources.get(index)
            ctx.taint_state[param_name] = JSTaintState(
                variable=param_name,
                is_tainted=True,
                source=source,
                taint_kind=TaintKind.PARAMETER,
                confidence=source.confidence if source else 0.8,
            )

        # Analyze each line
        for index, line in enumerate(lines):
            self._analyze_line(line, ctx.line_for(index, ctx.start_line), ctx)

    def _get_param_names(self, code: str) -> list[str]:
        """Get parameter names from function code.

        Retained for compatibility; ``JSFunctionContext.param_names`` is the
        authoritative list because re-scanning ``code`` cannot recover a
        single-parameter arrow's name.
        """
        match = re.search(r"\(([^)]*)\)", code)
        if match:
            params_str = match.group(1)
            params = [p.strip() for p in params_str.split(",") if p.strip()]
            return [re.sub(r"[\{\}\[\]\.\.\.=:].*", "", p).strip() for p in params]
        return []

    def _analyze_line(self, line: str, line_num: int, ctx: JSFunctionContext) -> None:
        """Analyze a single line of code."""
        stripped = line.strip()

        # Skip comments
        if not stripped or stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
            return

        # Assignments first: a value introduced on this line has to be visible
        # to a sink that consumes it on the same line.
        handled = False
        assign_match = re.match(r"(?:const|let|var)\s+(\w+)\s*=\s*(.+);?", stripped)
        if assign_match:
            var_name = assign_match.group(1)
            value = assign_match.group(2)
            self._analyze_assignment(var_name, value, line_num, ctx)
            handled = True

        # ``obj.prop = <expr>`` -- the shape of every DOM-XSS sink in the
        # registry (``el.innerHTML = location.hash``).
        member_match = self.MEMBER_ASSIGN_PATTERN.match(stripped)
        if member_match:
            self._check_assign_sink(
                member_match.group("target"),
                member_match.group("value"),
                line_num,
                ctx,
                stripped,
            )
            handled = True

        if not handled:
            reassign_match = re.match(r"(?<![\w$.])(\w+)\s*=\s*(.+);?", stripped)
            if reassign_match and not stripped.startswith(("const", "let", "var")):
                var_name = reassign_match.group(1)
                value = reassign_match.group(2)
                self._analyze_assignment(var_name, value, line_num, ctx)

        # Calls
        for callee, _open_idx, _close_idx, args_str in self._find_calls(stripped):
            self._analyze_call_expr(callee, args_str, line_num, ctx, stripped)

        # Returns
        return_match = self.RETURN_PATTERN.match(stripped)
        if return_match:
            self._analyze_return(return_match.group(1), line_num, ctx)

    def _analyze_assignment(self, var_name: str, value: str, line_num: int, ctx: JSFunctionContext) -> None:
        """Analyze a variable assignment."""
        value = value.strip().rstrip(";,")
        value_taint = self._get_taint_from_expression(value, ctx)

        if value_taint is not None and value_taint.is_tainted:
            existing = ctx.taint_state.get(var_name)
            trace = self._create_trace(line_num, ctx, var_name, "assignment", value[:160])
            ctx.taint_state[var_name] = JSTaintState(
                variable=var_name,
                is_tainted=True,
                source=value_taint.source,
                taint_kind=TaintKind.DIRECT,
                traces=(existing.traces if existing else []) + [trace],
                confidence=max(0.0, (value_taint.confidence or 1.0) * 0.95),
            )
            return

        # Clear taint
        if var_name in ctx.taint_state:
            ctx.taint_state[var_name].is_tainted = False

    def _analyze_call_expr(self, callee: str, args_str: str, line_num: int, ctx: JSFunctionContext, line: str) -> None:
        """Analyze one call expression found on a line."""
        callee = callee.replace(" ", "")
        if not callee:
            return
        ctx.calls.append(callee)

        # Add to call graph
        caller_key = f"{self._file_path}:{ctx.name}:{ctx.start_line}"
        callee_key = f"{self._file_path}:{callee}:0"
        self.call_graph.add_edge(caller_key, callee_key)

        call_text = f"{callee}({args_str})"

        # Check if source
        source = self._source_for_text(call_text)
        if source is not None:
            ctx.sources_found.append(source)

        # Check if sanitizer -- a *strong* sanitizing call neutralises the sink
        # classes it is defined for, which is what makes ``db.query(q, [host])``
        # and ``res.send(DOMPurify.sanitize(x))`` safe.  A weak one (VALIDATE)
        # only lowers confidence and still lets the sink be checked.
        sanitizer = self._sanitizer_for_call(callee, args_str)
        if sanitizer is not None:
            ctx.sanitizers_found.append(sanitizer)
            if sanitizer.is_strong:
                return

        # Sinks
        for sink in self._sinks_for_call(callee, args_str):
            if (
                sanitizer is not None
                and sanitizer.is_strong
                and sink.category in self._SANITIZER_BLOCKS.get(sanitizer.category, frozenset())
            ):
                continue
            ctx.sinks_found.append(sink)
            if not self._call_is_dangerous_shape(callee, args_str):
                continue
            args = self._split_args(args_str)
            indices: list[int] = []
            if isinstance(sink.vulnerable_param, int) and 0 <= sink.vulnerable_param < len(args):
                indices.append(sink.vulnerable_param)
            indices.extend(i for i in range(len(args)) if i not in indices)
            for i in indices:
                arg = args[i]
                if not arg:
                    continue
                taint = self._get_taint_from_expression(arg, ctx)
                if taint is not None and taint.is_tainted and not taint.sanitized:
                    if not self._is_attacker_controlled(taint):
                        continue
                    self._record_taint_path(taint, sink, line_num, ctx, line.strip(), arg)
                    break

    def _check_assign_sink(self, target: str, value: str, line_num: int, ctx: JSFunctionContext, line: str) -> None:
        """Check ``obj.prop = <expr>`` against the assignment-shaped sinks."""
        target = target.replace(" ", "")
        statement = f"{target} = {value.strip()}"

        # The sanitizer has to be a call on the right-hand side, not merely a
        # pattern that appears somewhere in the statement.  ``react-autoescape``
        # is the reason: its pattern is the bare ``\\{[^}]+\\}``, written for JSX,
        # and matching it against a whole statement would declare every
        # ``el.innerHTML = render({data})`` sanitized.
        sanitizer: Optional[Sanitizer] = None
        for callee, _o, _c, args_str in self._find_calls(value):
            candidate = self._sanitizer_for_call(callee, args_str)
            if candidate is not None and candidate.is_strong:
                sanitizer = candidate
                break
        if sanitizer is not None:
            ctx.sanitizers_found.append(sanitizer)
            return

        for sink in self._sinks_for_text(statement):
            ctx.sinks_found.append(sink)
            taint = self._get_taint_from_expression(value.strip(), ctx)
            if taint is not None and taint.is_tainted and not taint.sanitized:
                if not self._is_attacker_controlled(taint):
                    continue
                self._record_taint_path(taint, sink, line_num, ctx, line.strip(), target)
                break

    def _is_attacker_controlled(self, taint: JSTaintState) -> bool:
        """Whether the data behind a taint state is attacker-controlled."""
        source = taint.source
        if source is None:
            # A parameter taint with no recorded source: the request object is
            # the only case, and it is attacker-controlled by definition.
            return taint.taint_kind is TaintKind.PARAMETER
        return source.category in self._ATTACKER_CONTROLLED_CATEGORIES

    def _call_is_dangerous_shape(self, callee: str, args_str: str) -> bool:
        """Whether an argv-style spawn call actually interprets a shell."""
        name = callee.rsplit(".", 1)[-1]
        if name not in self._ARGV_CALLS:
            return True
        call_text = f"{name}({args_str})"
        if re.search(r"shell\s*:\s*true", call_text):
            return True
        args = self._split_args(args_str)
        if args and re.search(r"[+`$]", args[0]):
            # The command itself is built from parts, so a shell is implied.
            return True
        return False

    def _analyze_return(self, ret_value: str, line_num: int, ctx: JSFunctionContext) -> None:
        """Analyze a return statement."""
        ret_taint = self._get_taint_from_expression(ret_value, ctx)
        if ret_taint is not None and ret_taint.is_tainted:
            ctx.return_tainted = True
            # Find which parameters taint this return
            for param_name, param_taint in ctx.taint_state.items():
                if param_taint.is_tainted and param_name in ret_value:
                    for i, pn in enumerate(ctx.param_names):
                        if pn == param_name:
                            ctx.return_tainted_by.add(i)

    # ------------------------------------------------------------------
    # expression taint
    # ------------------------------------------------------------------

    def _get_taint_from_expression(self, expr: str, ctx: JSFunctionContext) -> JSTaintState | None:
        """Get taint state from an expression.

        The order matters, and the central rule is that **a call consumes its
        arguments unless it is registered as a transparent pass-through.**

        Without that rule, any expression merely mentioning a request value is
        tainted, and the safe corpus proved why that is wrong: ``mac`` built from
        ``crypto.createHmac('sha256', token).update(req.query.msg)`` is an HMAC,
        not user input, and reporting it is how a scanner loses its audience.

        A sanitizing call is therefore checked *first*, then a source pattern
        against the expression with every call's argument list removed (so
        ``JSON.parse(x)`` is still a source -- the pattern is the callee -- while
        ``hmac(k).update(req.query.msg)`` is not), then receiver propagation,
        then explicit pass-throughs, then concatenation, then variables.
        """
        expr = expr.strip().rstrip(";,")
        if not expr:
            return None

        calls = self._find_calls(expr)
        if calls:
            # A *strong* sanitizer removes the taint; a VALIDATE/TRANSFORM one
            # (``path.join``, ``new URL``) only reduces confidence, so the taint
            # survives and is reported with the sanitizer recorded on the path.
            # Treating both as removing was what made ``path.join(base, user)``
            # look clean, when join preserves an absolute path that escapes.
            if all(
                (s := self._sanitizer_for_call(c[0], c[3])) is not None and s.is_strong
                for c in calls
            ):
                return None

        # The expression with call argument lists replaced by "()".  Callee text
        # survives -- which is what makes ``JSON.parse(...)`` and
        # ``location.hash.substring(...)`` still match their source patterns --
        # while argument payloads do not.
        stripped = self._strip_call_args(expr, calls)

        # 1. A source pattern in the expression's own structure.
        source = self._source_for_text(stripped)
        if source is not None:
            return JSTaintState(
                variable="<expr>",
                is_tainted=True,
                source=source,
                taint_kind=TaintKind.DIRECT,
                traces=[self._create_trace(0, ctx, "<expr>", f"source: {source.name}", stripped[:160])],
                confidence=source.confidence,
            )

        # 2. Receiver propagation: ``name.trim()`` is still ``name``.
        head = self._IDENT_CHAIN.match(stripped)
        if head:
            base = head.group(0).split(".")[0].strip()
            if base and base not in self._NON_TAINT_WORDS:
                state = ctx.taint_state.get(base)
                if state is not None and state.is_tainted:
                    return state

        # 3. Explicit pass-through calls carry their arguments' taint.  A weak
        #    sanitizer is skipped here only for the sink gate, not for taint:
        #    it is transparent to this list by virtue of not being strong.
        for callee, _o, _c, args_str in calls:
            sanitizer = self._sanitizer_for_call(callee, args_str)
            if sanitizer is not None and sanitizer.is_strong:
                continue
            leaf = callee.rsplit(".", 1)[-1]
            if leaf not in self._TRANSPARENT_CALLS:
                continue
            for arg in self._split_args(args_str):
                inner = self._get_taint_from_expression(arg, ctx)
                if inner is not None and inner.is_tainted:
                    return inner

        # 4. Template literal interpolations.
        if "`" in expr or "${" in expr:
            for var in re.findall(r"\$\{([^}]*)\}", expr):
                inner = self._get_taint_from_expression(var, ctx)
                if inner is not None and inner.is_tainted:
                    return inner

        # 5. Concatenation over parts.
        if "+" in expr:
            for part in self._split_concat(expr):
                inner = self._get_taint_from_expression(part, ctx)
                if inner is not None and inner.is_tainted:
                    return inner

        # 6. A bare variable reference, or a member chain rooted at one.
        for name in re.findall(r"[A-Za-z_$][\w$]*", stripped):
            if name in self._NON_TAINT_WORDS:
                continue
            state = ctx.taint_state.get(name)
            if state is not None and state.is_tainted:
                return state

        return None

    def _source_for_text(self, text: str) -> Optional[Source]:
        """Return the first JS source whose pattern matches ``text``."""
        for source in self.registry.get_sources("javascript"):
            try:
                if source.matches(text, "javascript"):
                    return source
            except re.error:
                continue
        return None

    def _sanitizer_for_call(self, callee: str, args_str: str) -> Optional[Sanitizer]:
        """Return the sanitizer neutralising this call, if any.

        A sanitizer is a *callee*, so its pattern must begin inside the callee
        span.  Requiring that is what stops ``react-autoescape`` -- whose
        pattern is the bare ``\\{[^}]+\\}``, written for JSX -- from declaring
        every ``foo({bar})`` object literal sanitized.
        """
        found = self._match_within_callee(callee, args_str, self.registry.get_sanitizers("javascript"))
        return found[0] if found else None

    def _sinks_for_call(self, callee: str, args_str: str) -> list[Sink]:
        """Sinks whose pattern begins inside this call's callee span."""
        return self._match_within_callee(callee, args_str, self.registry.get_sinks("javascript"))

    def _sinks_for_text(self, text: str) -> list[Sink]:
        """Sinks matched against a whole statement (assignment sinks)."""
        found: list[Sink] = []
        for sink in self.registry.get_sinks("javascript"):
            try:
                if re.search(sink.pattern, text, re.IGNORECASE):
                    found.append(sink)
            except re.error:
                continue
        return found

    def _match_within_callee(self, callee: str, args_str: str, candidates: list) -> list:
        """Match registry patterns against ``callee(args)``.

        The match must start at or before the end of the callee span.  A pattern
        that only matches something inside an argument would otherwise fire for
        every call that happens to pass a suspicious-looking value.
        """
        callee = callee.replace(" ", "")
        text = f"{callee}({args_str})"
        span = len(callee)
        found = []
        for entry in candidates:
            try:
                match = re.search(entry.pattern, text, re.IGNORECASE)
            except re.error:
                continue
            if match and match.start() <= span:
                found.append(entry)
        return found

    # ------------------------------------------------------------------
    # scanning helpers
    # ------------------------------------------------------------------

    def _find_calls(self, text: str) -> list[tuple[str, int, int, str]]:
        """Find every ``callee(args)`` in ``text``, including nested ones.

        Returns ``(callee, open_index, close_index, args_text)``.  String and
        template literals are skipped, so a call inside a comment or a string is
        not seen, and an unbalanced paren simply ends the scan for that call.

        A chain preceded by ``.`` is *not* skipped.  ``_IDENT_CHAIN`` is greedy
        and already absorbs ``a.b.c`` as one match, so a leading ``.`` only
        survives when the previous token ended in ``)`` or ``]`` -- which is
        exactly a method call on a computed receiver, e.g. ``update(...)`` in
        ``crypto.createHmac(k).update(msg)``.  Skipping those lost the very calls
        whose arguments had to be excluded.
        """
        out: list[tuple[str, int, int, str]] = []
        length = len(text)
        for match in self._IDENT_CHAIN.finditer(text):
            start = match.start()
            if start > 0:
                prev = text[start - 1]
                if prev.isalnum() or prev in "_$":
                    continue  # part of a longer identifier already matched
            j = match.end()
            while j < length and text[j] in " \t":
                j += 1
            if j >= length or text[j] != "(":
                continue
            close = self._match_paren(text, j)
            if close < 0:
                continue
            callee = match.group(0).replace(" ", "")
            out.append((callee, j, close, text[j + 1:close]))
        return out

    @classmethod
    def _strip_call_args(cls, text: str, calls: list[tuple[str, int, int, str]]) -> str:
        """Replace each call's argument list with ``()``, keeping callees.

        Applied right-to-left so earlier indices stay valid.  Grouping parens
        are untouched -- only the argument lists ``_find_calls`` identified.
        """
        stripped = text
        for _callee, open_idx, close_idx, _args in sorted(calls, key=lambda c: c[1], reverse=True):
            stripped = stripped[:open_idx] + "()" + stripped[close_idx + 1:]
        return stripped

    @classmethod
    def _match_paren(cls, text: str, open_idx: int) -> int:
        """Index of the parenthesis matching ``text[open_idx]``, or -1."""
        depth = 0
        in_string: Optional[str] = None
        escaped = False
        for i in range(open_idx, len(text)):
            char = text[i]
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if in_string:
                if char == in_string:
                    in_string = None
                continue
            if char in "\"'`":
                in_string = char
                continue
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return i
        return -1

    @classmethod
    def _split_args(cls, args_str: str) -> list[str]:
        """Split an argument list on top-level commas.

        Tracks ``()``, ``[]`` and ``{}`` depth and string literals, so
        ``db.query('... ?', [a, b], (e, r) => f(e))`` splits into three
        arguments rather than being cut at the first comma inside the array.
        """
        args: list[str] = []
        current: list[str] = []
        stack: list[str] = []
        in_string: Optional[str] = None
        escaped = False
        for char in args_str:
            if escaped:
                current.append(char)
                escaped = False
                continue
            if char == "\\":
                current.append(char)
                escaped = True
                continue
            if in_string:
                current.append(char)
                if char == in_string:
                    in_string = None
                continue
            if char in "\"'`":
                in_string = char
                current.append(char)
                continue
            if char in cls._OPENERS:
                stack.append(cls._OPENERS[char])
                current.append(char)
                continue
            if char in cls._CLOSERS:
                if stack:
                    stack.pop()
                current.append(char)
                continue
            if char == "," and not stack:
                args.append("".join(current).strip())
                current = []
                continue
            current.append(char)
        tail = "".join(current).strip()
        if tail:
            args.append(tail)
        return args

    @classmethod
    def _split_concat(cls, expr: str) -> list[str]:
        """Split an expression on top-level ``+`` operators."""
        parts: list[str] = []
        current: list[str] = []
        stack: list[str] = []
        in_string: Optional[str] = None
        escaped = False
        i = 0
        while i < len(expr):
            char = expr[i]
            if escaped:
                current.append(char)
                escaped = False
                i += 1
                continue
            if char == "\\":
                current.append(char)
                escaped = True
                i += 1
                continue
            if in_string:
                current.append(char)
                if char == in_string:
                    in_string = None
                i += 1
                continue
            if char in "\"'`":
                in_string = char
                current.append(char)
                i += 1
                continue
            if char in cls._OPENERS:
                stack.append(cls._OPENERS[char])
                current.append(char)
                i += 1
                continue
            if char in cls._CLOSERS:
                if stack:
                    stack.pop()
                current.append(char)
                i += 1
                continue
            if char == "+" and not stack:
                # ``++`` is not concatenation.
                if i + 1 < len(expr) and expr[i + 1] == "+":
                    current.append(char)
                    i += 1
                    continue
                parts.append("".join(current).strip())
                current = []
                i += 1
                continue
            current.append(char)
            i += 1
        tail = "".join(current).strip()
        if tail:
            parts.append(tail)
        return [p for p in parts if p]

    def _extract_call_args(self, line: str, func_name: str) -> list[str]:
        """Extract arguments from a function call."""
        pattern = re.escape(func_name) + r"\s*\(([^)]*)\)"
        match = re.search(pattern, line)
        if match:
            return self._split_args(match.group(1))
        return []

    def _create_trace(self, line_num: int, ctx: JSFunctionContext, variable: str, description: str, snippet: str) -> TaintTrace:
        """Create a taint trace step."""
        return TaintTrace(
            step_number=1,
            kind=TaintKind.DIRECT,
            file_path=self._file_path,
            line_number=line_num,
            column_number=None,
            function_name=ctx.name,
            snippet=snippet[:160],
            tainted_variable=variable,
            description=description,
            confidence=0.9,
        )

    def _record_taint_path(self, taint_state: JSTaintState, sink: Sink, line_num: int, ctx: JSFunctionContext, snippet: str, argument: str = "") -> None:
        """Record a discovered taint path."""
        if not taint_state.source:
            return

        path = TaintPath(
            source=taint_state.source,
            sink=sink,
            traces=taint_state.traces + [self._create_trace(line_num, ctx, taint_state.variable, f"sink: {sink.name}", snippet)],
            sanitizers_encountered=[taint_state.sanitizer] if taint_state.sanitizer else [],
            is_sanitized=taint_state.sanitized,
            breaking_sanitizer=taint_state.sanitizer if taint_state.sanitized and taint_state.sanitizer.is_strong else None,
            severity=sink.severity,
            cwe_ids=list(set(taint_state.source.cwe_ids + sink.cwe_ids)),
            sink_file=self._file_path,
            sink_line=line_num,
            attack_vector=f"Tainted data from {taint_state.source.name} flows to {sink.name}"
                         + (f" (argument: {argument})" if argument else "")
                         + " without proper sanitization",
            remediation=self._get_remediation(sink),
        )
        path.confidence = path.compute_confidence()
        self.taint_paths.append(path)

    def _get_remediation(self, sink: Sink) -> str:
        """Get remediation advice for a sink."""
        remediation_map = {
            "sql-execution": "Use parameterized queries. Never concatenate user input into SQL strings.",
            "command-execution": "Avoid shell command execution with user input. Use argv arrays.",
            "code-execution": "Never use eval/Function on untrusted input.",
            "xss": "Use safe DOM APIs (textContent). Enable CSP. Use DOMPurify for HTML.",
            "path-traversal": "Validate and normalize paths. Use path.resolve() and check against allowlist.",
            "open-redirect": "Validate redirect targets against an allowlist of permitted hosts.",
            "prototype-pollution": "Reject payloads containing __proto__/constructor/prototype keys; use a Map or Object.create(null).",
        }
        return remediation_map.get(sink.category, "Validate and sanitize all user input before use.")

    def _interprocedural_analysis(self) -> None:
        """Perform interprocedural analysis (simplified)."""
        # Build summaries
        summaries = {}
        for key, ctx in self.function_contexts.items():
            summary = FunctionSummary(
                name=ctx.name,
                file_path=ctx.file_path,
                line_number=ctx.start_line,
                tainted_params=list(ctx.tainted_params),
                returns_taint=ctx.return_tainted,
                return_tainted_by=list(ctx.return_tainted_by),
                sanitizers_called=[s.name for s in ctx.sanitizers_found],
                sinks_called=[s.name for s in ctx.sinks_found],
                sources_called=[s.name for s in ctx.sources_found],
                propagates_taint=ctx.return_tainted and len(ctx.tainted_params) > 0,
            )
            summaries[key] = summary
            cg_node = self.call_graph.get_node(key)
            if cg_node:
                cg_node.summary = summary

    def _deduplicate_paths(self) -> None:
        """Deduplicate taint paths.

        Keyed on sink category rather than sink name: the registry now contains
        several overlapping spellings of the same class (``child-process`` for
        ``child_process.exec`` and ``child-process-shell`` for a destructured
        ``exec``), and two findings for one line is noise, not signal.
        """
        seen: set[tuple[str, str, int, str]] = set()
        unique: list[TaintPath] = []
        for path in self.taint_paths:
            key = (path.sink.category, path.sink_file, path.sink_line, path.sink.name)
            if key in seen:
                continue
            seen.add(key)
            unique.append(path)
        self.taint_paths = unique


def analyze_js_file(file_path: str) -> list[TaintPath]:
    """Convenience function to analyze a single JS/TS file."""
    analyzer = JSTaintAnalyzer()
    return analyzer.analyze_file(file_path)


def analyze_js_directory(dir_path: str, max_files: int = 1000) -> list[TaintPath]:
    """Convenience function to analyze an JS/TS directory."""
    analyzer = JSTaintAnalyzer()
    return analyzer.analyze_directory(dir_path, max_files)
