from __future__ import annotations

import json
import re
from typing import Any, Optional

from openai import OpenAI

from .config import get_settings


def _extract_json_object(raw: str) -> str:
    m = re.search(r"\{[\s\S]*\}", raw)
    if not m:
        raise ValueError(f"LLM returned no JSON:\n{(raw or '')[:700]}")
    return m.group()


def _fix_trailing_commas(s: str) -> str:
    return re.sub(r",\s*([}\]])", r"\1", s)


def _repair_string_escapes(s: str) -> str:
    def fix(match: re.Match) -> str:
        text = match.group(0)
        out: list[str] = []
        i = 0
        while i < len(text):
            ch = text[i]
            if ch == "\\" and i + 1 < len(text):
                nxt = text[i + 1]
                if nxt in '"\\/bfnrt':
                    out.append("\\" + nxt)
                    i += 2
                    continue
                if nxt == "u" and i + 5 < len(text) and re.match(
                    r"[0-9a-fA-F]{4}", text[i + 2 : i + 6]
                ):
                    out.append(text[i : i + 6])
                    i += 6
                    continue
                out.append("\\\\")
                i += 1
                continue
            out.append(ch)
            i += 1
        return "".join(out)

    return re.sub(r'"(?:[^"\\]|\\.)*"', fix, s)


def _truncate_to_balanced(s: str) -> str:
    depth = 0
    in_str = False
    esc = False
    last_ok = None
    for i, ch in enumerate(s):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "{[":
            depth += 1
        elif ch in "}]":
            depth -= 1
            if depth == 0 and ch == "}":
                last_ok = i
    if last_ok is not None:
        return s[: last_ok + 1]
    return s


def _close_open_structures(s: str) -> str:
    depth_obj = depth_arr = 0
    in_str = esc = False
    for ch in s:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth_obj += 1
        elif ch == "}":
            depth_obj -= 1
        elif ch == "[":
            depth_arr += 1
        elif ch == "]":
            depth_arr -= 1
    if in_str:
        s += '"'
    s += "]" * max(0, depth_arr)
    s += "}" * max(0, depth_obj)
    return s


def parse_llm_json(raw: str) -> dict[str, Any]:
    blob = _extract_json_object(raw)
    candidates = [
        blob,
        _fix_trailing_commas(blob),
        _repair_string_escapes(blob),
        _fix_trailing_commas(_repair_string_escapes(blob)),
    ]
    truncated = _truncate_to_balanced(blob)
    candidates += [
        truncated,
        _fix_trailing_commas(truncated),
        _close_open_structures(truncated),
        _fix_trailing_commas(
            _close_open_structures(_repair_string_escapes(truncated))
        ),
    ]
    last_err: Optional[Exception] = None
    for c in candidates:
        try:
            data = json.loads(c)
            if isinstance(data, dict):
                return data
        except Exception as e:
            last_err = e
    raise ValueError(f"Invalid JSON from LLM: {last_err}\n{(raw or '')[:700]}") from last_err


class LLMClient:
    """OpenAI-compatible client — OpenAI, NVIDIA NIM, Ollama local & cloud."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
    ):
        s = get_settings()
        api_key = api_key or s.resolved_api_key()
        base_url = base_url or s.resolved_base_url()
        model = model or s.resolved_model()

        if base_url:
            bu = base_url.rstrip("/")
            if bu in ("https://ollama.com/api", "http://ollama.com/api"):
                bu = "https://ollama.com/v1"
            elif bu in ("https://ollama.com", "http://ollama.com"):
                bu = "https://ollama.com/v1"
            base_url = bu

        self._is_ollama = bool(
            base_url
            and (
                "11434" in base_url
                or "ollama.com" in base_url.lower()
                or "ollama" in base_url.lower()
            )
        )

        if not api_key:
            if self._is_ollama:
                api_key = "ollama"
            else:
                raise ValueError(
                    "LLM API key is required. Set LLM_API_KEY in .env\n"
                    "  Ollama local:  LLM_BASE_URL=http://localhost:11434/v1  LLM_API_KEY=ollama\n"
                    "  Ollama cloud:  LLM_BASE_URL=https://ollama.com/v1  LLM_API_KEY=<key>\n"
                    "  NVIDIA NIM:    LLM_BASE_URL=https://integrate.api.nvidia.com/v1"
                )

        self.client = OpenAI(api_key=api_key, base_url=base_url)
        self.model = model
        self.base_url = base_url
        self.temperature = getattr(s, "temperature", 0.1) or 0.1
        self.max_tokens = getattr(s, "max_tokens", 5000) or 5000

    def complete(self, system: str, user: str, *, force_json: bool = False) -> str:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": self.temperature,
        }
        if self.max_tokens:
            kwargs["max_tokens"] = self.max_tokens

        # response_format breaks / empties on many Ollama models — skip for Ollama
        use_json_mode = force_json and not self._is_ollama
        try:
            if use_json_mode:
                r = self.client.chat.completions.create(
                    **kwargs, response_format={"type": "json_object"}
                )
            else:
                r = self.client.chat.completions.create(**kwargs)
        except Exception as e:
            if use_json_mode:
                r = self.client.chat.completions.create(**kwargs)
            else:
                raise RuntimeError(
                    f"LLM request failed (model={self.model!r}, base_url={self.base_url!r}): {e}"
                ) from e

        if not r.choices:
            raise RuntimeError(
                f"LLM returned empty choices (model={self.model!r}). "
                "Check the model name: ollama list   or   ollama.com model id."
            )
        content = (r.choices[0].message.content or "").strip()
        return content

    def complete_json(self, system: str, user: str) -> dict[str, Any]:
        raw = self.complete(system, user)
        if not raw:
            # retry once with explicit JSON instruction
            raw = self.complete(
                system + "\n\nReply with a single JSON object only. No markdown.",
                user + "\n\nReturn ONLY valid JSON.",
            )
        if not raw:
            raise ValueError(
                f"LLM returned empty content (model={self.model!r}, base_url={self.base_url!r}).\n"
                "Ollama tips:\n"
                "  • Local: ollama pull llama3.2 && ollama list\n"
                "  • Cloud: LLM_BASE_URL=https://ollama.com/v1 and a cloud API key\n"
                "  • Model id must exist (e.g. llama3.2, not a typo)"
            )
        try:
            return parse_llm_json(raw)
        except ValueError:
            # last retry with shorter hard instruction
            raw2 = self.complete(
                "You are a JSON API. Output one JSON object only.",
                user[:6000] + "\n\nRespond with JSON keys: summary, one_line_verdict, "
                "primary_change_type, risk_level, risk_score, risk_factors, "
                "suggestions, recommended_actions, confidence, needs_human_review.",
            )
            return parse_llm_json(raw2)
