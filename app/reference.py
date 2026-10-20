"""Thin, side-effect-free wrappers around the vendored Progent reference code."""

from __future__ import annotations

import contextlib
import io
import sys
import threading
from pathlib import Path
from typing import Any

_VENDOR = Path(__file__).resolve().parent.parent / "vendor"
if str(_VENDOR) not in sys.path:
    sys.path.insert(0, str(_VENDOR))

with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
    from secagent import tool as _ref_tool  # noqa: E402
    from secagent.policy_analysis import security_policy_subset_check as _ref_subset  # noqa: E402
    from secagent.utils import extract_json  # noqa: E402,F401

from .policy_format import Policy, to_reference

# Z3's Python bindings share one global context and are not thread-safe.
# Every Z3 use in this process (reference and spec checker) takes this lock.
Z3_LOCK = threading.Lock()

# Prompts, verbatim from the reference implementation.
SYS_PROMPT_INIT = _ref_tool.SYS_PROMPT
SYS_PROMPT_GATE = _ref_tool.SYS_PROMPT_UPDATE
SYS_PROMPT_UPDATE = _ref_tool.SYS_PROMPT_2

# The paper's default fallback message (Section 4.1).
FALLBACK_TEMPLATE = (
    "The tool call is not allowed due to {reason}. Please try other tools or arguments "
    "and continue to finish the user task: {task}."
)


def init_prompt_for(model: str) -> str:
    """Reproduce get_SYS_PROMPT() output formatting for a given policy model."""
    sys_prompt = SYS_PROMPT_INIT
    if model.startswith("claude"):
        return sys_prompt[:-1] + (
            " with json block. You only need to output the restrictions and do not need to "
            "include other fields like description, title."
        )
    if model.startswith(("o1", "o3", "gpt-4.1", "gemini")):
        return sys_prompt + '\nOutput format: ```json [{"name": tool_name, "args": restrictions}, ...] ```'
    return sys_prompt


def update_prompt_for(model: str) -> str:
    """Reproduce get_SYS_PROMPT_2() output formatting for a given policy model."""
    sys_prompt = SYS_PROMPT_UPDATE
    if model.startswith("claude"):
        return sys_prompt[:-1] + " with json block."
    if model.startswith("gpt-4o-mini"):
        return sys_prompt[:-1] + (
            ' with json block. It should be an array of dictionaries like {"name": tool_name, "args": restrictions}.'
        )
    if model.startswith(("o1", "o3")):
        return sys_prompt + '\nThe policy should be in JSON format: ```json [{"name": tool_name, "args": restrictions}, ...] ```'
    return sys_prompt


def check_call(policy: Policy, tool: str, args: dict[str, Any]) -> dict[str, Any]:
    """Enforce one tool call exactly as the reference `check_tool_call` does (fallback = return msg)."""
    ref = to_reference(policy)
    rules = ref.get(tool)
    if not rules:
        return {"allowed": False, "reason": f"The tool '{tool}' is not allowed."}
    # Only fallback 0 ("return msg") is ever produced by to_reference, so the
    # reference code's sys.exit()/input() branches are unreachable here.
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            _ref_tool._check_tool_call(tool, args, rules)
        return {"allowed": True, "reason": None}
    except Exception as e:  # jsonschema.ValidationError or the reference ValidationError
        msg = getattr(e, "message", None) or str(e)
        return {"allowed": False, "reason": msg.splitlines()[0][:400]}


def is_narrowing(old: Policy, new: Policy) -> dict[str, Any]:
    """Run the reference `security_policy_subset_check` and capture its log."""
    log = io.StringIO()
    with Z3_LOCK, contextlib.redirect_stderr(log), contextlib.redirect_stdout(log):
        try:
            result = bool(_ref_subset(to_reference(old), to_reference(new)))
            error = None
        except Exception as e:  # surfaced, not swallowed: we want to show it
            result = None
            error = f"{type(e).__name__}: {e}"
    return {"narrowing": result, "error": error, "log": log.getvalue()[-4000:]}
