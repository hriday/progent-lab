"""The "does this step need a policy update?" gate (Section 5, first sub-step).

The gate sees the tool call but not its result, so injected text cannot steer
it. Three backends:

* ``paper``  - the reference prompt (SYS_PROMPT_UPDATE), answer starts with Yes/No.
* ``jev``    - one TypeSafe Jev Noul over the same inputs; returns a probability.
* ``always`` - skip the gate (every call goes to the updater), for comparison.
"""

from __future__ import annotations

import json
import os
from typing import Any

from . import llm
from .reference import SYS_PROMPT_GATE

JEV_THRESHOLD = float(os.getenv("JEV_GATE_THRESHOLD", "0.5"))

JEV_INSTRUCTIONS = (
    "An AI agent works on `user_task` under a least-privilege policy that lists which tool calls it may make. "
    "It has just made `tool_call` and has not yet seen the result. Judge whether the result of this call could "
    "contain information needed to make the policy more accurate: identities, recipients, account numbers, "
    "URLs or file names that the user task refers to but does not spell out, or instructions the user "
    "explicitly asked the agent to follow from that source."
)
JEV_CRITERIA = {
    "true": "The result could reveal a missing identifier or task instruction that should narrow or extend the policy.",
    "false": "The call finishes part of the task (sends, pays, posts) or reads data that cannot change which "
             "tool calls the user's task needs.",
}


def available() -> list[str]:
    out = ["paper", "always"]
    if os.getenv("TYPESAFE_API_KEY"):
        out.insert(1, "jev")
    return out


async def decide(backend: str, tools: list[dict], task: str, call: dict, policy_model: str) -> dict[str, Any]:
    if backend == "always":
        return {"update": True, "backend": "always", "detail": "gate disabled"}
    if backend == "jev":
        from typesafe_sdk import AsyncTypeSafeClient, Noul

        async with AsyncTypeSafeClient() as client:
            res = await client.system_one(
                state={"user_task": task, "tool_call": call, "available_tools": tools},
                questions={"needs_update": Noul(instructions=JEV_INSTRUCTIONS, criteria=JEV_CRITERIA)},
            )
        p = res.nouls["needs_update"].noul
        return {"update": p >= JEV_THRESHOLD, "backend": "jev", "probability": p, "model": res.model,
                "detail": f"P(yes) = {p:.2f}, threshold {JEV_THRESHOLD}"}
    content = (
        "TOOLS: " + json.dumps(tools) + "\nUSER_QUERY: " + task + "\nTOOL_CALL_PARAM: " + json.dumps([call])
    )
    text = await llm.complete(SYS_PROMPT_GATE, content, policy_model)
    return {"update": text.strip().lower().startswith("yes"), "backend": "paper", "detail": text.strip()[:600]}
