"""Model access. Keys stay server-side; the browser never sees them."""

from __future__ import annotations

import os
from typing import Any

AGENT_MODEL = os.getenv("AGENT_MODEL", "claude-sonnet-5-5")
POLICY_MODEL = os.getenv("POLICY_MODEL", "claude-sonnet-5-5")

_anthropic = None
_openai = None
_no_temperature: set[str] = set()


def available_policy_models() -> list[str]:
    models = [POLICY_MODEL]
    if os.getenv("OPENAI_API_KEY"):
        models.append("gpt-4o-2024-08-06")  # the paper's policy model
    return list(dict.fromkeys(models))


def _anthropic_client():
    global _anthropic
    if _anthropic is None:
        from anthropic import AsyncAnthropic

        _anthropic = AsyncAnthropic()
    return _anthropic


def _openai_client():
    global _openai
    if _openai is None:
        from openai import AsyncOpenAI

        _openai = AsyncOpenAI()
    return _openai


async def _anthropic_create(**kw: Any):
    model = kw["model"]
    if model in _no_temperature:
        kw.pop("temperature", None)
    try:
        return await _anthropic_client().messages.create(**kw)
    except Exception as e:  # some models reject sampling parameters
        if "temperature" in str(e).lower() and "temperature" in kw:
            _no_temperature.add(model)
            kw.pop("temperature")
            return await _anthropic_client().messages.create(**kw)
        raise


async def complete(system: str, user: str, model: str, temperature: float = 0.0) -> str:
    """One-shot completion for the policy model (mirrors the reference api_request)."""
    if model.startswith("claude"):
        msg = await _anthropic_create(
            model=model, system=system, max_tokens=8192, temperature=temperature,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
    resp = await _openai_client().chat.completions.create(
        model=model, temperature=temperature, seed=0,
        messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
    )
    return resp.choices[0].message.content or ""


async def agent_step(system: str, messages: list[dict], tools: list[dict], model: str = AGENT_MODEL):
    return await _anthropic_create(
        model=model, system=system, max_tokens=4096, temperature=0.0, messages=messages, tools=tools,
    )
