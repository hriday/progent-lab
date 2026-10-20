from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import gate, lab, llm, reference, spec_checker
from .policy_format import PolicyFormatError, normalize
from .scenarios import SCENARIOS, public_catalog

STATIC = Path(__file__).resolve().parent.parent / "static"


def _load_secret_files() -> None:
    """Read keys from mounted files (Docker secrets) when they are not in the environment.

    Keeps keys out of .env and out of `docker inspect`. File names follow the variable names.
    """
    secrets_dir = Path(os.getenv("SECRETS_DIR", "/run/secrets"))
    for var in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "TYPESAFE_API_KEY"):
        f = secrets_dir / var.lower()
        if not os.getenv(var) and f.is_file():
            value = f.read_text().strip()
            if value:
                os.environ[var] = value


_load_secret_files()
MAX_BODY = 64 * 1024

app = FastAPI(title="Progent explorer", docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def limit_body(request: Request, call_next):
    if int(request.headers.get("content-length") or 0) > MAX_BODY:
        return JSONResponse({"detail": "request too large"}, status_code=413)
    return await call_next(request)


# --------------------------------------------------------------------------- models


class CheckReq(BaseModel):
    policy: dict[str, Any]
    tool: str = Field(max_length=200)
    args: dict[str, Any] = {}


class CompareReq(BaseModel):
    old: dict[str, Any]
    new: dict[str, Any]
    tools: dict[str, dict] | None = None


class RunReq(BaseModel):
    scenario: str
    injection_template: str = "important"
    injection_custom: str | None = None
    task: str | None = None
    approver: str = "auto-approve"
    implementation: str = "reference"
    gate: str = "paper"
    generic_readonly: bool = True
    policy_model: str | None = None


class ApprovalReq(BaseModel):
    approval_id: str
    approved: bool


def _policy(p: dict, label: str):
    try:
        pol = normalize(p)
    except PolicyFormatError as e:
        raise HTTPException(422, f"{label}: {e}") from e
    errs = spec_checker.validate_schemas(pol)
    if errs:
        raise HTTPException(422, f"{label}: " + "; ".join(errs))
    return pol


# --------------------------------------------------------------------------- routes


@app.get("/healthz")
async def healthz():
    return {"ok": True}


@app.get("/api/meta")
async def meta():
    return {
        **public_catalog(),
        "gates": gate.available(),
        "policy_models": llm.available_policy_models(),
        "agent_model": llm.AGENT_MODEL,
        "approvers": list(lab.APPROVERS),
        "lab_enabled": bool(os.getenv("ANTHROPIC_API_KEY")),
        "reference_commit": "5be7b63",
    }


@app.post("/api/check")
async def check(req: CheckReq):
    pol = _policy(req.policy, "policy")
    return {
        "reference": reference.check_call(pol, req.tool, req.args),
        "spec": spec_checker.evaluate_call(pol, req.tool, req.args),
    }


@app.post("/api/compare")
async def compare(req: CompareReq):
    old, new = _policy(req.old, "old policy"), _policy(req.new, "new policy")
    tools = req.tools
    if tools is None:  # fall back to the scenario tool schemas when names match
        tools = {t.name: t.properties for s in SCENARIOS.values() for t in s.tools}
    ref = await asyncio.to_thread(reference.is_narrowing, old, new)
    spec = await asyncio.to_thread(spec_checker.compare, old, new, tools)
    confirmations = []
    for t in spec["tools"]:
        if t.get("basis") == "witness":
            w = t["witness"]
            confirmations.append({
                "tool": t["tool"], "witness": w,
                "old": {"reference": reference.check_call(old, t["tool"], w), "spec": spec_checker.evaluate_call(old, t["tool"], w)},
                "new": {"reference": reference.check_call(new, t["tool"], w), "spec": spec_checker.evaluate_call(new, t["tool"], w)},
            })
    return {"reference": ref, "spec": spec, "confirmations": confirmations}


@app.post("/api/lab/runs")
async def create_run(req: RunReq):
    if not os.getenv("ANTHROPIC_API_KEY"):
        raise HTTPException(503, "The attack lab needs ANTHROPIC_API_KEY on the server.")
    cfg = lab.RunConfig(**{k: v for k, v in req.model_dump().items() if v is not None})
    try:
        run = lab.start(cfg)
    except ValueError as e:
        raise HTTPException(422, str(e)) from e
    except RuntimeError as e:
        raise HTTPException(429, str(e)) from e
    return {"id": run.id}


@app.get("/api/lab/runs/{run_id}/events")
async def run_events(run_id: str, since: int = 0):
    run = lab.RUNS.get(run_id)
    if not run:
        raise HTTPException(404, "unknown run")

    async def stream():
        i, idle = max(0, since), 0.0
        while True:
            while i < len(run.events):
                yield f"data: {json.dumps(run.events[i], default=str)}\n\n"
                i, idle = i + 1, 0.0
            if run.finished and i >= len(run.events):
                yield "event: end\ndata: {}\n\n"
                return
            await asyncio.sleep(0.25)  # polling keeps several viewers of one run independent
            idle += 0.25
            if idle >= 15:
                yield ": keepalive\n\n"
                idle = 0.0

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/api/lab/runs/{run_id}/approval")
async def approve(run_id: str, req: ApprovalReq):
    run = lab.RUNS.get(run_id)
    if not run or not run.answer(req.approval_id, req.approved):
        raise HTTPException(409, "no matching pending approval")
    return {"ok": True}


app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/")
async def index():
    return FileResponse(STATIC / "index.html")
