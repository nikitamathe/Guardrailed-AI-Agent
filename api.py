"""Guardrailed AI SOC Agent — FastAPI microservice (API layer).

Phase 2 (M2): Decouple the presentation tier from the engine. This module is
the canonical REST boundary: the Streamlit UI (`app.py`) talks to it over HTTP
instead of importing `GuardedToolAgent` / `ToolRegistry` in-process.

Endpoints:
  - GET  /health          Readiness / status check
  - POST /agent/process   Process a user prompt through guardrails + RAG + LLM
  - POST /agent/approve   Execute or reject a staged destructive tool approval

Run with:  uvicorn api:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field

from agent import GuardedToolAgent
from schemas import AgentResponse, RestartServiceSchema, GetMemoryUsageSchema, BlockIPSchema
from tools import (
    ToolRegistry,
    restart_service_handler,
    get_memory_usage_handler,
    block_ip_handler,
)

logger = logging.getLogger("guardrailed.api")


def build_agent() -> GuardedToolAgent:
    """Register the full, consistent tool set (single source of truth)."""
    registry = ToolRegistry()
    registry.register_tool("restart_service", RestartServiceSchema, restart_service_handler)
    registry.register_tool("get_memory_usage", GetMemoryUsageSchema, get_memory_usage_handler)
    registry.register_tool("block_ip", BlockIPSchema, block_ip_handler)

    model = os.environ.get("OLLAMA_MODEL", "llama3")
    return GuardedToolAgent(name="SOC-Engine-Agent", registry=registry, model_name=model)


class ProcessRequest(BaseModel):
    user_input: str = Field(..., min_length=1, max_length=4096)
    model_override: Optional[str] = Field(default=None, max_length=128)
    dry_run: bool = Field(default=False)
    require_approval: bool = Field(default=False)


class ApproveRequest(BaseModel):
    action_id: str = Field(..., min_length=1, max_length=64)
    decision: str = Field(default="approve", pattern="^(approve|reject)$")


def create_app() -> Any:
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware

    api = FastAPI(
        title="Guardrailed AI SOC Engine",
        version="2.0.0",
        description=(
            "REST microservice exposing the guarded AI SOC agent for log-aware "
            "threat analysis and gated remediation actions."
        ),
    )

    # CORS is restrictive by default (no origins). Configure explicitly for the
    # Streamlit UI origin(s); never use "*" for mutation APIs.
    allowed_origins = os.environ.get("CORS_ORIGINS", "").split(",")
    allowed_origins = [o.strip() for o in allowed_origins if o.strip()]
    if allowed_origins:
        api.add_middleware(
            CORSMiddleware,
            allow_origins=allowed_origins,
            allow_methods=["POST", "GET"],
            allow_headers=["*"],
        )

    agent = build_agent()

    @api.get("/health", summary="Readiness and status check", tags=["ops"])
    def health() -> Dict[str, Any]:
        return {
            "status": "ok",
            "model": agent.model_name,
            "tools": sorted(agent.registry.get_tools_manifest().keys()),
        }

    @api.post(
        "/agent/process",
        response_model=AgentResponse,
        summary="Process a user prompt with guardrails & RAG context",
        tags=["agent"],
    )
    def process(req: ProcessRequest) -> AgentResponse:
        try:
            return agent.process(
                req.user_input,
                model_override=req.model_override,
                dry_run=req.dry_run,
                require_approval=req.require_approval,
            )
        except Exception:
            logger.exception("Unhandled agent.process error")
            raise HTTPException(status_code=500, detail="Internal engine error")

    @api.post(
        "/agent/approve",
        summary="Execute or reject a pending destructive tool approval",
        tags=["agent"],
    )
    def approve(req: ApproveRequest) -> Dict[str, Any]:
        if req.decision == "reject":
            if not agent.reject(req.action_id):
                raise HTTPException(status_code=404, detail="Action not found")
            return {"decision": "rejected", "action_id": req.action_id}

        success, result, err = agent.approve(req.action_id)
        if not success:
            raise HTTPException(status_code=404, detail=err or "Action not found")
        return {"decision": "approved", "action_id": req.action_id, "result": result}

    return api


app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
