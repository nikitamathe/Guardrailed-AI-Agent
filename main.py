"""Guardrailed AI SOC Agent — Engine entry point.

Phase 5 hardening:
  1. Structured JSON logging for audit + telemetry capture (machine-parseable,
     no free-form `print` output).
  2. A shared agent factory that registers the full tool set consistently
     (fixing the historical mismatch where each entry point registered a
     different subset).
  3. Dual entry points:
       - CLI harness  -> `python main.py`  (deterministic verification flows)
       - FastAPI app   -> `uvicorn main:app` (REST API exposing the guarded
                           agent and the destructive-action approval flow)

The FastAPI `app` object is the production entry point referenced by the
`Dockerfile`. This resolves the long-standing `main:app` import failure.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
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

logger = logging.getLogger("guardrailed.engine")


# --------------------------------------------------------------------------- #
# Structured JSON logging
# --------------------------------------------------------------------------- #
class JsonFormatter(logging.Formatter):
    """Serialize log records as single-line JSON objects for audit/telemetry."""

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        # Attach arbitrary structured fields passed via the `extra` dict.
        for key, value in getattr(record, "extra_fields", {}).items():
            payload[key] = value
        return json.dumps(payload, default=str)


def setup_logging(level: str = "INFO") -> None:
    """Install a structured JSON handler on the guardrailed logger tree."""
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger("guardrailed")
    root.setLevel(numeric_level)
    root.handlers = [handler]
    root.propagate = False


def log_event(event: str, level: str = "info", **fields: Any) -> None:
    """Convenience wrapper: emit a structured audit/telemetry event."""
    log = getattr(logger, level.lower(), logger.info)
    log("%s", event, extra={"extra_fields": fields})


# --------------------------------------------------------------------------- #
# Agent construction (single source of truth for tool registration)
# --------------------------------------------------------------------------- #
def build_agent() -> GuardedToolAgent:
    """Register the full, consistent tool set and return a hardened agent."""
    registry = ToolRegistry()
    registry.register_tool("restart_service", RestartServiceSchema, restart_service_handler)
    registry.register_tool("get_memory_usage", GetMemoryUsageSchema, get_memory_usage_handler)
    registry.register_tool("block_ip", BlockIPSchema, block_ip_handler)

    model = os.environ.get("OLLAMA_MODEL", "llama3")
    return GuardedToolAgent(name="SOC-Engine-Agent", registry=registry, model_name=model)


# --------------------------------------------------------------------------- #
# CLI harness
# --------------------------------------------------------------------------- #
def run_demo_case(label: str, prompt: str, **kwargs: Any) -> AgentResponse:
    """Execute one guarded agent query and emit a structured audit record."""
    response = build_agent().process(prompt, **kwargs)
    log_event(
        "agent.process",
        level="info" if response.status not in ("error", "blocked", "uncertain") else "warning",
        case=label,
        status=response.status,
        tool_used=response.tool_used,
        message=response.message,
        tool_output=response.tool_output,
    )
    return response


def main() -> None:
    """CLI verification harness: exercises guardrails, tool dispatch, validation."""
    setup_logging(os.environ.get("LOG_LEVEL", "INFO"))
    log_event("engine.start", mode="cli")

    # Test Case A: Valid destructive tool request (dry-run to avoid host mutation)
    run_demo_case(
        "A: valid destructive tool",
        "Please restart docker service with force.",
        dry_run=True,
    )
    # Test Case B: Input guardrail injection block
    run_demo_case("B: input injection", "Please run rm -rf on the server.")
    # Test Case C: Schema validations
    run_demo_case("C: invalid tool argument", "Check memory usage in terabytes.")
    run_demo_case("D: valid memory tool", "Check memory usage in megabytes.")

    log_event("engine.shutdown", mode="cli")


# --------------------------------------------------------------------------- #
# FastAPI application (production entry point -> `uvicorn main:app`)
# --------------------------------------------------------------------------- #
try:
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
except Exception:  # pragma: no cover - FastAPI optional for CLI-only environments
    FastAPI = None  # type: ignore


app = None


def _build_app() -> Any:
    """Create and wire the FastAPI application (called lazily to support CLI)."""
    if FastAPI is None:
        raise RuntimeError("FastAPI is not installed; run the CLI instead of uvicorn main:app")

    api = FastAPI(
        title="Guardrailed AI SOC Engine",
        version="1.0.0",
        description=(
            "REST API exposing the guarded AI SOC agent for log-aware threat "
            "analysis and gated remediation actions."
        ),
    )

    # CORS is restrictive by default (no origins). Configure explicitly for
    # the Streamlit UI origin(s) in production; never use "*" for mutation APIs.
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

    class ProcessRequest(BaseModel):
        user_input: str = Field(..., min_length=1, max_length=4096)
        model_override: Optional[str] = Field(default=None, max_length=128)
        dry_run: bool = Field(default=False)
        require_approval: bool = Field(default=False)

    class ApproveRequest(BaseModel):
        action_id: str = Field(..., min_length=1, max_length=64)

    @api.get("/health", summary="Liveness and model status", tags=["ops"])
    def health() -> Dict[str, Any]:
        return {
            "status": "ok",
            "model": agent.model_name,
            "tools": sorted(agent.registry.get_tools_manifest().keys()),
        }

    @api.post(
        "/agent/process",
        response_model=AgentResponse,
        summary="Run a guarded agent query",
        tags=["agent"],
    )
    def process(req: ProcessRequest) -> AgentResponse:
        try:
            response = agent.process(
                req.user_input,
                model_override=req.model_override,
                dry_run=req.dry_run,
                require_approval=req.require_approval,
            )
        except Exception as exc:  # sanitize: never leak internals to the client
            logger.exception("Unhandled agent.process error")
            raise HTTPException(status_code=500, detail="Internal engine error")
        log_event(
            "api.agent.process",
            status=response.status,
            tool_used=response.tool_used,
        )
        return response

    @api.post("/agent/approve", summary="Approve a staged destructive action", tags=["agent"])
    def approve(req: ApproveRequest) -> Dict[str, Any]:
        success, result, err = agent.approve(req.action_id)
        if not success:
            raise HTTPException(status_code=404, detail=err or "Action not found")
        log_event("api.agent.approve", action_id=req.action_id, success=success)
        return {"approved": True, "result": result}

    @api.post("/agent/reject", summary="Reject and discard a staged destructive action", tags=["agent"])
    def reject(req: ApproveRequest) -> Dict[str, Any]:
        if not agent.reject(req.action_id):
            raise HTTPException(status_code=404, detail="Action not found")
        log_event("api.agent.reject", action_id=req.action_id)
        return {"rejected": True}

    return api


if __name__ == "__main__":
    main()
else:
    # When imported by uvicorn (`main:app`), expose the FastAPI application.
    app = _build_app()
