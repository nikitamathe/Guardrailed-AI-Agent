from typing import Dict, Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from agent import GuardedToolAgent
from schemas import AgentResponse
from tools import ToolRegistry, restart_service_handler, get_memory_usage_handler, block_ip_handler
from schemas import RestartServiceSchema, GetMemoryUsageSchema, BlockIPSchema


class QueryRequest(BaseModel):
    query: str
    model: str | None = None


class RemediationRequest(BaseModel):
    tool: str
    args: Dict[str, Any]


registry = ToolRegistry()
registry.register_tool("restart_service", RestartServiceSchema, restart_service_handler)
registry.register_tool("get_memory_usage", GetMemoryUsageSchema, get_memory_usage_handler)
registry.register_tool("block_ip", BlockIPSchema, block_ip_handler)

agent = GuardedToolAgent(name="ProductionAgent", registry=registry)
app = FastAPI(title="Guardrailed AI SOC Engine", version="1.0.0")


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/query")
def query_security(request: QueryRequest) -> Dict[str, Any]:
    response = agent.process(request.query, model_override=request.model)
    return {
        "status": response.status,
        "message": response.message,
        "tool_used": response.tool_used,
        "tool_output": response.tool_output,
    }


@app.post("/api/v1/remediate")
def remediate(request: RemediationRequest) -> Dict[str, Any]:
    try:
        result = registry.execute(request.tool, **request.args)
        return {
            "status": "success",
            "tool": request.tool,
            "result": result,
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/v1/telemetry")
def telemetry() -> Dict[str, Any]:
    return {
        "status": "ok",
        "engine": "Guardrailed AI SOC Engine",
        "available_tools": list(registry.get_tools_manifest().keys()),
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
