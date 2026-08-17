from typing import Optional
from pydantic import BaseModel, Field


class RestartServiceSchema(BaseModel):
    service_name: str = Field(..., min_length=1)
    force: bool = Field(default=False)


class GetMemoryUsageSchema(BaseModel):
    unit: str = Field(..., pattern="^(KB|MB|GB)$")


class BlockIPSchema(BaseModel):
    ip_address: str = Field(..., pattern=r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    reason: str = Field(default="Security threat")


class AgentResponse(BaseModel):
    status: str
    message: str
    tool_used: Optional[str] = None
    tool_output: Optional[str] = None