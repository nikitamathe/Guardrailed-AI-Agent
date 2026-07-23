from typing import Dict, Any, Optional
from pydantic import BaseModel, Field

# Final Agent Response Envelope
class AgentResponse(BaseModel):
    status: str  # "success", "blocked", "tool_execution", "error"
    message: str
    tool_used: Optional[str] = None
    tool_output: Optional[Any] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

# Tool Schema 1: Service Management
class RestartServiceSchema(BaseModel):
    service_name: str = Field(description="Target service name e.g. nginx, docker")
    force: bool = Field(default=False, description="Forced restart flag")

# Tool Schema 2: System Metrics (Restricted via regex constraint)
class GetMemoryUsageSchema(BaseModel):
    unit: str = Field(
        default="MB", 
        pattern="^(KB|MB|GB)$", 
        description="Accepted units: KB, MB, or GB"
    )
