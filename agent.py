from typing import Dict, Any, Optional
from guardrails import SafetyGuardrails
from schemas import AgentResponse
from tools import ToolRegistry

class GuardedToolAgent:
    def __init__(self, name: str, registry: ToolRegistry):
        self.name = name
        self.registry = registry

    def process(self, prompt: str) -> AgentResponse:
        # 1. Input Guardrail
        is_safe, check_msg = SafetyGuardrails.validate_input(prompt)
        if not is_safe:
            return AgentResponse(status="blocked", message=check_msg)

        # 2. Simulated LLM Tool Call Decision
        tool_call = self._mock_intent_parsing(check_msg)

        if tool_call:
            name = tool_call["name"]
            args = tool_call["args"]

            # 3. Validated Tool Execution
            success, output, err = self.registry.execute_tool(name, args)
            if not success:
                return AgentResponse(status="error", message=f"Tool Guardrail: {err}", tool_used=name)

            # 4. Output Guardrail on Tool Output
            safe_out = SafetyGuardrails.sanitize_output(str(output))
            return AgentResponse(
                status="tool_execution",
                message=f"Tool '{name}' executed.",
                tool_used=name,
                tool_output=safe_out
            )

        # Fallback Direct Response
        return AgentResponse(status="success", message=f"Query processed: '{prompt}'")

    def _mock_intent_parsing(self, prompt: str) -> Optional[Dict[str, Any]]:
        p = prompt.lower()
        if "restart" in p:
            if "force" in p:
                return {"name": "restart_service", "args": {"service_name": "nginx", "force": True}}
            return {"name": "restart_service", "args": {"service_name": "docker"}}
        elif "memory" in p:
            if "terabytes" in p:
                return {"name": "get_memory_usage", "args": {"unit": "TB"}}  # Triggers Pydantic Regex Failure
            return {"name": "get_memory_usage", "args": {"unit": "GB"}}
        return None
