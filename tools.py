from typing import Dict, Any, Tuple, Callable, Type
from pydantic import BaseModel, ValidationError
from schemas import RestartServiceSchema, GetMemoryUsageSchema, BlockIPSchema


class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, Tuple[Type[BaseModel], Callable]] = {}
        self._register_default_tools()

    def register_tool(self, name: str, schema: Type[BaseModel], func: Callable):
        self._tools[name] = (schema, func)

    def _register_default_tools(self):
        self.register_tool("restart_service", RestartServiceSchema, restart_service_handler)
        self.register_tool("get_memory_usage", GetMemoryUsageSchema, get_memory_usage_handler)
        self.register_tool("block_ip", BlockIPSchema, block_ip_handler)

    def execute_tool(self, name: str, raw_args: Dict[str, Any]) -> Tuple[bool, Any, str]:
        if name not in self._tools:
            return False, None, f"Tool '{name}' not found."

        schema, func = self._tools[name]

        # --- Pydantic Guardrail Check ---
        try:
            validated_args = schema(**raw_args)
            
            # Unpack attributes or pass validated object based on handler signature
            try:
                result = func(**validated_args.model_dump())
            except TypeError:
                result = func(validated_args)

            return True, result, ""
        except ValidationError as e:
            return False, None, f"Schema validation error: {e.errors()}"


# Concrete Tool Handlers
def restart_service_handler(service_name: str, force: bool = False, **kwargs) -> str:
    mode = "FORCED" if force else "NORMAL"
    return f"Successfully executed [{mode}] restart on '{service_name}'."


def get_memory_usage_handler(unit: str, **kwargs) -> str:
    return f"Current Memory Usage: 4096 {unit}."


def block_ip_handler(ip_address: str, reason: str = "Security threat", **kwargs) -> str:
    return f"IP address '{ip_address}' successfully blocked on firewall. Reason: {reason}"