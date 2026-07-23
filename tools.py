from typing import Dict, Any, Tuple, Callable, Type
from pydantic import BaseModel, ValidationError
from schemas import RestartServiceSchema, GetMemoryUsageSchema

class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, Tuple[Type[BaseModel], Callable]] = {}

    def register_tool(self, name: str, schema: Type[BaseModel], func: Callable):
        self._tools[name] = (schema, func)

    def execute_tool(self, name: str, raw_args: Dict[str, Any]) -> Tuple[bool, Any, str]:
        if name not in self._tools:
            return False, None, f"Tool '{name}' not found."

        schema, func = self._tools[name]
        
        # --- Pydantic Guardrail Check ---
        try:
            validated_args = schema(**raw_args)
            result = func(validated_args)
            return True, result, "Success"
        except ValidationError as e:
            return False, None, f"Schema validation error: {e.errors()}"

# Concrete Tool Handlers
def restart_service_handler(args: RestartServiceSchema) -> str:
    mode = "FORCED" if args.force else "NORMAL"
    return f"Successfully executed [{mode}] restart on '{args.service_name}'."

def get_memory_usage_handler(args: GetMemoryUsageSchema) -> str:
    return f"Current Memory Usage: 4096 {args.unit}."
