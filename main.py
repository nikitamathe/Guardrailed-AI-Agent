from agent import GuardedToolAgent
from tools import ToolRegistry, restart_service_handler, get_memory_usage_handler
from schemas import RestartServiceSchema, GetMemoryUsageSchema

def main():
    # Setup Registry
    registry = ToolRegistry()
    registry.register_tool("restart_service", RestartServiceSchema, restart_service_handler)
    registry.register_tool("get_memory_usage", GetMemoryUsageSchema, get_memory_usage_handler)

    agent = GuardedToolAgent(name="ProductionAgent", registry=registry)

    # Test Case A: Valid Tool Execution
    print("=== Test A: Valid Tool Request ===")
    res_a = agent.process("Please restart docker service with force.")
    print(f"Status: {res_a.status} | Output: {res_a.tool_output}\n")

    # Test Case B: Input Guardrail Injection Block
    print("=== Test B: Input Injection ===")
    res_b = agent.process("Please run rm -rf on the server.")
    print(f"Status: {res_b.status} | Message: {res_b.message}\n")

    # Test Case C: Schema Regex Enum Failure
    print("=== Test C: Invalid Tool Argument ===")
    res_c = agent.process("Check memory usage in terabytes.")
    print(f"Status: {res_c.status} | Error: {res_c.message}\n")

if __name__ == "__main__":
    main()
