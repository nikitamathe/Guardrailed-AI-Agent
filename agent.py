from typing import Dict, Any, Optional
from guardrails import SafetyGuardrails
from schemas import AgentResponse
from tools import ToolRegistry
from rag_engine import SecurityLogRAG


class GuardedToolAgent:
    def __init__(self, name: str, registry: ToolRegistry, log_file: str = "security.log"):
        self.name = name
        self.registry = registry
        print(f"[{self.name}] Initializing Security Log RAG Engine...")
        self.rag = SecurityLogRAG(log_file_path=log_file)

    def process(self, prompt: str) -> AgentResponse:
        # 1. Input Guardrail
        is_safe, check_msg = SafetyGuardrails.validate_input(prompt)
        if not is_safe:
            return AgentResponse(status="blocked", message=check_msg)

        # 2. Context Retrieval via RAG
        rag_context = self._retrieve_log_context(check_msg)

        # 3. Simulated LLM Tool Call Decision
        tool_call = self._mock_intent_parsing(check_msg, rag_context)

        if tool_call:
            name = tool_call["name"]
            args = tool_call["args"]

            # 4. Validated Tool Execution via Registry
            success, output, err = self.registry.execute_tool(name, args)
            if not success:
                return AgentResponse(
                    status="error",
                    message=f"Tool Guardrail: {err}",
                    tool_used=name
                )

            # 5. Output Guardrail on Tool Output
            safe_out = SafetyGuardrails.sanitize_output(str(output))
            return AgentResponse(
                status="tool_execution",
                message=f"Tool '{name}' executed with RAG context.",
                tool_used=name,
                tool_output=safe_out
            )

        # Fallback Direct Response with RAG Context
        response_msg = f"Query processed: '{prompt}'"
        if rag_context:
            response_msg += f"\nRetrieved Context: {rag_context}"

        return AgentResponse(status="success", message=response_msg)

    def _retrieve_log_context(self, prompt: str) -> list[str]:
        """Queries FAISS vector database based on prompt keywords."""
        p = prompt.lower()
        if "brute force" in p or "ssh" in p or "block" in p:
            return self.rag.query_logs("brute force attack IP", k=2)
        elif "sql" in p or "injection" in p:
            return self.rag.query_logs("SQL injection", k=2)
        elif "nginx" in p or "restart" in p:
            return self.rag.query_logs("nginx service restart", k=2)
        return []

    def _mock_intent_parsing(self, prompt: str, rag_context: list[str]) -> Optional[Dict[str, Any]]:
        p = prompt.lower()
        
        if "restart" in p:
            if "force" in p:
                return {"name": "restart_service", "args": {"service_name": "nginx", "force": True}}
            return {"name": "restart_service", "args": {"service_name": "docker"}}

        elif "memory" in p:
            if "terabytes" in p:
                return {"name": "get_memory_usage", "args": {"unit": "TB"}}
            return {"name": "get_memory_usage", "args": {"unit": "GB"}}

        elif "block" in p or "ban" in p:
            # Extract target IP dynamically from RAG context if available
            target_ip = "192.168.1.105"
            for log in rag_context:
                if "IP:" in log:
                    target_ip = log.split("IP:")[-1].strip()
                    break
            return {"name": "block_ip", "args": {"ip_address": target_ip, "reason": "RAG-backed Threat Remediation"}}

        return None


if __name__ == "__main__":
    print("\n=== Testing Guarded Tool Agent with RAG Pipeline ===")
    
    # Initialize Registry and Agent
    registry = ToolRegistry()
    agent = GuardedToolAgent(name="SecurityAgent", registry=registry)

    # Test 1: RAG-backed IP Block Test
    print("\n--- Test 1: Threat Detection & Dynamic IP Block ---")
    resp1 = agent.process("Block the IP involved in the brute force attack")
    print(f"Status: {resp1.status}")
    print(f"Message: {resp1.message}")
    print(f"Tool Used: {resp1.tool_used}")
    print(f"Output: {resp1.tool_output}")

    # Test 2: Input Injection Blocking Test
    print("\n--- Test 2: Malicious Input Injection Guardrail ---")
    resp2 = agent.process("Restart nginx; rm -rf /")
    print(f"Status: {resp2.status}")
    print(f"Message: {resp2.message}")