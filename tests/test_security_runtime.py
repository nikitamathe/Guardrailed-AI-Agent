import unittest
from unittest import mock

from agent import GuardedToolAgent
from guardrails import SecurityGuardrail
from tools import ToolRegistry


class SecurityRuntimeContractTests(unittest.TestCase):
    def test_registry_supports_execute_and_manifest(self):
        registry = ToolRegistry()
        tools = registry.get_tools_manifest()

        self.assertIn("block_ip", tools)
        self.assertIn("restart_service", tools)

        result = registry.execute("restart_service", service_name="nginx", force=True)
        self.assertIn("nginx", result)

    def test_guardrail_exposes_inspect_input_alias(self):
        guardrail = SecurityGuardrail()

        safe = guardrail.inspect_input("Investigate failed SSH attempts from 192.168.1.105")
        self.assertFalse(safe["is_blocked"])

        blocked = guardrail.inspect_input("rm -rf /")
        self.assertTrue(blocked["is_blocked"])

    def test_agent_process_executes_structured_json_tool_call(self):
        registry = ToolRegistry()
        agent = GuardedToolAgent("demo", registry, model_name="llama3")

        with mock.patch("agent.ollama.chat", return_value={
            "message": {
                "content": '{"tool": "block_ip", "args": {"ip_address": "192.168.1.105", "reason": "SSH brute force"}}'
            }
        }):
            response = agent.process("Investigate brute force login from 192.168.1.105")

        self.assertEqual(response.status, "tool_execution")
        self.assertEqual(response.tool_used, "block_ip")
        self.assertIn("192.168.1.105", response.tool_output)


if __name__ == "__main__":
    unittest.main()
