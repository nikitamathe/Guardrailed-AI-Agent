import json
import os
import shutil
import subprocess
from typing import Dict, Any, Tuple, Callable, Type

from pydantic import BaseModel, ValidationError

from schemas import RestartServiceSchema, GetMemoryUsageSchema, BlockIPSchema


class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, Tuple[Type[BaseModel], Callable]] = {}
        self._register_default_tools()

    def register_tool(self, name: str, schema: Type[BaseModel], func: Callable):
        self._tools[name] = (schema, func)

    def get_tools_manifest(self) -> Dict[str, Dict[str, Any]]:
        manifest = {}
        for name, (schema, _) in self._tools.items():
            manifest[name] = {
                "name": name,
                "schema": schema.model_json_schema(),
            }
        return manifest

    def _register_default_tools(self):
        self.register_tool("restart_service", RestartServiceSchema, restart_service_handler)
        self.register_tool("get_memory_usage", GetMemoryUsageSchema, get_memory_usage_handler)
        self.register_tool("block_ip", BlockIPSchema, block_ip_handler)

    def execute(self, name: str, **kwargs) -> str:
        if name not in self._tools:
            raise ValueError(f"Tool '{name}' not found.")

        schema, func = self._tools[name]
        try:
            validated_args = schema(**kwargs)
        except ValidationError as e:
            raise ValueError(f"Schema validation error: {e.errors()}") from e

        try:
            result = func(**validated_args.model_dump())
        except TypeError:
            result = func(validated_args)

        return str(result)

    def execute_tool(self, name: str, raw_args: Dict[str, Any]) -> Tuple[bool, Any, str]:
        if name not in self._tools:
            return False, None, f"Tool '{name}' not found."

        try:
            result = self.execute(name, **raw_args)
            return True, result, ""
        except ValueError as exc:
            return False, None, str(exc)


# Concrete Tool Handlers
def _run_command(command: list[str]) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)
        output = result.stdout.strip() or result.stderr.strip() or "Command completed without text output."
        if result.returncode == 0:
            return output
        return f"Command failed ({result.returncode}): {output}"
    except FileNotFoundError:
        return f"Command not available: {' '.join(command)}"
    except subprocess.TimeoutExpired:
        return f"Command timed out after 20 seconds: {' '.join(command)}"


def restart_service_handler(service_name: str, force: bool = False, **kwargs) -> str:
    service_name = str(service_name).strip()
    mode = "forced" if force else "normal"

    if shutil.which("systemctl"):
        args = ["systemctl", "restart", service_name]
        if force:
            args = ["systemctl", "restart", service_name]
        return f"Executed {mode} service restart for '{service_name}'. Result: {_run_command(args)}"

    if shutil.which("sc"):
        return f"Executed Windows service restart for '{service_name}'. Result: {_run_command(['sc', 'stop', service_name])}; {_run_command(['sc', 'start', service_name])}"

    return f"No service manager available for '{service_name}'. The restart was not executed."


def get_memory_usage_handler(unit: str = "GB", **kwargs) -> str:
    unit = str(unit).upper()
    if shutil.which("free"):
        output = _run_command(["free", "-m"])
        return f"Current memory usage: {output} | Requested unit: {unit}"

    if shutil.which("wmic"):
        output = _run_command(["wmic", "OS", "get", "FreePhysicalMemory", "/Value"])
        return f"Current memory usage: {output} | Requested unit: {unit}"

    return f"Memory utilization could not be measured automatically. Requested unit: {unit}."


def block_ip_handler(ip_address: str, reason: str = "Security threat", **kwargs) -> str:
    ip = str(ip_address).strip()

    if shutil.which("iptables"):
        return f"IP '{ip}' blocked via iptables. Reason: {reason}. Result: {_run_command(['iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'])}"

    if shutil.which("nft"):
        return f"IP '{ip}' blocked via nftables. Reason: {reason}. Result: {_run_command(['nft', 'add', 'rule', 'inet', 'filter', 'input', 'ip', 'saddr', ip, 'drop'])}"

    if shutil.which("netsh"):
        rule_name = f"block_{ip.replace('.', '_')}"
        message = _run_command(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name=' + rule_name, 'dir=in', 'action=block', 'remoteip=' + ip])
        return f"IP '{ip}' blocked via Windows firewall. Reason: {reason}. Result: {message}"

    return f"Firewall tool unavailable. Manual remediation required for '{ip}' due to: {reason}."