import ipaddress
import json
import os
import shutil
import subprocess
from typing import Dict, Any, Tuple, Callable, Optional, Type

from pydantic import BaseModel, ValidationError

from schemas import ALLOWED_SERVICES, RestartServiceSchema, GetMemoryUsageSchema, BlockIPSchema


class ToolRegistry:
    def __init__(self, audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None):
        self._tools: Dict[str, Tuple[Type[BaseModel], Callable]] = {}
        self._audit_callback = audit_callback
        self._register_default_tools()

    def set_audit_callback(self, audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None) -> None:
        self._audit_callback = audit_callback

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
            self._emit_audit("tool.execution", "validation_failed", name, kwargs, "", str(e))
            raise ValueError(f"Schema validation error: {e.errors()}") from e

        try:
            result = func(**validated_args.model_dump())
            self._emit_audit("tool.execution", "success", name, kwargs, str(result), "")
            return str(result)
        except TypeError:
            result = func(validated_args)
            self._emit_audit("tool.execution", "success", name, kwargs, str(result), "")
            return str(result)
        except Exception as exc:
            self._emit_audit("tool.execution", "failed", name, kwargs, "", str(exc))
            raise

    def execute_tool(self, name: str, raw_args: Dict[str, Any]) -> Tuple[bool, Any, str]:
        if name not in self._tools:
            return False, None, f"Tool '{name}' not found."

        try:
            result = self.execute(name, **raw_args)
            return True, result, ""
        except ValueError as exc:
            return False, None, str(exc)

    def _emit_audit(self, stage: str, status: str, tool: str, args: Any, result: str, error: str) -> None:
        if self._audit_callback is None:
            return
        try:
            self._audit_callback({
                "stage": stage,
                "status": status,
                "tool": tool,
                "args": args if isinstance(args, dict) else {},
                "result": result,
                "error": error,
            })
        except Exception:
            pass


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


def get_memory_usage_handler(unit: str = "GB", **kwargs) -> str:
    unit = str(unit).upper()
    if shutil.which("free"):
        output = _run_command(["free", "-m"])
        return f"Current memory usage: {output} | Requested unit: {unit}"

    if shutil.which("wmic"):
        output = _run_command(["wmic", "OS", "get", "FreePhysicalMemory", "/Value"])
        return f"Current memory usage: {output} | Requested unit: {unit}"

    return f"Memory utilization could not be measured automatically. Requested unit: {unit}."


def restart_service_handler(service_name: str, force: bool = False, dry_run: bool = False, **kwargs) -> str:
    service_name = str(service_name).strip().lower()

    if service_name not in ALLOWED_SERVICES:
        allowed = ", ".join(sorted(ALLOWED_SERVICES))
        return (
            f"Refused: service '{service_name}' is not in the approved allow-list "
            f"({allowed}). No action was taken."
        )

    mode = "forced" if force else "normal"
    dry_run_note = "[DRY-RUN, not executed] " if dry_run else ""

    if shutil.which("systemctl"):
        args = ["systemctl", "restart", service_name]
        if dry_run:
            return f"{dry_run_note}Would execute {' '.join(args)} for '{service_name}' (mode: {mode})."
        return f"Executed {mode} service restart for '{service_name}'. Result: {_run_command(args)}"

    if shutil.which("sc"):
        stop_cmd = ["sc", "stop", service_name]
        start_cmd = ["sc", "start", service_name]
        if dry_run:
            return f"{dry_run_note}Would execute {' '.join(stop_cmd)} then {' '.join(start_cmd)} for '{service_name}'."
        return f"Executed Windows service restart for '{service_name}'. Result: {_run_command(stop_cmd)}; {_run_command(start_cmd)}"

    return f"No service manager available for '{service_name}'. The restart was not executed."


def rollback_restart_service(service_name: str, **kwargs) -> str:
    """Restore a previously restarted service to its prior state.

    A full stateful rollback (capturing the exact pre-restart PID/state) is not
    yet implemented. This stub returns a safe, documented restore procedure;
    the caller should confirm the service is healthy before relying on it.
    """
    clean = str(service_name).strip().lower()
    if clean not in ALLOWED_SERVICES:
        return f"Refused rollback: '{service_name}' is not an approved service."
    if shutil.which("systemctl"):
        return (
            f"Rollback guidance for '{clean}': verify current health with "
            f"'systemctl status {clean}'. If unhealthy, restore previous state via "
            f"'systemctl restart {clean}' (stateful snapshot not implemented)."
        )
    return f"Rollback guidance for '{clean}': no systemd available; stateful undo is not supported here."


def block_ip_handler(ip_address: str, reason: str = "Security threat", dry_run: bool = False, **kwargs) -> str:
    ip = str(ip_address).strip()
    dry_run_note = "[DRY-RUN, not executed] " if dry_run else ""

    if shutil.which("iptables"):
        args = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
        if dry_run:
            return f"{dry_run_note}Would block '{ip}' via iptables: {' '.join(args)}. Reason: {reason}."
        return f"IP '{ip}' blocked via iptables. Reason: {reason}. Result: {_run_command(args)}"

    if shutil.which("nft"):
        args = ["nft", "add", "rule", "inet", "filter", "input", "ip", "saddr", ip, "drop"]
        if dry_run:
            return f"{dry_run_note}Would block '{ip}' via nftables: {' '.join(args)}. Reason: {reason}."
        return f"IP '{ip}' blocked via nftables. Reason: {reason}. Result: {_run_command(args)}"

    if shutil.which("netsh"):
        rule_name = f"block_{ip.replace('.', '_')}"
        args = ['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name=' + rule_name, 'dir=in', 'action=block', 'remoteip=' + ip]
        if dry_run:
            return f"{dry_run_note}Would block '{ip}' via Windows firewall: {' '.join(args)}. Reason: {reason}."
        return f"IP '{ip}' blocked via Windows firewall. Reason: {reason}. Result: {_run_command(args)}"

    return f"Firewall tool unavailable. Manual remediation required for '{ip}' due to: {reason}."


def rollback_block_ip(ip_address: str, **kwargs) -> str:
    """Revert a prior block for ``ip_address`` using the matching reverse rule.

    Because the agent could have blocked the IP over iptables, nftables or the
    Windows firewall, the rollback attempts the exact reverse command for the
    available backend. This is idempotent and safe if the rule does not exist.
    """
    ip = str(ip_address).strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return f"Rollback refused: '{ip}' is not a valid IP address."

    if shutil.which("iptables"):
        return f"Reverse rule for '{ip}': {_run_command(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'])}"

    if shutil.which("nft"):
        return f"Reverse rule for '{ip}': {_run_command(['nft', 'delete', 'rule', 'inet', 'filter', 'input', 'ip', 'saddr', ip, 'drop'])}"

    if shutil.which("netsh"):
        rule_name = f"block_{ip.replace('.', '_')}"
        return f"Reverse rule for '{ip}': {_run_command(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=' + rule_name])}"

    return f"No firewall tool available to rollback block for '{ip}'; manual removal required."