import ipaddress
from typing import Optional
from pydantic import BaseModel, Field, field_validator

# Authorized systemd / OS services that the agent is permitted to restart.
ALLOWED_SERVICES = {"nginx", "ollama", "sshd"}


class RestartServiceSchema(BaseModel):
    service_name: str = Field(..., min_length=1)
    force: bool = Field(default=False)

    @field_validator("service_name")
    @classmethod
    def validate_service_name(cls, value: str) -> str:
        name = str(value).strip().lower()
        if not name:
            raise ValueError("service_name must not be empty.")
        if name not in ALLOWED_SERVICES:
            allowed = ", ".join(sorted(ALLOWED_SERVICES))
            raise ValueError(
                f"service '{name}' is not in the approved allow-list ({allowed})."
            )
        return name


class GetMemoryUsageSchema(BaseModel):
    unit: str = Field(..., pattern="^(KB|MB|GB)$")


class BlockIPSchema(BaseModel):
    ip_address: str = Field(..., min_length=1)
    reason: str = Field(default="Security threat")

    @field_validator("ip_address")
    @classmethod
    def validate_ip_address(cls, value: str) -> str:
        raw = str(value).strip()
        try:
            addr = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise ValueError(f"'{raw}' is not a valid IP address.") from exc

        if addr.version != 4:
            raise ValueError(
                f"'{raw}' is not an IPv4 address; only IPv4 targets are supported."
            )

        if (
            addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_unspecified
            or addr.is_reserved
        ):
            raise ValueError(
                f"'{raw}' is a loopback/link-local/multicast/reserved address and "
                "cannot be blocked."
            )

        if addr.is_private:
            raise ValueError(
                f"'{raw}' is a private/rfc1918 address; blocking is restricted to "
                "public routable targets."
            )

        return str(addr)


class AgentResponse(BaseModel):
    status: str
    message: str
    tool_used: Optional[str] = None
    tool_output: Optional[str] = None