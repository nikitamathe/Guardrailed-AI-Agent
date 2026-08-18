import re
from typing import Tuple, Dict, Any


class SecurityGuardrail:
    """Deterministic security filter for input sanitization."""

    def __init__(self):
        # List of critical bash/system commands to block entirely
        self.blocklist_patterns = [
            r"rm\s+-rf",      # Destructive delete
            r"mkfs",          # Format filesystem
            r":\(\)\{.*:\|:&\};:", # Fork bomb
            r"sh\s+<",         # Pipe shell input
            r"wget\s+http",    # Remote download execute
            r"curl\s+http",    # Remote download execute
            r"dd\s+if=/dev/zero", # Overwrite disk
            r"iptables\s+-F",  # Flush firewall entirely
        ]

    def inspect_input(self, user_input: str) -> Dict[str, Any]:
        """Compatibility method used by the app layer and agent layer."""
        cleaned_input = (user_input or "").strip()

        if not cleaned_input:
            return {"is_blocked": True, "reason": "Query cannot be empty."}

        for pattern in self.blocklist_patterns:
            if re.search(pattern, cleaned_input, re.IGNORECASE):
                return {
                    "is_blocked": True,
                    "reason": f"Input contains potentially destructive command pattern: '{pattern}'",
                }

        if len(cleaned_input) > 2048:
            return {"is_blocked": True, "reason": "Input exceeds maximum character length (2048)."}

        return {"is_blocked": False, "reason": "Safe"}

    def validate_input(self, user_input: str) -> Tuple[bool, str]:
        """Checks input against blocklist and common sanitization rules."""
        result = self.inspect_input(user_input)
        if result["is_blocked"]:
            return False, result["reason"]
        return True, result["reason"]