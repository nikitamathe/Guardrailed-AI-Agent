import re
from typing import Tuple

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

    def validate_input(self, user_input: str) -> Tuple[bool, str]:
        """Checks input against blocklist and common sanitization rules."""
        cleaned_input = user_input.strip()

        # 1. Null/Empty Check
        if not cleaned_input:
            return False, "Query cannot be empty."

        # 2. Pattern Matching against dangerous system commands
        for pattern in self.blocklist_patterns:
            if re.search(pattern, cleaned_input, re.IGNORECASE):
                return False, f"Input contains potentially destructive command pattern: '{pattern}'"

        # 3. Input length check (prevent buffer issues/resource exhaustion)
        if len(cleaned_input) > 2048:
            return False, "Input exceeds maximum character length (2048)."

        # Input is valid and safe for agent processing
        return True, "Safe"