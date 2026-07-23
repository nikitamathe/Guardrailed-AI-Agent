import re
from typing import Tuple

class SafetyGuardrails:
    PROMPT_INJECTION_PATTERNS = [
        r"ignore previous instructions",
        r"system prompt",
        r"bypass restriction",
        r"rm -rf",
        r"drop database",
    ]
    
    API_KEY_PATTERN = r"(sk-[a-zA-Z0-9]{32,}|ghp_[a-zA-Z0-9]{36})"

    @classmethod
    def validate_input(cls, user_input: str) -> Tuple[bool, str]:
        lowered = user_input.lower()
        for pattern in cls.PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, lowered):
                return False, f"Input blocked: Malicious pattern matched ('{pattern}')."
        return True, user_input

    @classmethod
    def sanitize_output(cls, raw_output: str) -> str:
        return re.sub(cls.API_KEY_PATTERN, "[REDACTED_API_KEY]", raw_output)
