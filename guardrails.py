import re
import unicodedata
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple


class SecurityGuardrail:
    """Deterministic security filter for input sanitization.

    Two-layer defense:
      1. deny-list of potentially destructive command patterns,
      2. prompt-injection / meta-instruction patterns (blocked too).

    Input is normalized first (NFKC, lowercase, whitespace collapse,
    homoglyph folding, shell-obfuscation folding) so the deny rules
    cannot be trivially bypassed with spacing, backslash escapes,
    ``${IFS}``, or unicode lookalikes.
    """

    _CYRILLIC_LOOKALIKES = str.maketrans(
        {
            "а": "a",
            "в": "b",
            "е": "e",
            "к": "k",
            "м": "m",
            "н": "h",
            "о": "o",
            "р": "p",
            "с": "c",
            "т": "t",
            "у": "y",
            "х": "x",
            "ѕ": "s",
            "і": "i",
            "ј": "j",
        }
    )

    _DEFAULT_BLOCKLIST = [
        r"\brm\s+-(?:rf|fr)\b",
        r"\bsudo\s+rm\b",
        r"\b/bin/rm\b",
        r"--no-preserve-root",
        r"\bmkfs(?:\s|\.|$)",
        r":\(\)\s*\{",
        r":\(\)\s*\{.*\}\s*;\s*:",
        r"\bsh\s+<",
        r"\b(?:wget|curl)\s+https?://",
        r"\b(?:wget|curl)\s+ftps?://",
        r"\bdd\s+.*if=/dev/zero",
        r"\bdd\s+.*of=/dev/",
        r"\b(?:iptables|ip6tables)\s+(?:-f\b|--flush\b)",
        r"\bbase64\s+(?:-d|--decode)\b",
        r"\bxxd\s+-r\b",
        r"\bchmod\s+(?:-R\s+)?777\b",
        r"\betc/(?:passwd|shadow|sudoers)\b",
    ]

    _DEFAULT_INJECTION_PATTERNS = [
        r"\bignore\s+(?:all\s+)?(?:your\s+|the\s+)?(?:previous|prior|above)\s+instructions\b",
        r"\bignore\s+(?:any\s+|the\s+)?(?:previous|prior)\s+(?:instructions|prompts|context|messages)\b",
        r"\bdisregard\s+(?:all\s+|any\s+)?(?:previous|prior)\s+instructions\b",
        r"\bdo\s+not\s+(?:follow|obey|mind)\s+(?:the\s+|any\s+)?(?:previous|prior|above)\s+instructions\b",
        r"\b(?:reveal|show|print|produce|give|extract|leak|repeat)\b[^|]{0,60}\bsystem\s+prompt\b",
        r"\b(?:what\s+(?:is|are)|repeat)\b[^|]{0,40}\bsystem\s+prompt\b",
        r"\b(?:reveal|show|print|return|echo|copy|paste)\b[^|]{0,60}\b(?:rag|log|retrieved|siem|context)\b",
        r"\bact\s+as\s+(?:if\s+you\s+were\b|a\s+different\s+(?:ai|model|persona)\b|an?\s+ai\s+with\s+no\s+)",
        r"\bjailbreak\b",
        r"\bdeveloper\s+mode\b",
        r"\bdo\s+anything\s+now\b",
        r"\bno\s+(?:filters|restrictions|limitations|guardrails)\b",
        r"\b(?:unfiltered|uncensored)\b",
        r"\btake\s+precedence\b",
        r"\bnew\s+instructions\b",
        r"\binstructions?\s+above\b",
        r"\bbypass\s+(?:the\s+)?(?:guardrail|agent)\b",
        r"\bignore\s+(?:the\s+)?(?:guardrail|agent)\b",
    ]

    def __init__(
        self,
        blocklist_patterns: Optional[List[str]] = None,
        injection_patterns: Optional[List[str]] = None,
        max_length: int = 2048,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.blocklist_patterns = list(blocklist_patterns or self._DEFAULT_BLOCKLIST)
        self.injection_patterns = list(injection_patterns or self._DEFAULT_INJECTION_PATTERNS)
        self.max_length = max_length
        self.audit_callback = audit_callback
        self._compiled_blocklist = [re.compile(p) for p in self.blocklist_patterns]
        self._compiled_injections = [re.compile(p) for p in self.injection_patterns]

    def normalize(self, user_input: str) -> str:
        """Normalize raw input into a canonical form for rule matching."""
        text = unicodedata.normalize("NFKC", user_input or "")
        text = text.lower()
        text = text.translate(self._CYRILLIC_LOOKALIKES)
        text = text.replace("${ifs}", " ")
        text = text.replace("\\", "")
        text = re.sub(r"[\"'`]", "", text)
        text = re.sub(r"\s+", " ", text).strip()
        return text

    def inspect_input(self, user_input: str) -> Dict[str, Any]:
        """Compatibility method used by the app layer and agent layer."""
        normalized = self.normalize(user_input)

        if not normalized:
            return self._blocked("Query cannot be empty.", [], normalized)

        if len(normalized) > self.max_length:
            return self._blocked(
                f"Input exceeds maximum character length ({self.max_length}).",
                [],
                normalized,
            )

        deny_hits = self._match(self._compiled_blocklist, normalized, "deny")
        if deny_hits:
            return self._blocked(
                "Input contains a potentially destructive command pattern.",
                deny_hits,
                normalized,
            )

        injection_hits = self._match(self._compiled_injections, normalized, "injection")
        if injection_hits:
            return self._blocked(
                "Input contains prompt-injection / meta-instruction content.",
                injection_hits,
                normalized,
            )

        self._emit_audit(
            {
                "stage": "input_guardrail",
                "status": "passed",
                "reason": "Safe",
                "matched_patterns": [],
                "normalized_input": normalized,
            }
        )
        return {
            "is_blocked": False,
            "reason": "Safe",
            "matched_patterns": [],
            "normalized_input": normalized,
        }

    def inspect_context(self, fragments: Optional[Iterable[str]]) -> Dict[str, Any]:
        """Scan RAG/log fragments for deny + injection patterns (indirect injection).

        Intended to be used by the agent layer before injecting retrieved
        context into the system prompt.
        """
        flagged = []
        for frag in fragments or []:
            normalized = self.normalize(frag)
            if not normalized:
                continue
            reasons = self._match(self._compiled_blocklist, normalized, "deny")
            reasons += self._match(self._compiled_injections, normalized, "injection")
            if reasons:
                flagged.append({"fragment": frag, "reasons": reasons})
        return {
            "is_clean": not flagged,
            "flagged_fragments": flagged,
        }

    def validate_input(self, user_input: str) -> Tuple[bool, str]:
        """Legacy alias for inspect_input."""
        result = self.inspect_input(user_input)
        if result["is_blocked"]:
            return False, result["reason"]
        return True, result["reason"]

    def _match(self, compiled: List[re.Pattern], text: str, kind: str) -> List[str]:
        hits = []
        for pat in compiled:
            if pat.search(text):
                hits.append(f"{kind}:{pat.pattern}")
        return hits

    def _blocked(self, reason: str, matches: List[str], normalized: str) -> Dict[str, Any]:
        result = {
            "is_blocked": True,
            "reason": reason,
            "matched_patterns": matches,
            "normalized_input": normalized,
        }
        self._emit_audit(
            {
                "stage": "input_guardrail",
                "status": "blocked",
                "reason": reason,
                "matched_patterns": matches,
                "normalized_input": normalized,
            }
        )
        return result

    def _emit_audit(self, event: Dict[str, Any]) -> None:
        if self.audit_callback is None:
            return
        try:
            self.audit_callback(event)
        except Exception:
            pass