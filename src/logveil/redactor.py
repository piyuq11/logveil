from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping


@dataclass(frozen=True)
class RedactionResult:
    value: str
    replacements: int


DEFAULT_SENSITIVE_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "apikey",
        "authorization",
        "cookie",
        "password",
        "passwd",
        "refresh_token",
        "secret",
        "set-cookie",
        "client_secret",
        "private_key",
        "token",
    }
)


class Redactor:
    def __init__(
        self,
        replacement: str = "[REDACTED]",
        sensitive_keys: Iterable[str] = (),
        redact_emails: bool = True,
    ) -> None:
        self.replacement = replacement
        self.sensitive_keys = DEFAULT_SENSITIVE_KEYS | {
            key.casefold() for key in sensitive_keys
        }
        self.redact_emails = redact_emails
        self._patterns = self._build_patterns()

    def _build_patterns(self) -> tuple[re.Pattern[str], ...]:
        patterns = [
            r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}",
            r"\bgh[pousr]_[A-Za-z0-9]{20,}\b",
            r"\bgithub_pat_[A-Za-z0-9_]{20,}\b",
            r"\bsk-[A-Za-z0-9_-]{16,}\b",
            r"\bAKIA[0-9A-Z]{16}\b",
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            r"(?i)(?P<prefix>\b(?:password|passwd|api[_-]?key|token|secret)\s*[=:]\s*)"
            r"(?P<quote>['\"]?)[^\s,'\";]+(?P=quote)",
        ]
        if self.redact_emails:
            patterns.append(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
        return tuple(re.compile(pattern) for pattern in patterns)

    def redact_text(self, text: str) -> RedactionResult:
        replacements = 0
        value = text
        for pattern in self._patterns:
            def replace(match: re.Match[str]) -> str:
                nonlocal replacements
                replacements += 1
                prefix = match.groupdict().get("prefix")
                return f"{prefix}{self.replacement}" if prefix else self.replacement

            value = pattern.sub(replace, value)
        return RedactionResult(value, replacements)

    def redact_json(self, value: Any) -> tuple[Any, int]:
        if isinstance(value, Mapping):
            output: dict[str, Any] = {}
            replacements = 0
            for key, item in value.items():
                if str(key).casefold() in self.sensitive_keys:
                    output[str(key)] = self.replacement
                    replacements += 1
                else:
                    output[str(key)], count = self.redact_json(item)
                    replacements += count
            return output, replacements
        if isinstance(value, list):
            output_list = []
            replacements = 0
            for item in value:
                redacted, count = self.redact_json(item)
                output_list.append(redacted)
                replacements += count
            return output_list, replacements
        if isinstance(value, str):
            result = self.redact_text(value)
            return result.value, result.replacements
        return value, 0

    def redact_json_line(self, line: str) -> RedactionResult:
        value = json.loads(line)
        redacted, replacements = self.redact_json(value)
        return RedactionResult(
            json.dumps(redacted, ensure_ascii=False, separators=(",", ":")),
            replacements,
        )
