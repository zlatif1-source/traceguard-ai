import re

SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|access[_-]?token|password)\s*[=:]\s*\S+"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END[^-]+-----"),
]


def redact_secrets(text: str) -> tuple[str, int]:
    redacted = text
    redaction_count = 0
    for pattern in SECRET_PATTERNS:
        redacted, replacements = pattern.subn("[REDACTED_SECRET]", redacted)
        redaction_count += replacements
    return redacted, redaction_count


def safe_prompt_section(label: str, value: str) -> str:
    """Mark user-controlled content as untrusted data, not model instructions."""
    return f'<{label} untrusted_data="true">\n{value}\n</{label}>'
