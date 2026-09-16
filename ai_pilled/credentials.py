"""Shared recognizable-credential patterns and output redaction."""
import re


PATTERNS = (
    ('aws-access-key', re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b')),
    ('aws-secret-key', re.compile(
        r"(?i)\b(?:aws_secret_access_key|secretaccesskey)[\"']?[ \t]*[:=][ \t]*[\"']?"
        r"[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")),
    ('github-token', re.compile(r'\bgh[pousr]_[A-Za-z0-9]{36,}\b')),
    ('github-fine-grained-token', re.compile(r'\bgithub_pat_[A-Za-z0-9_]{40,}\b')),
    ('pypi-token', re.compile(r'\bpypi-[A-Za-z0-9_-]{85,}')),
    ('private-key', re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----')),
    ('openai-token', re.compile(r'\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}\b')),
    ('slack-webhook', re.compile(r'https://hooks\.slack\.com/services/[A-Za-z0-9_-]{8,}/[A-Za-z0-9_-]{8,}/[A-Za-z0-9_-]{16,}')),
    ('slack-token', re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{20,}\b')),
)

PRIVATE_KEY_BLOCK = re.compile(
    r'-----BEGIN (?P<kind>(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----'
    r'[\s\S]*?(?:-----END (?P=kind)-----|\Z)')


def redact(text):
    text = PRIVATE_KEY_BLOCK.sub('[REDACTED PRIVATE KEY]', text)
    for _, pattern in PATTERNS:
        text = pattern.sub('[REDACTED]', text)
    return text


def redact_data(value):
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {redact(key) if isinstance(key, str) else key: redact_data(item)
                for key, item in value.items()}
    if isinstance(value, list):
        return [redact_data(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_data(item) for item in value)
    return value
