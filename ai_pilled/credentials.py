"""Shared recognizable-credential patterns and output redaction."""
import json
import re


# Token alphabets are ASCII; non-ASCII neighbors must not suppress their boundaries.
PATTERNS = (
    ('aws-access-key', re.compile(r'(?a)\b(?:AKIA|ASIA)[A-Z0-9]{16}\b')),
    ('aws-secret-key', re.compile(
        r"(?ai)\b(?:aws_secret_access_key|secretaccesskey)[\"']?[ \t]*[:=][ \t]*[\"']?"
        r"[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")),
    ('github-token', re.compile(r'(?a)\bgh[pousr]_[A-Za-z0-9]{36,}\b')),
    ('github-fine-grained-token', re.compile(r'(?a)\bgithub_pat_[A-Za-z0-9_]{40,}\b')),
    ('pypi-token', re.compile(r'(?a)\bpypi-[A-Za-z0-9_-]{85,}')),
    ('private-key', re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----')),
    ('openai-token', re.compile(r'(?a)\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}\b')),
    ('slack-webhook', re.compile(r'https://hooks\.slack\.com/services/[A-Za-z0-9_-]{8,}/[A-Za-z0-9_-]{8,}/[A-Za-z0-9_-]{16,}')),
    ('slack-token', re.compile(r'(?a)\bxox[baprs]-[A-Za-z0-9-]{20,}\b')),
)

AWS_SECRET_ASSIGNMENT = dict(PATTERNS)['aws-secret-key']

PRIVATE_KEY_BLOCK = re.compile(
    r'-----BEGIN (?P<kind>(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----'
    r'[\s\S]*?(?:-----END (?P=kind)-----|\Z)')


def redact_plain(text):
    text = PRIVATE_KEY_BLOCK.sub('[REDACTED PRIVATE KEY]', text)
    for _, pattern in PATTERNS:
        text = pattern.sub('[REDACTED]', text)
    return text


def json_string_literals(text):
    """Yield quoted JSON strings in one linear pass, including source locations."""
    if '"' not in text:
        return
    start = None
    start_line = line = 1
    escaped = False
    for index, character in enumerate(text):
        if character == '\n':
            line += 1
        if start is None:
            if character == '"':
                start, start_line, escaped = index, line, False
        elif character in '\r\n':
            start = None  # Literal newlines are invalid in JSON strings.
        elif escaped:
            escaped = False
        elif character == '\\':
            escaped = True
        elif character == '"':
            try:
                value = json.loads(text[start:index + 1])
            except ValueError:
                pass
            else:
                yield start, index + 1, start_line, value
            start = None


def aws_secret_field(key, value):
    if not isinstance(key, str) or not isinstance(value, str):
        return False
    boundary = len(key) + 1
    return any(match.end() > boundary for match in AWS_SECRET_ASSIGNMENT.finditer(key + '=' + value))


def json_secret_literals(text):
    previous_end, previous_value = 0, None
    for start, end, line, value in json_string_literals(text):
        secret_field = (text[previous_end:start].strip() == ':'
                        and aws_secret_field(previous_value, value))
        yield start, end, line, value, secret_field
        previous_end, previous_value = end, value


def redact(text):
    # Preserve whole-block privacy before rewriting any individually quoted header.
    text = PRIVATE_KEY_BLOCK.sub('[REDACTED PRIVATE KEY]', text)
    pieces: list[str] = []
    position = 0
    for start, end, _, value, secret_field in json_secret_literals(text):
        cleaned = '[REDACTED]' if secret_field else redact_plain(value)
        if cleaned != value:
            pieces.extend((text[position:start], json.dumps(cleaned)))
            position = end
    if not pieces:
        return redact_plain(text)
    pieces.append(text[position:])
    return redact_plain(''.join(pieces))


def redact_data(value):
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {redact(key) if isinstance(key, str) else key:
                '[REDACTED]' if aws_secret_field(key, item) else redact_data(item)
                for key, item in value.items()}
    if isinstance(value, list):
        return [redact_data(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_data(item) for item in value)
    return value
