"""Small validators for identities and timestamps returned by hosted providers."""
from datetime import datetime
import re
from typing import TypeGuard


def object_id(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and bool(re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', value))


def timestamp(value):
    if not isinstance(value, str):
        return False
    match = re.fullmatch(
        r'([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})'
        r'(?:\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})', value)
    if match is None:
        return False
    try:
        # Validate the calendar without fractions; Python 3.10 cannot parse nanoseconds.
        parsed = datetime.fromisoformat((match[1] + match[2]).replace('Z', '+00:00'))
        # GitHub CLI's Go time.Time emits year one for an absent non-pointer value.
        return parsed.year > 1 and parsed.utcoffset() is not None
    except ValueError:
        return False
