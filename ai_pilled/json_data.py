"""Decode structured inputs with bounded nesting and predictable errors."""
import json

MAX_NESTING = 100


def loads(content):
    try:
        data = json.loads(content)
    except RecursionError as exc:
        raise ValueError('JSON nesting exceeds the supported limit') from exc
    # Walk iteratively so validation itself cannot exhaust the Python call stack.
    frames = [iter([data])]
    while frames:
        try:
            value = next(frames[-1])
        except StopIteration:
            frames.pop()
            continue
        if isinstance(value, (dict, list)):
            if len(frames) > MAX_NESTING:
                raise ValueError('JSON nesting exceeds the supported limit')
            frames.append(iter(value.values() if isinstance(value, dict) else value))
    return data
