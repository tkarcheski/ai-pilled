"""Decode structured inputs with bounded nesting and predictable errors."""
import json
import math

MAX_NESTING = 100


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            # Keys may contain credentials; never reproduce them in parser errors.
            raise ValueError('JSON object contains duplicate keys')
        result[key] = value
    return result


def loads(content):
    try:
        data = json.loads(content, object_pairs_hook=unique_object)
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
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError('JSON numbers must be finite')
        if isinstance(value, (dict, list)):
            if len(frames) > MAX_NESTING:
                raise ValueError('JSON nesting exceeds the supported limit')
            frames.append(iter(value.values() if isinstance(value, dict) else value))
    return data
