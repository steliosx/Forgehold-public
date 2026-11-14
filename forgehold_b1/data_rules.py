"""Bounded data primitives. Source only; no import-time I/O or installation."""
import hashlib
import json
import math
import re


class Refused(RuntimeError):
    """An unmet predicate is non-PASS. It is never an authorization fallback."""


def require(condition, reason):
    if not condition:
        raise Refused(reason)


def hex64(value):
    require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'MISSING digest')
    return value


def number(value):
    require(type(value) in (int, float) and math.isfinite(value), 'invalid time/number')
    return value


def integer(value, low, high):
    require(type(value) is int and low <= value <= high, 'integer bound')
    return value


def exact(row, keys):
    require(type(row) is dict and set(row) == set(keys), 'exact schema required')
    return row


def digest(raw):
    require(type(raw) is bytes, 'bytes required')
    return hashlib.sha256(raw).hexdigest()


def encode(value, ceiling=16384):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'),
                     allow_nan=False, ensure_ascii=True).encode('utf-8')
    require(0 < len(raw) <= ceiling, 'output bound')
    return raw


def decode(raw, ceiling=16384, max_nodes=4096):
    require(type(raw) is bytes and 0 < len(raw) <= ceiling, 'input bound')
    try:
        text = raw.decode('utf-8', errors='strict')
    except UnicodeDecodeError as error:
        raise Refused('JSON not UTF-8') from error
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in '{[':
            depth += 1
            require(depth <= 16, 'JSON depth')
        elif char in '}]':
            depth -= 1
            require(depth >= 0, 'JSON framing')
    require(depth == 0 and not quoted, 'JSON framing')

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result

    def constant(_):
        raise Refused('nonfinite JSON')

    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    except ValueError as error:             # json.JSONDecodeError is a ValueError; Refused is not
        raise Refused('malformed JSON') from error
    work = [value]
    count = 0
    while work:
        node = work.pop()
        count += 1
        require(count <= max_nodes, 'JSON node count')
        if type(node) is dict:
            work.extend(node.keys())
            work.extend(node.values())
        elif type(node) is list:
            work.extend(node)
        elif type(node) is float:
            number(node)
    return value
