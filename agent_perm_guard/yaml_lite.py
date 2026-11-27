"""A deliberately small YAML subset parser (stdlib only).

Supported: comments, nested mappings, sequences (including sequences of
mappings), quoted and plain scalars, inline lists ``[a, b]`` and inline maps
``{a: b}``. Not supported: anchors, multi-document streams, block scalars,
complex keys. Raises ``YamlError`` on malformed input.
"""

from __future__ import annotations

import json


class YamlError(ValueError):
    pass


def _strip_comment(line: str) -> str:
    quote = None
    previous = ""
    for index, char in enumerate(line):
        if quote:
            if char == quote and previous != "\\":
                quote = None
        elif char in "'\"":
            quote = char
        elif char == "#" and (index == 0 or line[index - 1] in " \t"):
            return line[:index]
        previous = char
    return line


def _scalar(text: str):
    text = text.strip()
    if text == "":
        return None
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        if not inner:
            return []
        return [_scalar(part) for part in _split_inline(inner)]
    if text.startswith("{") and text.endswith("}"):
        inner = text[1:-1].strip()
        if not inner:
            return {}
        result = {}
        for part in _split_inline(inner):
            key, _, value = part.partition(":")
            result[str(_scalar(key))] = _scalar(value)
        return result
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        return text[1:-1]
    lowered = text.lower()
    if lowered in ("true", "yes", "on"):
        return True
    if lowered in ("false", "no", "off"):
        return False
    if lowered in ("null", "~"):
        return None
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        pass
    return text


def _split_inline(text: str) -> list:
    parts = []
    current = []
    depth = 0
    quote = None
    for char in text:
        if quote:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if char in "'\"":
            quote = char
            current.append(char)
        elif char in "[{":
            depth += 1
            current.append(char)
        elif char in "]}":
            depth -= 1
            current.append(char)
        elif char == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if current:
        parts.append("".join(current).strip())
    return parts


def _tokenise(text: str) -> list:
    tokens = []
    for raw in text.splitlines():
        line = _strip_comment(raw).rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        if "\t" in line[: indent + 1]:
            raise YamlError("tabs are not supported for indentation")
        tokens.append([indent, line.strip()])
    return tokens


def _parse_block(tokens: list, index: int, indent: int):
    if index >= len(tokens):
        return None, index
    if tokens[index][1].startswith("- "):
        return _parse_sequence(tokens, index, indent)
    return _parse_mapping(tokens, index, indent)


def _parse_sequence(tokens: list, index: int, indent: int):
    result = []
    while index < len(tokens) and tokens[index][0] == indent and tokens[index][1].startswith("- "):
        rest = tokens[index][1][2:].strip()
        if not rest:
            index += 1
            if index < len(tokens) and tokens[index][0] > indent:
                item, index = _parse_block(tokens, index, tokens[index][0])
            else:
                item = None
            result.append(item)
        elif _looks_like_key(rest):
            key, _, value = rest.partition(":")
            item = {}
            key = str(_scalar(key))
            value = value.strip()
            if value:
                item[key] = _scalar(value)
                index += 1
            else:
                index += 1
                if index < len(tokens) and tokens[index][0] > indent:
                    item[key], index = _parse_block(tokens, index, tokens[index][0])
                else:
                    item[key] = None
            while index < len(tokens) and tokens[index][0] > indent and not tokens[index][1].startswith("- "):
                sub, index = _parse_mapping(tokens, index, tokens[index][0])
                item.update(sub)
            result.append(item)
        else:
            result.append(_scalar(rest))
            index += 1
    return result, index


def _looks_like_key(text: str) -> bool:
    key, sep, _rest = text.partition(":")
    if not sep:
        return False
    key = key.strip()
    return bool(key) and "://" not in key


def _parse_mapping(tokens: list, index: int, indent: int):
    result = {}
    while index < len(tokens) and tokens[index][0] == indent and not tokens[index][1].startswith("- "):
        line = tokens[index][1]
        if not _looks_like_key(line):
            raise YamlError("expected a 'key: value' mapping entry at line %r" % line)
        key, _, value = line.partition(":")
        key = str(_scalar(key))
        value = value.strip()
        if value:
            result[key] = _scalar(value)
            index += 1
        else:
            index += 1
            if index < len(tokens) and tokens[index][0] > indent:
                result[key], index = _parse_block(tokens, index, tokens[index][0])
            else:
                result[key] = None
    return result, index


def loads(text: str):
    """Parse a YAML-subset document into Python objects."""
    tokens = _tokenise(text)
    if not tokens:
        return {}
    value, index = _parse_block(tokens, 0, tokens[0][0])
    if index != len(tokens):
        raise YamlError("unexpected indentation near %r" % (tokens[index][1],))
    return value


def load_file(path):
    from pathlib import Path

    return loads(Path(path).read_text(encoding="utf-8"))


def dumps_smoke(value) -> str:  # tiny helper used by tests
    return json.dumps(value, sort_keys=True)
