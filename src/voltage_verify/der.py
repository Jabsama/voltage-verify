# SPDX-License-Identifier: MIT
"""A deliberately small DER reader, enough to walk the Intel SGX PCK certificate extension.

The extension (OID 1.2.840.113741.1.13.1) is a SEQUENCE of SEQUENCE { OID, value } pairs whose
values are OCTET STRINGs, INTEGERs, ENUMERATEDs or nested SEQUENCEs. Nothing else is needed,
so nothing else is implemented; unknown tags are returned as raw bytes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

TAG_INTEGER = 0x02
TAG_OCTET_STRING = 0x04
TAG_OID = 0x06
TAG_ENUMERATED = 0x0A
TAG_SEQUENCE = 0x30


class DerError(ValueError):
    """Raised on malformed DER."""


@dataclass(frozen=True)
class Node:
    tag: int
    value: Any  # int | bytes | str (OID) | list[Node]


def _read_length(data: bytes, pos: int) -> tuple[int, int]:
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    count = first & 0x7F
    if count == 0 or count > 4 or pos + count > len(data):
        raise DerError("unsupported DER length encoding")
    return int.from_bytes(data[pos : pos + count], "big"), pos + count


def _decode_oid(raw: bytes) -> str:
    if not raw:
        raise DerError("empty OID")
    first = raw[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    if value:
        raise DerError("truncated OID")
    return ".".join(parts)


def decode(data: bytes) -> list[Node]:
    """Decode a concatenation of DER TLVs into nodes (SEQUENCEs are decoded recursively)."""
    nodes: list[Node] = []
    pos = 0
    while pos < len(data):
        if pos + 2 > len(data):
            raise DerError("truncated TLV")
        tag = data[pos]
        length, body_start = _read_length(data, pos + 1)
        body_end = body_start + length
        if body_end > len(data):
            raise DerError("TLV runs past the end of the buffer")
        body = data[body_start:body_end]
        if tag == TAG_SEQUENCE:
            nodes.append(Node(tag, decode(body)))
        elif tag == TAG_OID:
            nodes.append(Node(tag, _decode_oid(body)))
        elif tag in (TAG_INTEGER, TAG_ENUMERATED):
            nodes.append(Node(tag, int.from_bytes(body, "big", signed=True)))
        else:
            nodes.append(Node(tag, body))
        pos = body_end
    return nodes


def pairs(sequence: Node) -> dict[str, Node]:
    """Turn a SEQUENCE of { OID, value } SEQUENCEs into a dict keyed by dotted OID."""
    if sequence.tag != TAG_SEQUENCE:
        raise DerError("expected a SEQUENCE")
    out: dict[str, Node] = {}
    for item in sequence.value:
        if item.tag != TAG_SEQUENCE or len(item.value) != 2 or item.value[0].tag != TAG_OID:
            raise DerError("expected SEQUENCE { OID, value }")
        out[item.value[0].value] = item.value[1]
    return out
