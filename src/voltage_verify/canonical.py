# SPDX-License-Identifier: MIT
"""Canonical serialisation of the workload manifest and the two commitments derived from it.

The manifest is serialised the way RFC 8785 (JSON Canonicalization Scheme) does for the
value types this tool emits: object keys sorted by code point, no insignificant whitespace,
UTF-8, no floats. Two parties that hold the same manifest therefore compute byte-identical
input and, from it, the same commitments:

* ``commitment256`` = SHA-256(canonical manifest): the 32-byte nonce handed to the NVIDIA
  attestation flow (NRAS echoes it back in ``eat_nonce``).
* ``commitment512`` = SHA-512(canonical manifest): the 64-byte ``report_data`` written into
  the Intel TDX quote request (the quote embeds it verbatim).

Anyone who changes a single byte of the manifest (image digest, model digest, challenge,
anything) changes both commitments, and both proofs stop matching.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


class CanonicalError(ValueError):
    """Raised when a manifest cannot be canonicalised deterministically."""


def _reject_floats(value: Any, path: str = "$") -> None:
    if isinstance(value, float):
        raise CanonicalError(f"floats are not allowed in a manifest (at {path})")
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise CanonicalError(f"object keys must be strings (at {path})")
            _reject_floats(v, f"{path}.{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            _reject_floats(v, f"{path}[{i}]")


def canonical_bytes(manifest: dict[str, Any]) -> bytes:
    """Return the canonical UTF-8 encoding of ``manifest``."""
    _reject_floats(manifest)
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True)
class Commitments:
    canonical: bytes
    sha256: bytes
    sha512: bytes

    @property
    def sha256_hex(self) -> str:
        return self.sha256.hex()

    @property
    def sha512_hex(self) -> str:
        return self.sha512.hex()


def commitments(manifest: dict[str, Any]) -> Commitments:
    """Compute both commitments of a manifest."""
    raw = canonical_bytes(manifest)
    return Commitments(raw, hashlib.sha256(raw).digest(), hashlib.sha512(raw).digest())
