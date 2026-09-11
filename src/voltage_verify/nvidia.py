# SPDX-License-Identifier: MIT
"""NVIDIA Remote Attestation Service (NRAS) token verification.

The nv-attestation-sdk stores the NRAS answer as a JSON array::

    [["JWT", <overall token>],
     {"REMOTE_GPU_CLAIMS": [["JWT", <verifier token>], {"GPU-0": <device token>, ...}]}]

The verifier token and every device token are JWTs signed by NVIDIA (ES384) with a key
published in NRAS's JWKS. This module verifies those signatures, reads the claims, checks
that ``eat_nonce`` equals the workload commitment, and applies a small policy on the
per-GPU claims (measurements succeeded, secure boot on, debug off, nonce matched, report
signature and certificate chain validated by NVIDIA).

A verification proves that NVIDIA issued these claims for that GPU at that time, against
that nonce. It does not name the operator of the machine; the TDX quote and the fresh
challenge take care of that side.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from jwt.algorithms import ECAlgorithm

NRAS_ISSUER = "https://nras.attestation.nvidia.com"
NRAS_JWKS_URL = "https://nras.attestation.nvidia.com/.well-known/jwks.json"
ALLOWED_ALGS = ["ES384", "ES256"]

DEVICE_POLICY: dict[str, Any] = {
    "measres": "success",
    "secboot": True,
    "dbgstat": "disabled",
    "x-nvidia-gpu-attestation-report-nonce-match": True,
    "x-nvidia-gpu-attestation-report-signature-verified": True,
    "x-nvidia-gpu-attestation-report-cert-chain-validated": True,
}


class NrasError(ValueError):
    """Raised when the token bundle is malformed or fails verification."""


@dataclass
class VerifiedToken:
    kind: str  # "overall" | "verifier" | "device"
    name: str
    header: dict[str, Any]
    claims: dict[str, Any]
    signed_by_nvidia: bool
    kid: str | None
    x5c_subjects: list[str] = field(default_factory=list)


def _b64url_json(segment: str) -> dict[str, Any]:
    segment += "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment))


def unverified_header(token: str) -> dict[str, Any]:
    return _b64url_json(token.split(".")[0])


def unverified_claims(token: str) -> dict[str, Any]:
    return _b64url_json(token.split(".")[1])


def split_tokens(payload: Any) -> tuple[str, str, dict[str, str]]:
    """Return (overall, verifier, {device_name: token}) from the SDK's JSON array."""
    try:
        overall = payload[0][1]
        claims = payload[1]["REMOTE_GPU_CLAIMS"]
        verifier = claims[0][1]
        devices = dict(claims[1])
    except (IndexError, KeyError, TypeError) as err:
        raise NrasError(f"unexpected NRAS token layout: {err}") from err
    if not isinstance(overall, str) or not isinstance(verifier, str) or not devices:
        raise NrasError("NRAS token layout has the wrong types")
    return overall, verifier, devices


def _key_for(jwks: dict[str, Any], kid: str | None) -> tuple[Any, list[str]]:
    for key in jwks.get("keys", []):
        if kid and key.get("kid") != kid:
            continue
        subjects = []
        for cert_b64 in key.get("x5c", []):
            try:
                cert = x509.load_der_x509_certificate(base64.b64decode(cert_b64))
                subjects.append(cert.subject.rfc4514_string())
            except ValueError:
                continue
        return ECAlgorithm.from_jwk(json.dumps(key)), subjects
    raise NrasError(f"no JWKS key matches kid {kid!r}")


def verify_token(token: str, jwks: dict[str, Any], kind: str, name: str) -> VerifiedToken:
    """Verify one JWT signature against the JWKS and return its claims."""
    header = unverified_header(token)
    alg = header.get("alg")
    if alg not in ALLOWED_ALGS:
        raise NrasError(f"{name}: algorithm {alg!r} is not allowed")
    key, subjects = _key_for(jwks, header.get("kid"))
    try:
        claims = jwt.decode(
            token,
            key=key,
            algorithms=[alg],
            options={"verify_exp": False, "verify_aud": False, "verify_iat": False, "verify_nbf": False},
        )
    except jwt.PyJWTError as err:
        raise NrasError(f"{name}: signature does not verify: {err}") from err
    if claims.get("iss") != NRAS_ISSUER:
        raise NrasError(f"{name}: issuer {claims.get('iss')!r} is not NRAS")
    return VerifiedToken(kind, name, header, claims, True, header.get("kid"), subjects)


@dataclass
class NrasResult:
    verifier: VerifiedToken
    devices: list[VerifiedToken]
    overall_claims: dict[str, Any]
    nonce: str
    issued_at: datetime | None
    expires_at: datetime | None
    policy_failures: list[str]

    @property
    def overall_ok(self) -> bool:
        return bool(self.verifier.claims.get("x-nvidia-overall-att-result")) and not self.policy_failures


def _ts(value: Any) -> datetime | None:
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc)
    except (TypeError, ValueError):
        return None


def verify_nras(
    payload: Any,
    jwks: dict[str, Any],
    expected_nonce_hex: str,
    require_devices: int | None = None,
    allowed_hwmodels: set[str] | None = None,
) -> NrasResult:
    """Verify every NVIDIA-signed token in ``payload`` and apply the claims policy."""
    overall, verifier_tok, devices = split_tokens(payload)
    failures: list[str] = []
    verifier = verify_token(verifier_tok, jwks, "verifier", "REMOTE_GPU_CLAIMS")
    nonce = str(verifier.claims.get("eat_nonce", "")).lower()
    if nonce != expected_nonce_hex.lower():
        failures.append(f"eat_nonce {nonce[:16]}... does not match the commitment {expected_nonce_hex[:16]}...")
    if verifier.claims.get("x-nvidia-overall-att-result") is not True:
        failures.append("x-nvidia-overall-att-result is not true")

    verified_devices: list[VerifiedToken] = []
    for name, tok in sorted(devices.items()):
        dev = verify_token(tok, jwks, "device", name)
        for claim, wanted in DEVICE_POLICY.items():
            if dev.claims.get(claim) != wanted:
                failures.append(f"{name}: {claim} is {dev.claims.get(claim)!r}, expected {wanted!r}")
        if allowed_hwmodels and dev.claims.get("hwmodel") not in allowed_hwmodels:
            failures.append(f"{name}: hwmodel {dev.claims.get('hwmodel')!r} not in {sorted(allowed_hwmodels)}")
        verified_devices.append(dev)
    if require_devices is not None and len(verified_devices) != require_devices:
        failures.append(f"expected {require_devices} attested GPU(s), got {len(verified_devices)}")

    return NrasResult(
        verifier=verifier,
        devices=verified_devices,
        overall_claims=unverified_claims(overall),
        nonce=nonce,
        issued_at=_ts(verifier.claims.get("iat")),
        expires_at=_ts(verifier.claims.get("exp")),
        policy_failures=failures,
    )


def jwks_fingerprints(jwks: dict[str, Any]) -> dict[str, str]:
    """SHA-256 fingerprint of the leaf certificate of every JWKS key, keyed by kid."""
    out: dict[str, str] = {}
    for key in jwks.get("keys", []):
        x5c = key.get("x5c") or []
        if not x5c:
            continue
        cert = x509.load_der_x509_certificate(base64.b64decode(x5c[0]))
        out[key.get("kid", "")] = cert.fingerprint(hashes.SHA256()).hex()
    return out
