# SPDX-License-Identifier: MIT
"""NRAS token verification against real tokens and a JWKS snapshot of 12 September 2026."""

import base64
import json

import pytest

from voltage_verify import nvidia


def _kid(token: str) -> str:
    return nvidia.unverified_header(token).get("kid", "")


def _available(jwks: dict, token: str) -> bool:
    return any(k.get("kid") == _kid(token) for k in jwks["keys"])


def test_split_layout(nras_ppcie):
    overall, verifier, devices = nvidia.split_tokens(nras_ppcie)
    assert overall.count(".") == 2 and verifier.count(".") == 2
    assert len(devices) == 8 and set(devices) == {f"GPU-{i}" for i in range(8)}


def test_ppcie_tokens_verify_and_policy_holds(nras_ppcie, jwks):
    _, verifier, _ = nvidia.split_tokens(nras_ppcie)
    if not _available(jwks, verifier):
        pytest.skip("signing key of the 10 September token has rotated out of the JWKS snapshot")
    nonce = nvidia.unverified_claims(verifier)["eat_nonce"]
    res = nvidia.verify_nras(nras_ppcie, jwks, nonce, require_devices=8, allowed_hwmodels={"GH100"})
    assert res.overall_ok, res.policy_failures
    assert len(res.devices) == 8
    assert all(d.claims.get("measres") == "success" for d in res.devices)


def test_nonce_mismatch_is_reported(nras_ppcie, jwks):
    _, verifier, _ = nvidia.split_tokens(nras_ppcie)
    if not _available(jwks, verifier):
        pytest.skip("signing key rotated")
    res = nvidia.verify_nras(nras_ppcie, jwks, "00" * 32)
    assert not res.overall_ok and any("eat_nonce" in f for f in res.policy_failures)


def test_tampered_claim_breaks_signature(nras_ppcie, jwks):
    _, verifier, devices = nvidia.split_tokens(nras_ppcie)
    if not _available(jwks, verifier):
        pytest.skip("signing key rotated")
    payload = json.loads(json.dumps(nras_ppcie))
    tok = payload[1]["REMOTE_GPU_CLAIMS"][1]["GPU-0"]
    h, p, s = tok.split(".")
    body = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    body["secboot"] = False
    forged = base64.urlsafe_b64encode(json.dumps(body, separators=(",", ":")).encode()).decode().rstrip("=")
    payload[1]["REMOTE_GPU_CLAIMS"][1]["GPU-0"] = ".".join([h, forged, s])
    nonce = nvidia.unverified_claims(verifier)["eat_nonce"]
    with pytest.raises(nvidia.NrasError, match="signature"):
        nvidia.verify_nras(payload, jwks, nonce)


def test_unknown_kid_is_an_error(nras_h200, jwks):
    _, verifier, _ = nvidia.split_tokens(nras_h200)
    nonce = nvidia.unverified_claims(verifier)["eat_nonce"]
    if _available(jwks, verifier):
        res = nvidia.verify_nras(nras_h200, jwks, nonce)
        assert res.overall_ok
    else:
        with pytest.raises(nvidia.NrasError, match="no JWKS key"):
            nvidia.verify_nras(nras_h200, jwks, nonce)


def test_algorithm_none_rejected(nras_ppcie, jwks):
    _, verifier, _ = nvidia.split_tokens(nras_ppcie)
    h, p, s = verifier.split(".")
    none_header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
    with pytest.raises(nvidia.NrasError, match="not allowed"):
        nvidia.verify_token(".".join([none_header, p, ""]), jwks, "verifier", "x")
