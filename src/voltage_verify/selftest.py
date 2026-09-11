# SPDX-License-Identifier: MIT
"""Negative tests: prove the verifier rejects what it must reject.

Each mutation takes a bundle that verifies cleanly and changes one thing an attacker might
change. Where the manifest is altered, the bundle's commitments are recomputed as a
sophisticated attacker would, so the failure has to come from the hardware-signed evidence
no longer matching, not from a bookkeeping field.
"""

from __future__ import annotations

import base64
import copy
import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .bundle import Bundle
from .canonical import commitments
from .verify import Report, verify_bundle


@dataclass
class Mutation:
    name: str
    description: str
    apply: Callable[[Bundle], Bundle]
    must_fail: tuple[str, ...]  # at least one of these checks must fail


def _with_manifest(bundle: Bundle, manifest: dict[str, Any]) -> Bundle:
    com = commitments(manifest)
    clone = copy.deepcopy(bundle)
    clone.manifest = manifest
    clone.commitments = {"sha256": com.sha256_hex, "sha512": com.sha512_hex}
    return clone


def _flip_hex(value: str, position: int = -1) -> str:
    chars = list(value)
    chars[position] = "0" if chars[position] != "0" else "1"
    return "".join(chars)


def mutate_image_digest(bundle: Bundle) -> Bundle:
    manifest = copy.deepcopy(bundle.manifest)
    image = manifest["workload"].get("image") or {"reference": "example", "digest": "sha256:" + "0" * 64}
    image["digest"] = _flip_hex(image["digest"])
    manifest["workload"]["image"] = image
    return _with_manifest(bundle, manifest)


def mutate_artifact(bundle: Bundle) -> Bundle:
    manifest = copy.deepcopy(bundle.manifest)
    arts = manifest["workload"].get("artifacts") or []
    if arts:
        arts[0]["sha256"] = _flip_hex(arts[0]["sha256"])
    else:
        arts.append({"name": "injected.bin", "sha256": "0" * 64, "size": 1})
    manifest["workload"]["artifacts"] = arts
    return _with_manifest(bundle, manifest)


def mutate_manifest_field(bundle: Bundle) -> Bundle:
    manifest = copy.deepcopy(bundle.manifest)
    manifest["workload"]["extra"] = {**manifest["workload"].get("extra", {}), "injected": "value"}
    return _with_manifest(bundle, manifest)


def mutate_challenge(bundle: Bundle) -> Bundle:
    manifest = copy.deepcopy(bundle.manifest)
    manifest["challenge"] = secrets.token_hex(32)
    return _with_manifest(bundle, manifest)


def mutate_quote(bundle: Bundle) -> Bundle:
    clone = copy.deepcopy(bundle)
    raw = bytearray(clone.quote)
    raw[48 + 136] ^= 0x01  # first byte of MRTD inside the TD report
    clone.quote = bytes(raw)
    return clone


def mutate_nras(bundle: Bundle) -> Bundle:
    clone = copy.deepcopy(bundle)
    nras = json.loads(json.dumps(clone.nras))
    devices = nras[1]["REMOTE_GPU_CLAIMS"][1]
    name = sorted(devices)[0]
    header, payload, signature = devices[name].split(".")
    body = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    body["dbgstat"] = "enabled"
    forged = base64.urlsafe_b64encode(json.dumps(body, separators=(",", ":")).encode()).decode().rstrip("=")
    devices[name] = ".".join([header, forged, signature])
    clone.nras = nras
    return clone


BOUND = ("tdx.report_data", "nvidia.nonce")
MUTATIONS: list[Mutation] = [
    Mutation("image-digest", "container image digest changed, commitments recomputed", mutate_image_digest, BOUND),
    Mutation("artifact", "model or artifact digest changed, commitments recomputed", mutate_artifact, BOUND),
    Mutation("manifest-field", "another manifest field changed, commitments recomputed", mutate_manifest_field, BOUND),
    Mutation(
        "challenge-replay",
        "challenge replaced by a fresh one (replay of old evidence)",
        mutate_challenge,
        (*BOUND, "manifest.challenge"),
    ),
    Mutation("quote-tamper", "one byte of the TDX quote body altered", mutate_quote, ("tdx.signatures",)),
    Mutation("nras-tamper", "one claim inside a GPU token altered", mutate_nras, ("nvidia.signatures",)),
]


@dataclass
class SelfTestResult:
    name: str
    description: str
    passed: bool
    failed_checks: list[str]


def run_selftest(
    bundle: Bundle, online: bool = False, expected_challenge: str | None = None
) -> tuple[Report, list[SelfTestResult]]:
    """Return the clean report and one result per mutation (passed = verifier rejected it)."""
    clean = verify_bundle(bundle, online=online, expected_challenge=expected_challenge)
    results: list[SelfTestResult] = []
    for mutation in MUTATIONS:
        mutated = mutation.apply(bundle)
        rep = verify_bundle(mutated, online=online, expected_challenge=expected_challenge)
        failed = rep.failed()
        rejected = any(f in failed for f in mutation.must_fail) and not rep.ok
        results.append(SelfTestResult(mutation.name, mutation.description, rejected, failed))
    return clean, results
