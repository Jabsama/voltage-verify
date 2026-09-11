# SPDX-License-Identifier: MIT
import hashlib
import json

import pytest

from voltage_verify.canonical import CanonicalError, canonical_bytes, commitments
from voltage_verify.manifest import ManifestError, build_manifest, validate_manifest
from voltage_verify.registry import parse_reference


def test_canonical_is_order_independent_and_compact():
    a = {"b": 1, "a": {"y": [1, 2], "x": "é"}}
    b = {"a": {"x": "é", "y": [1, 2]}, "b": 1}
    assert canonical_bytes(a) == canonical_bytes(b) == '{"a":{"x":"é","y":[1,2]},"b":1}'.encode()


def test_floats_are_rejected():
    with pytest.raises(CanonicalError):
        canonical_bytes({"a": 1.5})


def test_commitments_are_sha256_and_sha512_of_canonical_bytes():
    m = {"k": "v"}
    raw = canonical_bytes(m)
    c = commitments(m)
    assert c.sha256 == hashlib.sha256(raw).digest()
    assert c.sha512 == hashlib.sha512(raw).digest()
    assert len(c.sha512) == 64 and len(c.sha256) == 32


def test_build_manifest_hashes_artifacts_and_validates(tmp_path):
    f = tmp_path / "weights.bin"
    f.write_bytes(b"hello weights")
    m = build_manifest(
        image_digest="sha256:" + "ab" * 32, image="ghcr.io/org/app:1", artifacts=[f], extra={"z": "1", "a": "2"}
    )
    validate_manifest(m)
    expected_artifact = {"name": "weights.bin", "sha256": hashlib.sha256(b"hello weights").hexdigest(), "size": 13}
    assert m["workload"]["artifacts"] == [expected_artifact]
    assert list(m["workload"]["extra"]) == ["a", "z"]
    assert len(m["challenge"]) == 64
    # a different challenge changes both commitments
    m2 = json.loads(json.dumps(m))
    m2["challenge"] = "0" * 64
    assert commitments(m).sha256 != commitments(m2).sha256
    assert commitments(m).sha512 != commitments(m2).sha512


def test_manifest_rejects_bad_digest_and_challenge():
    with pytest.raises(ManifestError):
        build_manifest(image_digest="sha256:short")
    with pytest.raises(ManifestError):
        build_manifest(challenge="zz")
    with pytest.raises(ManifestError):
        validate_manifest({"format": "other"})


def test_parse_reference_docker_hub_and_ghcr():
    assert parse_reference("ubuntu:22.04") == ("registry-1.docker.io", "library/ubuntu", "22.04")
    cuda = parse_reference("nvidia/cuda:12.8.1-runtime-ubuntu24.04")
    assert cuda == ("registry-1.docker.io", "nvidia/cuda", "12.8.1-runtime-ubuntu24.04")
    assert parse_reference("ghcr.io/org/app:1.2") == ("ghcr.io", "org/app", "1.2")
    assert parse_reference("ghcr.io/org/app@sha256:" + "0" * 64) == ("ghcr.io", "org/app", "sha256:" + "0" * 64)
    assert parse_reference("localhost:5000/x") == ("localhost:5000", "x", "latest")
