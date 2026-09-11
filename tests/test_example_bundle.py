# SPDX-License-Identifier: MIT
"""The reference bundle captured on a VoltageGPU h100-xlarge Confidential VM on 12 September 2026.

Verified offline against the Intel collateral and NVIDIA JWKS embedded at attestation time,
so this test stays deterministic after Intel re-issues TCB info and NVIDIA rotates keys.
"""

from pathlib import Path

from voltage_verify.bundle import Bundle
from voltage_verify.selftest import run_selftest
from voltage_verify.verify import verify_bundle

EXAMPLE = Path(__file__).parent.parent / "examples" / "hello-workload" / "bundle-8xh100-2026-09-12.json"
CHALLENGE = "ef7f54c160627ee536a02b5e73896ac4b1ac2cdefdb7cfaaf2366a7d33cc8731"


def test_reference_bundle_verifies_offline():
    bundle = Bundle.load(EXAMPLE)
    report = verify_bundle(bundle, online=False, expected_challenge=CHALLENGE, allowed_hwmodels={"GH100"}, require_devices=8)
    assert report.ok, report.failed()
    assert report.facts["tdx"]["tcb_status"] == "UpToDate"
    assert report.facts["tdx"]["qe_status"] == "UpToDate"
    assert len(report.facts["nvidia"]["devices"]) == 8
    assert bundle.nvidia_mode == "multi-gpu-ppcie"


def test_reference_bundle_rejects_every_mutation():
    bundle = Bundle.load(EXAMPLE)
    clean, results = run_selftest(bundle, online=False, expected_challenge=CHALLENGE)
    assert clean.ok
    assert all(r.passed for r in results), [(r.name, r.failed_checks) for r in results if not r.passed]


def test_reference_bundle_fails_with_another_challenge():
    bundle = Bundle.load(EXAMPLE)
    report = verify_bundle(bundle, online=False, expected_challenge="00" * 32)
    assert not report.ok and "manifest.challenge" in report.failed()
