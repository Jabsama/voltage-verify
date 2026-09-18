# Changelog

## 0.2.0 (2026-09-18)

* New command `voltage-verify quote <file>`: verifies a bare Intel TDX quote from any provider,
  raw, hex or base64, with no manifest and no NVIDIA token. Structure, signature chain up to
  the pinned Intel root, TCB status, QE identity and revocation from Intel PCS. Options
  `--report-data` (bind to the 64 bytes you expect), `--offline`, `--accept-out-of-date`,
  `--json`. Tested against Google's production Sapphire Rapids quote from go-tdx-guest, now
  vendored under `tests/fixtures/third-party/`.
* `tdx.parse_quote(raw, allow_trailing=True)` tolerates bytes after the signature data and
  reports how many were ignored (`Quote.trailing`); the default stays strict, so bundles
  produced by `attest` are checked exactly as before.
* A platform whose TCB components match no level in Intel's TCB info is reported as OutOfDate
  (Intel's own rule) and, with `--accept-out-of-date`, becomes a warning instead of a failure.

## 0.1.2 (2026-09-18)

* Docs only, no code change. Spells out what the Protected PCIe reference tokens in
  `examples/hello-workload/` actually cover (CC State OFF reading, one token per GPU, no NVSwitch
  fabric attestation). Adds a "Works with any Intel TDX host, any provider" section: `attest` and
  `verify` never call a VoltageGPU endpoint, they read the kernel's own configfs TSM interface and
  NVIDIA's own SDK and collateral, so the tool works the same on any TDX host with a confidential
  NVIDIA GPU, on any cloud.

## 0.1.1 (2026-09-12)

* Dependencies: the upper bound `cryptography<47` is removed. It existed only so that the
  `[attest]` extra could co-install with nv-attestation-sdk (which pins `cryptography==43.0.1`),
  but it also stopped verifier machines from getting current cryptography releases and their
  security fixes. The lower bound is unchanged; the test suite passes on 43.0.1 and 50.0.1.
  No code change.

## 0.1.0 (2026-09-12)

First release.

* `manifest`: image digest resolution through the OCI registry API (no pull), artifact
  hashing, free-form extras, verifier-side random challenge.
* `attest`: TDX quote through configfs TSM with `report_data = SHA-512(manifest)`, NVIDIA
  NRAS attestation with `nonce = SHA-256(manifest)`, single-GPU and multi-GPU Protected PCIe
  modes, Intel and NVIDIA collateral embedded for offline verification.
* `verify`: quote structure, attestation key signature, Quoting Enclave binding and signature,
  PCK chain to the pinned Intel SGX Root CA, TCB level and TDX module identity against Intel's
  signed TCB info, Quoting Enclave identity, CRLs, NRAS ES384 signatures, nonce, claims policy,
  token freshness, challenge and image expectations.
* `selftest`: six negative tests (image digest, artifact, manifest field, challenge replay,
  quote tampering, GPU claim tampering).
* Tests against real evidence captured on VoltageGPU Confidential VMs.
