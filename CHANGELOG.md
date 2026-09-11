# Changelog

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
