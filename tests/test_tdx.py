# SPDX-License-Identifier: MIT
"""Offline checks against a real TDX quote captured on a VoltageGPU H200 VM on 4 September 2026."""

from datetime import datetime, timezone

import pytest

from voltage_verify import tdx

AT = datetime(2026, 9, 12, tzinfo=timezone.utc)


def test_parse_real_quote(quote_bytes, report_data):
    q = tdx.parse_quote(quote_bytes)
    assert q.version == 4 and q.tee_type == 0x81 and q.att_key_type == 2
    assert q.qe_vendor_id == tdx.INTEL_QE_VENDOR_ID
    assert q.report.report_data == report_data
    assert quote_bytes[tdx.REPORT_DATA_OFFSET : tdx.REPORT_DATA_OFFSET + 64] == report_data
    assert len(q.pck_chain) == 3
    assert q.tdx_module_version == 1
    # trailing zero padding from the TSM outblob is dropped
    assert len(q.raw) < len(quote_bytes)


def test_signatures_and_chain_verify_to_pinned_intel_root(quote_bytes):
    q = tdx.parse_quote(quote_bytes)
    tdx.verify_signatures(q, at=AT)


def test_pinned_root_matches_intel_publication():
    root = tdx.intel_root_ca()
    assert "Intel SGX Root CA" in root.subject.rfc4514_string()


def test_pck_extension_fields(quote_bytes):
    q = tdx.parse_quote(quote_bytes)
    info = tdx.pck_info(q.pck_leaf)
    assert info.fmspc.hex() == "90c06f000000"
    assert len(info.tcb_components) == 16 and len(info.cpu_svn) == 16
    assert info.pce_svn > 0


def test_tampered_body_fails_signature(quote_bytes):
    raw = bytearray(quote_bytes)
    raw[48 + 136] ^= 1  # MRTD
    q = tdx.parse_quote(bytes(raw))
    with pytest.raises(tdx.QuoteError, match="quote signature"):
        tdx.verify_signatures(q, at=AT)


def test_tampered_attestation_key_fails_binding(quote_bytes):
    raw = bytearray(quote_bytes)
    raw[636 + 64] ^= 1  # first byte of the attestation public key
    q = tdx.parse_quote(bytes(raw))
    with pytest.raises(tdx.QuoteError):
        tdx.verify_signatures(q, at=AT)


def test_wrong_version_rejected(quote_bytes):
    raw = bytearray(quote_bytes)
    raw[0] = 5
    with pytest.raises(tdx.QuoteError, match="version"):
        tdx.parse_quote(bytes(raw))


def test_garbage_after_signature_rejected(quote_bytes):
    with pytest.raises(tdx.QuoteError, match="non-zero"):
        tdx.parse_quote(quote_bytes + b"\x01")
