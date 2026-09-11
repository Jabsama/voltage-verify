# SPDX-License-Identifier: MIT
"""Offline checks of Intel collateral handling, using a snapshot fetched on 12 September 2026."""

from datetime import datetime, timezone

import pytest

from voltage_verify import pcs, tdx

AT = datetime(2026, 9, 12, tzinfo=timezone.utc)


def test_collateral_documents_verify(collateral_json):
    col = pcs.Collateral.from_json(collateral_json)
    pcs.verify_document(col.tcb_info, at=AT)
    pcs.verify_document(col.qe_identity, at=AT)
    assert col.tcb_info.inner["fmspc"].lower() == "90c06f000000"
    assert col.qe_identity.inner["id"] == "TD_QE"


def test_tampered_collateral_fails(collateral_json):
    col = pcs.Collateral.from_json(collateral_json)
    col.tcb_info.body = col.tcb_info.body.replace('"tcbStatus":"UpToDate"', '"tcbStatus":"UpToDat3"', 1)
    with pytest.raises(pcs.CollateralError, match="signature"):
        pcs.verify_document(col.tcb_info, at=AT)


def test_evaluate_real_quote(quote_bytes, collateral_json):
    q = tdx.parse_quote(quote_bytes)
    pck = tdx.pck_info(q.pck_leaf)
    col = pcs.Collateral.from_json(collateral_json)
    ev = pcs.evaluate(q, pck, col, at=AT)
    assert ev.status in pcs.STATUS_ORDER
    assert ev.qe_status in pcs.STATUS_ORDER
    assert ev.tdx_module_id == "TDX_01"
    assert ev.tdx_module_status in pcs.STATUS_ORDER


def test_evaluate_rejects_wrong_fmspc(quote_bytes, collateral_json):
    q = tdx.parse_quote(quote_bytes)
    pck = tdx.pck_info(q.pck_leaf)
    col = pcs.Collateral.from_json(collateral_json)
    body = col.tcb_info.body
    assert '"fmspc":"90c06f000000"' in body
    col.tcb_info.body = body.replace('"fmspc":"90c06f000000"', '"fmspc":"00c06f000000"', 1)
    with pytest.raises(pcs.CollateralError, match="FMSPC"):
        pcs.evaluate(q, pck, col, at=AT)


def test_revocation_not_checked_without_crls(quote_bytes, collateral_json):
    q = tdx.parse_quote(quote_bytes)
    col = pcs.Collateral.from_json(collateral_json)
    notes = pcs.check_revocation(q, col, at=AT)
    assert any("NOT checked" in n for n in notes)
