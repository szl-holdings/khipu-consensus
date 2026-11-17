# SPDX-License-Identifier: Apache-2.0
# © 2026 Lutar, Stephen P. — SZL Holdings · ORCID 0009-0001-0110-4173
"""Covenant v0.4 step 5 spec-conformance tests: read-only adjudication endpoint.

No fabricated constants: every expected digest is recomputed in-test (the
double-entry agreement philosophy applied locally). READ-ONLY is TESTED, not
asserted: input bundles are deep-compared before and after adjudication, and
the response receipt digest is independently recomputed.
"""
from __future__ import annotations

import copy
import hashlib
import json
import threading
import urllib.error
import urllib.request

import pytest

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from khipu_consensus import canonical_json
from khipu_consensus.adjudicate import (
    ADJUDICATION_BUNDLE_SCHEMA,
    ADJUDICATION_NOTE,
    ADJUDICATION_TAMPERED,
    ADJUDICATION_UNKNOWN,
    ADJUDICATION_VERIFIED,
    adjudicate,
    handle_adjudicate,
    make_adjudication_server,
)
from khipu_consensus.receipt_tree import ReceiptTree, seal_receipt_tree
from khipu_consensus.witness import Witness, WitnessRegistry

TS = "2026-11-15T00:00:00+00:00"


def _digest(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _new_keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    pem_priv = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pem_pub = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return pem_priv, pem_pub


def _registry(keepers=("sentra", "amaru", "a11oy")):
    """4-organ registry; only keepers hold keys (others abstain honestly)."""
    ws = []
    for organ in ("sentra", "amaru", "a11oy", "killinchu"):
        pem_priv, pem_pub = _new_keypair()
        ws.append(Witness(
            organ=organ, public_key_pem=pem_pub, region="test", org="test",
            private_key_pem=pem_priv if organ in keepers else None,
        ))
    return WitnessRegistry(ws, threshold=3)


def _honest_bundle(session_id="sess-adjudicate-1", seeds=("op-a", "op-b", "op-c")):
    registry = _registry()
    leaves = [_digest(s) for s in seeds]
    tree = ReceiptTree.build(session_id, leaves)
    receipt = seal_receipt_tree(tree, registry)
    bundle = {
        "schema": ADJUDICATION_BUNDLE_SCHEMA,
        "session_id": session_id,
        "leaves": leaves,
        "sth": receipt.to_dict(),
    }
    return bundle, registry.pubkeys()


def test_verified_round_trip():
    bundle, pubkeys = _honest_bundle()
    decision = adjudicate(bundle, pubkeys, ts=TS)
    assert decision.verdict == ADJUDICATION_VERIFIED
    assert decision.verified is True
    assert decision.sth_status == ADJUDICATION_VERIFIED
    assert decision.consensus_count == 3
    assert decision.threshold == 3
    assert decision.n == 4
    assert decision.tree_size == 3
    assert decision.session_id == "sess-adjudicate-1"
    tree = ReceiptTree.build(bundle["session_id"], bundle["leaves"])
    assert decision.sha256_root_hash == tree.sha256_root_hash
    assert decision.reasons == ["3-of-4 distinct witnesses countersigned"]
    assert decision.note == ADJUDICATION_NOTE


def test_response_is_a_receipt_with_own_digest():
    bundle, pubkeys = _honest_bundle()
    decision = adjudicate(bundle, pubkeys, ts=TS)
    receipt = decision.receipt
    body = {k: v for k, v in receipt.items() if k != "digest"}
    recomputed = hashlib.sha256(canonical_json(body)).hexdigest()
    assert receipt["digest"] == recomputed
    assert receipt["schema"] == "szl.khipu.adjudication/v1"
    assert receipt["verdict"] == ADJUDICATION_VERIFIED
    # standalone: no chain linkage field of any kind (a write path would need one)
    assert "prev" not in receipt and "prev_digest" not in receipt


def test_deterministic_with_fixed_ts():
    bundle, pubkeys = _honest_bundle()
    d1 = adjudicate(bundle, pubkeys, ts=TS)
    d2 = adjudicate(copy.deepcopy(bundle), pubkeys, ts=TS)
    assert d1.receipt == d2.receipt
    assert d1.bundle_digest == d2.bundle_digest


def test_bundle_digest_is_over_canonical_bundle():
    bundle, pubkeys = _honest_bundle()
    decision = adjudicate(bundle, pubkeys, ts=TS)
    assert decision.bundle_digest == hashlib.sha256(canonical_json(bundle)).hexdigest()


def test_read_only_inputs_unchanged():
    bundle, pubkeys = _honest_bundle()
    snapshot = copy.deepcopy((bundle, pubkeys))
    decision = adjudicate(bundle, pubkeys, ts=TS)
    assert decision.verdict == ADJUDICATION_VERIFIED
    assert copy.deepcopy((bundle, pubkeys)) == snapshot


def test_leaf_tamper_located_is_tampered():
    bundle, pubkeys = _honest_bundle()
    bundle["leaves"][1] = _digest("op-b-tampered")
    decision = adjudicate(bundle, pubkeys, ts=TS)
    assert decision.verdict == ADJUDICATION_TAMPERED
    assert decision.sth_status == ADJUDICATION_TAMPERED
    assert any("located" in r for r in decision.reasons)
    assert decision.verified is False


def test_session_swap_located_is_tampered():
    bundle, pubkeys = _honest_bundle()
    bundle["session_id"] = "sess-other"
    decision = adjudicate(bundle, pubkeys, ts=TS)
    assert decision.verdict == ADJUDICATION_TAMPERED
    assert any("located" in r for r in decision.reasons)


def test_witness_signature_flip_is_tampered():
    bundle, pubkeys = _honest_bundle()
    sigs = bundle["sth"]["signatures"]
    flipped = dict(sigs[0])
    first = "A" if flipped["signature"][0] != "A" else "B"
    flipped["signature"] = first + flipped["signature"][1:]
    bundle["sth"]["signatures"] = [flipped] + sigs[1:]
    decision = adjudicate(bundle, pubkeys, ts=TS)
    assert decision.verdict == ADJUDICATION_TAMPERED
    assert decision.sth_status == ADJUDICATION_TAMPERED
    assert any("invalid signature" in r for r in decision.reasons)


def test_quorum_strip_is_unknown_never_pass():
    bundle, pubkeys = _honest_bundle()
    sigs = bundle["sth"]["signatures"]
    bundle["sth"]["signatures"] = [sigs[0], sigs[1], None, None]
    # the receipt CLAIMS countersign_count 3; the claim is never trusted
    assert bundle["sth"]["countersign_count"] == 3
    decision = adjudicate(bundle, pubkeys, ts=TS)
    assert decision.verdict == ADJUDICATION_UNKNOWN
    assert decision.sth_status == ADJUDICATION_UNKNOWN
    assert decision.consensus_count == 2
    assert any("insufficient quorum" in r for r in decision.reasons)
    assert decision.verified is False


def test_no_trusted_keys_is_unknown():
    bundle, _pubkeys = _honest_bundle()
    decision = adjudicate(bundle, {}, ts=TS)
    assert decision.verdict == ADJUDICATION_UNKNOWN
    assert decision.n == 0


def test_wrong_trusted_keys_is_tampered():
    bundle, _pubkeys = _honest_bundle()
    wrong = {organ: _new_keypair()[1] for organ in ("sentra", "amaru", "a11oy", "killinchu")}
    decision = adjudicate(bundle, wrong, ts=TS)
    assert decision.verdict == ADJUDICATION_TAMPERED
    assert decision.sth_status == ADJUDICATION_TAMPERED


def test_missing_sth_is_unknown():
    bundle, pubkeys = _honest_bundle()
    bundle["sth"] = None
    decision = adjudicate(bundle, pubkeys, ts=TS)
    assert decision.verdict == ADJUDICATION_UNKNOWN
    assert any("missing STH receipt" in r for r in decision.reasons)


def test_empty_tree_with_countersigned_sth_is_verified():
    # a zero-operation session is a fact like any other: the empty root
    # (SHA-256 of empty input) with a valid countersigned STH adjudicates
    # VERIFIED; it proves nothing beyond chain integrity of zero ops.
    registry = _registry()
    tree = ReceiptTree.build("sess-empty", [])
    receipt = seal_receipt_tree(tree, registry)
    bundle = {
        "schema": ADJUDICATION_BUNDLE_SCHEMA,
        "session_id": "sess-empty",
        "leaves": [],
        "sth": receipt.to_dict(),
    }
    decision = adjudicate(bundle, registry.pubkeys(), ts=TS)
    assert decision.verdict == ADJUDICATION_VERIFIED
    assert decision.tree_size == 0
    assert decision.sha256_root_hash == hashlib.sha256(b"").hexdigest()


@pytest.mark.parametrize("mutate,expect_reason", [
    (None, "bundle is not an object"),
    (lambda b: b.update({"schema": "wrong/schema"}), "bundle schema mismatch"),
    (lambda b: b.update({"session_id": ""}), "missing or malformed session id"),
    (lambda b: b.update({"session_id": 7}), "missing or malformed session id"),
    (lambda b: b.update({"leaves": "nope"}), "missing leaves"),
    (lambda b: b.update({"leaves": ["zz", _digest("x")]}), "malformed leaf digest"),
    (lambda b: b.update({"leaves": [_digest("x"), "0" * 63]}), "malformed leaf digest"),
    (lambda b: b.update({"sth": None}), "missing STH receipt"),
    (lambda b: b.update({"sth": "receipt-as-string"}), "missing STH receipt"),
])
def test_malformed_bundles_are_unknown_never_pass(mutate, expect_reason):
    bundle, pubkeys = _honest_bundle()
    if mutate is None:
        decision = adjudicate("not-a-dict", pubkeys, ts=TS)
    else:
        mutate(bundle)
        decision = adjudicate(bundle, pubkeys, ts=TS)
    assert decision.verdict == ADJUDICATION_UNKNOWN
    assert decision.verified is False
    assert any(expect_reason in r for r in decision.reasons)


def test_adjudicate_never_raises_to_caller():
    bundle, pubkeys = _honest_bundle()
    # non-object inputs
    for bad in (None, 42, [], "bundle"):
        decision = adjudicate(bad, pubkeys, ts=TS)
        assert isinstance(decision.verdict, str)
        assert decision.verdict == ADJUDICATION_UNKNOWN
    # Uncanonicalizable evidence has no bound identity and must stay UNKNOWN.
    weird = copy.deepcopy(bundle)
    weird["extra"] = {"unserializable-set"}
    decision = adjudicate(weird, pubkeys, ts=TS)
    assert decision.bundle_digest == ""
    assert decision.verdict == ADJUDICATION_UNKNOWN
    # NaN never hashes: canonical_json refuses, digest stays empty
    nan_bundle = copy.deepcopy(bundle)
    nan_bundle["extra"] = float("nan")
    decision = adjudicate(nan_bundle, pubkeys, ts=TS)
    assert decision.bundle_digest == ""
    assert decision.verdict == ADJUDICATION_UNKNOWN


def test_handle_adjudicate_fail_closed_body():
    good, pubkeys = _honest_bundle()
    decision = handle_adjudicate(json.dumps(good).encode(), pubkeys, ts=TS)
    assert decision.verdict == ADJUDICATION_VERIFIED
    for bad_body in (b"", b"not json", b"[1,2,3]", b"null"):
        decision = handle_adjudicate(bad_body, pubkeys, ts=TS)
        assert decision.verdict == ADJUDICATION_UNKNOWN
        assert any("not a JSON object" in r for r in decision.reasons)


def test_http_endpoint_round_trip_loopback():
    bundle, pubkeys = _honest_bundle()
    srv = make_adjudication_server(pubkeys, host="127.0.0.1", port=0)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{port}"
        # 1. honest bundle over POST /adjudicate -> 200 VERIFIED receipt
        req = urllib.request.Request(
            f"{base}/adjudicate", data=json.dumps(bundle).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            payload = json.loads(resp.read().decode())
        assert payload["verdict"] == ADJUDICATION_VERIFIED
        assert payload["receipt"]["verdict"] == ADJUDICATION_VERIFIED
        assert payload["note"] == ADJUDICATION_NOTE
        # 2. tampered leaf -> 200 TAMPERED (located)
        tampered = copy.deepcopy(bundle)
        tampered["leaves"][2] = _digest("op-c-tampered")
        req = urllib.request.Request(
            f"{base}/adjudicate", data=json.dumps(tampered).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            assert json.loads(resp.read().decode())["verdict"] == ADJUDICATION_TAMPERED
        # 3. garbage body -> 200 UNKNOWN (fail-closed; never PASS)
        req = urllib.request.Request(
            f"{base}/adjudicate", data=b"{{not-json", method="POST")
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            assert json.loads(resp.read().decode())["verdict"] == ADJUDICATION_UNKNOWN
        # 4. wrong path -> 404
        with pytest.raises(urllib.error.HTTPError) as e404:
            urllib.request.urlopen(urllib.request.Request(
                f"{base}/other", data=b"{}", method="POST"))
        assert e404.value.code == 404
        # 5. read-only: GET is refused with 405
        with pytest.raises(urllib.error.HTTPError) as e405:
            urllib.request.urlopen(f"{base}/adjudicate")
        assert e405.value.code == 405
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)
