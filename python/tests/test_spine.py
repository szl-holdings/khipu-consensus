# SPDX-License-Identifier: Apache-2.0
"""Focused tests for the PCGI spine fold (khipu consensus -> canonical szl-receipt).

Uses REAL throwaway P-256 keys (never written to disk) to produce a real
MultiWitnessReceipt, folds it onto the canonical szl-receipt spine, and asserts
the honest binding: subject/round id, quorum input digest, agreed-value output
digest, governing policy id, energy=UNAVAILABLE, real signature verifies, tamper
is rejected, and the receipt asserts integrity/reproducibility (NOT correctness).

``szl_receipt`` is an optional dependency; if it is not importable these tests are
skipped rather than failing (the core BFT primitives never depend on it).
"""
import base64
import json

import pytest

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from khipu_consensus.witness import Witness, WitnessRegistry, attest

szl_receipt = pytest.importorskip("szl_receipt")

from khipu_consensus.spine import (  # noqa: E402
    ENERGY_UNAVAILABLE,
    PCGI_RECEIPT_SCHEMA,
    DEFAULT_POLICY_ID,
    build_consensus_receipt_body,
    consensus_input_digest,
    consensus_output_digest,
    consensus_receipt_body_digest,
    emit_consensus_receipt,
    verify_consensus_receipt,
)

ACTION_HASH = "c67945277763d12641ba4649349e42f221d4bd637268623ebe8a500edac02312"
ORGANS = ["sentra", "amaru", "a11oy", "killinchu"]


def _keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv_pem, pub_pem


def _signing_registry(threshold=3):
    ws = []
    for o in ORGANS:
        priv, pub = _keypair()
        ws.append(Witness(organ=o, public_key_pem=pub, private_key_pem=priv,
                          region="test", org="test"))
    return WitnessRegistry(ws, threshold=threshold)


def _canonical_receipt():
    return attest(ACTION_HASH, _signing_registry())


def test_body_binds_the_pcgi_tuple_with_energy_unavailable():
    receipt = _canonical_receipt()
    body = build_consensus_receipt_body(receipt)

    assert body["schema"] == PCGI_RECEIPT_SCHEMA
    assert body["subject"]["action_hash"] == ACTION_HASH
    assert body["policy_id"] == DEFAULT_POLICY_ID
    assert body["input_digest"] == consensus_input_digest(receipt)
    assert body["output_digest"] == consensus_output_digest(receipt)

    # Energy is the honest sentinel — never a fabricated joule.
    assert body["energy"]["status"] == ENERGY_UNAVAILABLE
    assert body["energy"]["joules"] is None

    # The four counting witnesses are bound as BFT co-signers.
    organs = {w["organ"] for w in body["witnesses"]}
    assert organs == set(ORGANS)

    assert body["quorum"]["decision"] == "canonical"
    assert body["quorum"]["consensus_count"] == 4
    # Receipt = evidence trail, never a correctness proof.
    assert body["honesty"]["asserts"].endswith("NOT correctness")


def test_body_is_deterministic_for_a_fixed_receipt():
    receipt = _canonical_receipt()
    d1 = consensus_receipt_body_digest(receipt)
    d2 = consensus_receipt_body_digest(receipt.to_dict())
    assert d1 == d2


def test_signed_receipt_verifies_and_rebinds():
    receipt = _canonical_receipt()
    priv, pub = szl_receipt.generate_keypair()
    env = emit_consensus_receipt(receipt, private_key_pem=priv, organ="khipu")
    assert env["signed"] is True

    ok, detail = verify_consensus_receipt(env, public_key_pem=pub)
    assert ok, detail

    ok2, detail2 = verify_consensus_receipt(env, public_key_pem=pub, receipt=receipt)
    assert ok2, detail2


def test_keyless_is_unsigned_honest_never_faked():
    receipt = _canonical_receipt()
    env = emit_consensus_receipt(receipt)
    assert env["signed"] is False
    ok, detail = verify_consensus_receipt(env)
    assert ok is False
    assert detail == "unsigned-honest"


def test_tamper_is_rejected():
    receipt = _canonical_receipt()
    priv, pub = szl_receipt.generate_keypair()
    env = emit_consensus_receipt(receipt, private_key_pem=priv)

    payload = json.loads(base64.b64decode(env["payload"]).decode("utf-8"))
    payload["policy_id"] = "attacker-swapped-policy"
    env["payload"] = base64.b64encode(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).decode()

    ok, _ = verify_consensus_receipt(env, public_key_pem=pub)
    assert ok is False


def test_rejected_decision_still_emits_honest_receipt():
    reg = _signing_registry()
    receipt = attest(ACTION_HASH, reg,
                     verdicts={"killinchu": "block", "a11oy": "block"})
    assert receipt.decision == "rejected"

    priv, pub = szl_receipt.generate_keypair()
    env = emit_consensus_receipt(receipt, private_key_pem=priv)
    ok, detail = verify_consensus_receipt(env, public_key_pem=pub, receipt=receipt)
    assert ok, detail

    body = json.loads(base64.b64decode(env["payload"]).decode("utf-8"))
    assert body["quorum"]["decision"] == "rejected"
    assert body["energy"]["status"] == ENERGY_UNAVAILABLE
    # Only the two witnesses that counted are bound as co-signers.
    assert len(body["witnesses"]) == 2


def test_rebind_fails_after_output_edit():
    receipt = _canonical_receipt()
    priv, pub = szl_receipt.generate_keypair()
    env = emit_consensus_receipt(receipt, private_key_pem=priv)

    tampered = receipt.to_dict()
    tampered["decision"] = "canonical-but-lied"
    ok, detail = verify_consensus_receipt(env, public_key_pem=pub, receipt=tampered)
    assert ok is False
    assert detail == "output-digest-rebind-mismatch"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
