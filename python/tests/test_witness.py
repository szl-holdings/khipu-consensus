# SPDX-License-Identifier: Apache-2.0
"""End-to-end witness-coordinator tests with REAL throwaway P-256 keys.

Keys are generated in-memory per test and never written to disk (doctrine: never commit
a private key). Each test produces REAL ECDSA-P256-SHA256 signatures and re-verifies them
through the BFT tally — no mocks, no fakes.
"""
import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from khipu_consensus import canonical_json
from khipu_consensus.witness import Witness, WitnessRegistry, attest, verify_receipt
from khipu_consensus.sdk import KhipuWitnessClient

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


def test_4_of_4_canonical_and_reverifies():
    reg = _signing_registry()
    receipt = attest(ACTION_HASH, reg)
    assert receipt.decision == "canonical"
    assert receipt.consensus_count == 4
    assert receipt.khipu_consensus == "4-of-4"
    # Independent re-verification uses the operator registry, never embedded trust claims.
    receipt_dict = receipt.to_dict()
    rv = verify_receipt(receipt_dict, registry=reg)
    assert rv["decision"] == "canonical"
    assert rv["trust_policy_matches"] is True
    assert rv["matches_claimed_decision"] is True
    assert rv["receipt_identity"]["sha256"] == hashlib.sha256(
        canonical_json(receipt_dict)
    ).hexdigest()


def test_3_of_4_one_block_still_canonical():
    reg = _signing_registry()
    receipt = attest(ACTION_HASH, reg, verdicts={"killinchu": "block"})
    assert receipt.decision == "canonical"
    assert receipt.consensus_count == 3


def test_2_of_4_two_block_rejected():
    reg = _signing_registry()
    receipt = attest(ACTION_HASH, reg, verdicts={"killinchu": "block", "a11oy": "block"})
    assert receipt.decision == "rejected"
    assert receipt.consensus_count == 2


def test_unsigned_honest_fallback_when_no_keys():
    # registry with public keys only ⇒ every witness abstains, nothing faked
    ws = [Witness(organ=o, public_key_pem=_keypair()[1]) for o in ORGANS]
    reg = WitnessRegistry(ws, threshold=3)
    receipt = attest(ACTION_HASH, reg)
    assert receipt.decision == "rejected"
    assert receipt.consensus_count == 0
    assert all(s is None for s in receipt.signatures)  # UNSIGNED-honest abstentions


def test_tamper_forged_sig_excluded():
    reg = _signing_registry()
    receipt = attest(ACTION_HASH, reg)
    d = receipt.to_dict()
    # forge sentra's signature → must drop below threshold-by-one for that witness
    for s in d["signatures"]:
        if s and s["organ"] == "sentra":
            s["signature"] = "AAAA" + s["signature"][4:]
    rv = verify_receipt(d, registry=reg)
    sentra = next(c for c in rv["checks"] if c["organ"] == "sentra")
    assert sentra["counts"] is False
    assert rv["consensus_count"] == 3  # the other 3 still verify


def test_verify_requires_external_trust_policy():
    reg = _signing_registry()
    receipt = attest(ACTION_HASH, reg).to_dict()
    with pytest.raises(ValueError, match="trusted witness registry"):
        verify_receipt(receipt)


def test_embedded_key_substitution_cannot_define_trust_roots():
    trusted_registry = _signing_registry()
    attacker_registry = _signing_registry()
    attacker_receipt = attest(ACTION_HASH, attacker_registry).to_dict()

    assert attacker_receipt["decision"] == "canonical"
    rv = verify_receipt(attacker_receipt, registry=trusted_registry)

    assert rv["decision"] == "rejected"
    assert rv["consensus_count"] == 0
    assert rv["trust_policy_matches"] is False
    assert rv["matches_claimed_decision"] is False


def test_embedded_threshold_weakening_cannot_define_quorum():
    reg = _signing_registry(threshold=3)
    receipt = attest(
        ACTION_HASH, reg,
        verdicts={"killinchu": "block", "a11oy": "block"},
    ).to_dict()
    assert receipt["consensus_count"] == 2
    assert receipt["decision"] == "rejected"

    receipt["threshold"] = 1
    receipt["decision"] = "canonical"
    rv = verify_receipt(receipt, registry=reg)

    assert rv["threshold"] == 3
    assert rv["consensus_count"] == 2
    assert rv["decision"] == "rejected"
    assert rv["trust_policy_matches"] is False
    assert rv["matches_claimed_decision"] is False


def test_sdk_in_process_roundtrip():
    reg = _signing_registry()
    client = KhipuWitnessClient(registry=reg)
    receipt = client.attest(ACTION_HASH)
    assert receipt["decision"] == "canonical"
    rv = client.verify(receipt)
    assert rv["decision"] == "canonical"
    assert len(client.witnesses()) == 4
