# SPDX-License-Identifier: Apache-2.0
# © 2026 Lutar, Stephen P. — SZL Holdings · ORCID 0009-0001-0110-4173
"""Covenant v0.4 step 1 spec-conformance tests: STH format + witness countersign.

No fabricated constants: every expected digest is recomputed in-test with an
INDEPENDENT implementation (double-entry agreement, the szl-crosscheck
philosophy applied locally) or derived directly from hashlib primitives.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json

import pytest

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from khipu_consensus import sign_verdict
from khipu_consensus.sth import (
    STH_RECEIPT_SCHEMA,
    STH_STATUS_TAMPERED,
    STH_STATUS_UNKNOWN,
    STH_STATUS_VERIFIED,
    STHReceipt,
    SignedTreeHead,
    build_sth,
    countersign_sth,
    merkle_root,
    node_hash,
    release_allowed,
    sth_binding,
    verify_sth_receipt,
)
from khipu_consensus.witness import Witness, WitnessRegistry

HEX = "0123456789abcdef"


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
    """4-organ registry; only `keepers` hold keys (others abstain honestly)."""
    ws = []
    privs = {}
    for organ in ("sentra", "amaru", "a11oy", "killinchu"):
        pem_priv, pem_pub = _new_keypair()
        privs[organ] = pem_priv
        ws.append(Witness(
            organ=organ, public_key_pem=pem_pub, region="test", org="test",
            private_key_pem=pem_priv if organ in keepers else None,
        ))
    return WitnessRegistry(ws, threshold=3), privs


def _trusted(registry):
    return registry.pubkeys()


def _ref_merkle_root(leaves):
    """Independent reference over INDICES (module recursion slices lists)."""
    if not leaves:
        return hashlib.sha256(b"").hexdigest()
    def sub(lo, hi):
        if hi - lo == 1:
            return hashlib.sha256(b"\x00" + bytes.fromhex(leaves[lo])).hexdigest()
        k = 1
        while (k * 2) < (hi - lo):
            k *= 2
        left = sub(lo, lo + k)
        right = sub(lo + k, hi)
        return hashlib.sha256(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()
    return sub(0, len(leaves))

class TestRFC6962Merkle:
    def test_empty_tree_root_is_sha256_of_empty(self):
        assert merkle_root([]) == hashlib.sha256(b"").hexdigest()

    def test_single_leaf_is_leaf_hash(self):
        d0 = _digest("op-0")
        assert merkle_root([d0]) == hashlib.sha256(b"\x00" + bytes.fromhex(d0)).hexdigest()

    def test_two_leaves_direct(self):
        d0, d1 = _digest("a"), _digest("b")
        l0 = hashlib.sha256(b"\x00" + bytes.fromhex(d0)).hexdigest()
        l1 = hashlib.sha256(b"\x00" + bytes.fromhex(d1)).hexdigest()
        assert merkle_root([d0, d1]) == hashlib.sha256(b"\x01" + bytes.fromhex(l0) + bytes.fromhex(l1)).hexdigest()

    @pytest.mark.parametrize("n", list(range(1, 18)))
    def test_agrees_with_independent_reference(self, n):
        leaves = [_digest(f"leaf-{i}") for i in range(n)]
        assert merkle_root(leaves) == _ref_merkle_root(leaves)

    @pytest.mark.parametrize("n", list(range(1, 18)))
    def test_power_of_two_shape(self, n):
        leaves = [_digest(f"p-{i}") for i in range(n)]
        # RFC 6962 split: k = largest power of two strictly below n.
        if n > 1:
            k = 1
            while (k * 2) < n:
                k *= 2
            assert merkle_root(leaves) == node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))

    def test_order_sensitive(self):
        a = [_digest("x"), _digest("y")]
        b = [_digest("y"), _digest("x")]
        assert merkle_root(a) != merkle_root(b)

    def test_invalid_leaf_rejects_before_hashing(self):
        with pytest.raises(ValueError):
            merkle_root(["not-hex"])
        with pytest.raises(ValueError):
            merkle_root([_digest("ok"), "deadbeef"])


class TestSTHFormat:
    def test_build_sth_carries_root_and_size(self):
        leaves = [_digest(f"op-{i}") for i in range(7)]
        sth = build_sth("session-alpha", leaves, timestamp="2026-11-15T00:00:00Z")
        assert sth.sha256_root_hash == merkle_root(leaves)
        assert sth.tree_size == 7
        assert sth.session_id == "session-alpha"
        assert sth.version == 2
        d = sth.to_dict()
        assert SignedTreeHead.from_dict(d).to_dict() == d

    def test_binding_deterministic(self):
        assert sth_binding("s", 5) == "v0.4-sth session=s tree_size=5"
        assert sth_binding("s", 5) == sth_binding("s", 5)


class TestCountersign:
    def test_three_of_four_verified(self):
        reg, _ = _registry()
        leaves = [_digest(f"op-{i}") for i in range(3)]
        sth = build_sth("sess-1", leaves, timestamp="t")
        receipt = countersign_sth(sth, reg)
        assert receipt.schema == STH_RECEIPT_SCHEMA
        assert receipt.countersign_count == 3
        assert receipt.decision == "canonical"
        v = verify_sth_receipt(receipt.to_dict(), _trusted(reg))
        assert v.status == STH_STATUS_VERIFIED
        assert v.consensus_count == 3
        assert release_allowed(v) is False  # status alone is not evidence at action time

    def test_two_of_four_fails_closed_unknown(self):
        reg, _ = _registry(keepers=("sentra", "amaru"))
        sth = build_sth("sess-2", [_digest("a")], timestamp="t")
        receipt = countersign_sth(sth, reg)
        v = verify_sth_receipt(receipt.to_dict(), _trusted(reg))
        assert v.status == STH_STATUS_UNKNOWN
        assert v.reason.startswith("insufficient quorum")
        assert release_allowed(v) is False

    def test_roundtrip_serialization(self):
        reg, _ = _registry()
        sth = build_sth("sess-3", [_digest("a"), _digest("b")], timestamp="t")
        receipt = countersign_sth(sth, reg)
        parsed = STHReceipt.from_dict(json.loads(receipt.to_json()))
        v = verify_sth_receipt(parsed.to_dict(), _trusted(reg))
        assert v.status == STH_STATUS_VERIFIED

    def test_abstention_recorded_honestly(self):
        reg, _ = _registry(keepers=("sentra", "amaru", "a11oy"))
        sth = build_sth("sess-abs", [_digest("a")], timestamp="t")
        receipt = countersign_sth(sth, reg)
        # killinchu holds no key: its slot must be an honest None, never a fake sig
        assert receipt.signatures[3] is None
        v = verify_sth_receipt(receipt.to_dict(), _trusted(reg))
        assert v.status == STH_STATUS_VERIFIED
        abstains = [c for c in v.checks if c.get("reason") == "abstain/timeout"]
        assert len(abstains) == 1


class TestFailClosed:
    def _good(self):
        reg, _ = _registry()
        sth = build_sth("sess-fc", [_digest("x"), _digest("y")], timestamp="t")
        return reg, sth, countersign_sth(sth, reg)

    def test_missing_receipt_unknown(self):
        reg, _, _ = self._good()
        for bad in (None, {}, {"schema": "other"}, [], "nope"):
            v = verify_sth_receipt(bad, _trusted(reg))
            assert v.status == STH_STATUS_UNKNOWN
            assert release_allowed(v) is False

    def test_empty_signatures_unknown(self):
        reg, sth, receipt = self._good()
        d = receipt.to_dict()
        d["signatures"] = []
        v = verify_sth_receipt(d, _trusted(reg))
        assert v.status == STH_STATUS_UNKNOWN

    def test_tampered_signature_is_tampered(self):
        reg, sth, receipt = self._good()
        d = receipt.to_dict()
        sig = copy.deepcopy(d["signatures"][0])
        raw = bytearray(base64.b64decode(sig["signature"]))
        raw[0] ^= 0xFF
        sig["signature"] = base64.b64encode(bytes(raw)).decode()
        d["signatures"][0] = sig
        v = verify_sth_receipt(d, _trusted(reg))
        assert v.status == STH_STATUS_TAMPERED
        assert "invalid signature" in v.reason
        assert release_allowed(v) is False

    def test_root_mismatch_against_expected_root_tampered(self):
        reg, sth, receipt = self._good()
        leaves2 = [_digest("x"), _digest("z")]
        other_root = merkle_root(leaves2)
        assert other_root != sth.sha256_root_hash
        v = verify_sth_receipt(receipt.to_dict(), _trusted(reg), expected_root=other_root)
        assert v.status == STH_STATUS_TAMPERED
        assert "root mismatch" in v.reason

    def test_binding_mismatch_tampered(self):
        # A receipt whose claimed session differs from the signed binding.
        reg, sth, receipt = self._good()
        d = receipt.to_dict()
        d["session_id"] = "sess-OTHER"
        v = verify_sth_receipt(d, _trusted(reg))
        assert v.status == STH_STATUS_TAMPERED
        assert "binding-mismatch" in v.reason

    def test_witness_disagreement_tampered(self):
        # One witness signs a different root: located tamper evidence.
        reg, privs = self._registry_with_privs()
        sth = build_sth("sess-wd", [_digest("p")], timestamp="t")
        receipt = countersign_sth(sth, reg)
        d = receipt.to_dict()
        wrong = sign_verdict("a11oy", merkle_root([_digest("q")]), "allow",
                             privs["a11oy"], reason=sth.binding())
        d["signatures"][2] = wrong
        v = verify_sth_receipt(d, _trusted(reg))
        assert v.status == STH_STATUS_TAMPERED
        assert "different statement" in v.reason

    def test_duplicate_witness_cannot_inflate(self):
        reg, sth, receipt = self._good()
        d = receipt.to_dict()
        # Duplicate one valid signature in the abstain slot.
        d["signatures"][3] = copy.deepcopy(d["signatures"][0])
        v = verify_sth_receipt(d, _trusted(reg))
        assert v.status == STH_STATUS_VERIFIED
        assert v.consensus_count == 3  # not 4: distinct witnesses only
        dup = [c for c in v.checks if "duplicate" in (c.get("reason") or "")]
        assert len(dup) == 1

    def test_unknown_key_never_counts(self):
        reg, sth, receipt = self._good()
        d = receipt.to_dict()
        v = verify_sth_receipt(d, {"stranger": list(_trusted(reg).values())[0]})
        assert v.status == STH_STATUS_UNKNOWN
        assert v.consensus_count == 0

    @staticmethod
    def _registry_with_privs():
        ws = []
        privs = {}
        for organ in ("sentra", "amaru", "a11oy", "killinchu"):
            pem_priv, pem_pub = _new_keypair()
            privs[organ] = pem_priv
            ws.append(Witness(organ=organ, public_key_pem=pem_pub,
                              private_key_pem=pem_priv))
        return WitnessRegistry(ws, threshold=3), privs
