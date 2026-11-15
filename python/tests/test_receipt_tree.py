# SPDX-License-Identifier: Apache-2.0
# © 2026 Lutar, Stephen P. — SZL Holdings · ORCID 0009-0001-0110-4173
"""Covenant v0.4 step 2 tests: receipt-tree builder + fail-closed recall gate.

No fabricated constants: every expected root and audit path is recomputed
in-test with an INDEPENDENT index-based implementation (double-entry
agreement, the szl-crosscheck philosophy applied locally). Every deny path
is exercised: UNKNOWN never PASS and DENY is the gate default.
"""
from __future__ import annotations

import copy
import hashlib

import pytest

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from khipu_consensus.sth import (
    STH_RECEIPT_SCHEMA,
    merkle_root,
)
from khipu_consensus.receipt_tree import (
    RECALL_DECISION_SCHEMA,
    RECALL_DENY,
    RECALL_GATE_NOTE,
    RECALL_RELEASE,
    RECEIPT_TREE_SCHEMA,
    ReceiptTree,
    RecallDecision,
    recall_gate,
    seal_receipt_tree,
    verify_inclusion,
)
from khipu_consensus.witness import Witness, WitnessRegistry


def _digest(seed):
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
    privs = {}
    for organ in ("sentra", "amaru", "a11oy", "killinchu"):
        pem_priv, pem_pub = _new_keypair()
        privs[organ] = pem_priv
        ws.append(Witness(
            organ=organ, public_key_pem=pem_pub, region="test", org="test",
            private_key_pem=pem_priv if organ in keepers else None,
        ))
    return WitnessRegistry(ws, threshold=3), privs


def _leaves(n, prefix="op"):
    return [_digest(f"{prefix}-{i}") for i in range(n)]


def _ref_root(leaves):
    """Independent index-based RFC 6962 MTH (double-entry agreement)."""
    if not leaves:
        return hashlib.sha256(b"").hexdigest()

    def sub(lo, hi):
        if hi - lo == 1:
            return hashlib.sha256(
                b"\x00" + bytes.fromhex(leaves[lo])).hexdigest()
        k = 1
        while (k * 2) < (hi - lo):
            k *= 2
        left = sub(lo, lo + k)
        right = sub(lo + k, hi)
        return hashlib.sha256(
            b"\x01" + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()

    return sub(0, len(leaves))


def _ref_path(leaves, index):
    """Independent index-based audit path: [(node_hex, is_left), ...]."""
    if len(leaves) == 1:
        return []
    k = 1
    while (k * 2) < len(leaves):
        k *= 2
    if index < k:
        return _ref_path(leaves[:k], index) + [(_ref_root(leaves[k:]), False)]
    return _ref_path(leaves[k:], index - k) + [(_ref_root(leaves[:k]), True)]


def _sealed_session(session_id="session-alpha", n=7,
                    keepers=("sentra", "amaru", "a11oy")):
    registry, _ = _registry(keepers=keepers)
    tree = ReceiptTree.build(session_id, _leaves(n))
    receipt = seal_receipt_tree(tree, registry)
    return tree, registry, receipt.to_dict()


class TestReceiptTree:
    def test_empty_session_tree(self):
        tree = ReceiptTree.build("session-empty", [])
        assert tree.sha256_root_hash == hashlib.sha256(b"").hexdigest()
        assert tree.tree_size == 0
        assert tree.schema == RECEIPT_TREE_SCHEMA

    def test_empty_tree_has_no_recalls(self):
        tree = ReceiptTree.build("session-empty", [])
        with pytest.raises(IndexError):
            tree.leaf(0)
        with pytest.raises(IndexError):
            tree.inclusion_proof(0)

    def test_root_agrees_with_step1_and_reference(self):
        leaves = _leaves(7)
        tree = ReceiptTree.build("session-alpha", leaves)
        assert tree.sha256_root_hash == merkle_root(leaves)
        assert tree.sha256_root_hash == _ref_root(leaves)
        assert tree.tree_size == 7

    def test_dict_roundtrip(self):
        tree = ReceiptTree.build("session-alpha", _leaves(5))
        d = tree.to_dict()
        assert d["schema"] == RECEIPT_TREE_SCHEMA
        assert ReceiptTree.from_dict(d).to_dict() == d

    def test_rejects_empty_session_id(self):
        with pytest.raises(ValueError):
            ReceiptTree.build("", _leaves(3))

    def test_rejects_malformed_leaves(self):
        with pytest.raises(ValueError):
            ReceiptTree.build("s", ["not-hex"])
        with pytest.raises(ValueError):
            ReceiptTree.build("s", [_digest("ok"), "deadbeef"])
        with pytest.raises(ValueError):
            ReceiptTree.build("s", [_digest("ok").upper()])

    def test_sth_head_covers_tree(self):
        tree = ReceiptTree.build("session-alpha", _leaves(4))
        head = tree.sth(timestamp="2026-11-16T00:00:00Z")
        assert head.sha256_root_hash == tree.sha256_root_hash
        assert head.tree_size == tree.tree_size
        assert head.session_id == tree.session_id


class TestInclusionProofs:
    @pytest.mark.parametrize("n", list(range(1, 18)))
    def test_path_agrees_with_reference_and_verifies(self, n):
        leaves = _leaves(n, prefix=f"inc-{n}")
        tree = ReceiptTree.build("session-proof", leaves)
        for i in range(n):
            path = tree.inclusion_proof(i)
            ref = [{"node": h, "left": left} for (h, left) in _ref_path(leaves, i)]
            assert path == ref
            assert verify_inclusion(leaves[i], i, n, path,
                                    tree.sha256_root_hash)

    def test_single_leaf_has_empty_path(self):
        leaves = _leaves(1)
        tree = ReceiptTree.build("session-one", leaves)
        assert tree.inclusion_proof(0) == []
        assert verify_inclusion(leaves[0], 0, 1, [],
                                tree.sha256_root_hash)

    def test_wrong_index_never_verifies(self):
        leaves = _leaves(5)
        tree = ReceiptTree.build("session-five", leaves)
        path = tree.inclusion_proof(2)
        assert not verify_inclusion(leaves[2], 3, 5, path,
                                    tree.sha256_root_hash)

    def test_wrong_leaf_never_verifies(self):
        leaves = _leaves(5)
        tree = ReceiptTree.build("session-five", leaves)
        path = tree.inclusion_proof(2)
        assert not verify_inclusion(_digest("not-the-leaf"), 2, 5, path,
                                    tree.sha256_root_hash)

    def test_tampered_proof_node_never_verifies(self):
        leaves = _leaves(17)
        tree = ReceiptTree.build("session-17", leaves)
        path = copy.deepcopy(tree.inclusion_proof(0))
        path[0]["node"] = _digest("attacker-node")
        assert not verify_inclusion(leaves[0], 0, 17, path,
                                    tree.sha256_root_hash)

    def test_flipped_orientation_never_verifies(self):
        leaves = _leaves(17)
        tree = ReceiptTree.build("session-17", leaves)
        path = copy.deepcopy(tree.inclusion_proof(9))
        for step in path:
            step["left"] = not step["left"]
        assert not verify_inclusion(leaves[9], 9, 17, path,
                                    tree.sha256_root_hash)

    def test_truncated_path_never_verifies(self):
        leaves = _leaves(17)
        tree = ReceiptTree.build("session-17", leaves)
        path = tree.inclusion_proof(0)[:-1]
        assert not verify_inclusion(leaves[0], 0, 17, path,
                                    tree.sha256_root_hash)

    def test_wrong_root_never_verifies(self):
        leaves = _leaves(9)
        tree = ReceiptTree.build("session-nine", leaves)
        other = ReceiptTree.build("session-other", _leaves(9, prefix="other"))
        path = tree.inclusion_proof(4)
        assert not verify_inclusion(leaves[4], 4, 9, path,
                                    other.sha256_root_hash)

    @pytest.mark.parametrize("bad_index", [True, False, 1.0, "0", None, -1, 5])
    def test_malformed_index_never_true(self, bad_index):
        leaves = _leaves(5)
        tree = ReceiptTree.build("session-mal", leaves)
        path = tree.inclusion_proof(1)
        assert not verify_inclusion(leaves[1], bad_index, 5, path,
                                    tree.sha256_root_hash)

    @pytest.mark.parametrize("bad_proof", [
        None,
        "path",
        [{"node": "zz", "left": True}],
        [{"node": _digest("x"), "left": "yes"}],
        [{"node": _digest("x").upper(), "left": True}],
        ["node"],
        [[_digest("x")]],
    ])
    def test_malformed_proof_never_true(self, bad_proof):
        leaves = _leaves(5)
        tree = ReceiptTree.build("session-mal", leaves)
        assert not verify_inclusion(leaves[1], 1, 5, bad_proof,
                                    tree.sha256_root_hash)

    def test_malformed_leaf_size_root_never_true(self):
        leaves = _leaves(5)
        tree = ReceiptTree.build("session-mal", leaves)
        path = tree.inclusion_proof(1)
        assert not verify_inclusion(_digest("x")[:63], 1, 5, path,
                                    tree.sha256_root_hash)
        assert not verify_inclusion(_digest("x").upper(), 1, 5, path,
                                    tree.sha256_root_hash)
        assert not verify_inclusion(leaves[1], 1, 5, path,
                                    tree.sha256_root_hash.upper())
        assert not verify_inclusion(leaves[1], 1, 0, path,
                                    tree.sha256_root_hash)


class TestSeal:
    def test_seal_canonical_3of4(self):
        registry, _ = _registry()
        tree = ReceiptTree.build("session-alpha", _leaves(7))
        receipt = seal_receipt_tree(tree, registry)
        assert receipt.schema == STH_RECEIPT_SCHEMA
        assert receipt.decision == "canonical"
        assert receipt.countersign_count == 3
        assert receipt.sha256_root_hash == tree.sha256_root_hash
        assert receipt.tree_size == tree.tree_size

    def test_seal_requires_tree(self):
        registry, _ = _registry()
        with pytest.raises(TypeError):
            seal_receipt_tree("not-a-tree", registry)


class TestRecallGate:
    def test_release_on_verified_quorum(self):
        tree, registry, receipt = _sealed_session()
        idx = 3
        decision = recall_gate(tree, receipt, registry.pubkeys(), idx,
                               tree.leaf(idx))
        assert decision.status == RECALL_RELEASE
        assert decision.release is True
        assert decision.sth_status == "VERIFIED"
        assert decision.schema == RECALL_DECISION_SCHEMA
        assert decision.target_index == idx
        assert decision.target_digest == tree.leaf(idx)
        assert decision.sha256_root_hash == tree.sha256_root_hash
        assert decision.note == RECALL_GATE_NOTE
        assert decision.adjudication["status"] == "VERIFIED"

    def test_release_with_sth_receipt_object(self):
        registry, _ = _registry()
        tree = ReceiptTree.build("session-alpha", _leaves(7))
        receipt = seal_receipt_tree(tree, registry)
        idx = 5
        decision = recall_gate(tree, receipt, registry.pubkeys(), idx,
                               tree.leaf(idx))
        assert decision.status == RECALL_RELEASE
        assert decision.release is True

    def test_deny_when_no_receipt(self):
        tree, registry, _ = _sealed_session()
        decision = recall_gate(tree, None, registry.pubkeys(), 0,
                               tree.leaf(0))
        assert decision.status == RECALL_DENY
        assert decision.release is False
        assert "no countersigned STH" in decision.reason

    def test_deny_on_insufficient_quorum(self):
        tree, registry, receipt = _sealed_session(
            keepers=("sentra", "amaru"))
        decision = recall_gate(tree, receipt, registry.pubkeys(), 0,
                               tree.leaf(0))
        assert decision.status == RECALL_DENY
        assert decision.release is False
        assert decision.sth_status == "UNKNOWN"

    def test_deny_on_index_out_of_range(self):
        tree, registry, receipt = _sealed_session(n=7)
        decision = recall_gate(tree, receipt, registry.pubkeys(), 7,
                               _digest("op-7"))
        assert decision.status == RECALL_DENY
        assert decision.release is False
        assert "out of range" in decision.reason

    def test_deny_on_negative_and_bool_index(self):
        tree, registry, receipt = _sealed_session(n=7)
        for bad in (-1, True, False, "0", None, 1.5):
            decision = recall_gate(tree, receipt, registry.pubkeys(), bad,
                                   tree.leaf(0))
            assert decision.status == RECALL_DENY
            assert decision.release is False

    def test_deny_on_digest_mismatch(self):
        tree, registry, receipt = _sealed_session(n=7)
        decision = recall_gate(tree, receipt, registry.pubkeys(), 3,
                               _digest("impostor"))
        assert decision.status == RECALL_DENY
        assert decision.release is False
        assert "digest mismatch" in decision.reason

    def test_deny_on_malformed_target_digest(self):
        tree, registry, receipt = _sealed_session(n=7)
        for bad in ("", "deadbeef", _digest("x").upper(), None, 5):
            decision = recall_gate(tree, receipt, registry.pubkeys(), 3, bad)
            assert decision.status == RECALL_DENY
            assert decision.release is False

    def test_deny_on_tree_root_mismatch(self):
        tree, registry, receipt = _sealed_session(n=7)
        tampered = ReceiptTree.from_dict(tree.to_dict())
        tampered.sha256_root_hash = _digest("attacker-root")
        decision = recall_gate(tampered, receipt, registry.pubkeys(), 3,
                               tampered.leaf(3))
        assert decision.status == RECALL_DENY
        assert decision.release is False
        assert "root mismatch" in decision.reason

    def test_deny_on_malformed_leaves(self):
        tree, registry, receipt = _sealed_session(n=7)
        tampered = ReceiptTree.from_dict(tree.to_dict())
        tampered.leaves = ["zz"] * 7
        decision = recall_gate(tampered, receipt, registry.pubkeys(), 3,
                               _digest("op-3"))
        assert decision.status == RECALL_DENY
        assert decision.release is False
        assert "malformed tree" in decision.reason

    def test_deny_on_receipt_root_tamper(self):
        tree, registry, receipt = _sealed_session(n=7)
        forged = copy.deepcopy(receipt)
        forged["sha256_root_hash"] = _digest("forged-root")
        decision = recall_gate(tree, forged, registry.pubkeys(), 3,
                               tree.leaf(3))
        assert decision.status == RECALL_DENY
        assert decision.release is False
        assert decision.sth_status == "TAMPERED"

    def test_deny_on_session_mismatch(self):
        tree_a, registry, _ = _sealed_session("session-alpha")
        tree_b, _, receipt_b = _sealed_session("session-beta")
        decision = recall_gate(tree_a, receipt_b, registry.pubkeys(), 3,
                               tree_a.leaf(3))
        assert decision.status == RECALL_DENY
        assert decision.release is False
        assert decision.sth_status == "TAMPERED"

    def test_deny_on_empty_tree(self):
        registry, _ = _registry()
        tree = ReceiptTree.build("session-empty", [])
        receipt = seal_receipt_tree(tree, registry)
        decision = recall_gate(tree, receipt.to_dict(), registry.pubkeys(),
                               0, _digest("op-0"))
        assert decision.status == RECALL_DENY
        assert decision.release is False
        assert "out of range" in decision.reason

    def test_deny_on_missing_tree(self):
        registry, _ = _registry()
        decision = recall_gate(None, {"schema": STH_RECEIPT_SCHEMA},
                               registry.pubkeys(), 0, _digest("op-0"))
        assert decision.status == RECALL_DENY
        assert decision.release is False
        assert "missing receipt tree" in decision.reason

    def test_deny_on_schema_mismatch_tree(self):
        tree, registry, receipt = _sealed_session(n=7)
        bad = ReceiptTree.from_dict(tree.to_dict())
        bad.schema = "szl.khipu.evil-tree/v9"
        decision = recall_gate(bad, receipt, registry.pubkeys(), 3,
                               bad.leaf(3))
        assert decision.status == RECALL_DENY
        assert decision.release is False
        assert "schema mismatch" in decision.reason

    def test_deny_on_untrusted_keys(self):
        tree, _, receipt = _sealed_session(n=7)
        decision = recall_gate(tree, receipt, {}, 3, tree.leaf(3))
        assert decision.status == RECALL_DENY
        assert decision.release is False
        assert decision.sth_status == "UNKNOWN"

    def test_decisions_roundtrip(self):
        tree, registry, receipt = _sealed_session(n=7)
        ok = recall_gate(tree, receipt, registry.pubkeys(), 2,
                         tree.leaf(2))
        assert RecallDecision.from_dict(ok.to_dict()).to_dict() == ok.to_dict()
        denied = recall_gate(tree, None, registry.pubkeys(), 2,
                             tree.leaf(2))
        assert RecallDecision.from_dict(denied.to_dict()).to_dict() == denied.to_dict()
        assert denied.release is False
        assert denied.note == RECALL_GATE_NOTE

    def test_release_note_is_read_only_honesty(self):
        tree, registry, receipt = _sealed_session(n=7)
        decision = recall_gate(tree, receipt, registry.pubkeys(), 1,
                               tree.leaf(1))
        assert decision.note == RECALL_GATE_NOTE
        assert "never lifts a hard deny" in decision.note
