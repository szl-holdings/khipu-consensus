# SPDX-License-Identifier: Apache-2.0
# © 2026 Lutar, Stephen P. — SZL Holdings · ORCID 0009-0001-0110-4173
"""Covenant v0.4 step 2 — receipt-tree builder + fail-closed recall gate.

Implements the plane-side software gates of the Memory Covenant v0.4 spec
(szl-frontier docs/COVENANT_V0_4_COUNTERSIGN_SPEC_2026-11-15.md, section 1.1
and section 6 step 2):

  * A RECEIPT TREE per plane session: the leaves are the SHA-256 digests of
    the per-operation receipts of the existing v0.3 chain (retained
    unchanged), in chain order. The tree is the RFC 6962 construction from
    step 1 (leaf hash = SHA-256(0x00 || leaf), interior node =
    SHA-256(0x01 || left || right), empty root = SHA-256()). This module adds
    portable INCLUSION PROOFS (RFC 6962 audit paths) so any party can prove
    one operation receipt is covered by a witnessed root without replaying
    the whole session.
  * SEALING: build the SignedTreeHead over the session leaves and run the
    3-of-4 witness countersign round (step 1 primitives, no new
    cryptography, no new signature verifier surface).
  * FAIL-CLOSED RECALL GATE (spec 1.3, the v0.4 invariant candidate): no
    countersigned STH, no release of recalls from that session. recall_gate
    releases a recall ONLY when ALL of the following hold: the tree
    recomputes to its claimed root; the target index and digest are located
    and covered by an inclusion proof; and the STH receipt adjudicates
    VERIFIED (at least threshold DISTINCT trusted witnesses over the SAME
    root and binding). Missing evidence (no receipt, out-of-range index,
    malformed digests, empty tree, untrusted keys) yields DENY; a located
    mismatch (wrong root, wrong digest at index, signed different
    statement) yields DENY with the located reason. DENY is the default
    state and is never overridden by a claim inside the receipt.

Honesty (binding, doctrine):
  * RELEASE proves COVERAGE, never authorization: the gate NEVER lifts a
    hard deny (recon / foreign-write / weaponize). DenyMonotonic — that no
    sequence of approvals lifts a hard deny — is spec step 4 (lutar-lean)
    and is NOT proved here. The software gates remain the enforcement; the
    theorem will verify the gate semantics.
  * Adjudication is read-only (spec 4): this module proves facts about a
    tree and receipt bundle; it never lifts denies and never authorizes.
  * Witness nodes are estate-operated in v0.4.0; the claim is exactly
    "multi-party-witnessed", never "trustless" (spec 1.4).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, asdict
from typing import Optional, Sequence

from . import __version__
from .sth import (
    STHReceipt,
    SignedTreeHead,
    build_sth,
    countersign_sth,
    leaf_hash,
    merkle_root,
    node_hash,
    verify_sth_receipt,
)
from .witness import WitnessRegistry

RECEIPT_TREE_SCHEMA = "szl.khipu.receipt-tree/v1"
RECALL_DECISION_SCHEMA = "szl.khipu.recall-decision/v1"

RECALL_RELEASE = "RELEASE"
RECALL_DENY = "DENY"

RECALL_GATE_NOTE = (
    "release proves coverage only; it never lifts a hard deny "
    "(recon/foreign-write/weaponize) and never authorizes; "
    "adjudication is read-only (spec 4)"
)


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _is_digest(x) -> bool:
    return (isinstance(x, str) and len(x) == 64
            and x == x.lower() and all(c in "0123456789abcdef" for c in x))


def _subtree_root(leaves: Sequence[str], lo: int, hi: int) -> str:
    """RFC 6962 MTH over leaves[lo:hi] (same split rule as sth.merkle_root)."""
    if hi - lo == 1:
        return leaf_hash(leaves[lo])
    k = 1
    while (k * 2) < (hi - lo):
        k *= 2
    return node_hash(_subtree_root(leaves, lo, lo + k),
                     _subtree_root(leaves, lo + k, hi))


@dataclass
class ReceiptTree:
    """Per-plane-session receipt tree (spec 1.1): ordered operation-receipt
    digests as leaves, RFC 6962 root, portable inclusion proofs."""

    schema: str
    session_id: str
    leaves: list
    sha256_root_hash: str
    tree_size: int
    version: str

    @staticmethod
    def build(session_id: str, leaf_hexes: Sequence[str]) -> "ReceiptTree":
        """Build the tree for one plane session, validating every leaf digest
        BEFORE any hashing (fail-closed: never hash ambiguous input)."""
        if not isinstance(session_id, str) or not session_id:
            raise ValueError("session_id must be a non-empty string")
        leaves = list(leaf_hexes)
        for d in leaves:
            if not _is_digest(d):
                raise ValueError("leaves must be 64-char lowercase hex digests")
        return ReceiptTree(
            schema=RECEIPT_TREE_SCHEMA,
            session_id=session_id,
            leaves=leaves,
            sha256_root_hash=merkle_root(leaves),
            tree_size=len(leaves),
            version=__version__,
        )

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "ReceiptTree":
        return ReceiptTree(
            schema=d.get("schema", ""),
            session_id=d.get("session_id", ""),
            leaves=list(d.get("leaves", [])),
            sha256_root_hash=d.get("sha256_root_hash", ""),
            tree_size=d.get("tree_size", -1),
            version=d.get("version", ""),
        )

    def leaf(self, index: int) -> str:
        """The operation-receipt digest at index (chain order)."""
        if type(index) is not int or index < 0 or index >= len(self.leaves):
            raise IndexError("index out of range")
        return self.leaves[index]

    def inclusion_proof(self, index: int) -> list:
        """RFC 6962 audit path for leaf index: a bottom-up list of
        {"node": <hex>, "left": bool} sibling-subtree roots."""
        if type(index) is not int or index < 0 or index >= len(self.leaves):
            raise IndexError("index out of range")
        path = []
        lo, hi = 0, len(self.leaves)
        while hi - lo > 1:
            k = 1
            while (k * 2) < (hi - lo):
                k *= 2
            if index - lo < k:
                path.append({"node": _subtree_root(self.leaves, lo + k, hi),
                             "left": False})
                hi = lo + k
            else:
                path.append({"node": _subtree_root(self.leaves, lo, lo + k),
                             "left": True})
                lo = lo + k
        return path

    def sth(self, timestamp: str = "") -> SignedTreeHead:
        """The SignedTreeHead over this tree (step 1 format)."""
        return build_sth(self.session_id, self.leaves, timestamp=timestamp)


def verify_inclusion(leaf_hex: str, index: int, tree_size: int,
                     proof: list, root_hex: str) -> bool:
    """Verify a portable RFC 6962 inclusion proof bottom-up.

    Fail-closed: any malformed input (bad digest, bool posing as int,
    out-of-range index, non-list proof, malformed node) yields False — the
    proof NEVER verifies on missing or ambiguous evidence.
    """
    if not _is_digest(leaf_hex) or not _is_digest(root_hex):
        return False
    if type(index) is not int or type(tree_size) is not int:
        return False
    if index < 0 or tree_size < 1 or index >= tree_size:
        return False
    if not isinstance(proof, list):
        return False
    h = leaf_hash(leaf_hex)
    for step in proof:
        if not isinstance(step, dict):
            return False
        node = step.get("node")
        left = step.get("left")
        if not _is_digest(node) or type(left) is not bool:
            return False
        h = node_hash(node, h) if left else node_hash(h, node)
    return h == root_hex


def seal_receipt_tree(tree: ReceiptTree, registry: WitnessRegistry,
                      verdicts: Optional[dict] = None) -> STHReceipt:
    """Seal the session: build the STH over the tree and run the 3-of-4
    witness countersign round (step 1 primitives, no new cryptography)."""
    if not isinstance(tree, ReceiptTree):
        raise TypeError("tree must be a ReceiptTree")
    return countersign_sth(tree.sth(), registry, verdicts=verdicts)


@dataclass
class RecallDecision:
    """Fail-closed recall gate outcome for one recall target (spec 1.3)."""

    schema: str
    session_id: str
    status: str                    # RELEASE | DENY
    release: bool
    reason: str
    target_index: Optional[int]
    target_digest: Optional[str]
    sha256_root_hash: Optional[str]
    tree_size: Optional[int]
    sth_status: Optional[str]     # VERIFIED | TAMPERED | UNKNOWN | None
    threshold: int
    n: int
    note: str
    adjudication: dict
    version: str

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "RecallDecision":
        return RecallDecision(
            schema=d.get("schema", ""),
            session_id=d.get("session_id", ""),
            status=d.get("status", RECALL_DENY),
            release=bool(d.get("release", False)),
            reason=d.get("reason", ""),
            target_index=d.get("target_index"),
            target_digest=d.get("target_digest"),
            sha256_root_hash=d.get("sha256_root_hash"),
            tree_size=d.get("tree_size"),
            sth_status=d.get("sth_status"),
            threshold=d.get("threshold", 0),
            n=d.get("n", 0),
            note=d.get("note", ""),
            adjudication=dict(d.get("adjudication", {})),
            version=d.get("version", ""),
        )


def _deny(tree, target_index, target_digest, threshold, n,
          reason, sth_status=None, adjudication=None) -> RecallDecision:
    is_tree = isinstance(tree, ReceiptTree)
    return RecallDecision(
        schema=RECALL_DECISION_SCHEMA,
        session_id=tree.session_id if is_tree else "",
        status=RECALL_DENY,
        release=False,
        reason=reason,
        target_index=target_index if type(target_index) is int else None,
        target_digest=target_digest if _is_digest(target_digest) else None,
        sha256_root_hash=tree.sha256_root_hash if is_tree else None,
        tree_size=tree.tree_size if is_tree else None,
        sth_status=sth_status,
        threshold=threshold,
        n=n,
        note=RECALL_GATE_NOTE,
        adjudication=dict(adjudication or {}),
        version=__version__,
    )


def recall_gate(tree, sth_receipt, trusted_pubkeys: dict, target_index,
                target_digest: str, threshold: int = 3) -> RecallDecision:
    """Fail-closed recall gate (spec 1.3): a recall from a plane session is
    RELEASEd only when the tree is intact, the target is located and covered
    by an inclusion proof, and the STH receipt adjudicates VERIFIED against
    the caller's TRUSTED witness keys (at least threshold DISTINCT trusted
    witnesses over the SAME root and binding). Every other state denies.

    Read-only: proves coverage facts; NEVER lifts a hard deny, NEVER
    authorizes (spec 4).
    """
    n = len(trusted_pubkeys) if isinstance(trusted_pubkeys, dict) else 0
    # 1. tree present, correct schema
    if not isinstance(tree, ReceiptTree):
        return _deny(tree, target_index, target_digest, threshold, n,
                     "missing receipt tree (fail-closed deny)")
    if tree.schema != RECEIPT_TREE_SCHEMA:
        return _deny(tree, target_index, target_digest, threshold, n,
                     "schema mismatch (fail-closed deny)")
    # 2. tree root recomputes from its leaves (structure intact)
    try:
        recomputed = merkle_root(tree.leaves)
    except Exception:
        return _deny(tree, target_index, target_digest, threshold, n,
                     "malformed tree: leaves fail validation")
    if recomputed != tree.sha256_root_hash:
        return _deny(tree, target_index, target_digest, threshold, n,
                     "located: tree root mismatch with recomputed root")
    # 3. target located and covered by an inclusion proof
    if type(target_index) is not int:
        return _deny(tree, target_index, target_digest, threshold, n,
                     "missing or malformed target index")
    if target_index < 0 or target_index >= tree.tree_size:
        return _deny(tree, target_index, target_digest, threshold, n,
                     "target index out of range (no evidence)")
    if not _is_digest(target_digest):
        return _deny(tree, target_index, target_digest, threshold, n,
                     "missing or malformed target digest")
    if tree.leaf(target_index) != target_digest:
        return _deny(tree, target_index, target_digest, threshold, n,
                     "located: target digest mismatch at index")
    proof = tree.inclusion_proof(target_index)
    if not verify_inclusion(target_digest, target_index, tree.tree_size,
                            proof, tree.sha256_root_hash):
        return _deny(tree, target_index, target_digest, threshold, n,
                     "located: inclusion proof disagreement")
    # 4. countersigned STH present and VERIFIED (the spec 1.3 hard rule)
    if sth_receipt is None:
        return _deny(tree, target_index, target_digest, threshold, n,
                     "no countersigned STH (fail-closed deny)")
    if isinstance(sth_receipt, STHReceipt):
        receipt_dict = sth_receipt.to_dict()
    elif isinstance(sth_receipt, dict):
        receipt_dict = sth_receipt
    else:
        receipt_dict = sth_receipt  # let the adjudicator classify it UNKNOWN
    verdict = verify_sth_receipt(
        receipt_dict, trusted_pubkeys, threshold=threshold,
        expected_root=tree.sha256_root_hash,
        expected_session_id=tree.session_id,
        expected_tree_size=tree.tree_size,
    )
    if not verdict.verified:
        return _deny(tree, target_index, target_digest, threshold, n,
                     verdict.reason,
                     sth_status=verdict.status,
                     adjudication=verdict.to_dict())
    # 5. all evidence present and located: release the recall
    return RecallDecision(
        schema=RECALL_DECISION_SCHEMA,
        session_id=tree.session_id,
        status=RECALL_RELEASE,
        release=True,
        reason=(f"recall covered by {verdict.consensus_count}-of-{n} "
                f"witness-countersigned tree head"),
        target_index=target_index,
        target_digest=target_digest,
        sha256_root_hash=tree.sha256_root_hash,
        tree_size=tree.tree_size,
        sth_status=verdict.status,
        threshold=threshold,
        n=n,
        note=RECALL_GATE_NOTE,
        adjudication=verdict.to_dict(),
        version=__version__,
    )
