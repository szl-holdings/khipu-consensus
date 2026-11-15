# SPDX-License-Identifier: Apache-2.0
# © 2026 Lutar, Stephen P. — SZL Holdings · ORCID 0009-0001-0110-4173
"""Covenant v0.4 step 1 — Signed Tree Head (STH) format + witness countersigning.

Implements the witness-countersigned receipt-chain head of the Memory Covenant
v0.4 spec (szl-frontier docs/COVENANT_V0_4_COUNTERSIGN_SPEC_2026-11-15.md, §1):

  * A per-session RECEIPT TREE whose leaves are the SHA-256 digests of the
    per-operation receipts of the existing v0.3 chain (retained unchanged),
    in chain order. The root is a Signed Tree Head (STH) in the RFC 6962
    (Certificate Transparency) construction: leaf hash = SHA-256(0x00 || leaf),
    interior node hash = SHA-256(0x01 || left || right), MTH of the empty list
    = SHA-256(), tree shape by the RFC 6962 split rule (k = largest power of
    two strictly below n).
  * WITNESS COUNTERSIGNING: the 3-of-4 BFT witness pool signs the STH root
    hash with the EXISTING, mutation-tested primitives (sign_verdict /
    verify_verdict / tally — ECDSA-P256-SHA256 over the DSSE PAE). The v0.4
    STH binding (session id + tree size) travels INSIDE the signed statement
    (the `reason` field), so the binding is covered by the witness
    signature. This module adds NO new cryptography and NO new signature
    verifier surface.
  * FAIL-CLOSED RULE (spec §1.3): an STH receipt is VERIFIED only when at
    least `threshold` (3-of-4) DISTINCT trusted witnesses' signatures
    verify over the SAME root with a matching STH binding. Missing evidence
    — no signatures, absent root, malformed receipt, unparseable binding, or
    an insufficient quorum — yields UNKNOWN; an invalid signature or a
    located mismatch yields TAMPERED. `release_allowed` is True only for
    VERIFIED: no countersigned STH, no release of recalls.

Honesty (binding, doctrine):
  * Witness nodes are estate-operated in v0.4.0 (distinct keys, distinct
    hosts). The claim is exactly "multi-party-witnessed", never "trustless"
    (spec §1.4). BFT safety/liveness remain Conjecture 2/3, proof-deferred.
  * `verify_sth_receipt` proves facts about a receipt bundle; it NEVER lifts
    denies and NEVER authorizes anything (spec §4: adjudication read-only).
  * This module does NOT implement the plane integration (spec step 2 —
    receipt-tree builder + fail-closed recall gate) nor the mutation report
    (spec step 3); those are separate owner-gated steps.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Optional, Sequence

from . import (
    OrganVerdict,
    _valid_quorum_counts,
    sign_verdict,
    tally,
    verify_verdict,
    __version__,
)
from .witness import SAFETY_STATUS, WitnessRegistry

STH_SCHEMA = "szl.khipu.sth/v1"
STH_RECEIPT_SCHEMA = "szl.khipu.sth-countersign-receipt/v1"
STH_ADJUDICATION_SCHEMA = "szl.khipu.sth-adjudication/v1"
STH_BINDING_PREFIX = "v0.4-sth"

STH_STATUS_VERIFIED = "VERIFIED"
STH_STATUS_TAMPERED = "TAMPERED"
STH_STATUS_UNKNOWN = "UNKNOWN"

STH_PROVENANCE = dict(SAFETY_STATUS)
STH_PROVENANCE["witness_scope"] = {
    "status": "v0.4.0",
    "note": ("estate-operated witnesses, distinct keys/hosts; claim is "
             "multi-party-witnessed, never trustless (spec 1.4)"),
}


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def leaf_hash(leaf_hex: str) -> str:
    """RFC 6962 leaf hash: SHA-256(0x00 || leaf)."""
    return _sha256_hex(b"\x00" + bytes.fromhex(leaf_hex))


def node_hash(left_hex: str, right_hex: str) -> str:
    """RFC 6962 interior node hash: SHA-256(0x01 || left || right)."""
    return _sha256_hex(b"\x01" + bytes.fromhex(left_hex) + bytes.fromhex(right_hex))


def merkle_root(leaf_hexes: Sequence[str]) -> str:
    """RFC 6962 section 2.1 Merkle Tree Hash over hex leaf digests.

    MTH({}) = SHA-256(); MTH of one leaf is its leaf hash; otherwise split at
    k = the largest power of two strictly smaller than n and hash the two
    subtree roots. Invalid leaf digests raise ValueError BEFORE any hashing
    (fail-closed: never hash ambiguous or truncated input).
    """
    leaves = list(leaf_hexes)
    for d in leaves:
        if not isinstance(d, str) or len(d) != 64:
            raise ValueError("leaf digests must be 64-char hex strings")
        bytes.fromhex(d)  # raises ValueError on non-hex
    if not leaves:
        return _sha256_hex(b"")
    if len(leaves) == 1:
        return leaf_hash(leaves[0])
    n = len(leaves)
    k = 1
    while (k * 2) < n:
        k *= 2
    return node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def sth_binding(session_id: str, tree_size: int) -> str:
    """The STH binding string carried inside every witness's signed statement."""
    return f"{STH_BINDING_PREFIX} session={session_id} tree_size={int(tree_size)}"


@dataclass
class SignedTreeHead:
    """The RFC 6962-style signed tree head body for one plane session."""

    schema: str
    session_id: str
    version: int
    tree_size: int
    timestamp: str
    sha256_root_hash: str

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "SignedTreeHead":
        return SignedTreeHead(
            schema=d.get("schema", ""),
            session_id=d.get("session_id", ""),
            version=d.get("version", 0),
            tree_size=d.get("tree_size", -1),
            timestamp=d.get("timestamp", ""),
            sha256_root_hash=d.get("sha256_root_hash", ""),
        )

    def binding(self) -> str:
        return sth_binding(self.session_id, self.tree_size)


def build_sth(session_id: str, leaf_hexes: Sequence[str],
              timestamp: str = "") -> SignedTreeHead:
    """Build the STH over the session's operation-receipt digests (chain order)."""
    if not isinstance(session_id, str) or not session_id:
        raise ValueError("session_id must be a non-empty string")
    root = merkle_root(leaf_hexes)
    return SignedTreeHead(
        schema=STH_SCHEMA,
        session_id=session_id,
        version=1,
        tree_size=len(list(leaf_hexes)),
        timestamp=timestamp or datetime.now(timezone.utc).isoformat(),
        sha256_root_hash=root,
    )


@dataclass
class STHReceipt:
    """Portable record of one witnessed STH countersign round (spec 1.1-1.2)."""

    schema: str
    sth: dict                     # the SignedTreeHead body under agreement
    sha256_root_hash: str
    session_id: str
    tree_size: int
    threshold: int
    n: int
    decision: str                 # "canonical" | "rejected"
    countersign_count: int
    khipu_consensus: str          # "X-of-N"
    signatures: list              # per-witness wire DSSE verdicts (None = abstain)
    checks: list                   # per-witness verification outcomes (public)
    witnesses: list               # public witness identity metadata
    provenance: dict
    version: str

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @staticmethod
    def from_dict(d: dict) -> "STHReceipt":
        return STHReceipt(
            schema=d.get("schema", ""),
            sth=d.get("sth", {}),
            sha256_root_hash=d.get("sha256_root_hash", ""),
            session_id=d.get("session_id", ""),
            tree_size=d.get("tree_size", -1),
            threshold=d.get("threshold", 0),
            n=d.get("n", 0),
            decision=d.get("decision", ""),
            countersign_count=d.get("countersign_count", 0),
            khipu_consensus=d.get("khipu_consensus", ""),
            signatures=list(d.get("signatures", [])),
            checks=list(d.get("checks", [])),
            witnesses=list(d.get("witnesses", [])),
            provenance=dict(d.get("provenance", {})),
            version=d.get("version", ""),
        )


def countersign_sth(sth: SignedTreeHead, registry: WitnessRegistry,
                    verdicts: Optional[dict] = None) -> STHReceipt:
    """Coordinate one witnessed STH countersign round.

    Fans the STH root hash out to every witness in `registry` as the action
    hash; each keyed witness signs it with the STH binding in the signed
    `reason`. Keyless witnesses abstain (UNSIGNED-honest -> None). The
    collected verdicts are re-verified by the BFT `tally` over the root.
    """
    if not isinstance(sth, SignedTreeHead):
        raise TypeError("sth must be a SignedTreeHead")
    if not _valid_quorum_counts(registry.threshold, registry.n):
        raise ValueError("quorum counts must be integers with 1 <= threshold <= n")
    binding = sth.binding()
    votes = verdicts or {}
    collected = []
    for w in registry.all():
        v = w.sign(sth.sha256_root_hash, verdict=votes.get(w.organ, "allow"),
                   reason=binding)
        collected.append(v)  # None -> abstain/UNSIGNED-honest
    result = tally(sth.sha256_root_hash, collected, registry.pubkeys(),
                   threshold=registry.threshold, n=registry.n)
    public_checks = []
    for c in result.checks:
        public_checks.append({
            "organ": c.organ, "keyid": c.keyid, "valid": c.valid,
            "verdict": c.verdict, "action_hash_match": c.action_hash_match,
            "counts": c.counts, "reason": c.reason,
        })
    return STHReceipt(
        schema=STH_RECEIPT_SCHEMA,
        sth=sth.to_dict(),
        sha256_root_hash=sth.sha256_root_hash,
        session_id=sth.session_id,
        tree_size=sth.tree_size,
        threshold=registry.threshold,
        n=registry.n,
        decision=result.decision,
        countersign_count=result.consensus_count,
        khipu_consensus=result.khipu_consensus,
        signatures=collected,
        checks=public_checks,
        witnesses=registry.public(),
        provenance=dict(STH_PROVENANCE),
        version=__version__,
    )


@dataclass
class STHVerdict:
    """Read-only adjudication outcome for one STH receipt bundle (spec 4)."""

    schema: str
    status: str                   # VERIFIED | TAMPERED | UNKNOWN
    session_id: Optional[str]
    tree_size: Optional[int]
    sha256_root_hash: Optional[str]
    consensus_count: int
    threshold: int
    n: int
    checks: list
    reason: str

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def verified(self) -> bool:
        return self.status == STH_STATUS_VERIFIED


def release_allowed(verdict: STHVerdict) -> bool:
    """Fail-closed recall gate (spec 1.3): only a VERIFIED countersigned STH
    releases recalls. Absent, insufficient, or disagreeing evidence denies."""
    return isinstance(verdict, STHVerdict) and verdict.verified


def _unknown(receipt, reason: str, threshold: int, n: int) -> STHVerdict:
    if isinstance(receipt, dict):
        sid = receipt.get("session_id")
        ts = receipt.get("tree_size")
        root = receipt.get("sha256_root_hash")
    else:
        sid = ts = root = None
    return STHVerdict(
        schema=STH_ADJUDICATION_SCHEMA, status=STH_STATUS_UNKNOWN,
        session_id=sid if isinstance(sid, str) else None,
        tree_size=ts if isinstance(ts, int) else None,
        sha256_root_hash=root if isinstance(root, str) else None,
        consensus_count=0, threshold=threshold, n=n, checks=[], reason=reason,
    )


def _is_root_hash(x) -> bool:
    return (isinstance(x, str) and len(x) == 64
            and x == x.lower() and all(c in "0123456789abcdef" for c in x))


def verify_sth_receipt(receipt, trusted_pubkeys: dict, threshold: int = 3,
                       expected_root: Optional[str] = None,
                       expected_session_id: Optional[str] = None,
                       expected_tree_size: Optional[int] = None) -> STHVerdict:
    """Adjudicate one STH receipt bundle against trusted witness public keys.

    Read-only: proves facts about the bundle; never lifts denies, never
    authorizes. Fail-closed taxonomy (spec 4):

      * VERIFIED  — at least `threshold` DISTINCT trusted witnesses signed
                    the SAME root with a matching STH binding.
      * TAMPERED  — an invalid signature, a located root/binding mismatch, or
                    a witness that signed a different statement.
      * UNKNOWN   — missing evidence (no/empty signatures, malformed receipt,
                    no trusted keys, insufficient quorum). Never PASS.

    `n` is the size of the TRUSTED pool, never a value claimed by the receipt.
    """
    n = len(trusted_pubkeys) if isinstance(trusted_pubkeys, dict) else 0
    if not _valid_quorum_counts(threshold, n):
        return _unknown(receipt, "invalid quorum counts (threshold/n)", threshold, n)
    if not isinstance(receipt, dict):
        return _unknown(receipt, "receipt is not an object", threshold, n)
    if receipt.get("schema") != STH_RECEIPT_SCHEMA:
        return _unknown(receipt, "schema mismatch", threshold, n)
    root = receipt.get("sha256_root_hash")
    session_id = receipt.get("session_id")
    tree_size = receipt.get("tree_size")
    sigs = receipt.get("signatures")
    if not _is_root_hash(root):
        return _unknown(receipt, "missing or malformed root hash", threshold, n)
    if not isinstance(session_id, str) or not session_id:
        return _unknown(receipt, "missing session id", threshold, n)
    if not isinstance(tree_size, int) or tree_size < 0:
        return _unknown(receipt, "missing or malformed tree size", threshold, n)
    if not isinstance(sigs, list):
        return _unknown(receipt, "missing signatures", threshold, n)

    # Located mismatches against caller-held expectations are TAMPERED.
    if expected_root is not None and root != expected_root:
        return STHVerdict(STH_ADJUDICATION_SCHEMA, STH_STATUS_TAMPERED,
                          session_id, tree_size, root, 0, threshold, n, [],
                          "root mismatch with expected root (located)")
    if expected_session_id is not None and session_id != expected_session_id:
        return STHVerdict(STH_ADJUDICATION_SCHEMA, STH_STATUS_TAMPERED,
                          session_id, tree_size, root, 0, threshold, n, [],
                          "session mismatch with expected session (located)")
    if expected_tree_size is not None and tree_size != expected_tree_size:
        return STHVerdict(STH_ADJUDICATION_SCHEMA, STH_STATUS_TAMPERED,
                          session_id, tree_size, root, 0, threshold, n, [],
                          "tree size mismatch with expected size (located)")

    binding = sth_binding(session_id, tree_size)
    checks = []
    counted = set()
    count = 0
    tamper = None
    for item in sigs:
        if item is None:
            checks.append({"organ": None, "keyid": None, "valid": False,
                           "verdict": None, "action_hash_match": False,
                           "counts": False, "reason": "abstain/timeout"})
            continue
        v = item if isinstance(item, OrganVerdict) else OrganVerdict.from_dict(item)
        pem = trusted_pubkeys.get(v.organ, "")
        if not pem:
            checks.append({"organ": v.organ, "keyid": v.keyid, "valid": False,
                           "verdict": None, "action_hash_match": False,
                           "counts": False, "reason": "no trusted public key"})
            continue
        chk = verify_verdict(v, pem, root)
        entry = {"organ": v.organ, "keyid": v.keyid, "valid": chk.valid,
                 "verdict": chk.verdict, "action_hash_match": chk.action_hash_match,
                 "counts": False, "reason": chk.reason}
        if chk.valid and chk.counts:
            # The signature verifies over this root; check WHAT it binds.
            try:
                stmt = json.loads(base64.b64decode(v.payload_b64))
                reason = stmt.get("reason", "")
            except Exception:
                reason = None
            if reason == binding:
                if v.organ in counted:
                    entry["reason"] = "duplicate-witness (already counted)"
                else:
                    counted.add(v.organ)
                    count += 1
                    entry["counts"] = True
            else:
                tamper = f"sth-binding-mismatch at witness {v.organ}"
                entry["reason"] = "sth-binding-mismatch"
        elif chk.valid:
            tamper = f"witness {v.organ} signed a different statement"
            entry["reason"] = chk.reason or "signed-different-statement"
        else:
            tamper = f"invalid signature at witness {v.organ}"
            entry["reason"] = chk.reason or "signature mismatch"
        checks.append(entry)

    if tamper is not None:
        return STHVerdict(STH_ADJUDICATION_SCHEMA, STH_STATUS_TAMPERED,
                          session_id, tree_size, root, count, threshold, n,
                          checks, tamper)
    if count >= threshold:
        return STHVerdict(STH_ADJUDICATION_SCHEMA, STH_STATUS_VERIFIED,
                          session_id, tree_size, root, count, threshold, n,
                          checks, f"{count}-of-{n} distinct witnesses countersigned")
    return STHVerdict(STH_ADJUDICATION_SCHEMA, STH_STATUS_UNKNOWN,
                      session_id, tree_size, root, count, threshold, n, checks,
                      f"insufficient quorum: {count}-of-{n} below threshold {threshold} (fail-closed deny)")
