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
    v2 STH binding (every header field, including timestamp) travels INSIDE the signed statement
    (the `reason` field), so the full-header binding is covered by the witness
    signature. This module adds NO new cryptography and NO new signature
    verifier surface.
  * FAIL-CLOSED RULE (spec §1.3): an STH receipt is VERIFIED only when at
    least `threshold` (3-of-4) DISTINCT trusted witnesses' signatures
    verify over the SAME root with a matching STH binding. Missing evidence
    — no signatures, absent root, malformed receipt, unparseable binding, or
    an insufficient quorum — yields UNKNOWN; an invalid signature or a
    located mismatch yields TAMPERED. Status objects never grant release;
    original evidence, caller-held context and freshness are checked at use.

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
    canonical_json,
    ORGAN_VERDICT_PAYLOAD_TYPE,
    tally,
    verify_verdict,
    __version__,
)
from .witness import SAFETY_STATUS, WitnessRegistry

STH_SCHEMA = "szl.khipu.sth/v2"
STH_RECEIPT_SCHEMA = "szl.khipu.sth-countersign-receipt/v2"
STH_ADJUDICATION_SCHEMA = "szl.khipu.sth-adjudication/v2"
STH_BINDING_PREFIX = "v0.4-sth"

STH_STATUS_VERIFIED = "VERIFIED"
STH_STATUS_TAMPERED = "TAMPERED"
STH_STATUS_UNKNOWN = "UNKNOWN"

STH_PROVENANCE = dict(SAFETY_STATUS)
STH_PROVENANCE["witness_scope"] = {
    "status": "DECLARED_NOT_ATTESTED",
    "note": ("caller-supplied witness configuration; signature verification does not "
             "establish distinct hosts, operators or independent failure domains"),
}
STH_PROVENANCE["host_independence_verified"] = False
STH_PROVENANCE["production_qualified"] = False


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
    if type(leaf_hexes) not in (list, tuple) or len(leaf_hexes) > 4096:
        raise ValueError("bounded list or tuple of at most 4096 leaf digests required")
    leaves = list(leaf_hexes)
    for d in leaves:
        if not _is_root_hash(d):
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


def _unique_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _full_head_binding(head: dict) -> str:
    """v2 signs all six header fields; v1 bytes are never reinterpreted."""
    fields = {"schema", "session_id", "version", "tree_size", "timestamp", "sha256_root_hash"}
    if (type(head) is not dict or set(head) != fields
            or head["schema"] != STH_SCHEMA or type(head["version"]) is not int
            or head["version"] != 2 or type(head["session_id"]) is not str
            or not 0 < len(head["session_id"]) <= 128
            or type(head["tree_size"]) is not int or not 0 <= head["tree_size"] <= 4096
            or type(head["timestamp"]) is not str or not 0 < len(head["timestamp"]) <= 80
            or not _is_root_hash(head["sha256_root_hash"])):
        raise ValueError("invalid v2 STH header")
    digest = hashlib.sha256(b"SZL-STH-HEADER-V2\x00" + canonical_json(head)).hexdigest()
    return "v0.4-sth-full/v2 sha256=" + digest


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
        return _full_head_binding(self.to_dict())


def build_sth(session_id: str, leaf_hexes: Sequence[str],
              timestamp: str = "") -> SignedTreeHead:
    """Build the STH over the session's operation-receipt digests (chain order)."""
    if not isinstance(session_id, str) or not session_id:
        raise ValueError("session_id must be a non-empty string")
    root = merkle_root(leaf_hexes)
    return SignedTreeHead(
        schema=STH_SCHEMA,
        session_id=session_id,
        version=2,
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
    receipt = STHReceipt(
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
    # Producer claims use the same scoped admission result as consumption.
    # Distinct organ labels alone must not make a rejected key pool canonical.
    verified = verify_sth_receipt(receipt.to_dict(), registry.pubkeys(),
                                  threshold=registry.threshold)
    receipt.decision = "canonical" if verified.verified else "rejected"
    receipt.countersign_count = verified.consensus_count
    receipt.khipu_consensus = f"{verified.consensus_count}-of-{registry.n}"
    receipt.checks = verified.checks
    return receipt


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
    """Legacy status-only helper: no submitted verdict can authorize a recall.

    Use receipt_release_eligible with original evidence and trusted action context.
    """
    # A submitted verdict is an assertion, not verification material. Existing
    # one-argument callers now deny; use the explicit evidence predicate below.
    return receipt_release_eligible(verdict)


def receipt_release_eligible(receipt, *, trusted_pubkeys=None,
                             expected_root=None, expected_session_id=None,
                             expected_tree_size=None, now=None,
                             max_age_seconds=None, hard_deny=True) -> bool:
    """Necessary coverage/freshness condition, never an execution capability.

    All keyword context comes from the trusted caller, not receipt fields.
    Reverify signatures at use time. This does not implement action-once effects,
    tenant authorization, independent hosts or append-only continuity.
    """
    if hard_deny is not False or type(receipt) is not dict:
        return False
    if (type(trusted_pubkeys) is not dict or not _is_root_hash(expected_root)
            or type(expected_session_id) is not str or not expected_session_id
            or type(expected_tree_size) is not int or not 0 < expected_tree_size <= 4096
            or type(max_age_seconds) is not int or not 0 < max_age_seconds <= 3600
            or not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None):
        return False
    verdict = verify_sth_receipt(receipt, trusted_pubkeys, expected_root=expected_root,
                                 expected_session_id=expected_session_id,
                                 expected_tree_size=expected_tree_size)
    if not verdict.verified:
        return False
    try:
        timestamp = datetime.fromisoformat(receipt["sth"]["timestamp"].replace("Z", "+00:00"))
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            return False
        age = (now - timestamp).total_seconds()
    except (ValueError, TypeError, KeyError, OverflowError):
        return False
    return 0 <= age < max_age_seconds


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
    if not _valid_quorum_counts(threshold, n) or threshold != 3 or n != 4:
        return _unknown(receipt, "v2 requires exactly three of four trusted witnesses", threshold, n)
    # Organ labels are not independent keys. Reject aliasing or malformed public
    # configuration before verifying attacker-supplied rows. No private key read.
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat, load_pem_public_key,
    )
    fingerprints = set()
    for organ, pem in trusted_pubkeys.items():
        if (type(organ) is not str or not organ or type(pem) is not str
                or not 0 < len(pem) <= 4096):
            return _unknown(receipt, "malformed trusted witness configuration", threshold, n)
        try:
            key = load_pem_public_key(pem.encode("ascii"))
        except (ValueError, TypeError, UnicodeError):
            return _unknown(receipt, "malformed trusted public key", threshold, n)
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            return _unknown(receipt, "trusted key must be ECDSA P-256", threshold, n)
        fingerprint = hashlib.sha256(key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).digest()
        if fingerprint in fingerprints:
            return _unknown(receipt, "duplicate trusted public key", threshold, n)
        fingerprints.add(fingerprint)
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
    if type(tree_size) is not int or not 0 <= tree_size <= 4096:
        return _unknown(receipt, "missing or malformed tree size", threshold, n)
    if type(sigs) is not list or len(sigs) > 4:
        return _unknown(receipt, "missing or excessive signatures", threshold, n)
    if type(receipt.get("threshold")) is not int or receipt.get("threshold") != threshold:
        return _unknown(receipt, "receipt threshold differs from trusted policy", threshold, n)
    if type(receipt.get("n")) is not int or receipt.get("n") != n:
        return _unknown(receipt, "receipt witness count differs from trusted policy", threshold, n)

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

    try:
        binding = _full_head_binding(receipt.get("sth"))
    except (ValueError, TypeError, UnicodeError):
        return _unknown(receipt, "missing or malformed full STH header", threshold, n)
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
        if not isinstance(item, (dict, OrganVerdict)):
            return _unknown(receipt, "malformed signature entry", threshold, n)
        if isinstance(item, dict):
            fields = ("organ", "keyid", "payloadType", "payload", "signature")
            if any(type(item.get(field)) is not str for field in fields):
                return _unknown(receipt, "malformed signature fields", threshold, n)
        v = item if isinstance(item, OrganVerdict) else OrganVerdict.from_dict(item)
        if any(type(value) is not str for value in (
                v.organ, v.keyid, v.payload_type, v.payload_b64, v.signature_b64)):
            return _unknown(receipt, "malformed signature fields", threshold, n)
        pem = trusted_pubkeys.get(v.organ, "")
        if not pem:
            checks.append({"organ": v.organ, "keyid": v.keyid, "valid": False,
                           "verdict": None, "action_hash_match": False,
                           "counts": False, "reason": "no trusted public key"})
            continue
        if (v.payload_type != ORGAN_VERDICT_PAYLOAD_TYPE
                or len(v.payload_b64) > 16384 or len(v.signature_b64) > 1024):
            return _unknown(receipt, "signature domain or size invalid", threshold, n)
        try:
            body = base64.b64decode(v.payload_b64, validate=True)
            statement = json.loads(body, object_pairs_hook=_unique_members)
            required = {"schema", "organ", "keyid", "action_hash", "verdict", "reason", "lean_sha", "ts"}
            if (type(statement) is not dict or set(statement) != required
                    or any(type(value) is not str for value in statement.values())
                    or body != canonical_json(statement)):
                return _unknown(receipt, "noncanonical witness statement", threshold, n)
        except (ValueError, TypeError, UnicodeError, RecursionError):
            return _unknown(receipt, "malformed witness statement", threshold, n)
        chk = verify_verdict(v, pem, root)
        entry = {"organ": v.organ, "keyid": v.keyid, "valid": chk.valid,
                 "verdict": chk.verdict, "action_hash_match": chk.action_hash_match,
                 "counts": False, "reason": chk.reason}
        if chk.valid and chk.counts:
            # The signature verifies over this root; check WHAT it binds.
            try:
                reason = statement.get("reason", "")
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
    head = receipt.get("sth")
    if (type(head) is not dict or head.get("schema") != STH_SCHEMA
            or type(head.get("version")) is not int or head.get("version") != 2
            or type(head.get("tree_size")) is not int
            or head.get("tree_size") != tree_size
            or head.get("session_id") != session_id
            or head.get("sha256_root_hash") != root):
        return STHVerdict(STH_ADJUDICATION_SCHEMA, STH_STATUS_TAMPERED,
                          session_id, tree_size, root, count, threshold, n,
                          checks, "located: sth-binding-mismatch between nested and outer receipt")
    if count >= threshold:
        return STHVerdict(STH_ADJUDICATION_SCHEMA, STH_STATUS_VERIFIED,
                          session_id, tree_size, root, count, threshold, n,
                          checks, f"{count}-of-{n} distinct witnesses countersigned")
    return STHVerdict(STH_ADJUDICATION_SCHEMA, STH_STATUS_UNKNOWN,
                      session_id, tree_size, root, count, threshold, n, checks,
                      f"insufficient quorum: {count}-of-{n} below threshold {threshold} (fail-closed deny)")
