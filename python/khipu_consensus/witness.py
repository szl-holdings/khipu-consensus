# SPDX-License-Identifier: Apache-2.0
# © 2026 Lutar, Stephen P. — SZL Holdings · ORCID 0009-0001-0110-4173
"""Multi-party-witnessed AI — the productization layer over the khipu BFT core.

This module turns the raw `sign_verdict` / `verify_verdict` / `tally` primitives in
`khipu_consensus/__init__.py` into a *coordinator*: submit one action hash, fan it out
to a registry of geographically / organizationally distributed witnesses, collect each
witness's own DSSE-signed verdict, and assemble a single verifiable **MultiWitnessReceipt**.

It reinvents NO cryptography. Every signature is still produced by `sign_verdict`
(ECDSA-P256-SHA256 over the DSSE PAE) and re-checked by `tally` against each witness's
published public key. This layer only adds *orchestration + witness identity metadata +
a portable receipt shape*.

Academic grounding (see docs/WITNESS_API.md):
  - CoSi witness cosigning (Syta et al., IEEE S&P 2016) — independent witnesses co-sign
    one statement; here each witness keeps its OWN key (stronger than a single aggregate).
  - arXiv:2504.14668 (deVadoss & Artzt, "BFT for AI Safety") — independent academic
    validation that BFT quorum among heterogeneous validators is the right safety
    primitive for AI actions.
  - Lackey, "epistemology of testimony" — no single witness's testimony is sufficient;
    the 3-of-4 quorum IS the epistemic primitive.

Honesty (binding): BFT *safety* is Conjecture 2 and *liveness* is Conjecture 3 — both
proof-deferred, NOT proven. Economic slashing ("EigenLayer for AI decisions") is ROADMAP.
A receipt with no private key available is emitted UNSIGNED-honest, never faked.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import Optional

from . import (
    OrganVerdict,
    ConsensusResult,
    sign_verdict,
    tally,
    canonical_json,
    __version__,
)

RECEIPT_SCHEMA = "szl.khipu.multi-witness-receipt/v1"

# Honest provenance taxonomy attached to every receipt — never claim proven safety.
SAFETY_STATUS = {
    "safety": {"id": "Conjecture 2", "name": "khipu_consensus_safety", "status": "proof-deferred"},
    "liveness": {"id": "Conjecture 3", "name": "khipu_consensus_liveness", "status": "proof-deferred"},
    "economic_slashing": {"status": "ROADMAP", "note": "EigenLayer-style AVS slashing not yet implemented"},
}


@dataclass
class Witness:
    """One independent witness ('organ'). Identity + published PUBLIC key only.

    Private keys never live here — a witness signs in its own trust domain and returns a
    DSSE verdict. `private_key_pem` is OPTIONAL and only set for an in-process/local
    witness used in tests or single-host demos; it must never be serialized.
    """
    organ: str
    public_key_pem: str
    region: str = "unknown"          # geographic distribution (e.g. "us-east", "eu-west")
    org: str = "unknown"             # organizational distribution (independent operator)
    endpoint: str = ""               # remote witness URL (empty ⇒ in-process)
    private_key_pem: Optional[str] = field(default=None, repr=False)

    @property
    def keyid(self) -> str:
        return f"{self.organ}-cosign"

    def public(self) -> dict:
        """Public, serializable view — deliberately omits any private key."""
        return {
            "organ": self.organ,
            "keyid": self.keyid,
            "region": self.region,
            "org": self.org,
            "endpoint": self.endpoint,
            "public_key_pem": self.public_key_pem,
        }

    def can_sign(self) -> bool:
        return bool(self.private_key_pem)

    def sign(self, action_hash: str, verdict: str = "allow", reason: str = "",
             lean_sha: str = "", ts: str = "") -> Optional[dict]:
        """Produce this witness's DSSE-signed verdict, or None if it holds no key
        (UNSIGNED-honest: the coordinator records the abstention rather than faking)."""
        if not self.can_sign():
            return None
        return sign_verdict(self.organ, action_hash, verdict, self.private_key_pem,
                            reason=reason, lean_sha=lean_sha, ts=ts)


class WitnessRegistry:
    """The set of witnesses the coordinator knows about, keyed by organ."""

    def __init__(self, witnesses: Optional[list] = None, threshold: int = 3):
        self._w: dict = {}
        for w in (witnesses or []):
            self.add(w)
        self.threshold = threshold

    def add(self, w: Witness) -> None:
        self._w[w.organ] = w

    def get(self, organ: str) -> Optional[Witness]:
        return self._w.get(organ)

    def all(self) -> list:
        return list(self._w.values())

    @property
    def n(self) -> int:
        return len(self._w)

    def pubkeys(self) -> dict:
        return {w.organ: w.public_key_pem for w in self._w.values()}

    def public(self) -> list:
        return [w.public() for w in self._w.values()]

    @staticmethod
    def from_dict(d: dict) -> "WitnessRegistry":
        """Load a registry from a JSON dict {threshold?, witnesses:[{organ,public_key_pem,...}]}."""
        ws = [Witness(
            organ=x["organ"],
            public_key_pem=x.get("public_key_pem", ""),
            region=x.get("region", "unknown"),
            org=x.get("org", "unknown"),
            endpoint=x.get("endpoint", ""),
            # Optional: only present for a single-host/local signing registry loaded from
            # a runtime file. The committed example registry has NONE (UNSIGNED-honest).
            private_key_pem=x.get("private_key_pem"),
        ) for x in d.get("witnesses", [])]
        return WitnessRegistry(ws, threshold=int(d.get("threshold", 3)))


@dataclass
class MultiWitnessReceipt:
    """A portable, independently-verifiable record of one witnessed decision.

    Carries every per-witness DSSE verdict (each re-checkable with
    `cosign verify-blob --key <organ>.pub`), the BFT decision, and the honest
    safety/liveness/slashing provenance. Serialize with `.to_dict()` / `.to_json()`.
    """
    schema: str
    action_hash: str
    threshold: int
    n: int
    decision: str                    # "canonical" | "rejected"
    consensus_count: int
    khipu_consensus: str             # "X-of-N"
    signatures: list                 # wire-shape DSSE verdicts (or None for abstain)
    checks: list                     # per-witness verification outcome
    witnesses: list                  # public witness identity metadata
    provenance: dict
    version: str

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @property
    def canonical(self) -> bool:
        return self.decision == "canonical"


def _checks_to_public(result: ConsensusResult) -> list:
    out = []
    for c in result.checks:
        out.append({
            "organ": c.organ,
            "keyid": c.keyid,
            "valid": c.valid,
            "verdict": c.verdict,
            "action_hash_match": c.action_hash_match,
            "counts": c.counts,
            "reason": c.reason,
        })
    return out


def attest(action_hash: str, registry: WitnessRegistry,
           verdicts: Optional[dict] = None, reason: str = "",
           lean_sha: str = "") -> MultiWitnessReceipt:
    """Coordinate one witnessed attestation.

    Fans the action hash out to every witness in `registry`. Each witness that holds a
    key signs its own DSSE verdict (default "allow"; override per-organ via `verdicts`,
    e.g. {"killinchu": "block"}). Witnesses with no key abstain (UNSIGNED-honest → None).
    The collected verdicts are then re-verified by the BFT `tally` and assembled into a
    MultiWitnessReceipt.

    `verdicts`: optional {organ: "allow"|"block"} to drive a specific witness's vote
    (used for demos/tests; in production each witness decides independently).
    """
    verdicts = verdicts or {}
    collected = []
    for w in registry.all():
        v = w.sign(action_hash, verdict=verdicts.get(w.organ, "allow"),
                   reason=reason, lean_sha=lean_sha)
        collected.append(v)  # None ⇒ abstain/UNSIGNED-honest

    result = tally(action_hash, collected, registry.pubkeys(),
                   threshold=registry.threshold, n=registry.n)

    return MultiWitnessReceipt(
        schema=RECEIPT_SCHEMA,
        action_hash=action_hash,
        threshold=registry.threshold,
        n=registry.n,
        decision=result.decision,
        consensus_count=result.consensus_count,
        khipu_consensus=result.khipu_consensus,
        signatures=collected,
        checks=_checks_to_public(result),
        witnesses=registry.public(),
        provenance=dict(SAFETY_STATUS),
        version=__version__,
    )


def _canonical_sha256(value: dict) -> str:
    """SHA-256 identity for an exact canonical JSON value."""
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _resolve_trust_policy(pubkeys: Optional[dict], threshold: Optional[int],
                          registry: Optional[WitnessRegistry]) -> tuple:
    """Resolve only caller/operator-owned trust policy, never receipt claims."""
    if registry is not None:
        if pubkeys is not None or threshold is not None:
            raise ValueError("provide either registry or trusted pubkeys+threshold, not both")
        pubkeys = registry.pubkeys()
        threshold = registry.threshold

    if pubkeys is None or threshold is None:
        raise ValueError(
            "trusted witness registry or explicit trusted pubkeys+threshold is required"
        )
    if not isinstance(pubkeys, dict) or not pubkeys:
        raise ValueError("trusted pubkeys must be a non-empty organ-to-PEM mapping")
    if type(threshold) is not int:
        raise ValueError("trusted threshold must be an integer")

    trusted_pubkeys = dict(pubkeys)
    for organ, pem in trusted_pubkeys.items():
        if not isinstance(organ, str) or not organ:
            raise ValueError("trusted pubkey organ names must be non-empty strings")
        if not isinstance(pem, str) or not pem.strip():
            raise ValueError(f"trusted public key for {organ!r} must be non-empty PEM")

    trusted_n = len(trusted_pubkeys)
    if threshold < 1 or threshold > trusted_n:
        raise ValueError("trusted threshold must be between 1 and the trusted witness count")
    return trusted_pubkeys, threshold, trusted_n


def _embedded_pubkeys(receipt: dict) -> tuple:
    """Extract untrusted embedded key claims and flag malformed/duplicate entries."""
    witnesses = receipt.get("witnesses")
    if not isinstance(witnesses, list):
        return {}, False

    embedded = {}
    for witness in witnesses:
        if not isinstance(witness, dict):
            return {}, False
        organ = witness.get("organ")
        pem = witness.get("public_key_pem")
        if (not isinstance(organ, str) or not organ or organ in embedded
                or not isinstance(pem, str) or not pem.strip()):
            return {}, False
        embedded[organ] = pem
    return embedded, True


def _validate_signature_entries(signatures, trusted_pubkeys: dict,
                                trusted_n: int) -> tuple:
    """Validate untrusted receipt rows before doing any cryptographic work.

    A canonical receipt has at most one row for each trusted witness. ``None``
    remains the explicit abstain/timeout value. Rejecting the entire collection
    before ``tally`` keeps attacker-controlled row counts and malformed mapping
    keys away from public-key lookup and ECDSA verification.
    """
    if not isinstance(signatures, list):
        return False, "signatures must be a list"
    if len(signatures) > trusted_n:
        return False, "signature count exceeds the trusted witness count"

    seen = set()
    required_strings = ("organ", "keyid", "payloadType", "payload", "signature")
    optional_strings = ("verdict", "reason")
    for index, item in enumerate(signatures):
        if item is None:
            continue
        if not isinstance(item, dict):
            return False, f"signature entry {index} must be an object or null"
        for field_name in required_strings:
            value = item.get(field_name)
            if not isinstance(value, str) or not value:
                return False, (
                    f"signature entry {index} field {field_name!r} "
                    "must be a non-empty string"
                )
        for field_name in optional_strings:
            if field_name in item and not isinstance(item[field_name], str):
                return False, (
                    f"signature entry {index} field {field_name!r} must be a string"
                )

        organ = item["organ"]
        if organ not in trusted_pubkeys:
            return False, f"signature entry {index} names an untrusted witness"
        if organ in seen:
            return False, f"signature entry {index} duplicates witness {organ!r}"
        seen.add(organ)

    return True, ""


def verify_receipt(receipt: dict, pubkeys: Optional[dict] = None, *,
                   threshold: Optional[int] = None,
                   registry: Optional[WitnessRegistry] = None) -> dict:
    """Independently re-verify a MultiWitnessReceipt.

    Recomputes the BFT tally against repository/operator-owned trust roots and threshold.
    Embedded keys, threshold, and witness count are non-authoritative claims that must
    exactly match that external policy. The result binds the exact canonical receipt and
    trust policy by SHA-256 and never trusts the receipt's own decision field.
    """
    trusted_pubkeys, trusted_threshold, trusted_n = _resolve_trust_policy(
        pubkeys, threshold, registry,
    )
    action_hash = receipt.get("action_hash")
    sigs = receipt.get("signatures")
    signatures_valid, signature_error = _validate_signature_entries(
        sigs, trusted_pubkeys, trusted_n,
    )
    safe_sigs = sigs if signatures_valid else []

    embedded_pubkeys, embedded_keys_well_formed = _embedded_pubkeys(receipt)
    trust_policy_matches = (
        embedded_keys_well_formed
        and embedded_pubkeys == trusted_pubkeys
        and receipt.get("threshold") == trusted_threshold
        and receipt.get("n") == trusted_n
    )
    schema_matches = receipt.get("schema") == RECEIPT_SCHEMA

    result = tally(
        action_hash, safe_sigs, trusted_pubkeys,
        threshold=trusted_threshold, n=trusted_n,
    )
    decision = (
        result.decision
        if schema_matches and trust_policy_matches and signatures_valid
        else "rejected"
    )
    receipt_identity = {
        "schema": receipt.get("schema"),
        "action_hash": action_hash,
        "sha256": _canonical_sha256(receipt),
    }
    trust_policy_identity = {
        "threshold": trusted_threshold,
        "n": trusted_n,
        "sha256": _canonical_sha256({
            "threshold": trusted_threshold,
            "n": trusted_n,
            "pubkeys": trusted_pubkeys,
        }),
    }
    return {
        "action_hash": action_hash,
        "decision": decision,
        "consensus_count": result.consensus_count,
        "khipu_consensus": result.khipu_consensus,
        "threshold": result.threshold,
        "n": result.n,
        "checks": _checks_to_public(result),
        "schema_matches": schema_matches,
        "trust_policy_matches": trust_policy_matches,
        "signatures_valid": signatures_valid,
        "signature_error": signature_error,
        "receipt_identity": receipt_identity,
        "trust_policy_identity": trust_policy_identity,
        "matches_claimed_decision": (
            schema_matches
            and trust_policy_matches
            and signatures_valid
            and decision == receipt.get("decision")
        ),
    }
