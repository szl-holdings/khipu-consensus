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


def verify_receipt(receipt: dict, pubkeys: Optional[dict] = None) -> dict:
    """Independently re-verify a MultiWitnessReceipt.

    Recomputes the BFT tally from the receipt's own signatures against the supplied
    public keys (or the public keys embedded in the receipt's witness metadata). Returns
    a fresh verification verdict — does NOT trust the receipt's own `decision` field.
    """
    action_hash = receipt.get("action_hash")
    sigs = receipt.get("signatures") or []
    threshold = int(receipt.get("threshold", 3))
    n = int(receipt.get("n", len(sigs)))

    if pubkeys is None:
        pubkeys = {}
        for w in receipt.get("witnesses", []):
            if w.get("public_key_pem"):
                pubkeys[w["organ"]] = w["public_key_pem"]

    result = tally(action_hash, sigs, pubkeys, threshold=threshold, n=n)
    return {
        "action_hash": action_hash,
        "decision": result.decision,
        "consensus_count": result.consensus_count,
        "khipu_consensus": result.khipu_consensus,
        "threshold": result.threshold,
        "n": result.n,
        "checks": _checks_to_public(result),
        "matches_claimed_decision": result.decision == receipt.get("decision"),
    }
