"""khipu-collusion — adversarial collusion lane for the khipu 3-of-4 BFT witness model.

Simulation harness motivated by long-horizon agent collusion research. It measures
where a 3-of-4 witness quorum repels collusion and where a committed-hash receipt
chain must catch quorum-approved tampering. HMAC-SHA256 is a labeled simulation
stand-in only; no production cryptography claim is made.
"""
from __future__ import annotations
import hashlib, hmac, json, secrets
from dataclasses import dataclass, field

SCHEMA_VERSION = "szl.khipu-collusion/v1"
STATE_MEASURED = "MEASURED"
TRUTH_LABELS = {"simulation": True, "signature_stand_in": "HMAC-SHA256", "not_production_crypto": True}

def _canon(obj): return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
def _sign(key, payload_hash): return hmac.new(key, payload_hash.encode("utf-8"), hashlib.sha256).hexdigest()

@dataclass
class Witness:
    witness_id: int
    key: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    colluder: bool = False
    def attest(self, committed_hash, presented_hash):
        if self.colluder: return _sign(self.key, presented_hash)
        if presented_hash == committed_hash: return _sign(self.key, committed_hash)
        return None

def run_round(witnesses, committed_payload, tampered):
    committed_hash = hashlib.sha256(_canon(committed_payload)).hexdigest()
    presented_payload = dict(committed_payload)
    if tampered: presented_payload["amount"] = committed_payload.get("amount", 0) * 100
    presented_hash = hashlib.sha256(_canon(presented_payload)).hexdigest()
    sigs = {}
    for w in witnesses:
        s = w.attest(committed_hash, presented_hash)
        if s is not None: sigs[w.witness_id] = s
    quorum_reached = len(sigs) >= 3
    tamper_detected = quorum_reached and presented_hash != committed_hash
    outcome = "REPELLED" if not quorum_reached else ("QUORUM_BREACH_CHAIN_CAUGHT" if tamper_detected else "PASSED")
    return {"quorum_reached": quorum_reached, "signers": sorted(sigs), "tampered": tampered, "tamper_detected": tamper_detected, "outcome": outcome, "presented_hash": presented_hash, "committed_hash": committed_hash}

def run_campaign(colluders, rounds=200, seed=1337):
    if colluders < 0 or colluders > 4: raise ValueError("colluders must be 0..4")
    witnesses = [Witness(i, colluder=(i < colluders)) for i in range(4)]
    payload = {"proposal": "interdiction", "amount": 1, "nonce": seed}
    results = [run_round(witnesses, payload, tampered=(colluders > 0)) for _ in range(rounds)]
    return {"colluders": colluders, "rounds": rounds, "repelled": sum(r["outcome"] == "REPELLED" for r in results), "quorum_breach_chain_caught": sum(r["outcome"] == "QUORUM_BREACH_CHAIN_CAUGHT" for r in results), "passed_honest": sum(r["outcome"] == "PASSED" for r in results)}

def _verdict(spectrum, rounds):
    repel_ok = all(s["repelled"] == s["rounds"] for s in spectrum[1:3])
    catch_ok = spectrum[3]["quorum_breach_chain_caught"] == rounds and spectrum[4]["quorum_breach_chain_caught"] == rounds
    if repel_ok and catch_ok: return "BFT holds below quorum; at and above quorum the committed-hash chain catches every tamper. DESIGN REQUIREMENT: khipu verdicts must always be paired with tamper-evident receipt verification — witnesses alone breach."
    return "INCONCLUSIVE"

def full_lane(seed=1337, rounds=200):
    spectrum = [run_campaign(k, rounds=rounds, seed=seed) for k in range(5)]
    lane = {"schema": SCHEMA_VERSION, "state": STATE_MEASURED, "quorum_model": "3-of-4 BFT (HMAC stand-in for ECDSA-P256 witness keys)", "spectrum": spectrum, "verdict": _verdict(spectrum, rounds), **TRUTH_LABELS}
    lane["lane_digest"] = hashlib.sha256(_canon({k:v for k,v in lane.items() if k != "lane_digest"})).hexdigest()
    return lane
