# SPDX-License-Identifier: Apache-2.0
"""Adversarial Byzantine fault-injection tests (REAL throwaway P-256 keys).

Each test drives the REAL cryptographic verifier (no mocks): keys are generated
in-memory per test and never written to disk. The suite asserts the operational
BFT safety property — no tested Byzantine strategy forges a false-canonical —
and pins the honest empirical finding about per-verdict vs distinct-witness
counting. It is EVIDENCE, not a proof: Conjecture 2 (safety) / Conjecture 3
(liveness) remain proof-deferred.
"""
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from khipu_consensus import tally, sign_verdict
from khipu_consensus.adversary import (
    ACTION_A,
    ACTION_B,
    DUPLICATE_STUFFING,
    distinct_witness_tally,
    duplicate_stuffing,
    equivocation_verdict,
    forged_signature_verdict,
    honest_allow_count,
    impersonation_verdict,
    replay_verdict,
    run_adversarial_suite,
    safety_holds,
    silent_verdict,
    tamper_verdict,
)

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


def _keys():
    keys = {o: _keypair() for o in ORGANS}
    pubkeys = {o: keys[o][1] for o in ORGANS}
    return keys, pubkeys


def _allow(keys, organ, action=ACTION_A):
    return sign_verdict(organ, action, "allow", keys[organ][0], ts="t")


def _block(keys, organ, action=ACTION_A):
    return sign_verdict(organ, action, "block", keys[organ][0], ts="t")


# --- single-attack safety: forged / impersonated / tampered never count ------


def test_forged_signature_never_counts():
    keys, pubkeys = _keys()
    verdicts = [
        _allow(keys, "sentra"),
        _allow(keys, "amaru"),
        forged_signature_verdict("a11oy", ACTION_A),
        forged_signature_verdict("killinchu", ACTION_A),
    ]
    res = tally(ACTION_A, verdicts, pubkeys, threshold=3, n=4)
    assert res.decision == "rejected"
    assert res.consensus_count == 2
    assert honest_allow_count(ACTION_A, verdicts, pubkeys) == 2
    ok, detail = safety_holds(ACTION_A, verdicts, pubkeys)
    assert ok, detail


def test_impersonation_wrong_key_never_counts():
    keys, pubkeys = _keys()
    attacker_priv, _ = _keypair()
    verdicts = [
        _allow(keys, "sentra"),
        _allow(keys, "amaru"),
        impersonation_verdict("a11oy", ACTION_A, attacker_priv),
        impersonation_verdict("killinchu", ACTION_A, attacker_priv),
    ]
    res = tally(ACTION_A, verdicts, pubkeys, threshold=3, n=4)
    assert res.decision == "rejected"
    assert res.consensus_count == 2


def test_equivocation_action_mismatch_never_counts():
    keys, pubkeys = _keys()
    verdicts = [
        _allow(keys, "sentra"),
        _allow(keys, "amaru"),
        equivocation_verdict("a11oy", ACTION_B, keys["a11oy"][0]),
        equivocation_verdict("killinchu", ACTION_B, keys["killinchu"][0]),
    ]
    res = tally(ACTION_A, verdicts, pubkeys, threshold=3, n=4)
    assert res.decision == "rejected"
    assert res.consensus_count == 2


def test_payload_tamper_verdict_flip_breaks_signature():
    keys, pubkeys = _keys()
    verdicts = [
        _allow(keys, "sentra"),
        _allow(keys, "amaru"),
        tamper_verdict(_block(keys, "a11oy"), new_verdict="allow"),
        tamper_verdict(_block(keys, "killinchu"), new_verdict="allow"),
    ]
    res = tally(ACTION_A, verdicts, pubkeys, threshold=3, n=4)
    assert res.decision == "rejected"
    assert res.consensus_count == 2


def test_replay_other_action_never_counts():
    keys, pubkeys = _keys()
    verdicts = [
        _allow(keys, "sentra"),
        _allow(keys, "amaru"),
        replay_verdict(_allow(keys, "a11oy", ACTION_B)),
        replay_verdict(_allow(keys, "killinchu", ACTION_B)),
    ]
    res = tally(ACTION_A, verdicts, pubkeys, threshold=3, n=4)
    assert res.decision == "rejected"


# --- silence / liveness boundary ---------------------------------------------


def test_two_silent_witnesses_forces_rejected():
    keys, pubkeys = _keys()
    verdicts = [
        _allow(keys, "sentra"),
        _allow(keys, "amaru"),
        silent_verdict(),
        silent_verdict(),
    ]
    res = tally(ACTION_A, verdicts, pubkeys, threshold=3, n=4)
    assert res.decision == "rejected"
    ok, detail = safety_holds(ACTION_A, verdicts, pubkeys)
    assert ok, detail


def test_one_fault_still_reaches_canonical():
    keys, pubkeys = _keys()
    verdicts = [
        _allow(keys, "sentra"),
        _allow(keys, "amaru"),
        _allow(keys, "a11oy"),
        _block(keys, "killinchu"),
    ]
    res = tally(ACTION_A, verdicts, pubkeys, threshold=3, n=4)
    assert res.decision == "canonical"
    assert res.consensus_count == 3


# --- the honest finding: per-verdict vs distinct-witness counting -------------


def test_duplicate_stuffing_exposes_gap_and_hardened_closes_it():
    keys, pubkeys = _keys()
    verdicts = duplicate_stuffing(_allow(keys, "sentra"), times=3)

    # Reference tally over-counts one witness three times -> FALSE canonical.
    core = tally(ACTION_A, verdicts, pubkeys, threshold=3, n=4)
    assert core.decision == "canonical"
    assert core.consensus_count == 3

    # Ground truth: only ONE distinct honest witness allowed.
    assert honest_allow_count(ACTION_A, verdicts, pubkeys) == 1

    # The harness must catch the reference gap...
    ok, detail = safety_holds(ACTION_A, verdicts, pubkeys, tally_fn=tally)
    assert ok is False
    assert "FALSE-CANONICAL" in detail

    # ...and the hardened distinct-witness verifier must close it.
    hard = distinct_witness_tally(ACTION_A, verdicts, pubkeys, threshold=3, n=4)
    assert hard.decision == "rejected"
    assert hard.consensus_count == 1
    ok2, detail2 = safety_holds(ACTION_A, verdicts, pubkeys, tally_fn=distinct_witness_tally)
    assert ok2, detail2


def test_duplicate_stuffing_cannot_beat_hardened_even_with_extra_honest():
    keys, pubkeys = _keys()
    # Two genuine distinct witnesses + one of them stuffed twice more.
    verdicts = [
        _allow(keys, "sentra"),
        _allow(keys, "amaru"),
        dict(_allow(keys, "sentra")),
        dict(_allow(keys, "sentra")),
    ]
    assert tally(ACTION_A, verdicts, pubkeys, threshold=3, n=4).decision == "canonical"
    assert distinct_witness_tally(ACTION_A, verdicts, pubkeys, threshold=3, n=4).decision == "rejected"


# --- property / fuzz sweep ---------------------------------------------------


def test_no_byzantine_strategy_forges_false_canonical_under_hardened():
    report = run_adversarial_suite(seed=1, fuzz_rounds=400)
    s = report["summary"]
    assert s["hardened_all_safe"] is True
    assert s["fuzz_hardened_safety_violations"] == 0
    # Every reference-tally violation in the sweep is a duplicate-stuffing case.
    assert s["fuzz_core_violations_all_from_duplicate_stuffing"] is True


def test_reference_gap_is_reproduced_and_isolated_to_duplicate_stuffing():
    report = run_adversarial_suite(seed=0, fuzz_rounds=200)
    gaps = [sc for sc in report["scenarios"] if not sc["core_safe"]]
    assert gaps, "expected the duplicate-stuffing gap to be reproduced"
    assert all(sc["attack"] == DUPLICATE_STUFFING for sc in gaps)
    assert all(sc["hardened_safe"] for sc in report["scenarios"])


# --- honesty framing ---------------------------------------------------------


def test_report_defers_conjectures_and_frames_evidence_not_proof():
    report = run_adversarial_suite(seed=0, fuzz_rounds=10)
    assert report["schema"] == "szl.khipu.adversarial-validation/v1"
    honesty = report["honesty"]
    assert "NOT a proof" in honesty["asserts"]
    assert honesty["safety"]["safety"]["status"] == "proof-deferred"
    assert honesty["safety"]["liveness"]["status"] == "proof-deferred"
    assert report["finding"]["id"] == "distinct-witness-counting"


if __name__ == "__main__":
    import sys

    import pytest

    raise SystemExit(pytest.main([__file__, "-q"] + sys.argv[1:]))
