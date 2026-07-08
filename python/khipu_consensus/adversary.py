# SPDX-License-Identifier: Apache-2.0
# © 2026 Lutar, Stephen P. — SZL Holdings · ORCID 0009-0001-0110-4173
"""Adversarial Byzantine fault-injection harness for khipu consensus.

The witness coordinator in :mod:`khipu_consensus.witness` and the raw
:func:`khipu_consensus.tally` primitive decide whether an action is *canonical*
(``>= threshold`` valid ``allow`` signatures over the exact action hash). Their
**safety** property is **Conjecture 2** and their **liveness** property is
**Conjecture 3** — both *proof-deferred* in the Lean 4 formal track
(``docs/FORMAL.md``), NOT theorems.

This module is the *empirical* complement to that formal track: it plays the
Byzantine adversary against the REAL cryptographic verifier (no mocks) and
gathers evidence about whether any adversarial strategy can forge a
**false-canonical** — a ``canonical`` decision that is not backed by
``>= threshold`` *distinct* honest witnesses.

Honesty (binding, doctrine):
  * The harness produces EMPIRICAL EVIDENCE, never a proof. A green run means
    "no *tested* Byzantine strategy forged a false-canonical", not "safety is
    proven". Conjecture 2 / Conjecture 3 stay **proof-deferred**
    (mirrors :data:`khipu_consensus.witness.SAFETY_STATUS`).
  * It reinvents NO cryptography: every signature check goes through the real
    :func:`khipu_consensus.verify_verdict` (ECDSA-P256-SHA256 over the DSSE PAE).
  * It is ADDITIVE. The reference :func:`khipu_consensus.tally` is not modified,
    so the Python/Go/TypeScript vector suite stays byte-for-byte aligned.

The threat model (seven injected attacks):

  1. ``FORGED_SIGNATURE``   — claim a witness ``allow`` with random signature bytes
     (the adversary holds no key).
  2. ``IMPERSONATION``      — sign with the adversary's OWN key but stamp the
     victim's ``organ``/``keyid``.
  3. ``ACTION_MISMATCH``    — a witness validly signs a DIFFERENT action hash
     (equivocation) than the one under agreement.
  4. ``PAYLOAD_TAMPER``     — take a genuine verdict and flip its ``verdict`` /
     swap its ``action_hash`` while keeping the original signature.
  5. ``REPLAY``             — replay a genuine ``allow`` captured over another
     action into this round.
  6. ``SILENCE``            — a witness abstains / times out (``None``).
  7. ``DUPLICATE_STUFFING`` — resubmit ONE genuine witness's ``allow`` verdict
     multiple times to inflate the count.

Empirical finding surfaced by (7): the reference :func:`tally` USED TO count
**per verdict**, not **per distinct witness**, so duplicated genuine verdicts
from a single witness inflated ``consensus_count`` past the honest
distinct-witness threshold (:func:`khipu_consensus.witness.verify_receipt` and
the CLI re-tally attacker-supplied lists, so they inherited it). This is now
FIXED: :func:`tally` de-duplicates by witness in python/, go/, and typescript/,
locked by a duplicate-stuffing case in ``testdata/vectors.json``.
:func:`distinct_witness_tally` remains as an explicit hardened equivalent, and
:func:`naive_perverdict_tally` is retained ONLY as a demonstrator so this suite
can keep exhibiting the historical vulnerability class.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import random
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from . import (
    OrganCheck,
    OrganVerdict,
    __version__,
    canonical_json,
    tally,
    sign_verdict,
    verify_verdict,
)
from .witness import SAFETY_STATUS

# --- attack taxonomy ---------------------------------------------------------

FORGED_SIGNATURE = "forged_signature"
IMPERSONATION = "impersonation_wrong_key"
ACTION_MISMATCH = "equivocation_action_mismatch"
PAYLOAD_TAMPER = "payload_tamper_verdict_flip"
REPLAY = "replay_other_action"
SILENCE = "silent_witness_abstain"
DUPLICATE_STUFFING = "duplicate_stuffing_single_witness"

#: Cryptographic / protocol attacks the reference ``tally`` is expected to
#: defend on its own (each must yield ``counts=False``).
CRYPTO_ATTACKS = (
    FORGED_SIGNATURE,
    IMPERSONATION,
    ACTION_MISMATCH,
    PAYLOAD_TAMPER,
    REPLAY,
)

ALL_ATTACKS = CRYPTO_ATTACKS + (SILENCE, DUPLICATE_STUFFING)

ADVERSARIAL_SCHEMA = "szl.khipu.adversarial-validation/v1"
ADVERSARIAL_KIND = "khipu-consensus-adversarial-validation"


# --- adversarial verdict generators (all against the REAL wire shape) --------


def forged_signature_verdict(
    organ: str, action_hash: str, verdict: str = "allow", ts: str = "seed"
) -> dict:
    """Claim ``organ`` allowed ``action_hash`` but attach random signature bytes.

    The adversary holds no key, so this must fail cryptographic verification.
    """
    statement = {
        "schema": "szl.khipu.organ_verdict/v1",
        "organ": organ,
        "keyid": f"{organ}-cosign",
        "action_hash": action_hash,
        "verdict": verdict,
        "reason": "",
        "lean_sha": "",
        "ts": ts,
    }
    return {
        "organ": organ,
        "keyid": f"{organ}-cosign",
        "payloadType": "application/vnd.szl.khipu.organ-verdict+json",
        "payload": base64.b64encode(canonical_json(statement)).decode(),
        "signature": base64.b64encode(os.urandom(72)).decode(),
        "verdict": verdict,
        "reason": "",
    }


def impersonation_verdict(
    organ: str, action_hash: str, attacker_private_key_pem: str,
    verdict: str = "allow", ts: str = "seed",
) -> dict:
    """Sign with the adversary's OWN key while stamping the victim ``organ``.

    Well-formed signature, but it verifies FALSE against the victim's published
    public key.
    """
    return sign_verdict(organ, action_hash, verdict, attacker_private_key_pem, ts=ts)


def equivocation_verdict(
    organ: str, other_action_hash: str, private_key_pem: str,
    verdict: str = "allow", ts: str = "seed",
) -> dict:
    """A witness validly signs a DIFFERENT action hash than the round's.

    The signature verifies, but ``action_hash_match`` is False, so it must not
    count toward the round under agreement.
    """
    return sign_verdict(organ, other_action_hash, verdict, private_key_pem, ts=ts)


def tamper_verdict(
    valid_verdict: dict, *, new_action_hash: Optional[str] = None,
    new_verdict: Optional[str] = None,
) -> dict:
    """Edit a genuine verdict's payload while keeping its ORIGINAL signature.

    Flipping ``verdict`` (e.g. ``block`` -> ``allow``) or swapping
    ``action_hash`` invalidates the signature over the original PAE.
    """
    tampered = dict(valid_verdict)
    body = json.loads(base64.b64decode(valid_verdict["payload"]).decode("utf-8"))
    if new_action_hash is not None:
        body["action_hash"] = new_action_hash
    if new_verdict is not None:
        body["verdict"] = new_verdict
        tampered["verdict"] = new_verdict
    tampered["payload"] = base64.b64encode(canonical_json(body)).decode()
    return tampered


def replay_verdict(valid_verdict_over_other_action: dict) -> dict:
    """Replay a genuine ``allow`` captured over another action, verbatim."""
    return dict(valid_verdict_over_other_action)


def silent_verdict() -> None:
    """A witness that abstains / times out (UNSIGNED-honest ``None``)."""
    return None


def duplicate_stuffing(valid_verdict: dict, times: int = 3) -> list:
    """Resubmit ONE genuine witness's verdict ``times`` times."""
    return [dict(valid_verdict) for _ in range(times)]


# --- honest oracle + safety invariant + hardened verifier --------------------


def honest_allow_count(action_hash: str, verdicts: list, pubkeys: dict) -> int:
    """Ground truth: number of DISTINCT registered witnesses with a
    cryptographically-valid ``allow`` over the EXACT ``action_hash``.

    Each organ is counted at most once — the distinctness the BFT / Lean
    ``validCount`` model assumes. Reuses the real :func:`verify_verdict` for the
    cryptographic check; the ONLY thing it adds over :func:`tally` is per-witness
    de-duplication, so it is a faithful adversarial oracle.
    """
    counted: set = set()
    for item in verdicts:
        if item is None:
            continue
        v = item if isinstance(item, OrganVerdict) else OrganVerdict.from_dict(item)
        pem = pubkeys.get(v.organ, "")
        if not pem:
            continue
        if verify_verdict(v, pem, action_hash).counts:
            counted.add(v.organ)
    return len(counted)


def safety_holds(
    action_hash: str, verdicts: list, pubkeys: dict,
    threshold: int = 3, n: int = 4, tally_fn=tally,
) -> tuple[bool, str]:
    """Operational BFT safety check for ONE round against ``tally_fn``.

    Safety (Conjecture 2, stated operationally): the verifier must NOT declare
    ``canonical`` unless ``>= threshold`` DISTINCT witnesses genuinely allowed
    the exact action. Returns ``(ok, detail)``. This is EVIDENCE for a single
    round, not a proof.
    """
    res = tally_fn(action_hash, verdicts, pubkeys, threshold=threshold, n=n)
    honest = honest_allow_count(action_hash, verdicts, pubkeys)
    if res.decision == "canonical" and honest < threshold:
        return False, (
            f"FALSE-CANONICAL: {tally_fn.__name__} returned canonical "
            f"({res.consensus_count}-of-{res.n}) but only {honest} distinct honest "
            f"allow(s) < threshold {threshold}"
        )
    return True, "ok"


def distinct_witness_tally(
    action_hash: str, verdicts: list, pubkeys: dict,
    threshold: int = 3, n: int = 4,
):
    """Explicit hardened verifier: :func:`tally` but each organ counts at most once.

    Enforces the distinct-witness rule the formal ``validCount`` assumes. As of the
    distinct-witness fix the reference :func:`tally` ALSO de-duplicates by witness,
    so this now agrees with it; it is kept as an independent, explicit reference and
    for backward compatibility. Returns a :class:`khipu_consensus.ConsensusResult`.
    """
    from . import ConsensusResult

    checks: list = []
    counted: set = set()
    count = 0
    for item in verdicts:
        if item is None:
            checks.append(OrganCheck(None, None, False, None, False, False, "abstain/timeout"))
            continue
        v = item if isinstance(item, OrganVerdict) else OrganVerdict.from_dict(item)
        pem = pubkeys.get(v.organ, "")
        if not pem:
            checks.append(OrganCheck(v.organ, v.keyid, False, None, False, False, "no public key"))
            continue
        chk = verify_verdict(v, pem, action_hash)
        if chk.counts and v.organ in counted:
            checks.append(OrganCheck(
                v.organ, v.keyid, chk.valid, chk.verdict, chk.action_hash_match,
                False, "duplicate-witness (already counted)",
            ))
            continue
        if chk.counts:
            counted.add(v.organ)
            count += 1
        checks.append(chk)
    decision = "canonical" if count >= threshold else "rejected"
    return ConsensusResult(action_hash, threshold, n, count, decision, checks)


def naive_perverdict_tally(
    action_hash: str, verdicts: list, pubkeys: dict,
    threshold: int = 3, n: int = 4,
):
    """HISTORICAL / INSECURE demonstrator: count per verdict, NO de-duplication.

    Reproduces the behaviour :func:`tally` had BEFORE the distinct-witness fix.
    Retained ONLY so the adversarial suite can keep exhibiting the
    ``DUPLICATE_STUFFING`` vulnerability class against a known-vulnerable baseline.
    NEVER use in production. Returns a :class:`khipu_consensus.ConsensusResult`.
    """
    from . import ConsensusResult

    checks: list = []
    count = 0
    for item in verdicts:
        if item is None:
            checks.append(OrganCheck(None, None, False, None, False, False, "abstain/timeout"))
            continue
        v = item if isinstance(item, OrganVerdict) else OrganVerdict.from_dict(item)
        pem = pubkeys.get(v.organ, "")
        if not pem:
            checks.append(OrganCheck(v.organ, v.keyid, False, None, False, False, "no public key"))
            continue
        chk = verify_verdict(v, pem, action_hash)
        checks.append(chk)
        if chk.counts:
            count += 1
    decision = "canonical" if count >= threshold else "rejected"
    return ConsensusResult(action_hash, threshold, n, count, decision, checks)


# --- scenario harness --------------------------------------------------------


@dataclass
class Scenario:
    """One adversarial round and how each verifier decided it."""

    name: str
    attack: str
    description: str
    honest_distinct_allow: int
    threshold: int
    n: int
    naive_decision: str
    core_decision: str
    hardened_decision: str
    naive_safe: bool
    core_safe: bool
    hardened_safe: bool
    note: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


def _keypair() -> tuple[str, str]:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization

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


DEFAULT_ORGANS = ("sentra", "amaru", "a11oy", "killinchu")
ACTION_A = "c67945277763d12641ba4649349e42f221d4bd637268623ebe8a500edac02312"
ACTION_B = "b100000000000000000000000000000000000000000000000000000000000b01"


def _scenario(name, attack, description, action_hash, verdicts, pubkeys, threshold, n):
    naive = naive_perverdict_tally(action_hash, verdicts, pubkeys, threshold=threshold, n=n)
    core = tally(action_hash, verdicts, pubkeys, threshold=threshold, n=n)
    hard = distinct_witness_tally(action_hash, verdicts, pubkeys, threshold=threshold, n=n)
    naive_ok, naive_detail = safety_holds(
        action_hash, verdicts, pubkeys, threshold, n, tally_fn=naive_perverdict_tally
    )
    core_ok, _core_detail = safety_holds(action_hash, verdicts, pubkeys, threshold, n, tally_fn=tally)
    hard_ok, _hard_detail = safety_holds(
        action_hash, verdicts, pubkeys, threshold, n, tally_fn=distinct_witness_tally
    )
    return Scenario(
        name=name,
        attack=attack,
        description=description,
        honest_distinct_allow=honest_allow_count(action_hash, verdicts, pubkeys),
        threshold=threshold,
        n=n,
        naive_decision=naive.decision,
        core_decision=core.decision,
        hardened_decision=hard.decision,
        naive_safe=naive_ok,
        core_safe=core_ok,
        hardened_safe=hard_ok,
        note="" if naive_ok else naive_detail,
    )


def run_adversarial_suite(
    seed: int = 0, fuzz_rounds: int = 200, organs: tuple = DEFAULT_ORGANS,
    threshold: int = 3,
) -> dict:
    """Run the full adversarial battery and return an honest evidence report.

    Builds a real signing registry (throwaway P-256 keys, never persisted), runs
    the named single-attack scenarios and a randomized fuzz sweep, and returns a
    self-describing report. The report asserts EMPIRICAL evidence only —
    Conjecture 2/3 remain proof-deferred.
    """
    rng = random.Random(seed)
    n = len(organs)

    keys = {o: _keypair() for o in organs}
    pubkeys = {o: keys[o][1] for o in organs}
    attacker_priv, _attacker_pub = _keypair()

    def allow(o, action=ACTION_A):
        return sign_verdict(o, action, "allow", keys[o][0], ts="seed")

    def block(o, action=ACTION_A):
        return sign_verdict(o, action, "block", keys[o][0], ts="seed")

    scenarios: list[Scenario] = []

    scenarios.append(_scenario(
        "happy-4-of-4", "none",
        "four honest witnesses allow the exact action -> canonical",
        ACTION_A, [allow(o) for o in organs], pubkeys, threshold, n,
    ))
    scenarios.append(_scenario(
        "one-fault-tolerated", "none",
        "three allow + one block -> canonical (tolerates f=1)",
        ACTION_A, [allow(organs[0]), allow(organs[1]), allow(organs[2]), block(organs[3])],
        pubkeys, threshold, n,
    ))
    scenarios.append(_scenario(
        "two-silent-rejected", SILENCE,
        "two witnesses abstain (>= 2 faults) -> must be rejected (safety)",
        ACTION_A, [allow(organs[0]), allow(organs[1]), silent_verdict(), silent_verdict()],
        pubkeys, threshold, n,
    ))
    scenarios.append(_scenario(
        "forged-below-threshold", FORGED_SIGNATURE,
        "two honest allow + two forged (random-sig) allow -> forged never count",
        ACTION_A,
        [allow(organs[0]), allow(organs[1]),
         forged_signature_verdict(organs[2], ACTION_A),
         forged_signature_verdict(organs[3], ACTION_A)],
        pubkeys, threshold, n,
    ))
    scenarios.append(_scenario(
        "impersonation-below-threshold", IMPERSONATION,
        "two honest allow + two impersonated (attacker-key) allow -> never count",
        ACTION_A,
        [allow(organs[0]), allow(organs[1]),
         impersonation_verdict(organs[2], ACTION_A, attacker_priv),
         impersonation_verdict(organs[3], ACTION_A, attacker_priv)],
        pubkeys, threshold, n,
    ))
    scenarios.append(_scenario(
        "equivocation-below-threshold", ACTION_MISMATCH,
        "two honest allow + two witnesses sign a DIFFERENT action -> never count",
        ACTION_A,
        [allow(organs[0]), allow(organs[1]),
         equivocation_verdict(organs[2], ACTION_B, keys[organs[2]][0]),
         equivocation_verdict(organs[3], ACTION_B, keys[organs[3]][0])],
        pubkeys, threshold, n,
    ))
    scenarios.append(_scenario(
        "tamper-verdict-flip", PAYLOAD_TAMPER,
        "two honest allow + two block verdicts flipped to allow -> signature breaks",
        ACTION_A,
        [allow(organs[0]), allow(organs[1]),
         tamper_verdict(block(organs[2]), new_verdict="allow"),
         tamper_verdict(block(organs[3]), new_verdict="allow")],
        pubkeys, threshold, n,
    ))
    scenarios.append(_scenario(
        "replay-other-action", REPLAY,
        "two honest allow + two genuine allows replayed from another action -> never count",
        ACTION_A,
        [allow(organs[0]), allow(organs[1]),
         replay_verdict(allow(organs[2], ACTION_B)),
         replay_verdict(allow(organs[3], ACTION_B))],
        pubkeys, threshold, n,
    ))
    scenarios.append(_scenario(
        "duplicate-stuffing-single-witness", DUPLICATE_STUFFING,
        "ONE genuine witness's allow resubmitted 3x -> naive per-verdict counting "
        "over-counts (false canonical); shipped distinct-witness tally rejects",
        ACTION_A, duplicate_stuffing(allow(organs[0]), times=3), pubkeys, threshold, n,
    ))

    fuzz_naive_violations = 0
    fuzz_core_violations = 0
    fuzz_hardened_violations = 0
    fuzz_naive_violation_had_duplicate = 0
    for _ in range(fuzz_rounds):
        verdicts: list = []
        used_genuine: dict = {}
        for o in organs:
            choice = rng.choice([
                "allow", "block", SILENCE, FORGED_SIGNATURE, IMPERSONATION,
                ACTION_MISMATCH, PAYLOAD_TAMPER, REPLAY,
            ])
            if choice == "allow":
                v = allow(o)
                used_genuine[o] = v
                verdicts.append(v)
            elif choice == "block":
                verdicts.append(block(o))
            elif choice == SILENCE:
                verdicts.append(silent_verdict())
            elif choice == FORGED_SIGNATURE:
                verdicts.append(forged_signature_verdict(o, ACTION_A))
            elif choice == IMPERSONATION:
                verdicts.append(impersonation_verdict(o, ACTION_A, attacker_priv))
            elif choice == ACTION_MISMATCH:
                verdicts.append(equivocation_verdict(o, ACTION_B, keys[o][0]))
            elif choice == PAYLOAD_TAMPER:
                verdicts.append(tamper_verdict(block(o), new_verdict="allow"))
            elif choice == REPLAY:
                verdicts.append(replay_verdict(allow(o, ACTION_B)))

        had_duplicate = False
        if used_genuine and rng.random() < 0.5:
            victim = rng.choice(list(used_genuine.values()))
            for _dup in range(rng.randint(1, 3)):
                verdicts.append(dict(victim))
            had_duplicate = True

        rng.shuffle(verdicts)
        naive_ok, _ = safety_holds(
            ACTION_A, verdicts, pubkeys, threshold, n, tally_fn=naive_perverdict_tally
        )
        core_ok, _ = safety_holds(ACTION_A, verdicts, pubkeys, threshold, n, tally_fn=tally)
        hard_ok, _ = safety_holds(
            ACTION_A, verdicts, pubkeys, threshold, n, tally_fn=distinct_witness_tally
        )
        if not naive_ok:
            fuzz_naive_violations += 1
            if had_duplicate:
                fuzz_naive_violation_had_duplicate += 1
        if not core_ok:
            fuzz_core_violations += 1
        if not hard_ok:
            fuzz_hardened_violations += 1

    naive_findings = [s.as_dict() for s in scenarios if not s.naive_safe]
    return {
        "schema": ADVERSARIAL_SCHEMA,
        "kind": ADVERSARIAL_KIND,
        "version": __version__,
        "params": {
            "organs": list(organs),
            "threshold": threshold,
            "n": n,
            "seed": seed,
            "fuzz_rounds": fuzz_rounds,
        },
        "scenarios": [s.as_dict() for s in scenarios],
        "summary": {
            "scenarios_total": len(scenarios),
            "core_all_safe": all(s.core_safe for s in scenarios),
            "hardened_all_safe": all(s.hardened_safe for s in scenarios),
            "naive_gap_findings": len(naive_findings),
            "fuzz_core_safety_violations": fuzz_core_violations,
            "fuzz_hardened_safety_violations": fuzz_hardened_violations,
            "fuzz_naive_safety_violations": fuzz_naive_violations,
            "fuzz_naive_violations_all_from_duplicate_stuffing": (
                fuzz_naive_violations == fuzz_naive_violation_had_duplicate
            ),
        },
        "finding": {
            "id": "distinct-witness-counting",
            "severity": "safety-relevant",
            "status": "fixed",
            "summary": (
                "reference tally() previously counted per-verdict, not per distinct "
                "witness, so duplicated genuine verdicts from one witness could "
                "inflate consensus_count past the honest distinct-witness threshold "
                "(verify_receipt() and the CLI re-tally attacker-supplied lists, so "
                "they inherited it). FIXED: tally() now de-duplicates by witness in "
                "python/, go/, and typescript/, locked by a duplicate-stuffing case "
                "in testdata/vectors.json. distinct_witness_tally() remains as an "
                "explicit hardened equivalent."
            ),
            "fixed_in": __version__,
            "demonstrated_by": "naive_perverdict_tally",
            "guarded_by": [
                "tally",
                "distinct_witness_tally",
                "testdata/vectors.json:duplicate stuffing",
            ],
        },
        "honesty": {
            "asserts": (
                "EMPIRICAL adversarial evidence that no tested Byzantine strategy "
                "forged a false-canonical against the shipped distinct-witness "
                "tally(); NOT a proof of safety or liveness"
            ),
            "relation_to_formal": (
                "complements the Lean 4 formal track (docs/FORMAL.md); it does NOT "
                "discharge or replace Conjecture 2 / Conjecture 3"
            ),
            "safety": SAFETY_STATUS,
        },
    }


def emit_adversarial_receipt(report: dict, private_key_pem: Optional[Any] = None) -> dict:
    """Fold an adversarial report onto the canonical szl-receipt (OPTIONAL).

    Uses the shared ``szl_receipt`` library lazily (extra ``[spine]``). Keyless it
    is UNSIGNED-honest (``signed=False``) — a signature is never faked. The core
    harness never depends on ``szl_receipt``; only this helper does.
    """
    try:
        import szl_receipt  # type: ignore
    except Exception as exc:  # pragma: no cover - exercised only without the lib
        raise RuntimeError(
            "szl_receipt is not installed; install the `spine` extra to sign the "
            "adversarial report. Refusing to fabricate a receipt."
        ) from exc
    return szl_receipt.sign_receipt(
        szl_receipt.Receipt(kind=ADVERSARIAL_KIND, body=dict(report)),
        private_key_pem,
        organ="khipu-consensus",
        keyid="",
    )


def _human_summary(report: dict) -> str:
    s = report["summary"]
    lines = [
        "khipu-consensus — adversarial Byzantine fault-injection report",
        f"  version {report['version']} · seed {report['params']['seed']} · "
        f"{report['params']['threshold']}-of-{report['params']['n']} · "
        f"fuzz_rounds {report['params']['fuzz_rounds']}",
        "",
        f"  scenarios              : {s['scenarios_total']}",
        f"  shipped-tally safe     : {'ALL' if s['core_all_safe'] else 'NO'}",
        f"  distinct-witness safe  : {'ALL' if s['hardened_all_safe'] else 'NO'}",
        f"  fuzz shipped violations: {s['fuzz_core_safety_violations']}",
        f"  fuzz hardened viol.    : {s['fuzz_hardened_safety_violations']}",
        f"  fuzz naive violations  : {s['fuzz_naive_safety_violations']} "
        f"(all from duplicate-stuffing: {s['fuzz_naive_violations_all_from_duplicate_stuffing']})",
        "",
        "  scenarios:",
    ]
    for sc in report["scenarios"]:
        flag = "ok " if sc["core_safe"] else "GAP"
        lines.append(
            f"    [{flag}] {sc['name']:34} naive={sc['naive_decision']:9} "
            f"tally={sc['core_decision']:9} hardened={sc['hardened_decision']:9} "
            f"honest={sc['honest_distinct_allow']}"
        )
    lines += [
        "",
        f"  finding: {report['finding']['id']} ({report['finding']['severity']})",
        f"    {report['finding']['summary']}",
        "",
        "  HONESTY: empirical evidence, NOT a proof. Conjecture 2 (safety) / "
        "Conjecture 3 (liveness) remain proof-deferred.",
    ]
    return "\n".join(lines)


def _main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--fuzz-rounds", type=int, default=200)
    ap.add_argument("--json", action="store_true", help="emit the full JSON report")
    args = ap.parse_args(argv)

    report = run_adversarial_suite(seed=args.seed, fuzz_rounds=args.fuzz_rounds)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(_human_summary(report))

    ok = (
        report["summary"]["core_all_safe"]
        and report["summary"]["hardened_all_safe"]
        and report["summary"]["fuzz_core_safety_violations"] == 0
        and report["summary"]["fuzz_hardened_safety_violations"] == 0
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_main())
