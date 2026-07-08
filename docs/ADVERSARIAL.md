# Adversarial Byzantine fault-injection harness

`khipu_consensus.adversary` is the **empirical** complement to the Lean 4 formal
track (see [`FORMAL.md`](FORMAL.md)). It plays the Byzantine adversary against the
**real** cryptographic verifier and gathers evidence about whether any tested
strategy can forge a **false-canonical** — a `canonical` decision that is *not*
backed by `>= threshold` **distinct** honest witnesses.

> **Honesty (binding).** This harness produces **empirical evidence, never a
> proof.** A green run means *"no tested Byzantine strategy forged a
> false-canonical"*, not *"safety is proven"*. Khipu **safety** is
> **Conjecture 2** and **liveness** is **Conjecture 3** — both **proof-deferred**
> (tracked, not theorems), siblings of SZL's Λ Conjecture. This harness does not
> discharge or replace them.

## Threat model

Each attack is injected against the genuine `sign_verdict` / `verify_verdict` /
`tally` primitives using throwaway P-256 keys generated in memory (never written
to disk):

| # | Attack | Mechanism | Expected outcome |
|---|--------|-----------|------------------|
| 1 | `FORGED_SIGNATURE` | claim a witness `allow` with random signature bytes (no key) | never counts |
| 2 | `IMPERSONATION` | sign with the adversary's own key, stamp the victim `organ` | never counts (wrong key) |
| 3 | `ACTION_MISMATCH` | a witness validly signs a *different* action hash | never counts (`action_hash_match` false) |
| 4 | `PAYLOAD_TAMPER` | flip `verdict` / swap `action_hash`, keep the old signature | never counts (signature breaks) |
| 5 | `REPLAY` | replay a genuine `allow` captured over another action | never counts |
| 6 | `SILENCE` | a witness abstains / times out (`None`) | reduces available quorum |
| 7 | `DUPLICATE_STUFFING` | resubmit one genuine witness's `allow` multiple times | **see finding below** |

## The operational safety invariant

For one round, `safety_holds(...)` asserts:

> the verifier must **not** return `canonical` unless `>= threshold` **distinct**
> witnesses produced a cryptographically-valid `allow` over the **exact**
> `action_hash`.

The ground truth is computed independently by `honest_allow_count(...)`, which
reuses the real signature check but counts **each organ at most once** — the
distinctness the Lean `validCount` model assumes.

## Finding: per-verdict vs distinct-witness counting

The reference `tally()` (and therefore `witness.verify_receipt()`, which
re-tallies an **attacker-supplied** signature list) counts **per verdict**, not
**per distinct witness**. Because a witness's signed verdict is public (it travels
in receipts), an adversary who captures **one** genuine `allow` can resubmit it
`threshold` times and drive an independent verifier to `canonical`:

```python
from khipu_consensus import tally, sign_verdict
v = sign_verdict("sentra", action_hash, "allow", sentra_priv)
tally(action_hash, [v, dict(v), dict(v)], {"sentra": sentra_pub}, threshold=3, n=4)
# -> decision="canonical", 3-of-4   (from ONE witness)
```

- **Severity:** safety-relevant. The primary `witness.attest()` path is *not*
  vulnerable (it iterates a registry one verdict per organ); the exposure is in
  the independent verifier path over an attacker-controlled verdict list.
- **Mitigation (shipped, additive):** `adversary.distinct_witness_tally()` is a
  drop-in verifier identical to `tally()` except it counts each organ at most
  once. It closes the gap while leaving the reference `tally()` byte-for-byte
  aligned with the Go and TypeScript vector suites.
- **Recommended upstream fix (follow-up):** de-duplicate counting verdicts by
  organ inside `tally()`; mirror the change in `go/` and `typescript/`; add a
  duplicate-stuffing case to `testdata/vectors.json` so all three
  implementations stay aligned.

## Running it

```bash
cd python
pip install cryptography
python -m khipu_consensus.adversary                 # human summary + exit code
python -m khipu_consensus.adversary --json          # full JSON evidence report
python -m pytest tests/test_adversary.py -q         # the adversarial test suite
```

The report (`run_adversarial_suite()`) is a self-describing JSON artifact
(`schema: szl.khipu.adversarial-validation/v1`) carrying every scenario, the
randomized fuzz-sweep counts, the finding, and the honesty block (Conjecture 2/3
proof-deferred). With the optional `[spine]` extra installed it can be folded
onto a canonical `szl-receipt` via `emit_adversarial_receipt(report, priv)`
(keyless ⇒ UNSIGNED-honest — a signature is never faked).
