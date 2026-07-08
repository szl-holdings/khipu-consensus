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
| 7 | `DUPLICATE_STUFFING` | resubmit one genuine witness's `allow` multiple times | never double-counts (distinct-witness rule — see finding) |

## The operational safety invariant

For one round, `safety_holds(...)` asserts:

> the verifier must **not** return `canonical` unless `>= threshold` **distinct**
> witnesses produced a cryptographically-valid `allow` over the **exact**
> `action_hash`.

The ground truth is computed independently by `honest_allow_count(...)`, which
reuses the real signature check but counts **each organ at most once** — the
distinctness the Lean `validCount` model assumes.

## Finding: per-verdict vs distinct-witness counting (FIXED)

The reference `tally()` **used to** count **per verdict**, not **per distinct
witness** (and `witness.verify_receipt()` and the CLI re-tally an
**attacker-supplied** signature list, so they inherited it). Because a witness's
signed verdict is public (it travels in receipts), an adversary who captured
**one** genuine `allow` could resubmit it `threshold` times and drive an
independent verifier to `canonical`.

**Status: FIXED.** `tally()` now counts each witness at most once — a second
valid `allow` from an already-counted organ is recorded (`counts=false`, reason
`"duplicate-witness (already counted)"`) but does not increment the tally. The
fix is mirrored across all three reference implementations (`python/`, `go/`,
`typescript/`) and locked by a shared vector:

```python
from khipu_consensus import tally, sign_verdict
v = sign_verdict("sentra", action_hash, "allow", sentra_priv)
tally(action_hash, [v, dict(v), dict(v)], {"sentra": sentra_pub}, threshold=3, n=4)
# -> decision="rejected", 1-of-4   (one witness counts once)
```

- **Severity:** safety-relevant. The primary `witness.attest()` path was never
  vulnerable (it iterates a registry one verdict per organ); the exposure was in
  the independent verifier path over an attacker-controlled verdict list.
- **Regression guard:** `testdata/vectors.json` carries a `duplicate stuffing`
  case (`decision: rejected`, `consensus_count: 2`) exercised by the Python, Go,
  and TypeScript vector suites, so the three implementations stay aligned.
- **Demonstrator:** `adversary.naive_perverdict_tally()` reproduces the old
  per-verdict behaviour and is retained ONLY so the harness can keep exhibiting
  the vulnerability class against a known-vulnerable baseline.
- **Explicit hardened equivalent:** `adversary.distinct_witness_tally()` remains
  as an independent distinct-witness verifier (now equivalent to the shipped
  `tally()`).

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
