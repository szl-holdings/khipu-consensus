# Khipu Consensus — BFT 3-of-4 multi-party signed agreement

> The category SZL invents: **multi-party-witnessed AI.** Turn a chain of
> governance "organs" into a **Byzantine-fault-tolerant multi-signature
> agreement**. Each witness signs an action hash with its **own** ECDSA-P256 key.
> **≥ 3 valid `allow` signatures over the same action ⇒ canonical.** 2-of-4 or
> fewer ⇒ **rejected**.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

This is the open-source reference for the consensus protocol that powers SZL
Holdings' Khipu receipts. It is named for the Inka *khipu* (knotted-cord record),
used here purely as a **brand**; the protocol itself is standard DSSE + cosign +
BFT quorum counting.

## The idea in one paragraph

A single AI action (e.g. "select this effector", "approve this transaction") is
hashed to a 32-byte `action_hash`. The hash is sent **in parallel** to `n`
independent witnesses. Each witness runs its own governance check and returns a
**DSSE-signed verdict** (`allow` or `block`) signed with its **own keyid**
(`<witness>-cosign`). A verifier counts how many signatures (a) cryptographically
verify against that witness's published public key, (b) carry an `allow` verdict,
and (c) are over the **exact** `action_hash`. If the count reaches the
`threshold`, the action is **canonical**; otherwise it is **rejected**. With
`n = 4, threshold = 3` the protocol tolerates exactly one faulty / Byzantine /
unavailable witness (the classic `n ≥ 3f + 1` bound for a witness quorum).

```
            ┌──────────┐   sign(action_hash, sentra-cosign)
   action ─▶│  Sentra  │───────────────────────────────┐
      │     └──────────┘                                │
      │     ┌──────────┐   sign(action_hash, amaru-cosign)
      ├────▶│  Amaru   │───────────────────────────────┤
      │     └──────────┘                                ▼
      │     ┌──────────┐   sign(action_hash, a11oy-cosign)   ┌───────────────┐
      ├────▶│  a11oy   │──────────────────────────────────▶ │  tally(≥3/4)? │
      │     └──────────┘                                     └───────┬───────┘
      │     ┌──────────┐   sign(action_hash, killinchu-cosign)       │
      └────▶│Killinchu │───────────────────────────────────────────▶│
            └──────────┘                              canonical ◀────┘────▶ rejected
```

## Why every signature is real

Each per-witness signature is **ECDSA-P256-SHA256 over the DSSE Pre-Authentication
Encoding (PAE)** of the canonical-JSON verdict statement. It is therefore
verifiable by the [Sigstore Cosign](https://docs.sigstore.dev/cosign) CLI:

```bash
cosign verify-blob --key sentra.pub --signature sig.b64 --insecure-ignore-tlog pae.bin
# Verified OK
```

…and by plain OpenSSL (`openssl dgst -sha256 -verify sentra.pub -signature sig.bin pae.bin`).

## Implementations

| Language   | Path          | Verify | Sign | Tests |
|------------|---------------|:------:|:----:|:-----:|
| Python     | `python/`     | ✓      | ✓    | `python/tests` |
| TypeScript | `typescript/` | ✓      | ✓    | `typescript/test` |
| Go         | `go/`         | ✓      | —    | `go/consensus_test.go` |

All three verify the **same** deterministic vectors in [`testdata/vectors.json`](testdata/vectors.json).

### Quick start (Python)

```python
import json
from khipu_consensus import tally
v = json.load(open("testdata/vectors.json"))
r = tally(v["action_hash"], v["cases"][0]["signatures"], v["pubkeys"], threshold=3, n=4)
print(r.khipu_consensus, r.decision)   # 4-of-4 canonical
```

## DSSE PAE (the exact bytes signed)

```
PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
SIGNATURE       = ECDSA_P256_SHA256( PAE("application/vnd.szl.khipu.organ-verdict+json", canonical_json(statement)) )
```

`canonical_json` = JSON with sorted keys, compact separators (`,`/`:`), UTF-8.

## Formal model

The safety and liveness properties are formalised in Lean 4 (see
[`docs/FORMAL.md`](docs/FORMAL.md)) as **Conjecture 2** (`khipu_consensus_safety`)
and **Conjecture 3** (`khipu_consensus_liveness`). They are **proof-deferred**
(tracked, not theorems) — siblings of SZL's Λ Conjecture. The decidable counting
predicates and the canonicity decision are fully proved.

## Honesty

- TEST keys in `testdata/*.test.{key,pub}` are **TEST-ONLY**; never production.
- This repo is the **protocol**, not the witnesses. Production witnesses run their
  own governance brains and publish their own per-witness public keys.
- Sigstore Rekor transparency-log anchoring is supported via DSSE bundles; the
  level of multi-sig support depends on your Rekor version (≥ v0.10 for DSSE
  bundles). See [`docs/REKOR.md`](docs/REKOR.md).

## License

Apache-2.0 © 2026 Lutar, Stephen P. — SZL Holdings. ORCID 0009-0001-0110-4173.

*Authored by Yachay. Co-Authored-By: Perplexity Computer Agent.*
