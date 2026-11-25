# khipu-consensus domain leader study r1 (propose-only)

Date: 2026-11-25. Method: web-verified leader landscape + owner-direct execution (standing authority GREENLIGHT-RULING-2026-11-24-K1 rank5; the Kimi ratification seat remains stood down by explicit owner directive, disclosed; owner-direct nonce T15-OWNER-DIRECT-20261125-K1). Study pinned to khipu-consensus HEAD f6afa89a24baa69047fb384c737ca219df45c807, fetched 2026-11-25. This card is documentation only; it changes no code, CI, config, or existing PR status. All absorb actions are FUTURE PROPOSALS (non-authorizing); implementation and merges remain separately reviewed and gated. L Conjecture 1: OPEN (advisory, never a closed theorem). No speedup, energy, or proven-trust claims; upstream performance claims are labeled as upstream claims only. No unverified signing, attestation, or provenance-level claims; this study verifies nothing about this repo's artifacts.

## Domain: BFT-style 3-of-4 multi-party-witnessed agreement in which each witness signs an action hash with its own ECDSA P-256 cosign key over DSSE

## Leaders studied (web-verified 2026-11-25)
1. CometBFT (https://github.com/cometbft/cometbft) - moat: battle-tested BFT consensus engine with validator-set finality adopted across many production systems.
2. HashiCorp Raft (https://github.com/hashicorp/raft) - moat: widely used replicated-log library with leader election and snapshotting.
3. pyca/cryptography (https://github.com/pyca/cryptography) - moat: maintained Python cryptographic primitives underlying many production signing stacks.

## Absorb actions (FUTURE PROPOSALS, non-authorizing)
1. (CometBFT) Propose a documentation-only comparison of validator-set BFT versus the estate's simpler 3-of-4 witnessed signing, and why the estate chose threshold signatures over full consensus for its scope. Cost: doc-only, with an honest estimate; limit: note only, no code, no infra changes.
2. (HashiCorp Raft) Propose a documentation-only note on append-only log discipline versus hash-chained witnessed receipts. Cost: doc-only, with an honest estimate; limit: note only, no code, no infra changes.
3. (pyca/cryptography) Propose a documentation-only note on signing-key handling hygiene conventions for independent witnesses. Cost: doc-only, with an honest estimate; limit: note only, no code, no infra changes.
4. Baseline preserve honestly: witness independence (4 distinct keys, no single-witness shortcuts), DSSE envelope discipline, and offline third-party verifiability are preserved; no stronger consensus claim is made than multi-party-witnessed agreement.

## Do not do (per governing seat)

Do not merge, bypass the signature wall, or claim implementation beyond this card.
