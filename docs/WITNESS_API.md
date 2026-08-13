# Multi-Party-Witnessed AI — Witness API & SDK

> Submit an action hash → **3-of-4 geographically / organizationally distributed
> witnesses** each CoSi-cosign over DSSE → get back a single **verifiable
> multi-witness receipt**. This is the productized public surface over the
> `khipu-consensus` BFT core. It reinvents no cryptography: every signature is the
> same `ECDSA-P256-SHA256` over the DSSE PAE that `khipu_consensus.sign_verdict`
> already produces, re-checkable by `cosign verify-blob`.

## Why this exists (the category: multi-party-witnessed AI)

A single AI action — "select this effector", "approve this transaction", "ship this
model" — is hashed to a 32-byte `action_hash` and submitted to **N independent
witnesses**. Each witness runs its own governance check in its own trust domain and
returns a **DSSE-signed verdict** (`allow` / `block`) under its **own keyid**
(`<organ>-cosign`). A verifier counts how many verdicts (a) cryptographically verify
against that witness's published public key, (b) carry `allow`, and (c) are over the
**exact** `action_hash`. `≥ threshold` ⇒ **canonical**, else **rejected**. With
`n=4, threshold=3` the protocol tolerates exactly one faulty / Byzantine / unavailable
witness (the classic `n ≥ 3f + 1` bound).

## Academic & industry grounding (independent validation)

- **CoSi witness cosigning** — Syta et al., *Keeping Authorities "Honest or Bust" with
  Decentralized Witness Cosigning*, IEEE S&P 2016. CoSi has a set of independent
  witnesses co-sign a statement so no single authority can act unwitnessed. Khipu is a
  deliberately **stronger** variant: each witness keeps its **own** key and emits its
  **own** DSSE envelope (no aggregate key to compromise), so every signature is
  individually attributable and individually `cosign`-verifiable.
- **arXiv:2504.14668** — deVadoss & Artzt, *Byzantine Fault Tolerance for AI Safety*.
  Independent academic argument that a BFT quorum among heterogeneous validators is the
  right safety primitive for autonomous AI actions. This validates the **exact**
  architecture here; we cite it as third-party confirmation, not as our own proof.
- **Epistemology of testimony** (Lackey) — no single witness's testimony is sufficient
  grounds for belief; warranted acceptance requires corroboration. The 3-of-4 quorum **is**
  the epistemic primitive: canonicity is not "the system says so" but "≥3 independent
  witnesses each testified, and you can check each one."
- **EigenLayer-for-AI-decisions** — positioning: witnesses are AVS-style operators whose
  cosignature is the security product. **Economic slashing is ROADMAP** (see Honesty).

## Honesty (binding — never violate)

| Property | Status | Label |
|----------|--------|-------|
| BFT safety (`khipu_consensus_safety`) | **Conjecture 2** — proof-deferred, NOT proven | gray / open |
| BFT liveness (`khipu_consensus_liveness`) | **Conjecture 3** — proof-deferred, NOT proven | gray / open |
| Economic slashing (AVS) | **ROADMAP** — not implemented | roadmap |
| Per-witness signature verification + quorum counting | implemented & tested | done |

When no private key is available, the coordinator emits an **UNSIGNED-honest** receipt
(every witness abstains, `signatures: [null, …]`, `decision: rejected`). It never fakes a
signature. The committed `service/witnesses.example.json` carries **TEST-ONLY public keys
and no private keys** — so the reference server runs in UNSIGNED-honest mode until each
witness `endpoint` is pointed at an independently-operated signer.

## API

```
POST /v1/attest    {action_hash, verdicts?, reason?, lean_sha?}  -> MultiWitnessReceipt
POST /v1/verify    {receipt, pubkeys?}                            -> operator-rooted re-verify
GET  /v1/witnesses                                                -> public witness registry
GET  /v1/healthz                                                  -> liveness + honest status
```

Verification is fail-closed against the registry loaded from `KHIPU_WITNESSES`.
Receipt-embedded keys, threshold, and witness count are non-authoritative claims and
must exactly match that operator-owned registry. The legacy `pubkeys` request field is
accepted only when it exactly matches the same registry; it cannot replace trust roots.
Library callers must pass `registry=trusted_registry`, or explicit trusted `pubkeys` and
`threshold`. Every result includes SHA-256 identities for the exact canonical receipt
and trust policy used during verification.

The CLI uses the same boundary:

```bash
khipu-verify receipt.json service/witnesses.example.json
```

The second argument is an operator-owned registry containing `threshold` and
`witnesses`. A public-key directory or receipt-embedded threshold is not accepted as a
trust policy.

Run it:

```bash
pip install -e 'python[service]'
KHIPU_WITNESSES=service/witnesses.example.json \
  uvicorn service.app:app --port 7861
curl -s localhost:7861/v1/healthz | jq .mode
# "UNSIGNED-honest (no private keys; witnesses abstain)"
```

## SDK

```python
from khipu_consensus.sdk import KhipuWitnessClient
from khipu_consensus.witness import WitnessRegistry

# In-process (embed the coordinator; zero network)
client = KhipuWitnessClient(registry=WitnessRegistry.from_dict(registry_dict))
receipt = client.attest("c67945277763d12641ba4649349e42f221d4bd637268623ebe8a500edac02312")
assert receipt["decision"] == "canonical"          # when ≥3 witnesses allow
client.verify(receipt)                              # independent re-check

# Remote (talk to a deployed witness API)
client = KhipuWitnessClient(base_url="https://witness.example/v1")  # needs [remote] extra
```

## Receipt shape (`szl.khipu.multi-witness-receipt/v1`)

```json
{
  "schema": "szl.khipu.multi-witness-receipt/v1",
  "action_hash": "c679…2312",
  "threshold": 3, "n": 4,
  "decision": "canonical", "consensus_count": 3, "khipu_consensus": "3-of-4",
  "signatures": [ { "organ": "sentra", "keyid": "sentra-cosign",
                    "payloadType": "application/vnd.szl.khipu.organ-verdict+json",
                    "payload": "<b64 canonical statement>",
                    "signature": "<b64 ECDSA-P256-SHA256 over DSSE PAE>",
                    "verdict": "allow" }, … ],
  "checks": [ { "organ": "sentra", "valid": true, "verdict": "allow",
                "action_hash_match": true, "counts": true }, … ],
  "witnesses": [ { "organ": "sentra", "region": "us-east-1", "org": "…",
                   "public_key_pem": "-----BEGIN PUBLIC KEY-----…" }, … ],
  "provenance": {
    "safety":   { "id": "Conjecture 2", "status": "proof-deferred" },
    "liveness": { "id": "Conjecture 3", "status": "proof-deferred" },
    "economic_slashing": { "status": "ROADMAP" }
  }
}
```

Each `signatures[i]` is independently verifiable with cosign:

```bash
cosign verify-blob --key sentra.pub --signature sig.b64 --insecure-ignore-tlog pae.bin
```

## How this surpasses the leaders

- **CoSi** publishes one aggregate cosignature; Khipu publishes **N individually
  attributable DSSE envelopes**, each `cosign`-verifiable and each carrying its own
  geographic/organizational witness identity — auditors prove *who* agreed, not just *that*
  ≥t agreed.
- **Sigstore/Rekor** attests software artifacts (1 signer → transparency log); Khipu
  attests **AI decisions** with a **BFT quorum** of heterogeneous witnesses.
- Unlike vendors that ship "verified by consensus" as a black box, every factor here is
  **independently checkable** and every unproven claim is **labeled** (Conjecture 2/3,
  slashing ROADMAP) rather than painted green.
