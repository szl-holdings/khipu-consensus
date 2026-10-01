# khipu-consensus (Python)

Byzantine-fault-tolerant multi-party signed agreement — a 3-of-4 witness quorum over
DSSE/cosign per-witness signatures. This is the Python package for the
[szl-holdings/khipu-consensus](https://github.com/szl-holdings/khipu-consensus) repository;
the repository README carries the full doctrine, demo links, and evidence boundaries.

```bash
pip install khipu-consensus
khipu-verify --help
```

Doctrine boundary: safety and liveness of the quorum are **Conjecture 2 / Conjecture 3**
(proof-deferred, not proven). Λ remains Conjecture 1. Nothing in this package asserts a
theorem it does not carry.

Optional extras: `service` (FastAPI witness API), `remote` (HTTP SDK transport),
`spine` (fold a witnessed decision into one canonical `szl-receipt-dsse` receipt).

License: Apache-2.0 · Source: https://github.com/szl-holdings/khipu-consensus
