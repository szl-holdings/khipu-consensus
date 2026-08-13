# SPDX-License-Identifier: Apache-2.0
# © 2026 Lutar, Stephen P. — SZL Holdings · ORCID 0009-0001-0110-4173
"""Public "multi-party-witnessed AI" API over the khipu BFT core.

Endpoints
---------
  POST /v1/attest    {action_hash, verdicts?, reason?, lean_sha?} -> MultiWitnessReceipt
  POST /v1/verify    {receipt, pubkeys?}                           -> operator-rooted re-verify
  GET  /v1/witnesses                                               -> public witness registry
  GET  /v1/healthz                                                 -> liveness + honest status

The witness registry is loaded from $KHIPU_WITNESSES (default service/witnesses.example.json),
which carries TEST-ONLY public keys and geo/org metadata. In this reference server the
example registry has NO private keys, so /attest returns an UNSIGNED-honest receipt
(every witness abstains) — exactly the doctrine fallback. A real deployment points each
witness `endpoint` at an independently-operated signer; this server never holds their keys.

Honesty: BFT safety = Conjecture 2, liveness = Conjecture 3 (proof-deferred). Economic
slashing ("EigenLayer for AI decisions") is ROADMAP. Nothing here is claimed proven.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from khipu_consensus import __version__
from khipu_consensus.witness import (
    WitnessRegistry, attest, verify_receipt, SAFETY_STATUS, RECEIPT_SCHEMA,
)

_DEFAULT_REGISTRY = Path(__file__).with_name("witnesses.example.json")


def load_registry() -> WitnessRegistry:
    path = Path(os.environ.get("KHIPU_WITNESSES", str(_DEFAULT_REGISTRY)))
    data = json.loads(path.read_text())
    return WitnessRegistry.from_dict(data)


app = FastAPI(
    title="Khipu Multi-Party-Witnessed AI API",
    version=__version__,
    description="Submit an action hash → 3-of-4 distributed witnesses CoSi-cosign over "
                "DSSE → verifiable multi-witness receipt. Safety=Conjecture 2, "
                "liveness=Conjecture 3 (proof-deferred). Slashing=ROADMAP.",
)

REGISTRY = load_registry()


class AttestRequest(BaseModel):
    action_hash: str
    verdicts: dict = {}
    reason: str = ""
    lean_sha: str = ""


class VerifyRequest(BaseModel):
    receipt: dict
    pubkeys: dict = {}


@app.post("/v1/attest")
def v1_attest(req: AttestRequest):
    receipt = attest(req.action_hash, REGISTRY, verdicts=req.verdicts,
                     reason=req.reason, lean_sha=req.lean_sha)
    return JSONResponse(receipt.to_dict())


@app.post("/v1/verify")
def v1_verify(req: VerifyRequest):
    if req.pubkeys and req.pubkeys != REGISTRY.pubkeys():
        return JSONResponse(
            {"detail": "pubkeys must exactly match the operator-owned witness registry"},
            status_code=400,
        )
    return JSONResponse(verify_receipt(req.receipt, registry=REGISTRY))


@app.get("/v1/witnesses")
def v1_witnesses():
    return JSONResponse({
        "schema": RECEIPT_SCHEMA,
        "threshold": REGISTRY.threshold,
        "n": REGISTRY.n,
        "witnesses": REGISTRY.public(),
    })


@app.get("/v1/healthz")
def v1_healthz():
    signing = any(w.can_sign() for w in REGISTRY.all())
    return JSONResponse({
        "status": "ok",
        "version": __version__,
        "n": REGISTRY.n,
        "threshold": REGISTRY.threshold,
        "signing_witnesses": signing,
        "mode": "signed" if signing else "UNSIGNED-honest (no private keys; witnesses abstain)",
        "provenance": SAFETY_STATUS,
    })


if __name__ == "__main__":  # pragma: no cover
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "7861")))
