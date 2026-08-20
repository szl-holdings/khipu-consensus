# SPDX-License-Identifier: Apache-2.0
# © 2026 Lutar, Stephen P. — SZL Holdings · ORCID 0009-0001-0110-4173
"""Public "multi-party-witnessed AI" API over the khipu BFT core.

Endpoints
---------
  POST /v1/attest    {action_hash, verdicts?, reason?, lean_sha?} -> MultiWitnessReceipt
  POST /v1/verify    {receipt, pubkeys?}                           -> operator-rooted re-verify
  GET  /v1/witnesses                                               -> public witness registry
  GET  /v1/healthz                                                 -> liveness + honest status

The operator trust registry must be explicitly selected with $KHIPU_WITNESSES.
There is no bundled fallback: without that setting, trust-dependent endpoints return 503
and health reports the service as not ready. The committed witnesses.example.json is
TEST-ONLY and is loaded only when an operator names it explicitly.

Honesty: BFT safety = Conjecture 2, liveness = Conjecture 3 (proof-deferred). Economic
slashing ("EigenLayer for AI decisions") is ROADMAP. Nothing here is claimed proven.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from khipu_consensus import __version__
from khipu_consensus.witness import (
    RECEIPT_SCHEMA,
    SAFETY_STATUS,
    WitnessRegistry,
    attest,
    verify_receipt,
)
from pydantic import BaseModel, Field


def load_registry() -> WitnessRegistry | None:
    configured_path = os.environ.get("KHIPU_WITNESSES", "").strip()
    if not configured_path:
        return None
    path = Path(configured_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    return WitnessRegistry.from_dict(data)


def require_registry() -> WitnessRegistry:
    if REGISTRY is None:
        raise HTTPException(
            status_code=503,
            detail="operator trust registry unavailable; set KHIPU_WITNESSES",
        )
    return REGISTRY


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
    verdicts: dict = Field(default_factory=dict)
    reason: str = ""
    lean_sha: str = ""


class VerifyRequest(BaseModel):
    receipt: dict
    pubkeys: dict = Field(default_factory=dict)


@app.post("/v1/attest")
def v1_attest(req: AttestRequest):
    registry = require_registry()
    receipt = attest(req.action_hash, registry, verdicts=req.verdicts,
                     reason=req.reason, lean_sha=req.lean_sha)
    return JSONResponse(receipt.to_dict())


@app.post("/v1/verify")
def v1_verify(req: VerifyRequest):
    registry = require_registry()
    if req.pubkeys and req.pubkeys != registry.pubkeys():
        return JSONResponse(
            {"detail": "pubkeys must exactly match the operator-owned witness registry"},
            status_code=400,
        )
    try:
        result = verify_receipt(req.receipt, registry=registry)
    except UnicodeEncodeError:
        # Python's JSON parser accepts escaped lone surrogates, but they are not
        # valid UTF-8 and therefore cannot have the canonical receipt identity
        # required by this endpoint. Reject them as malformed client input
        # instead of letting canonical hashing escape as a server error.
        return JSONResponse(
            {"detail": "receipt contains text that is not valid UTF-8"},
            status_code=400,
        )
    return JSONResponse(result)


@app.get("/v1/witnesses")
def v1_witnesses():
    registry = require_registry()
    return JSONResponse({
        "schema": RECEIPT_SCHEMA,
        "threshold": registry.threshold,
        "n": registry.n,
        "witnesses": registry.public(),
    })


@app.get("/v1/healthz")
def v1_healthz():
    if REGISTRY is None:
        return JSONResponse({
            "status": "unavailable",
            "ready": False,
            "version": __version__,
            "mode": "UNAVAILABLE (set KHIPU_WITNESSES)",
            "provenance": SAFETY_STATUS,
        }, status_code=503)

    signing = any(w.can_sign() for w in REGISTRY.all())
    return JSONResponse({
        "status": "ok",
        "ready": True,
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
