# SPDX-License-Identifier: Apache-2.0
# © 2026 Lutar, Stephen P. — SZL Holdings · ORCID 0009-0001-0110-4173
"""Covenant v0.4 step 5 — read-only adjudication endpoint (spec section 4).

Implements the adjudication surface of the Memory Covenant v0.4 spec
(szl-frontier docs/COVENANT_V0_4_COUNTERSIGN_SPEC_2026-11-15.md, section 4
and section 6 step 5):

  * POST /adjudicate: submit a receipt bundle (operations + STH + witness
    signatures). The RESPONSE IS A RECEIPT ITSELF, one of: VERIFIED (chain
    intact, witnesses valid), TAMPERED (mismatch located), UNKNOWN (never
    PASS on missing evidence).
  * Adjudication is READ-ONLY: it proves facts about a bundle; it never
    lifts denies and never authorizes. This module has no write path and
    no state: every adjudication is a pure function of its inputs. The
    adjudication receipt is STANDALONE — it carries its own SHA-256 digest
    over its canonical body and is NOT appended to the session operation
    chain (an append would be a write).
  * Fail-closed taxonomy (spec 4): malformed bundles, missing STH receipts,
    untrusted or missing keys, insufficient quorums, and any internal
    failure yield UNKNOWN — never PASS on missing evidence; a located
    mismatch (root, session id, tree size, signature, STH binding) yields
    TAMPERED; only a fully evidenced, fully located pass yields VERIFIED.

Verify-from-source (spec 6 step 5) — any party can re-derive every fact this
endpoint reports, without trusting it:
  1. Clone this repository (Apache-2.0) and install the dev dependency
     (cryptography); the package has no other runtime dependencies.
  2. Rebuild the tree root from the submitted operation-receipt digests
     with sth.merkle_root (RFC 6962) and compare it to the bundle STH root.
  3. Verify the witness signatures with sth.verify_sth_receipt against
     YOUR OWN held trusted public keys — never keys carried inside the
     bundle — or verify individual DSSE signatures with
     cosign verify-blob --key <witness>.pub.
  4. Re-run adjudicate with your trusted keys and compare receipts; the
     endpoint holds no trust of its own, embeds no keys, and adds no
     evidence beyond the bundle you submit.

Honesty (binding, doctrine):
  * The claim is exactly "multi-party-witnessed", never "trustless"
    (spec 1.4). DenyMonotonic (no sequence of approvals lifts a hard deny)
    is the lutar-lean step 4 lane; the software gates remain the
    enforcement (spec 2.3). VERIFIED certifies chain integrity and witness
    validity only; it is not an authorization of any kind.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional

from . import __version__, canonical_json
from .receipt_tree import ReceiptTree
from .sth import (
    STH_STATUS_TAMPERED,
    STH_STATUS_VERIFIED,
    verify_sth_receipt,
)

ADJUDICATION_BUNDLE_SCHEMA = "szl.khipu.adjudication-bundle/v1"
ADJUDICATION_SCHEMA = "szl.khipu.adjudication/v1"

ADJUDICATION_VERIFIED = "VERIFIED"
ADJUDICATION_TAMPERED = "TAMPERED"
ADJUDICATION_UNKNOWN = "UNKNOWN"

ADJUDICATION_NOTE = (
    "adjudication is read-only: it proves facts about a bundle; it never "
    "lifts denies and never authorizes (spec 4); VERIFIED certifies chain "
    "integrity and witness validity only"
)


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _is_digest(x) -> bool:
    return (isinstance(x, str) and len(x) == 64
            and x == x.lower() and all(c in "0123456789abcdef" for c in x))


def _bundle_digest(bundle) -> str:
    """Digest over the submitted bundle EXACTLY as received (canonical JSON).

    Empty string when the bundle is not canonically serializable (still
    fail-closed: the adjudication proceeds, the digest is just unclaimed).
    """
    try:
        return _sha256_hex(canonical_json(bundle))
    except Exception:
        return ""

@dataclass
class AdjudicationDecision:
    """Read-only adjudication outcome for one receipt bundle (spec 4).

    receipt is the response-as-a-receipt: a STANDALONE SHA-256 receipt over
    the canonical decision body. It is not appended to any session chain.
    """

    schema: str
    verdict: str                     # VERIFIED | TAMPERED | UNKNOWN
    reasons: list
    bundle_digest: str
    session_id: Optional[str]
    tree_size: Optional[int]
    sha256_root_hash: Optional[str]
    consensus_count: int
    threshold: int
    n: int
    sth_status: Optional[str]        # VERIFIED | TAMPERED | UNKNOWN | None
    note: str
    receipt: dict
    version: str

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "AdjudicationDecision":
        return AdjudicationDecision(
            schema=d.get("schema", ""),
            verdict=d.get("verdict", ADJUDICATION_UNKNOWN),
            reasons=list(d.get("reasons", [])),
            bundle_digest=d.get("bundle_digest", ""),
            session_id=d.get("session_id"),
            tree_size=d.get("tree_size"),
            sha256_root_hash=d.get("sha256_root_hash"),
            consensus_count=d.get("consensus_count", 0),
            threshold=d.get("threshold", 0),
            n=d.get("n", 0),
            sth_status=d.get("sth_status"),
            note=d.get("note", ""),
            receipt=dict(d.get("receipt", {})),
            version=d.get("version", ""),
        )

    @property
    def verified(self) -> bool:
        return self.verdict == ADJUDICATION_VERIFIED


def _decision(verdict: str, reasons: list, bundle_digest: str,
              session_id: Optional[str], tree_size: Optional[int],
              root: Optional[str], consensus_count: int, threshold: int,
              n: int, sth_status: Optional[str], ts: str) -> AdjudicationDecision:
    body = {
        "schema": ADJUDICATION_SCHEMA,
        "verdict": verdict,
        "reasons": list(reasons),
        "bundle_digest": bundle_digest,
        "session_id": session_id,
        "tree_size": tree_size,
        "sha256_root_hash": root,
        "consensus_count": consensus_count,
        "threshold": threshold,
        "n": n,
        "sth_status": sth_status,
        "ts": ts or datetime.now(timezone.utc).isoformat(),
        "note": ADJUDICATION_NOTE,
        "version": __version__,
    }
    receipt = dict(body)
    receipt["digest"] = _sha256_hex(canonical_json(body))
    return AdjudicationDecision(
        schema=ADJUDICATION_SCHEMA, verdict=verdict, reasons=list(reasons),
        bundle_digest=bundle_digest, session_id=session_id, tree_size=tree_size,
        sha256_root_hash=root, consensus_count=consensus_count,
        threshold=threshold, n=n, sth_status=sth_status,
        note=ADJUDICATION_NOTE, receipt=receipt, version=__version__,
    )


def _unknown(bundle_digest: str, trusted_pubkeys, reasons: list,
             threshold: int, ts: str) -> AdjudicationDecision:
    n = len(trusted_pubkeys) if isinstance(trusted_pubkeys, dict) else 0
    return _decision(ADJUDICATION_UNKNOWN, reasons, bundle_digest,
                     None, None, None, 0, threshold, n, None, ts)


def _adjudicate_inner(bundle, trusted_pubkeys: dict, threshold: int,
                      bundle_digest: str, ts: str) -> AdjudicationDecision:
    if not isinstance(bundle, dict):
        return _unknown(bundle_digest, trusted_pubkeys,
                        ["bundle is not an object (fail-closed)"], threshold, ts)
    if bundle.get("schema") != ADJUDICATION_BUNDLE_SCHEMA:
        return _unknown(bundle_digest, trusted_pubkeys,
                        ["bundle schema mismatch (fail-closed)"], threshold, ts)
    session_id = bundle.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        return _unknown(bundle_digest, trusted_pubkeys,
                        ["missing or malformed session id"], threshold, ts)
    leaves = bundle.get("leaves")
    if not isinstance(leaves, list):
        return _unknown(bundle_digest, trusted_pubkeys,
                        ["missing leaves (fail-closed)"], threshold, ts)
    for d in leaves:
        if not _is_digest(d):
            return _unknown(bundle_digest, trusted_pubkeys,
                            ["malformed leaf digest (fail-closed)"], threshold, ts)
    sth = bundle.get("sth")
    if not isinstance(sth, dict):
        return _unknown(bundle_digest, trusted_pubkeys,
                        ["missing STH receipt (fail-closed)"], threshold, ts)
    # 1. the tree recomputes from the submitted operation-receipt digests
    try:
        tree = ReceiptTree.build(session_id, leaves)
    except Exception as e:
        return _unknown(bundle_digest, trusted_pubkeys,
                        [f"tree build failed (fail-closed): {e}"], threshold, ts)
    # 2. the STH adjudicates against caller-held TRUSTED keys, bound to the
    #    RECOMPUTED root / session / size: located mismatch -> TAMPERED
    verdict = verify_sth_receipt(
        sth, trusted_pubkeys, threshold=threshold,
        expected_root=tree.sha256_root_hash,
        expected_session_id=tree.session_id,
        expected_tree_size=tree.tree_size,
    )
    if verdict.status == STH_STATUS_VERIFIED:
        outcome = ADJUDICATION_VERIFIED
    elif verdict.status == STH_STATUS_TAMPERED:
        outcome = ADJUDICATION_TAMPERED
    else:
        outcome = ADJUDICATION_UNKNOWN
    return _decision(outcome, [verdict.reason], bundle_digest,
                     tree.session_id, tree.tree_size, tree.sha256_root_hash,
                     verdict.consensus_count, verdict.threshold, verdict.n,
                     verdict.status, ts)


def adjudicate(bundle, trusted_pubkeys: dict, threshold: int = 3,
               ts: str = "") -> AdjudicationDecision:
    """Adjudicate one receipt bundle (operations + STH + witness signatures).

    READ-ONLY and fail-closed: proves facts about the bundle, never lifts
    denies, never authorizes, and never raises to the caller — any internal
    failure yields UNKNOWN, never PASS. VERIFIED requires the tree root to
    recompute from the submitted operation digests AND at least threshold
    DISTINCT trusted witnesses to have countersigned that SAME root with a
    matching STH binding.
    """
    digest = _bundle_digest(bundle)
    try:
        return _adjudicate_inner(bundle, trusted_pubkeys, threshold, digest, ts)
    except Exception as e:
        return _unknown(digest, trusted_pubkeys,
                        [f"internal adjudication failure (fail-closed): "
                         f"{type(e).__name__}: {e}"], threshold, ts)


def handle_adjudicate(body_bytes, trusted_pubkeys: dict, threshold: int = 3,
                      ts: str = "") -> AdjudicationDecision:
    """Parse one POST /adjudicate request body and adjudicate it.

    Fail-closed: a body that is not a JSON object yields UNKNOWN — the
    endpoint never raises to the caller and never PASSes on missing or
    unparseable evidence.
    """
    try:
        text = body_bytes.decode("utf-8") if isinstance(body_bytes, (bytes, bytearray)) else ""
        bundle = json.loads(text) if text else None
    except Exception:
        bundle = None
    if not isinstance(bundle, dict):
        return _unknown("", trusted_pubkeys,
                        ["request body is not a JSON object (fail-closed)"],
                        threshold, ts)
    return adjudicate(bundle, trusted_pubkeys, threshold=threshold, ts=ts)


class AdjudicationHTTPHandler(BaseHTTPRequestHandler):
    """Minimal read-only POST /adjudicate endpoint (stdlib only).

    The handler holds NO trust of its own: the trusted witness public keys
    and threshold are injected at construction and are NEVER read from the
    request. The route is adjudication-only; nothing else is served.
    """

    trusted_pubkeys: dict = {}
    threshold: int = 3

    def do_POST(self):  # noqa: N802 (stdlib handler naming)
        if self.path.split("?")[0] != "/adjudicate":
            self._respond(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except (TypeError, ValueError):
            length = 0
        body = self.rfile.read(length) if length > 0 else b""
        decision = handle_adjudicate(body, self.trusted_pubkeys,
                                     threshold=self.threshold)
        self._respond(200, decision.to_dict())

    def do_GET(self):  # noqa: N802 (stdlib handler naming)
        self._respond(405, {"error": "method not allowed (read-only endpoint)"})

    def _respond(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, sort_keys=True, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:  # quiet; no logging side effects
        pass


def make_adjudication_server(trusted_pubkeys: dict, host: str = "127.0.0.1",
                             port: int = 0,
                             threshold: int = 3) -> HTTPServer:
    """Bind the read-only adjudication endpoint (stdlib only).

    LOOPBACK BY DEFAULT: the endpoint is for callers who already hold the
    trusted keys; it embeds no trust and must not be exposed beyond the
    host that owns the keys. Returns a started-but-not-serving
    HTTPServer; call serve_forever() in a thread of your choosing.
    """
    handler = type("BoundAdjudicationHandler", (AdjudicationHTTPHandler,), {
        "trusted_pubkeys": dict(trusted_pubkeys or {}),
        "threshold": int(threshold),
    })
    return HTTPServer((host, port), handler)
