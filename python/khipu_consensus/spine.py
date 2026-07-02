# SPDX-License-Identifier: Apache-2.0
# © 2026 Lutar, Stephen P. — SZL Holdings · ORCID 0009-0001-0110-4173
"""PCGI spine fold — a khipu consensus decision as ONE canonical szl-receipt.

This is the WAVE-3 spine UNIFY step for khipu-consensus. The witness coordinator
in :mod:`khipu_consensus.witness` already produces a portable, re-verifiable
``MultiWitnessReceipt`` from per-witness DSSE verdicts. This module folds that
witnessed decision onto the org-canonical ``szl-receipt`` shape so a consensus
round becomes a first-class *Proof-Carrying Governed Intelligence* (PCGI) receipt
producer on the SAME spine as every other decision producer (a11oy, yarqa,
governed-inference-meter, killinchu, ...).

An emit_receipt-style binding carries, in ONE signed record:

  * ``subject``        — the witness/round id (the action hash under agreement),
  * ``input_digest``   — SHA-256 over the canonical quorum INPUTS (the action
                         hash + the collected per-witness DSSE verdicts + the
                         witness public-key identities + the BFT threshold/n),
  * ``output_digest``  — SHA-256 over the agreed VALUE (the BFT decision + the
                         consensus count + the per-witness check outcomes),
  * ``policy_id``      — the governing policy id,
  * ``energy``         — honest ``UNAVAILABLE`` (khipu consensus measures no
                         joules here — never a fabricated joule),
  * ``witnesses``      — the BFT witnesses (organ + keyid) that actually counted.

It invents NO new receipt shape and re-implements NO cryptography: it reuses
``szl_receipt.Receipt`` for the canonical body + digest and
``szl_receipt.sign_receipt`` / ``szl_receipt.verify_receipt`` for the DSSE
envelope. The shared library is the ONE source of truth for canonicalization and
signing. This is ADDITIVE — the existing ``MultiWitnessReceipt`` path is
untouched.

Honesty (binding, doctrine):
  * The receipt is EVIDENCE binding a decision (subject+input+output+policy+
    energy), NOT a proof that the agreed value is correct. Re-deriving a digest
    is evidence the exact quorum inputs/outputs are bound, not a re-run of BFT.
  * BFT *safety* is Conjecture 2 and *liveness* is Conjecture 3 — both
    proof-deferred, NOT proven (mirrors :data:`khipu_consensus.witness.SAFETY_STATUS`).
  * Energy is the literal string ``"UNAVAILABLE"`` (``joules=None``); a joule is
    never fabricated.
  * Keyless => UNSIGNED-honest (``signed=False``); a signature is never faked.
  * The canonical body is deterministic for a fixed input receipt (no timestamp
    or nonce is added here), so the same receipt serializes to byte-identical
    canonical JSON and the same digest.

``szl_receipt`` is an OPTIONAL dependency imported lazily, so importing this
module (or the package) never requires it. Producing a canonical receipt does
require it (install extra ``[spine]``); its absence raises
:class:`SpineUnavailable` rather than fabricating a receipt.
"""
from __future__ import annotations

from typing import Any, Optional, Union

from .witness import SAFETY_STATUS

# Canonical receipt kind + PCGI schema for the fold.
RECEIPT_KIND = "khipu-consensus-witness"
PCGI_RECEIPT_SCHEMA = "szl.pcgi.receipt/khipu-consensus/v1"

# Governing policy id (the BFT quorum policy this receipt is bound under).
DEFAULT_POLICY_ID = "szl.pcgi.policy/khipu-bft-quorum/v1"

# Default logical signing-authority label stamped onto the envelope.
DEFAULT_ORGAN = "khipu-consensus"

# Honest sentinel for energy that was not measured (never a fabricated joule).
ENERGY_UNAVAILABLE = "UNAVAILABLE"


class SpineUnavailable(RuntimeError):
    """Raised when the shared ``szl_receipt`` library is not importable.

    Callers MUST treat this as "no canonical receipt here", never as a reason to
    fabricate a receipt or duplicate the library's shapes locally.
    """


def _require_szl_receipt():
    """Lazily import the shared ``szl_receipt`` library; fail honestly if absent."""
    try:
        import szl_receipt  # type: ignore
    except Exception as exc:  # pragma: no cover - exercised only without the lib
        raise SpineUnavailable(
            "szl_receipt (v0.2.0) is not installed; install "
            "`szl-receipt @ git+https://github.com/szl-holdings/szl-receipt.git"
            "@v0.2.0` (the `spine` extra) to fold khipu consensus decisions onto "
            "the canonical szl-receipt spine. Refusing to duplicate the shared "
            "receipt shapes."
        ) from exc
    return szl_receipt


def _as_dict(receipt: Any) -> dict[str, Any]:
    """Accept a :class:`MultiWitnessReceipt` or its ``to_dict()`` form."""
    if hasattr(receipt, "to_dict"):
        return receipt.to_dict()
    return dict(receipt)


def _digest(body: dict[str, Any]) -> str:
    """SHA-256 hex over the shared canonical JSON of ``body``.

    Uses ``szl_receipt.Receipt.digest`` (SHA-256 over the library's canonical
    JSON) so the digest is byte-for-byte the same primitive that binds every
    other SZL receipt — nothing is re-implemented here.
    """
    szl_receipt = _require_szl_receipt()
    return szl_receipt.Receipt(kind="_digest", body=dict(body)).digest()


def consensus_input(receipt: Any) -> dict[str, Any]:
    """The canonical quorum INPUTS that determine a decision.

    Binds everything the BFT outcome depends on: the action hash under agreement,
    the collected per-witness DSSE verdicts (or ``None`` abstentions), the witness
    public-key identities, and the BFT threshold/n. Deriving this independently
    reproduces ``input_digest``.
    """
    r = _as_dict(receipt)
    return {
        "action_hash": r.get("action_hash"),
        "threshold": r.get("threshold"),
        "n": r.get("n"),
        "signatures": r.get("signatures"),
        "witnesses": r.get("witnesses"),
    }


def consensus_output(receipt: Any) -> dict[str, Any]:
    """The canonical agreed VALUE (the honest BFT result record)."""
    r = _as_dict(receipt)
    return {
        "decision": r.get("decision"),
        "consensus_count": r.get("consensus_count"),
        "khipu_consensus": r.get("khipu_consensus"),
        "checks": r.get("checks"),
    }


def consensus_input_digest(receipt: Any) -> str:
    """SHA-256 hex over :func:`consensus_input`."""
    return _digest(consensus_input(receipt))


def consensus_output_digest(receipt: Any) -> str:
    """SHA-256 hex over :func:`consensus_output`."""
    return _digest(consensus_output(receipt))


def _counting_witnesses(receipt: Any) -> list[dict[str, Any]]:
    """The BFT witnesses (organ + keyid) whose verdicts actually counted."""
    r = _as_dict(receipt)
    out: list[dict[str, Any]] = []
    for c in (r.get("checks") or []):
        if c.get("counts"):
            out.append({"organ": c.get("organ"), "keyid": c.get("keyid")})
    return out


def build_consensus_receipt_body(
    receipt: Any,
    *,
    policy_id: str = DEFAULT_POLICY_ID,
    witnesses: Optional[list[Any]] = None,
) -> dict[str, Any]:
    """Assemble the canonical PCGI receipt body for one consensus decision.

    Binds the spine tuple — subject (witness/round id), input digest (quorum
    inputs), output digest (agreed value), governing policy id, energy (honest
    ``UNAVAILABLE`` — khipu consensus measures no joules here), and the BFT
    witnesses that counted. The body is deterministic for a fixed input receipt
    (no timestamp / nonce is added here), so the same receipt always yields
    byte-identical canonical JSON and the same digest.
    """
    r = _as_dict(receipt)
    bft_witnesses = witnesses if witnesses is not None else _counting_witnesses(r)
    return {
        "schema": PCGI_RECEIPT_SCHEMA,
        "kind": RECEIPT_KIND,
        "subject": {
            "type": "khipu-consensus-round",
            "action_hash": r.get("action_hash"),  # the witness/round id
        },
        "input_digest": consensus_input_digest(r),
        "output_digest": consensus_output_digest(r),
        "policy_id": policy_id,
        "energy": {
            "status": ENERGY_UNAVAILABLE,
            "joules": None,
            "reason": (
                "khipu consensus measures no joules here; energy reported "
                "UNAVAILABLE, never fabricated."
            ),
        },
        "witnesses": bft_witnesses,
        "quorum": {
            "threshold": r.get("threshold"),
            "n": r.get("n"),
            "consensus_count": r.get("consensus_count"),
            "khipu_consensus": r.get("khipu_consensus"),
            "decision": r.get("decision"),
        },
        "honesty": {
            "asserts": "integrity/reproducibility of the quorum, NOT correctness",
            "receipt_is": (
                "evidence trail binding this decision (subject+input+output+"
                "policy+energy), not a proof the agreed value is correct"
            ),
            "safety": SAFETY_STATUS,
        },
    }


def consensus_receipt_body_digest(
    receipt: Any,
    *,
    policy_id: str = DEFAULT_POLICY_ID,
    witnesses: Optional[list[Any]] = None,
) -> str:
    """Independently (re-)derive the signed receipt's content digest."""
    return _digest(
        build_consensus_receipt_body(
            receipt, policy_id=policy_id, witnesses=witnesses
        )
    )


def emit_consensus_receipt(
    receipt: Any,
    *,
    private_key_pem: Optional[Union[str, bytes]] = None,
    policy_id: str = DEFAULT_POLICY_ID,
    organ: str = DEFAULT_ORGAN,
    keyid: str = "",
    witnesses: Optional[list[Any]] = None,
) -> dict[str, Any]:
    """Emit ONE canonical szl-receipt for a consensus decision (the PCGI spine).

    Wraps :func:`build_consensus_receipt_body` in a shared
    :class:`szl_receipt.Receipt` and signs it via
    :func:`szl_receipt.sign_receipt` (DSSE/ECDSA-P256-SHA256, cosign-compatible).

    With a PEM ECDSA-P256 ``private_key_pem`` the envelope is signed; keyless it
    is UNSIGNED-honest (``signed=False``) — never a fabricated signature.

    The returned DSSE envelope binds subject (witness/round id) + input digest
    (quorum inputs) + output digest (agreed value) + governing policy id + honest
    ``UNAVAILABLE`` energy. It is an EVIDENCE trail for the decision, not a proof
    the agreed value is correct; a ``rejected`` decision (below quorum) still
    emits a fully honest receipt.
    """
    szl_receipt = _require_szl_receipt()
    body = build_consensus_receipt_body(
        receipt, policy_id=policy_id, witnesses=witnesses
    )
    return szl_receipt.sign_receipt(
        szl_receipt.Receipt(kind=RECEIPT_KIND, body=body),
        private_key_pem,
        organ=organ,
        keyid=keyid,
    )


def verify_consensus_receipt(
    envelope: dict[str, Any],
    *,
    public_key_pem: Optional[Union[str, bytes]] = None,
    receipt: Optional[Any] = None,
) -> tuple[bool, str]:
    """Verify a canonical consensus receipt (and optionally rebind it).

    Delegates the cryptographic check to :func:`szl_receipt.verify_receipt`
    (keyless envelopes honestly return ``(False, "unsigned-honest")``; a tampered
    payload returns ``(False, "signature mismatch")``). When ``receipt`` is
    supplied, additionally confirms the signed body's ``input_digest`` /
    ``output_digest`` re-derive from that receipt — so any post-hoc edit to the
    quorum inputs or the agreed value flips a digest and fails the rebind.
    """
    szl_receipt = _require_szl_receipt()
    ok, detail = szl_receipt.verify_receipt(envelope, public_key_pem)
    if not ok:
        return ok, detail

    if receipt is not None:
        import base64
        import json

        try:
            body = json.loads(base64.b64decode(envelope["payload"]).decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            return False, f"payload decode error: {exc}"
        if body.get("input_digest") != consensus_input_digest(receipt):
            return False, "input-digest-rebind-mismatch"
        if body.get("output_digest") != consensus_output_digest(receipt):
            return False, "output-digest-rebind-mismatch"

    return True, "ok"
