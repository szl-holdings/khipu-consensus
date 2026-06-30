# SPDX-License-Identifier: Apache-2.0
# © 2026 Lutar, Stephen P. — SZL Holdings · ORCID 0009-0001-0110-4173
"""KhipuWitnessClient — the public SDK for multi-party-witnessed AI.

Two transports, one API:
  - In-process (default): drive a local WitnessRegistry directly. Zero network, used for
    tests, single-host demos, and embedding the coordinator inside another service.
  - Remote: talk to a deployed witness API (service/app.py) over HTTP. Requires the
    optional `requests` dependency; raised lazily so the in-process path has no deps
    beyond the core `cryptography`.

Either way you get the same `attest()` / `verify()` returning a MultiWitnessReceipt dict
that re-verifies with `cosign verify-blob` or `khipu_consensus.witness.verify_receipt`.
"""
from __future__ import annotations

from typing import Optional

from .witness import WitnessRegistry, attest, verify_receipt


class KhipuWitnessClient:
    """Submit an action hash → 3-of-4 witnesses cosign → verifiable receipt.

    Examples
    --------
    In-process::

        from khipu_consensus.sdk import KhipuWitnessClient
        client = KhipuWitnessClient(registry=my_registry)
        receipt = client.attest("c679...2312")
        assert receipt["decision"] == "canonical"

    Remote::

        client = KhipuWitnessClient(base_url="https://witness.example/v1")
        receipt = client.attest("c679...2312")
    """

    def __init__(self, registry: Optional[WitnessRegistry] = None,
                 base_url: Optional[str] = None, timeout: float = 10.0):
        if registry is None and not base_url:
            raise ValueError("provide either a registry (in-process) or a base_url (remote)")
        self.registry = registry
        self.base_url = base_url.rstrip("/") if base_url else None
        self.timeout = timeout

    # ---- in-process / remote dispatch -------------------------------------------------

    def attest(self, action_hash: str, verdicts: Optional[dict] = None,
               reason: str = "", lean_sha: str = "") -> dict:
        if self.base_url:
            return self._post("/attest", {
                "action_hash": action_hash, "verdicts": verdicts or {},
                "reason": reason, "lean_sha": lean_sha,
            })
        return attest(action_hash, self.registry, verdicts=verdicts,
                      reason=reason, lean_sha=lean_sha).to_dict()

    def verify(self, receipt: dict, pubkeys: Optional[dict] = None) -> dict:
        if self.base_url:
            return self._post("/verify", {"receipt": receipt, "pubkeys": pubkeys or {}})
        return verify_receipt(receipt, pubkeys=pubkeys)

    def witnesses(self) -> list:
        if self.base_url:
            return self._get("/witnesses")["witnesses"]
        return self.registry.public()

    # ---- remote transport (lazy requests import) --------------------------------------

    def _http(self):
        try:
            import requests  # noqa: WPS433 — optional dep, only for remote transport
        except ImportError as e:  # pragma: no cover
            raise RuntimeError(
                "remote transport needs `requests`: pip install 'khipu-consensus[remote]'"
            ) from e
        return requests

    def _post(self, path: str, body: dict) -> dict:
        r = self._http().post(f"{self.base_url}{path}", json=body, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def _get(self, path: str) -> dict:
        r = self._http().get(f"{self.base_url}{path}", timeout=self.timeout)
        r.raise_for_status()
        return r.json()
