# SPDX-License-Identifier: Apache-2.0
"""Fail-closed service trust-root configuration tests."""
import json
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from service import app as service_app


def test_missing_registry_environment_has_no_bundled_fallback(monkeypatch):
    monkeypatch.delenv("KHIPU_WITNESSES", raising=False)

    assert service_app.load_registry() is None


def test_trust_dependent_endpoints_fail_closed_without_registry(monkeypatch):
    monkeypatch.setattr(service_app, "REGISTRY", None)
    request = service_app.VerifyRequest(receipt={})

    with pytest.raises(HTTPException) as exc_info:
        service_app.v1_verify(request)

    assert exc_info.value.status_code == 503
    assert "set KHIPU_WITNESSES" in exc_info.value.detail

    health_response = service_app.v1_healthz()
    assert health_response.status_code == 503
    health = json.loads(health_response.body)
    assert health["status"] == "unavailable"
    assert health["ready"] is False
    assert "KHIPU_WITNESSES" in health["mode"]


def test_example_registry_requires_explicit_operator_selection(monkeypatch):
    example = Path(service_app.__file__).with_name("witnesses.example.json")
    monkeypatch.setenv("KHIPU_WITNESSES", str(example))

    registry = service_app.load_registry()

    assert registry is not None
    assert registry.n == 4
    assert registry.threshold == 3
