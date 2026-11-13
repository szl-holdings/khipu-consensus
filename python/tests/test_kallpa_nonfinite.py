"""Kallpa local adversarial test: non-finite numbers in a receipt must be a 400,
never a canonical identity hashed over non-JSON bytes (NaN/Infinity) or a 500."""
import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from service import app as service_app
from khipu_consensus import canonical_json


@pytest.mark.parametrize("raw", [
    '{"receipt": {"schema": "x", "extra": NaN}}',
    '{"receipt": {"schema": "x", "action_hash": Infinity}}',
])
def test_verify_rejects_nonfinite(monkeypatch, raw):
    example = Path(service_app.__file__).with_name("witnesses.example.json")
    monkeypatch.setenv("KHIPU_WITNESSES", str(example))
    monkeypatch.setattr(service_app, "REGISTRY", service_app.load_registry())
    client = TestClient(service_app.app, raise_server_exceptions=False)
    r = client.post("/v1/verify", content=raw, headers={"content-type": "application/json"})
    assert r.status_code == 400, (r.status_code, r.text[:200])


def test_canonical_json_rejects_nonfinite():
    with pytest.raises(ValueError):
        canonical_json({"x": float("nan")})
