# SPDX-License-Identifier: Apache-2.0
"""Runnable demo: generate 4 throwaway witnesses, attest a decision, re-verify.

Private keys are generated in-memory and NEVER written to disk. Run:

    python service/demo_witness.py
"""
from __future__ import annotations

import json

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from khipu_consensus.witness import Witness, WitnessRegistry, attest, verify_receipt
from khipu_consensus.sdk import KhipuWitnessClient

ACTION_HASH = "c67945277763d12641ba4649349e42f221d4bd637268623ebe8a500edac02312"
FLEET = [
    ("sentra", "us-east-1", "SZL Holdings"),
    ("amaru", "eu-west-1", "Amaru Operator"),
    ("a11oy", "us-west-2", "a11oy Command Center"),
    ("killinchu", "ap-southeast-1", "Killinchu Defense"),
]


def _witness(organ, region, org):
    p = ec.generate_private_key(ec.SECP256R1())
    priv = p.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption()).decode()
    pub = p.public_key().public_bytes(serialization.Encoding.PEM,
                                      serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return Witness(organ=organ, public_key_pem=pub, private_key_pem=priv, region=region, org=org)


def main():
    registry = WitnessRegistry([_witness(*w) for w in FLEET], threshold=3)
    client = KhipuWitnessClient(registry=registry)

    print("== attest (killinchu blocks → 3-of-4) ==")
    receipt = client.attest(ACTION_HASH, verdicts={"killinchu": "block"}, reason="demo")
    print(f"decision={receipt['decision']} {receipt['khipu_consensus']} "
          f"count={receipt['consensus_count']}")

    print("== independent re-verify ==")
    rv = client.verify(receipt)
    print(f"decision={rv['decision']} matches_claimed={rv['matches_claimed_decision']}")
    print(f"provenance: safety={receipt['provenance']['safety']['id']} "
          f"slashing={receipt['provenance']['economic_slashing']['status']}")
    assert rv["decision"] == "canonical" and rv["matches_claimed_decision"]
    print("OK")


if __name__ == "__main__":
    main()
