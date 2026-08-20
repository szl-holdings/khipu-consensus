# SPDX-License-Identifier: Apache-2.0
"""Operator-rooted CLI verifier.

``khipu-verify <receipt.json> <trust-policy.json>`` accepts a receipt only
against an external witness registry. The receipt's embedded keys, threshold,
and witness count are claims to compare with that policy, never verifier input.
"""
import json
import sys

from .witness import WitnessRegistry, verify_receipt


def main(argv=None):
    argv = argv or sys.argv[1:]
    if len(argv) != 2:
        print("usage: khipu-verify <receipt.json> <trust-policy.json>", file=sys.stderr)
        return 2
    try:
        with open(argv[0], encoding="utf-8") as receipt_file:
            receipt = json.load(receipt_file)
        with open(argv[1], encoding="utf-8") as policy_file:
            policy = json.load(policy_file)
        if not isinstance(receipt, dict) or not isinstance(policy, dict):
            raise TypeError("receipt and trust policy must be JSON objects")
        result = verify_receipt(
            receipt,
            registry=WitnessRegistry.from_dict(policy),
        )
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
        KeyError,
        AttributeError,
    ) as exc:
        print(f"verification input rejected: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["decision"] == "canonical" else 1


if __name__ == "__main__":
    raise SystemExit(main())
