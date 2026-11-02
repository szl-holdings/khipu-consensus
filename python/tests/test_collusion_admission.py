"""A measured collusion campaign requires actual, well-defined trials."""
from unittest.mock import patch

import pytest

from khipu_consensus import collusion


@pytest.mark.parametrize("rounds", [0, -1, True, False, 1.5, float("nan"), float("inf"), "1", None])
@pytest.mark.parametrize("entry", ["run_campaign", "full_lane"])
def test_invalid_round_count_cannot_emit_measurement(rounds, entry):
    with patch.object(collusion, "Witness") as witness:
        with pytest.raises(ValueError, match="rounds must be a positive integer"):
            if entry == "run_campaign":
                collusion.run_campaign(1, rounds=rounds)
            else:
                collusion.full_lane(rounds=rounds)
        witness.assert_not_called()


@pytest.mark.parametrize("colluders", [-1, 5, True, False, 1.5, float("nan"), float("inf"), "1", None])
def test_invalid_colluder_count_rejected_before_witness_creation(colluders):
    with patch.object(collusion, "Witness") as witness:
        with pytest.raises(ValueError, match="colluders must be an integer in 0..4"):
            collusion.run_campaign(colluders, rounds=1)
        witness.assert_not_called()


def test_minimum_campaign_records_one_actual_trial_per_spectrum_entry():
    lane = collusion.full_lane(rounds=1)
    assert lane["state"] == "MEASURED"
    assert lane["simulation"] is True
    assert lane["not_production_crypto"] is True
    for colluders, result in enumerate(lane["spectrum"]):
        assert result["colluders"] == colluders
        assert result["rounds"] == 1
        counts = [result[k] for k in ("repelled", "quorum_breach_chain_caught", "passed_honest")]
        assert sum(counts) == 1
        assert counts == ([0, 0, 1] if colluders == 0 else [1, 0, 0] if colluders < 3 else [0, 1, 0])
