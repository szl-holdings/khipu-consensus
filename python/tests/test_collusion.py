import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from khipu_consensus.collusion import Witness, full_lane, run_campaign, run_round
PAYLOAD = {"proposal":"interdiction", "amount":5, "nonce":42}
def test_honest_round_passes_with_all_four_signers():
 r=run_round([Witness(i) for i in range(4)],PAYLOAD,False); assert r["outcome"]=="PASSED" and r["signers"]==[0,1,2,3]
def test_honest_witness_never_signs_a_lie():
 r=run_round([Witness(i,colluder=(i==0)) for i in range(4)],PAYLOAD,True); assert r["outcome"]=="REPELLED" and r["signers"]==[0]
def test_below_quorum_attacks_repelled_for_1_and_2_colluders():
 for k in (1,2):
  s=run_campaign(k,rounds=50); assert s["repelled"]==50 and s["quorum_breach_chain_caught"]==0
def test_quorum_breach_caught_by_chain_for_3_and_4_colluders():
 for k in (3,4):
  s=run_campaign(k,rounds=50); assert s["repelled"]==0 and s["quorum_breach_chain_caught"]==50
def test_lane_is_deterministic(): assert full_lane(rounds=50)["lane_digest"]==full_lane(rounds=50)["lane_digest"]
def test_lane_contract_labels():
 l=full_lane(rounds=10); assert l["state"]=="MEASURED" and l["simulation"] and l["not_production_crypto"] and "witnesses alone breach" in l["verdict"]
def test_tamper_detection_is_hash_divergence():
 r=run_round([Witness(i,colluder=True) for i in range(3)]+[Witness(3)],PAYLOAD,True); assert r["quorum_reached"] and r["presented_hash"]!=r["committed_hash"] and r["tamper_detected"]
