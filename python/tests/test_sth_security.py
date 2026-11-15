"""Defensive review probes for PR66 at its exact head. Synthetic keys only.

These are proposed hardening requirements, not an assertion of deployed exposure.
No network, external data, production key or collaborator edit is involved.
"""
import copy
import hashlib
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from khipu_consensus.witness import Witness, WitnessRegistry
from khipu_consensus import sth as subject


def pair():
    private=ec.generate_private_key(ec.SECP256R1())
    return (private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()).decode(),
            private.public_key().public_bytes(serialization.Encoding.PEM,
                                  serialization.PublicFormat.SubjectPublicKeyInfo).decode())


def fixture(*,same_key=False,leaves=1):
    one=pair()
    ws=[]
    for index in range(4):
        private,public=one if same_key else pair()
        ws.append(Witness(organ=f'review-{index}',public_key_pem=public,
                          private_key_pem=private if index<3 else None,region='synthetic',org='test'))
    registry=WitnessRegistry(ws,threshold=3)
    head=subject.build_sth('review-session',[hashlib.sha256(f'record-{i}'.encode()).hexdigest()
                                           for i in range(leaves)],timestamp='2026-11-15T22:00:00Z')
    return registry,subject.countersign_sth(head,registry).to_dict()


def test_review_positive_real_signatures():
    registry,receipt=fixture()
    assert subject.verify_sth_receipt(receipt,registry.pubkeys()).status=='VERIFIED'


def test_review_signature_tamper_positive_control():
    registry,receipt=fixture()
    receipt['signatures'][0]['signature']='AAAA'
    assert subject.verify_sth_receipt(receipt,registry.pubkeys()).status!='VERIFIED'


def test_review_same_key_cannot_be_four_independent_witness_keys():
    registry,receipt=fixture(same_key=True)
    result=subject.verify_sth_receipt(receipt,registry.pubkeys())
    assert result.status!='VERIFIED', 'same private key under four organ names counted as distinct witness keys'


def test_review_timestamp_changes_invalidate_signed_head():
    registry,receipt=fixture()
    receipt['sth']['timestamp']='2099-01-01T00:00:00Z'
    result=subject.verify_sth_receipt(receipt,registry.pubkeys())
    assert result.status!='VERIFIED', 'advertised STH timestamp changed without changing any signature'


def test_review_nested_sth_must_agree_with_signed_top_level():
    registry,receipt=fixture()
    receipt['sth'].update(schema='different-schema',session_id='different-session',
                          tree_size=999,sha256_root_hash='f'*64,version=999)
    result=subject.verify_sth_receipt(receipt,registry.pubkeys())
    assert result.status!='VERIFIED', 'all nested STH fields contradicted the verified top-level claims'


def test_review_boolean_population_not_integer():
    registry,receipt=fixture(leaves=1)
    receipt['tree_size']=True
    result=subject.verify_sth_receipt(receipt,registry.pubkeys())
    assert result.status!='VERIFIED', 'True accepted as signed integer population 1'


def test_review_malformed_signature_yields_unknown_not_uncaught_error():
    registry,receipt=fixture()
    receipt['signatures']=[42]
    try:
        result=subject.verify_sth_receipt(receipt,registry.pubkeys())
    except Exception as exc:
        pytest.fail('Malformed signature raised '+type(exc).__name__+' instead of UNKNOWN')
    assert result.status=='UNKNOWN'


def test_review_empty_population_does_not_release_recalls():
    registry,receipt=fixture(leaves=0)
    result=subject.verify_sth_receipt(receipt,registry.pubkeys())
    assert subject.release_allowed(result) is False, 'zero receipt population enabled release_allowed'


def test_review_constructed_status_object_is_not_an_authorization_gate():
    fake=subject.STHVerdict(subject.STH_ADJUDICATION_SCHEMA,'VERIFIED','fake',1,'a'*64,0,3,4,[],
                           'constructed without signature verification')
    assert subject.release_allowed(fake) is False, 'mutable caller-constructed VERIFIED object enabled release_allowed'


from datetime import datetime, timedelta, timezone
from khipu_consensus import receipt_tree as rt


def context(receipt):
    return dict(expected_root=receipt['sha256_root_hash'],
                expected_session_id=receipt['session_id'],
                expected_tree_size=receipt['tree_size'],
                now=datetime(2026,11,15,22,0,1,tzinfo=timezone.utc),
                max_age_seconds=300,hard_deny=False)


def test_full_evidence_predicate_has_a_real_positive_path():
    registry,receipt=fixture()
    assert subject.receipt_release_eligible(receipt,trusted_pubkeys=registry.pubkeys(),**context(receipt))
    assert not subject.release_allowed(subject.verify_sth_receipt(receipt,registry.pubkeys()))


@pytest.mark.parametrize('missing',['expected_root','expected_session_id','expected_tree_size','now','max_age_seconds','hard_deny'])
def test_missing_caller_context_denies(missing):
    registry,receipt=fixture();ctx=context(receipt);ctx.pop(missing)
    assert not subject.receipt_release_eligible(receipt,trusted_pubkeys=registry.pubkeys(),**ctx)


@pytest.mark.parametrize('bad',[True,None,'false',0,1,[],{}])
def test_untrusted_or_hard_deny_values_never_grant(bad):
    registry,receipt=fixture();ctx={**context(receipt),'hard_deny':bad}
    assert not subject.receipt_release_eligible(receipt,trusted_pubkeys=registry.pubkeys(),**ctx)


@pytest.mark.parametrize('seconds',[-1,300,301,86400])
def test_expired_or_future_head_denies(seconds):
    registry,receipt=fixture();ctx=context(receipt)
    ctx['now']=datetime(2026,11,15,22,0,0,tzinfo=timezone.utc)+timedelta(seconds=seconds)
    assert not subject.receipt_release_eligible(receipt,trusted_pubkeys=registry.pubkeys(),**ctx)


@pytest.mark.parametrize('bad',[None,True,0,-1,1.5,3601,'300'])
def test_invalid_or_unbounded_ttl_denies(bad):
    registry,receipt=fixture();ctx={**context(receipt),'max_age_seconds':bad}
    assert not subject.receipt_release_eligible(receipt,trusted_pubkeys=registry.pubkeys(),**ctx)


def test_naive_clock_denies():
    registry,receipt=fixture();ctx=context(receipt);ctx['now']=ctx['now'].replace(tzinfo=None)
    assert not subject.receipt_release_eligible(receipt,trusted_pubkeys=registry.pubkeys(),**ctx)


@pytest.mark.parametrize('key,value',[('expected_root','f'*64),('expected_session_id','other'),('expected_tree_size',True),('expected_tree_size',0),('expected_tree_size',2)])
def test_expected_scope_is_not_taken_from_bundle(key,value):
    registry,receipt=fixture();ctx={**context(receipt),key:value}
    assert not subject.receipt_release_eligible(receipt,trusted_pubkeys=registry.pubkeys(),**ctx)


def test_legacy_v1_is_unknown_not_silently_upgraded():
    registry,receipt=fixture();receipt['schema']='szl.khipu.sth-countersign-receipt/v1'
    assert subject.verify_sth_receipt(receipt,registry.pubkeys()).status=='UNKNOWN'
    assert not subject.receipt_release_eligible(receipt,trusted_pubkeys=registry.pubkeys(),**context(receipt))


@pytest.mark.parametrize('field,value',[('timestamp','2099-01-01T00:00:00Z'),('schema','other'),('version',1),('session_id','other'),('tree_size',2),('sha256_root_hash','f'*64)])
def test_every_header_field_is_bound(field,value):
    registry,receipt=fixture();receipt['sth'][field]=value
    assert subject.verify_sth_receipt(receipt,registry.pubkeys()).status!='VERIFIED'


@pytest.mark.parametrize('field,value',[('threshold',True),('threshold',1),('n',True),('n',1),('tree_size',-1),('tree_size',4097)])
def test_claimed_population_and_threshold_cannot_downgrade_policy(field,value):
    registry,receipt=fixture();receipt[field]=value
    assert subject.verify_sth_receipt(receipt,registry.pubkeys()).status!='VERIFIED'


@pytest.mark.parametrize('bad',[42,[],{},'bad',{'organ':[]}, {'organ':'review-0','keyid':2}])
def test_malformed_signature_rows_fail_closed_without_exception(bad):
    registry,receipt=fixture();receipt['signatures']=[bad]
    assert subject.verify_sth_receipt(receipt,registry.pubkeys()).status=='UNKNOWN'


def test_excessive_signature_population_is_rejected():
    registry,receipt=fixture();receipt['signatures']*=2
    assert subject.verify_sth_receipt(receipt,registry.pubkeys()).status=='UNKNOWN'


def test_payload_size_is_bounded_before_parsing():
    registry,receipt=fixture();receipt['signatures'][0]['payload']='x'*16385
    assert subject.verify_sth_receipt(receipt,registry.pubkeys()).status=='UNKNOWN'


def test_merkle_population_is_bounded_and_hex_strict():
    with pytest.raises(ValueError):subject.merkle_root(['a'*64]*4097)
    with pytest.raises(ValueError):subject.merkle_root(['00 '*21+' '])
    with pytest.raises(ValueError):subject.merkle_root(iter(['a'*64]))


def test_readonly_verification_preserves_original_bundle():
    registry,receipt=fixture();before=copy.deepcopy(receipt)
    subject.verify_sth_receipt(receipt,registry.pubkeys())
    assert receipt==before


def sealed():
    registry,_=fixture()
    tree=rt.ReceiptTree.build('review-session',[hashlib.sha256(b'record-0').hexdigest()])
    receipt=subject.countersign_sth(tree.sth(timestamp='2026-11-15T22:00:00Z'),registry).to_dict()
    return tree,registry,receipt


def test_recall_positive_path_reverifies_original_material():
    tree,registry,receipt=sealed()
    result=rt.recall_gate(tree,receipt,registry.pubkeys(),0,tree.leaf(0),
                         hard_deny=False,now=context(receipt)['now'],max_age_seconds=300)
    assert result.release is True
    assert result.execution_authorized is False and result.policy_authorized is False


def test_recall_defaults_to_deny_without_trusted_policy_context():
    tree,registry,receipt=sealed()
    assert rt.recall_gate(tree,receipt,registry.pubkeys(),0,tree.leaf(0)).release is False


def test_no_signature_quorum_can_lift_hard_deny():
    tree,registry,receipt=sealed()
    result=rt.recall_gate(tree,receipt,registry.pubkeys(),0,tree.leaf(0),
                         hard_deny=True,now=context(receipt)['now'],max_age_seconds=300)
    assert result.release is False and result.execution_authorized is False


@pytest.mark.parametrize('size',[True,None,'1',2,-1,4097])
def test_malformed_tree_size_denies_without_exception(size):
    tree,registry,receipt=sealed();tree.tree_size=size
    result=rt.recall_gate(tree,receipt,registry.pubkeys(),0,hashlib.sha256(b'record-0').hexdigest(),
                         hard_deny=False,now=context(receipt)['now'],max_age_seconds=300)
    assert result.release is False


def test_inclusion_huge_claim_is_bounded_before_iteration():
    assert not rt.verify_inclusion('a'*64,0,1<<1000,[],'b'*64)


def test_serialized_status_and_authority_fields_do_not_grant():
    decision=rt.RecallDecision.from_dict({'status':'VERIFIED','release':'false',
                                        'execution_authorized':True,'policy_authorized':True})
    assert decision.release is False
    assert decision.execution_authorized is False and decision.policy_authorized is False
