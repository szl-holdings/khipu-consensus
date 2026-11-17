# SPDX-License-Identifier: Apache-2.0
"""Bounded admission/transport regressions. Synthetic keys and loopback only."""
import copy
from email.message import Message
import hashlib
import io
import json
import threading
import urllib.error
import urllib.request

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from khipu_consensus import adjudicate as api
from khipu_consensus.receipt_tree import ReceiptTree, seal_receipt_tree
from khipu_consensus.witness import Witness, WitnessRegistry

CAP = 1_048_576
TS = '2026-11-16T12:00:00+00:00'


@pytest.fixture
def valid():
    witnesses = []
    for i in range(4):
        key = ec.generate_private_key(ec.SECP256R1())
        public = key.public_key().public_bytes(serialization.Encoding.PEM,
                         serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        private = key.private_bytes(serialization.Encoding.PEM,
                         serialization.PrivateFormat.PKCS8,
                         serialization.NoEncryption()).decode() if i < 3 else None
        witnesses.append(Witness(organ=f'input-{i}', public_key_pem=public,
                                 private_key_pem=private, region='synthetic', org='test'))
    registry = WitnessRegistry(witnesses, threshold=3)
    leaves = [hashlib.sha256(f'case-{i}'.encode()).hexdigest() for i in range(3)]
    tree = ReceiptTree.build('bounded-input', leaves)
    receipt = seal_receipt_tree(tree, registry)
    return {'schema': api.ADJUDICATION_BUNDLE_SCHEMA, 'session_id': tree.session_id,
            'leaves': leaves, 'sth': receipt.to_dict()}, registry.pubkeys()


def test_security_canonical_positive_is_still_verified(valid):
    bundle, keys = valid
    before = copy.deepcopy(bundle)
    result = api.adjudicate(bundle, keys, ts=TS)
    assert result.verdict == 'VERIFIED' and len(result.bundle_digest) == 64
    assert bundle == before


@pytest.mark.parametrize('value', [float('nan'), float('inf'), float('-inf'),
                                   {'not-json'}, b'not-json', '\ud800'])
def test_security_unhashable_or_invalid_json_never_verified(valid, value):
    bundle, keys = valid
    bundle['extra'] = value
    result = api.adjudicate(bundle, keys, ts=TS)
    assert result.verdict == 'UNKNOWN'
    assert result.bundle_digest == ''


def test_security_cyclic_python_object_is_unknown(valid):
    bundle, keys = valid
    bundle['extra'] = bundle
    assert api.adjudicate(bundle, keys, ts=TS).verdict == 'UNKNOWN'


def test_security_direct_size_limit(valid):
    bundle, keys = valid
    bundle['extra'] = 'x' * (CAP + 1)
    assert api.adjudicate(bundle, keys, ts=TS).verdict == 'UNKNOWN'


def test_security_direct_depth_limit(valid):
    bundle, keys = valid
    value = 'leaf'
    for _ in range(66):
        value = [value]
    bundle['extra'] = value
    assert api.adjudicate(bundle, keys, ts=TS).verdict == 'UNKNOWN'


def test_security_nonstring_object_keys_rejected(valid):
    bundle, keys = valid
    bundle['extra'] = {1: 'value'}
    assert api.adjudicate(bundle, keys, ts=TS).verdict == 'UNKNOWN'


@pytest.mark.parametrize('token', ['NaN', 'Infinity', '-Infinity', '1e9999'])
def test_security_wire_nonfinite_unknown(valid, token):
    bundle, keys = valid
    body = ('{"extra":' + token + ',' + json.dumps(bundle)[1:]).encode()
    assert api.handle_adjudicate(body, keys, ts=TS).verdict == 'UNKNOWN'


@pytest.mark.parametrize('nested', [False, True])
def test_security_duplicate_json_members_unknown(valid, nested):
    bundle, keys = valid
    text = json.dumps(bundle)
    if nested:
        text = text.replace('"tree_size": 3', '"tree_size": 99, "tree_size": 3', 1)
    else:
        text = '{"session_id":"different",' + text[1:]
    assert api.handle_adjudicate(text.encode(), keys, ts=TS).verdict == 'UNKNOWN'


def test_security_oversized_wire_body_unknown(valid):
    bundle, keys = valid
    raw = json.dumps(bundle).encode() + b' ' * CAP
    assert api.handle_adjudicate(raw, keys, ts=TS).verdict == 'UNKNOWN'


@pytest.mark.parametrize('threshold,ts', [(True, TS), ('3', TS), (3, '\ud800'), (3, [])])
def test_security_invalid_caller_metadata_never_throws(valid, threshold, ts):
    bundle, keys = valid
    result = api.adjudicate(bundle, keys, threshold=threshold, ts=ts)
    assert result.verdict == 'UNKNOWN'
    assert isinstance(result.receipt['digest'], str)


class NoRead(io.BytesIO):
    def read(self, *args):
        raise AssertionError('Rejected framing must not read the body')
    read1 = read


class FakeSocket:
    def settimeout(self, value):
        self.timeout = value
    def gettimeout(self):
        return getattr(self, 'timeout', None)


def handler(headers, stream):
    instance = object.__new__(api.AdjudicationHTTPHandler)
    instance.path = '/adjudicate'
    instance.headers = Message()
    for key, value in headers:
        instance.headers.add_header(key, value)
    instance.rfile = stream
    instance.connection = FakeSocket()
    instance.trusted_pubkeys = {}
    instance.threshold = 3
    responses = []
    instance._respond = lambda code, payload: responses.append((code, payload))
    return instance, responses


@pytest.mark.parametrize('headers,code', [
    ([], 411),
    ([('Content-Length', '-1')], 400),
    ([('Content-Length', 'bad')], 400),
    ([('Content-Length', '+2')], 400),
    ([('Content-Length', str(CAP + 1))], 413),
    ([('Content-Length', '2'), ('Content-Length', '2')], 400),
    ([('Content-Length', '2'), ('Transfer-Encoding', 'chunked')], 400),
])
def test_security_framing_rejected_before_body_read(headers, code):
    instance, responses = handler(headers, NoRead())
    instance.do_POST()
    assert responses[0][0] == code


def test_security_incomplete_body_is_transport_error():
    instance, responses = handler([('Content-Length', '100')], io.BytesIO(b'{}'))
    instance.do_POST()
    assert responses[0][0] == 400


def test_security_body_timeout_is_transport_error():
    class TimeoutStream(io.BytesIO):
        def read(self, *args):
            raise TimeoutError('synthetic')
        read1 = read
    instance, responses = handler([('Content-Length', '2')], TimeoutStream())
    instance.do_POST()
    assert responses[0][0] == 408


@pytest.mark.parametrize('host', ['0.0.0.0', '192.0.2.1', 'example.invalid'])
def test_security_nonloopback_binding_rejected_before_socket(monkeypatch, host):
    def unexpected(*args, **kwargs):
        raise AssertionError('Must not bind an unapproved interface')
    monkeypatch.setattr(api, 'HTTPServer', unexpected)
    with pytest.raises(ValueError):
        api.make_adjudication_server({}, host=host)


@pytest.mark.parametrize('threshold', [True, '3', 1, 3.5])
def test_security_server_threshold_not_coerced(threshold):
    with pytest.raises(ValueError):
        server = api.make_adjudication_server({}, threshold=threshold)
        server.server_close()


def test_security_real_loopback_valid_then_ambiguous(valid):
    bundle, keys = valid
    server = api.make_adjudication_server(keys, port=0)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        url = f'http://127.0.0.1:{server.server_port}/adjudicate'
        for raw, expected in [(json.dumps(bundle).encode(), 'VERIFIED'),
                              (('{"session_id":"different",' + json.dumps(bundle)[1:]).encode(), 'UNKNOWN')]:
            request = urllib.request.Request(url, data=raw,
                                              headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(request, timeout=3) as response:
                assert response.status == 200
                assert json.loads(response.read())['verdict'] == expected
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)
    assert not worker.is_alive()
