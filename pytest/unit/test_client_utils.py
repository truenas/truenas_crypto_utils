import json

import josepy as jose
import pytest
import requests
from acme import client, errors, messages
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from truenas_acme_utils.client_utils import acme_order


def make_response(status_code, body=None, headers=None):
    response = requests.Response()
    response.status_code = status_code
    response.headers.update({'Replay-Nonce': jose.b64encode(b'nonce').decode(), **(headers or {})})
    if body is not None:
        response.headers['Content-Type'] = 'application/json'
        response._content = json.dumps(body).encode()
    else:
        response._content = b''
    return response


def test_acme_order_retries_without_replaces_on_conflict(monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr_pem = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'example.com')])
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName('example.com')]), critical=False,
    ).sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)

    net = client.ClientNetwork(jose.JWKRSA(key=key))
    acme_client = client.ClientV2(messages.Directory({
        'newNonce': 'https://acme.test/new-nonce',
        'newOrder': 'https://acme.test/new-order',
    }), net)

    order_payloads = []

    def send_request(method, url, *args, **kwargs):
        if method == 'HEAD':
            return make_response(200)
        order_payloads.append(json.loads(jose.JWS.json_loads(kwargs['data']).payload))
        if 'replaces' in order_payloads[-1]:
            return make_response(409, {
                'type': 'urn:ietf:params:acme:error:alreadyReplaced',
                'detail': 'certificate has already been replaced',
            })
        return make_response(201, {
            'status': 'pending',
            'identifiers': [{'type': 'dns', 'value': 'example.com'}],
            'authorizations': [],
            'finalize': 'https://acme.test/finalize/1',
        }, {'Location': 'https://acme.test/order/1'})

    monkeypatch.setattr(net, '_send_request', send_request)
    order = acme_order(acme_client, csr_pem, 'old-cert-id')
    assert order.uri == 'https://acme.test/order/1'
    assert [p.get('replaces') for p in order_payloads] == ['old-cert-id', None]

    monkeypatch.setattr(net, '_send_request', lambda method, url, *a, **k: make_response(
        200 if method == 'HEAD' else 409,
    ))
    with pytest.raises(errors.ConflictError):
        acme_order(acme_client, csr_pem)
