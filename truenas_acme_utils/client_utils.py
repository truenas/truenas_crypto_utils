import json
import typing

import josepy as jose
from acme import client, crypto_util, messages
from cryptography import x509


class BodyDict(typing.TypedDict):
    status: str
    key: str


class ACMEClientAndKeyData(typing.TypedDict):
    uri: str
    tos: bool | str
    new_account_uri: str
    new_nonce_uri: str
    new_order_uri: str
    revoke_cert_uri: str
    renewal_info: str | None
    body: BodyDict


def get_acme_client_and_key(data: ACMEClientAndKeyData) -> tuple[client.ClientV2, jose.JWKRSA]:
    """
    Expected data dict should contain the following
    - uri: str
    - tos: bool | str
    - new_account_uri: str
    - new_nonce_uri: str
    - new_order_uri: str
    - revoke_cert_uri: str
    - renewal_info: str (optional)
    - body: dict
        - status: str
        - key: dict
            - e: str
            - n
    """

    # Making key now
    key = jose.JWKRSA.fields_from_json(json.loads(data['body']['key']))
    key_dict = key.fields_to_partial_json()
    # Making registration resource now
    registration = messages.RegistrationResource.from_json({
        'uri': data['uri'],
        'terms_of_service': data['tos'],
        'body': {
            'status': data['body']['status'],
            'key': {
                'e': key_dict['e'],
                'kty': 'RSA',
                'n': key_dict['n']
            }
        }
    })

    return client.ClientV2(
        messages.Directory({
            'newAccount': data['new_account_uri'],
            'newNonce': data['new_nonce_uri'],
            'newOrder': data['new_order_uri'],
            'revokeCert': data['revoke_cert_uri'],
            **({'renewalInfo': data['renewal_info']} if data.get('renewal_info') else {}),
        }),
        client.ClientNetwork(key, account=registration)
    ), key


def acme_order(acme_client: client.ClientV2, csr_pem: bytes) -> messages.OrderResource:
    csr = x509.load_pem_x509_csr(csr_pem)
    dnsNames = crypto_util.get_names_from_subject_and_extensions(csr.subject, csr.extensions)
    try:
        san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        ipNames = []
    else:
        ipNames = san_ext.value.get_values_for_type(x509.IPAddress)

    identifiers = []
    for name in dnsNames:
        identifiers.append(messages.Identifier(typ=messages.IDENTIFIER_FQDN, value=name))

    for ip in ipNames:
        identifiers.append(messages.Identifier(typ=messages.IDENTIFIER_IP, value=str(ip)))

    order = messages.NewOrder(identifiers=identifiers)
    response = acme_client._post(acme_client.directory['newOrder'], order)
    body = messages.Order.from_json(response.json())

    authorizations = []
    # pylint has trouble understanding our josepy based objects which use
    # things like custom metaclass logic. body.authorizations should be a
    # list of strings containing URLs so let's disable this check here.
    for url in body.authorizations:  # pylint: disable=not-an-iterable
        authorizations.append(acme_client._authzr_from_response(acme_client._post_as_get(url), uri=url))

    return messages.OrderResource(
        body=body,
        uri=response.headers.get('Location'),
        authorizations=authorizations,
        csr_pem=csr_pem,
    )
