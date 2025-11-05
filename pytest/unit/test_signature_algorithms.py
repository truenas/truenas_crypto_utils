import pytest

from truenas_crypto_utils.read import load_certificate
from truenas_crypto_utils.generate_certs import generate_certificate


@pytest.mark.parametrize('digest_algo,expected_in_cert', [
    ('SHA256', 'SHA256'),
    ('SHA384', 'SHA384'),
    ('SHA512', 'SHA512'),
    ('SHA224', 'SHA224'),
])
def test_rsa_signature_algorithms(digest_algo, expected_in_cert):
    """Test RSA certificates with different digest algorithms"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test.example.com',
        'digest_algorithm': digest_algo,
        'lifetime': 365,
        'serial': 3001,
        'cert_extensions': {
            'BasicConstraints': {'enabled': False},
            'AuthorityKeyIdentifier': {'enabled': False},
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {'enabled': False},
        },
    })
    cert_info = load_certificate(cert)

    assert 'digest_algorithm' in cert_info
    assert cert_info['digest_algorithm'] == expected_in_cert


@pytest.mark.parametrize('digest_algo,expected_in_cert', [
    ('SHA256', 'SHA256'),
    ('SHA384', 'SHA384'),
    ('SHA512', 'SHA512'),
])
def test_ec_signature_algorithms(digest_algo, expected_in_cert):
    """Test EC certificates with different digest algorithms"""
    cert, _ = generate_certificate({
        'key_type': 'EC',
        'ec_curve': 'SECP384R1',
        'common': 'test.example.com',
        'digest_algorithm': digest_algo,
        'lifetime': 365,
        'serial': 3002,
        'cert_extensions': {
            'BasicConstraints': {'enabled': False},
            'AuthorityKeyIdentifier': {'enabled': False},
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {'enabled': False},
        },
    })
    cert_info = load_certificate(cert)

    assert 'digest_algorithm' in cert_info
    assert cert_info['digest_algorithm'] == expected_in_cert


def test_ed25519_signature_algorithm():
    """Test Ed25519 certificate signature algorithm"""
    cert, _ = generate_certificate({
        'key_type': 'ED25519',
        'common': 'test.example.com',
        'lifetime': 365,
        'serial': 3003,
        'cert_extensions': {
            'BasicConstraints': {'enabled': False},
            'AuthorityKeyIdentifier': {'enabled': False},
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {'enabled': False},
        },
    })
    cert_info = load_certificate(cert)

    assert 'digest_algorithm' in cert_info


def test_signature_algorithm_case_normalization():
    """Test that signature algorithms are normalized to uppercase"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test.example.com',
        'digest_algorithm': 'SHA256',
        'lifetime': 365,
        'serial': 3010,
        'cert_extensions': {
            'BasicConstraints': {'enabled': False},
            'AuthorityKeyIdentifier': {'enabled': False},
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {'enabled': False},
        },
    })
    cert_info = load_certificate(cert)

    assert cert_info['digest_algorithm'].isupper()
