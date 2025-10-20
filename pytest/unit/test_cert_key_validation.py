import pytest

from truenas_crypto_utils.validation import validate_certificate_with_key
from truenas_crypto_utils.key import generate_private_key
from truenas_crypto_utils.generate_certs import generate_certificate


@pytest.fixture
def rsa_cert_and_key():
    """Generate a matching RSA certificate and key pair"""
    cert, key = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test-rsa',
        'country': 'US',
        'digest_algorithm': 'SHA256',
        'lifetime': 365,
        'serial': 1001,
        'cert_extensions': {
            'BasicConstraints': {'enabled': False},
            'AuthorityKeyIdentifier': {'enabled': False},
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {'enabled': False},
        },
    })
    return cert, key


@pytest.fixture
def ec_cert_and_key():
    """Generate a matching EC certificate and key pair"""
    cert, key = generate_certificate({
        'key_type': 'EC',
        'ec_curve': 'SECP384R1',
        'common': 'test-ec',
        'country': 'US',
        'digest_algorithm': 'SHA256',
        'lifetime': 365,
        'serial': 1002,
        'cert_extensions': {
            'BasicConstraints': {'enabled': False},
            'AuthorityKeyIdentifier': {'enabled': False},
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {'enabled': False},
        },
    })
    return cert, key


@pytest.fixture
def rsa_key_4096():
    """Generate a 4096-bit RSA key"""
    return generate_private_key({'type': 'RSA', 'key_length': 4096}, serialize=True)


def test_validate_matching_rsa_cert_and_key(rsa_cert_and_key):
    """Test validation of matching RSA certificate and key"""
    cert, key = rsa_cert_and_key
    result = validate_certificate_with_key(cert, key)
    assert result is None  # None means success (no error message)


def test_validate_matching_ec_cert_and_key(ec_cert_and_key):
    """Test validation of matching EC certificate and key"""
    cert, key = ec_cert_and_key
    result = validate_certificate_with_key(cert, key)
    assert result is None  # None means success (no error message)


def test_validate_mismatched_cert_and_key(rsa_cert_and_key, rsa_key_4096):
    """Test validation of mismatched certificate and key"""
    cert, _ = rsa_cert_and_key
    wrong_key = rsa_key_4096
    result = validate_certificate_with_key(cert, wrong_key)
    assert result is not None  # Should return error message
    assert isinstance(result, str)


def test_validate_with_empty_certificate(rsa_cert_and_key):
    """Test validation with empty certificate"""
    _, key = rsa_cert_and_key
    result = validate_certificate_with_key("", key)
    assert result is None  # Returns None for empty cert


def test_validate_with_empty_key(rsa_cert_and_key):
    """Test validation with empty key"""
    cert, _ = rsa_cert_and_key
    result = validate_certificate_with_key(cert, "")
    assert result is None  # Returns None for empty key


def test_validate_with_both_empty():
    """Test validation with both certificate and key empty"""
    result = validate_certificate_with_key("", "")
    assert result is None


def test_validate_with_none_certificate(rsa_cert_and_key):
    """Test validation with None certificate"""
    _, key = rsa_cert_and_key
    result = validate_certificate_with_key(None, key)
    assert result is None


def test_validate_with_none_key(rsa_cert_and_key):
    """Test validation with None key"""
    cert, _ = rsa_cert_and_key
    result = validate_certificate_with_key(cert, None)
    assert result is None


def test_validate_different_key_types_mismatch(rsa_cert_and_key, ec_cert_and_key):
    """Test validation with different key types (RSA cert with EC key)"""
    rsa_cert, _ = rsa_cert_and_key
    _, ec_key = ec_cert_and_key
    result = validate_certificate_with_key(rsa_cert, ec_key)
    assert result is not None  # Should return error message
    assert isinstance(result, str)
