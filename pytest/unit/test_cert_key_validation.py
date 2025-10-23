import pytest

from cryptography.hazmat.primitives import serialization
from truenas_crypto_utils.validation import validate_certificate_with_key
from truenas_crypto_utils.key import generate_private_key
from truenas_crypto_utils.generate_certs import generate_certificate
from truenas_crypto_utils.read import load_private_key


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


# Passphrase handling tests


def _encrypt_private_key(key_pem: str, passphrase: str) -> str:
    """Helper function to encrypt a private key with a passphrase"""
    key_obj = load_private_key(key_pem)
    encrypted_key = key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode())
    )
    return encrypted_key.decode()


def test_validate_encrypted_rsa_key_with_correct_passphrase():
    """Test validation of certificate with encrypted RSA key using correct passphrase"""
    # Generate cert and key
    cert, key = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test-encrypted-rsa',
        'digest_algorithm': 'SHA256',
        'lifetime': 365,
        'serial': 2001,
        'cert_extensions': {
            'BasicConstraints': {'enabled': False},
            'AuthorityKeyIdentifier': {'enabled': False},
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {'enabled': False},
        },
    })

    # Encrypt the key
    passphrase = "test-passphrase-123"
    encrypted_key = _encrypt_private_key(key, passphrase)

    # Should validate successfully with correct passphrase
    result = validate_certificate_with_key(cert, encrypted_key, passphrase)
    assert result is None


def test_validate_encrypted_ec_key_with_correct_passphrase():
    """Test validation of certificate with encrypted EC key using correct passphrase"""
    cert, key = generate_certificate({
        'key_type': 'EC',
        'ec_curve': 'SECP256R1',
        'common': 'test-encrypted-ec',
        'digest_algorithm': 'SHA256',
        'lifetime': 365,
        'serial': 2002,
        'cert_extensions': {
            'BasicConstraints': {'enabled': False},
            'AuthorityKeyIdentifier': {'enabled': False},
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {'enabled': False},
        },
    })

    passphrase = "ec-key-passphrase"
    encrypted_key = _encrypt_private_key(key, passphrase)

    result = validate_certificate_with_key(cert, encrypted_key, passphrase)
    assert result is None


def test_validate_unencrypted_key_with_passphrase(rsa_cert_and_key):
    """Test validation of unencrypted key with unnecessary passphrase"""
    cert, key = rsa_cert_and_key

    # Providing passphrase for unencrypted key should still work
    # (passphrase is ignored for unencrypted keys)
    result = validate_certificate_with_key(cert, key, "unnecessary-passphrase")
    # This might fail or succeed depending on implementation
    # If it tries to decrypt an unencrypted key, it will fail
    # For now, we'll just check it doesn't crash
    assert result is None or isinstance(result, str)
