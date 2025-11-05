import textwrap

from cryptography.hazmat.primitives import serialization
from truenas_crypto_utils.validation import validate_private_key
from truenas_crypto_utils.key import generate_private_key
from truenas_crypto_utils.read import load_private_key


def test_validate_rsa_2048_key():
    """Test validation of RSA 2048-bit key"""
    key = generate_private_key({'type': 'RSA', 'key_length': 2048}, serialize=True)
    result = validate_private_key(key)
    assert result is None  # None means valid


def test_validate_rsa_4096_key():
    """Test validation of RSA 4096-bit key"""
    key = generate_private_key({'type': 'RSA', 'key_length': 4096}, serialize=True)
    result = validate_private_key(key)
    assert result is None  # None means valid


def test_validate_rsa_1024_key():
    """Test validation of RSA 1024-bit key (minimum allowed)"""
    key = generate_private_key({'type': 'RSA', 'key_length': 1024}, serialize=True)
    result = validate_private_key(key)
    assert result is None  # 1024 is the minimum allowed


def test_validate_ec_secp256r1_key():
    """Test validation of EC SECP256R1 key"""
    key = generate_private_key({'type': 'EC', 'curve': 'SECP256R1'}, serialize=True)
    result = validate_private_key(key)
    assert result is None  # EC keys are exempt from size check


def test_validate_ec_secp384r1_key():
    """Test validation of EC SECP384R1 key (default)"""
    key = generate_private_key({'type': 'EC'}, serialize=True)
    result = validate_private_key(key)
    assert result is None


def test_validate_ec_secp521r1_key():
    """Test validation of EC SECP521R1 key"""
    key = generate_private_key({'type': 'EC', 'curve': 'SECP521R1'}, serialize=True)
    result = validate_private_key(key)
    assert result is None


def test_validate_ed25519_key():
    """Test validation of Ed25519 key"""
    key = generate_private_key({'type': 'EC', 'curve': 'ed25519'}, serialize=True)
    result = validate_private_key(key)
    assert result is None  # Ed25519 keys are exempt from size check


def test_validate_invalid_key_format():
    """Test validation of invalid key format"""
    invalid_key = "NOT A VALID KEY"
    result = validate_private_key(invalid_key)
    assert result is not None
    assert 'valid private key is required' in result.lower()


def test_validate_empty_key():
    """Test validation of empty key"""
    result = validate_private_key("")
    assert result is not None
    assert 'valid private key is required' in result.lower()


def test_validate_none_key():
    """Test validation of None key"""
    result = validate_private_key(None)
    assert result is not None
    assert 'valid private key is required' in result.lower()


def test_validate_malformed_key():
    """Test validation of malformed key"""
    malformed_key = textwrap.dedent('''\
        -----BEGIN PRIVATE KEY-----
        THIS IS NOT A VALID BASE64 ENCODED KEY!!!
        -----END PRIVATE KEY-----
    ''')
    result = validate_private_key(malformed_key)
    assert result is not None
    assert 'valid private key is required' in result.lower()


def test_validate_key_missing_header():
    """Test validation of key with missing header"""
    no_header = textwrap.dedent('''\
        MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDVMPccUqq6jd8h
        -----END PRIVATE KEY-----
    ''')
    result = validate_private_key(no_header)
    assert result is not None
    assert 'valid private key is required' in result.lower()


def test_validate_key_missing_footer():
    """Test validation of key with missing footer"""
    no_footer = textwrap.dedent('''\
        -----BEGIN PRIVATE KEY-----
        MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDVMPccUqq6jd8h
    ''')
    result = validate_private_key(no_footer)
    assert result is not None
    assert 'valid private key is required' in result.lower()


def test_validate_public_key_instead_of_private():
    """Test validation when public key is provided instead of private key"""
    public_key = textwrap.dedent('''\
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw8xNMQbL8F7L1Q9L3N8T
        5L1Q9L3N8T5L1Q9L3N8T5L1Q9L3N8T5L1Q9L3N8T5L1Q9L3N8T5L1QIDAQAB
        -----END PUBLIC KEY-----
    ''')
    result = validate_private_key(public_key)
    assert result is not None
    assert 'valid private key is required' in result.lower()


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


def test_validate_encrypted_rsa_key_correct_passphrase():
    """Test validation of encrypted RSA key with correct passphrase"""
    key = generate_private_key({'type': 'RSA', 'key_length': 2048}, serialize=True)
    passphrase = "test-passphrase-rsa"
    encrypted_key = _encrypt_private_key(key, passphrase)

    result = validate_private_key(encrypted_key, passphrase)
    assert result is None


def test_validate_encrypted_ec_key_correct_passphrase():
    """Test validation of encrypted EC key with correct passphrase"""
    key = generate_private_key({'type': 'EC', 'curve': 'SECP256R1'}, serialize=True)
    passphrase = "test-passphrase-ec"
    encrypted_key = _encrypt_private_key(key, passphrase)

    result = validate_private_key(encrypted_key, passphrase)
    assert result is None


def test_validate_encrypted_ed25519_key_correct_passphrase():
    """Test validation of encrypted Ed25519 key with correct passphrase"""
    key = generate_private_key({'type': 'EC', 'curve': 'ed25519'}, serialize=True)
    passphrase = "test-passphrase-ed25519"
    encrypted_key = _encrypt_private_key(key, passphrase)

    result = validate_private_key(encrypted_key, passphrase)
    assert result is None


# RSA key size boundary tests


def test_validate_rsa_8192_key():
    """Test validation of RSA 8192-bit key (very large but valid)"""
    key = generate_private_key({'type': 'RSA', 'key_length': 8192}, serialize=True)
    result = validate_private_key(key)
    assert result is None
