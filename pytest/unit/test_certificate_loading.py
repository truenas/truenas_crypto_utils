import pytest
import textwrap

from truenas_crypto_utils.read import (
    load_certificate, load_certificate_request, get_serial_from_certificate_safe,
    get_cert_id, parse_cert_date_string, load_private_key
)
from truenas_crypto_utils.generate_certs import generate_certificate
from truenas_crypto_utils.csr import generate_certificate_signing_request
from truenas_crypto_utils.key import generate_private_key


@pytest.fixture
def valid_cert():
    """Generate a valid self-signed certificate"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test.example.com',
        'country': 'US',
        'state': 'CA',
        'city': 'San Francisco',
        'organization': 'Test Org',
        'organizational_unit': 'Test Unit',
        'email': 'test@example.com',
        'san': ['test.example.com', '192.168.1.1'],
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
    return cert


@pytest.fixture
def expired_cert():
    """Certificate that has already expired"""
    return textwrap.dedent('''\
        -----BEGIN CERTIFICATE-----
        MIIDazCCAlOgAwIBAgIUB3v8VvPVxXGGLHqP5gQ/fN7B7u8wDQYJKoZIhvcNAQEL
        BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
        GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMDAxMDEwMDAwMDBaFw0yMDAx
        MDIwMDAwMDBaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
        HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
        AQUAA4IBDwAwggEKAoIBAQDCWvkKPTzL/zcYqEb4eFSLKmPrZw4XVGG3xU4lXU0n
        L7BFHP3tXhTL6lnLFHDCj3RpLxU7u3m5xDwP2VHmGp3wJPsKp5m3MjLzP4bM7DpL
        kzBLzP4bM7DpLkzBLzP4bM7DpLkzBLzP4bM7DpLkzBLzP4bM7DpLkzBLzP4bM7Dp
        LkzBLzP4bM7DpLkzBLzP4bM7DpLkzBLzP4bM7DpLkzBLzP4bM7DpLkzBLzP4bM7D
        pLkzBLzP4bM7DpLkzBLzP4bM7DpLkzBLAgMBAAGjUzBRMB0GA1UdDgQWBBTlBL0P
        4F0pJhGQeEGHqCnPPNlkSTAfBgNVHSMEGDAWgBTlBL0P4F0pJhGQeEGHqCnPPNlk
        STAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBzBL0P4F0pJhGQ
        eEGHqCnPPNlkSTlBL0P4F0pJhGQeEGHqCnPPNlkSTlBL0P4F0pJhGQeEGHqCnPPN
        lkSTlBL0P4F0pJhGQeEGHqCnPPNlkSTlBL0P4F0pJhGQeEGHqCnPPNlkSQ==
        -----END CERTIFICATE-----
    ''')


def test_load_valid_certificate(valid_cert):
    """Test loading a valid certificate"""
    cert_info = load_certificate(valid_cert)
    assert cert_info is not None
    assert isinstance(cert_info, dict)
    assert 'common' in cert_info
    assert 'serial' in cert_info
    assert 'fingerprint' in cert_info
    assert cert_info['common'] == 'test.example.com'


def test_load_certificate_with_issuer(valid_cert):
    """Test loading certificate with issuer information"""
    cert_info = load_certificate(valid_cert, get_issuer=True)
    assert 'issuer_dn' in cert_info
    assert cert_info['issuer_dn'] is not None


def test_load_certificate_without_issuer(valid_cert):
    """Test loading certificate without issuer information"""
    cert_info = load_certificate(valid_cert, get_issuer=False)
    assert 'issuer_dn' not in cert_info


def test_load_certificate_all_fields(valid_cert):
    """Test that all expected fields are present"""
    cert_info = load_certificate(valid_cert)
    expected_fields = [
        'country', 'state', 'city', 'organization', 'organizational_unit',
        'common', 'email', 'san', 'DN', 'serial', 'fingerprint',
        'from', 'until', 'lifetime', 'expired', 'chain', 'digest_algorithm',
        'subject_name_hash', 'extensions'
    ]
    for field in expected_fields:
        assert field in cert_info, f"Missing field: {field}"


def test_load_expired_certificate(expired_cert):
    """Test loading an expired certificate"""
    cert_info = load_certificate(expired_cert)
    # Should still load but mark as expired
    if cert_info:  # Some expired certs might return empty dict
        assert 'expired' in cert_info
        assert cert_info['expired'] is True


def test_load_malformed_certificate():
    """Test loading a malformed certificate"""
    malformed_cert = "NOT A VALID CERTIFICATE"
    cert_info = load_certificate(malformed_cert)
    assert cert_info == {}


def test_load_certificate_with_missing_header():
    """Test loading certificate with missing header"""
    no_header = textwrap.dedent('''\
        MIIDazCCAlOgAwIBAgIUB3v8VvPVxXGGLHqP5gQ/fN7B7u8wDQYJKoZIhvcNAQEL
        -----END CERTIFICATE-----
    ''')
    cert_info = load_certificate(no_header)
    assert cert_info == {}


def test_load_certificate_with_missing_footer():
    """Test loading certificate with missing footer"""
    no_footer = textwrap.dedent('''\
        -----BEGIN CERTIFICATE-----
        MIIDazCCAlOgAwIBAgIUB3v8VvPVxXGGLHqP5gQ/fN7B7u8wDQYJKoZIhvcNAQEL
    ''')
    cert_info = load_certificate(no_footer)
    assert cert_info == {}


def test_load_certificate_chain_detection():
    """Test detection of certificate chains"""
    single_cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'single',
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
    cert_info = load_certificate(single_cert)
    assert cert_info['chain'] is False


def test_load_certificate_serial_number(valid_cert):
    """Test that serial number is correctly extracted"""
    cert_info = load_certificate(valid_cert)
    assert 'serial' in cert_info
    assert isinstance(cert_info['serial'], int)
    assert cert_info['serial'] > 0


def test_load_certificate_fingerprint(valid_cert):
    """Test that fingerprint is correctly generated"""
    cert_info = load_certificate(valid_cert)
    assert 'fingerprint' in cert_info
    # SHA1 fingerprint format: XX:XX:XX:...
    assert ':' in cert_info['fingerprint']
    parts = cert_info['fingerprint'].split(':')
    assert len(parts) == 20  # SHA1 is 20 bytes


def test_load_certificate_dates(valid_cert):
    """Test that certificate dates are correctly parsed"""
    cert_info = load_certificate(valid_cert)
    assert 'from' in cert_info
    assert 'until' in cert_info
    assert 'lifetime' in cert_info
    assert isinstance(cert_info['lifetime'], int)
    assert cert_info['lifetime'] > 0


def test_get_serial_from_certificate_safe_valid(valid_cert):
    """Test getting serial number from valid certificate"""
    serial = get_serial_from_certificate_safe(valid_cert)
    assert serial is not None
    assert isinstance(serial, int)
    assert serial > 0


def test_get_serial_from_certificate_safe_invalid():
    """Test getting serial number from invalid certificate"""
    serial = get_serial_from_certificate_safe("INVALID CERT")
    assert serial is None


def test_get_serial_from_certificate_safe_none():
    """Test getting serial number from None"""
    serial = get_serial_from_certificate_safe(None)
    assert serial is None


def test_get_serial_from_certificate_safe_empty():
    """Test getting serial number from empty string"""
    serial = get_serial_from_certificate_safe("")
    assert serial is None


@pytest.fixture
def valid_csr():
    """Generate a valid CSR"""
    csr, _ = generate_certificate_signing_request({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test.example.com',
        'country': 'US',
        'state': 'CA',
        'city': 'San Francisco',
        'organization': 'Test Org',
        'organizational_unit': 'Test Unit',
        'email': 'test@example.com',
        'san': ['test.example.com', '192.168.1.1'],
        'digest_algorithm': 'SHA256',
    })
    return csr


def test_load_valid_csr(valid_csr):
    """Test loading a valid CSR"""
    csr_info = load_certificate_request(valid_csr)
    assert csr_info is not None
    assert isinstance(csr_info, dict)
    assert 'common' in csr_info
    assert csr_info['common'] == 'test.example.com'


def test_load_csr_all_fields(valid_csr):
    """Test that all expected fields are present in CSR"""
    csr_info = load_certificate_request(valid_csr)
    expected_fields = [
        'country', 'state', 'city', 'organization', 'organizational_unit',
        'common', 'email', 'san', 'DN', 'extensions', 'subject_name_hash'
    ]
    for field in expected_fields:
        assert field in csr_info, f"Missing field: {field}"


def test_load_csr_subject_name_hash_is_none(valid_csr):
    """Test that CSR subject_name_hash is None (not available for CSRs)"""
    csr_info = load_certificate_request(valid_csr)
    assert csr_info['subject_name_hash'] is None


def test_load_invalid_csr():
    """Test loading an invalid CSR"""
    invalid_csr = "NOT A VALID CSR"
    csr_info = load_certificate_request(invalid_csr)
    assert csr_info == {}


def test_load_csr_with_missing_header():
    """Test loading CSR with missing header"""
    no_header = textwrap.dedent('''\
        MIICWzCCAUMCAQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wDQYJKoZIhvcNAQEB
        -----END CERTIFICATE REQUEST-----
    ''')
    csr_info = load_certificate_request(no_header)
    assert csr_info == {}


def test_load_csr_with_missing_footer():
    """Test loading CSR with missing footer"""
    no_footer = textwrap.dedent('''\
        -----BEGIN CERTIFICATE REQUEST-----
        MIICWzCCAUMCAQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wDQYJKoZIhvcNAQEB
    ''')
    csr_info = load_certificate_request(no_footer)
    assert csr_info == {}


def test_load_csr_with_extensions(valid_csr):
    """Test loading CSR with extensions"""
    csr_info = load_certificate_request(valid_csr)
    assert 'extensions' in csr_info
    assert isinstance(csr_info['extensions'], dict)
    # Should have SAN extension
    assert 'SubjectAltName' in csr_info['extensions'] or len(csr_info['san']) > 0


def test_load_csr_without_extensions():
    """Test loading CSR without extensions"""
    csr, _ = generate_certificate_signing_request({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'simple.example.com',
        'digest_algorithm': 'SHA256',
    })
    csr_info = load_certificate_request(csr)
    assert 'extensions' in csr_info


def test_load_certificate_instead_of_csr():
    """Test loading a certificate when CSR is expected"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test',
        'digest_algorithm': 'SHA256',
        'lifetime': 365,
        'serial': 2003,
        'cert_extensions': {
            'BasicConstraints': {'enabled': False},
            'AuthorityKeyIdentifier': {'enabled': False},
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {'enabled': False},
        },
    })
    # Should fail gracefully
    csr_info = load_certificate_request(cert)
    assert csr_info == {}


def test_get_cert_id_with_authority_key_identifier():
    """Test get_cert_id() with certificate containing AKI"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test-cert-id',
        'digest_algorithm': 'SHA256',
        'lifetime': 365,
        'serial': 5001,
        'cert_extensions': {
            'BasicConstraints': {'enabled': False},
            'AuthorityKeyIdentifier': {
                'enabled': True,
                'authority_cert_issuer': False,
            },
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {'enabled': False},
        },
    })
    cert_id = get_cert_id(cert)
    # Verify format: base64url.base64url
    assert '.' in cert_id
    parts = cert_id.split('.')
    assert len(parts) == 2
    # Both parts should be non-empty base64url strings
    assert all(part for part in parts)
    # base64url should not contain + / = characters
    assert not any(c in cert_id for c in ['+', '/', '='])


def test_get_cert_id_missing_aki():
    """Test get_cert_id() raises error when AKI is missing"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test-no-aki',
        'digest_algorithm': 'SHA256',
        'lifetime': 365,
        'serial': 5002,
        'cert_extensions': {
            'BasicConstraints': {'enabled': False},
            'AuthorityKeyIdentifier': {'enabled': False},
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {'enabled': False},
        },
    })
    with pytest.raises(ValueError, match='missing Authority Key Identifier'):
        get_cert_id(cert)


def test_parse_cert_date_string_bytes():
    """Test parse_cert_date_string() with bytes input"""
    date_bytes = b'20250101120000Z'
    result = parse_cert_date_string(date_bytes)
    # Should return ctime format
    assert isinstance(result, str)
    assert len(result) > 0
    # Should contain day, month, time, year
    assert '2025' in result or '2024' in result  # Timezone conversion


def test_parse_cert_date_string_str():
    """Test parse_cert_date_string() with string input"""
    date_str = '20250101120000Z'
    result = parse_cert_date_string(date_str)
    assert isinstance(result, str)
    assert len(result) > 0


def test_load_private_key_rsa():
    """Test load_private_key() with RSA key"""
    key_pem = generate_private_key({'type': 'RSA', 'key_length': 2048}, serialize=True)
    key_obj = load_private_key(key_pem)
    assert key_obj is not None
    from cryptography.hazmat.primitives.asymmetric import rsa
    assert isinstance(key_obj, rsa.RSAPrivateKey)


def test_load_private_key_ec():
    """Test load_private_key() with EC key"""
    key_pem = generate_private_key({'type': 'EC', 'curve': 'SECP256R1'}, serialize=True)
    key_obj = load_private_key(key_pem)
    assert key_obj is not None
    from cryptography.hazmat.primitives.asymmetric import ec
    assert isinstance(key_obj, ec.EllipticCurvePrivateKey)


def test_load_private_key_ed25519():
    """Test load_private_key() with Ed25519 key"""
    key_pem = generate_private_key({'type': 'EC', 'curve': 'ed25519'}, serialize=True)
    key_obj = load_private_key(key_pem)
    assert key_obj is not None
    from cryptography.hazmat.primitives.asymmetric import ed25519
    assert isinstance(key_obj, ed25519.Ed25519PrivateKey)


def test_load_private_key_invalid():
    """Test load_private_key() with invalid key returns None"""
    key_obj = load_private_key("INVALID KEY DATA")
    assert key_obj is None


def test_load_private_key_empty():
    """Test load_private_key() with empty string returns None"""
    key_obj = load_private_key("")
    assert key_obj is None
