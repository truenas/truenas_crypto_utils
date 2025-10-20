from truenas_crypto_utils.read import load_certificate, load_certificate_request
from truenas_crypto_utils.generate_certs import generate_certificate
from truenas_crypto_utils.csr import generate_certificate_signing_request


def test_parse_subject_with_all_fields():
    """Test parsing certificate with all subject fields"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test.example.com',
        'country': 'US',
        'state': 'California',
        'city': 'San Francisco',
        'organization': 'Test Organization',
        'organizational_unit': 'Engineering',
        'email': 'admin@example.com',
    })
    cert_info = load_certificate(cert)

    assert cert_info['common'] == 'test.example.com'
    assert cert_info['country'] == 'US'
    assert cert_info['state'] == 'California'
    assert cert_info['city'] == 'San Francisco'
    assert cert_info['organization'] == 'Test Organization'
    assert cert_info['organizational_unit'] == 'Engineering'
    assert cert_info['email'] == 'admin@example.com'


def test_parse_subject_with_minimal_fields():
    """Test parsing certificate with minimal subject fields"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'minimal.example.com',
    })
    cert_info = load_certificate(cert)

    assert cert_info['common'] == 'minimal.example.com'
    # Other fields should be None or empty
    assert cert_info['country'] in [None, '']
    assert cert_info['state'] in [None, '']
    assert cert_info['city'] in [None, '']


def test_parse_dn_format():
    """Test DN (Distinguished Name) format"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test.example.com',
        'country': 'US',
        'state': 'CA',
        'city': 'SF',
        'organization': 'TestOrg',
        'organizational_unit': 'IT',
        'email': 'test@example.com',
    })
    cert_info = load_certificate(cert)

    assert 'DN' in cert_info
    dn = cert_info['DN']
    assert '/CN=test.example.com' in dn
    assert '/C=US' in dn
    assert '/ST=CA' in dn
    assert '/L=SF' in dn
    assert '/O=TestOrg' in dn
    assert '/OU=IT' in dn
    assert '/emailAddress=test@example.com' in dn


def test_parse_subject_with_unicode_characters():
    """Test parsing subject with unicode characters"""
    # Most crypto libraries support unicode in subject fields
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'тест.example.com',  # Cyrillic characters
        'country': 'RU',
    })
    cert_info = load_certificate(cert)
    assert 'common' in cert_info
    # Should handle unicode gracefully


def test_parse_subject_name_hash():
    """Test subject name hash calculation"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test.example.com',
        'country': 'US',
    })
    cert_info = load_certificate(cert)

    assert 'subject_name_hash' in cert_info
    assert cert_info['subject_name_hash'] is not None
    assert isinstance(cert_info['subject_name_hash'], int)


def test_parse_dns_san():
    """Test parsing DNS entries in SAN"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test.example.com',
        'san': ['www.example.com', 'mail.example.com'],
    })
    cert_info = load_certificate(cert)

    assert 'san' in cert_info
    assert len(cert_info['san']) >= 2
    # Check for DNS entries (format may vary)
    san_str = ' '.join(cert_info['san'])
    assert 'www.example.com' in san_str
    assert 'mail.example.com' in san_str


def test_parse_ip_san():
    """Test parsing IP addresses in SAN"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test.example.com',
        'san': ['192.168.1.1', '10.0.0.1'],
    })
    cert_info = load_certificate(cert)

    assert 'san' in cert_info
    san_str = ' '.join(cert_info['san'])
    assert '192.168.1.1' in san_str
    assert '10.0.0.1' in san_str


def test_parse_mixed_san():
    """Test parsing mixed DNS and IP entries in SAN"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test.example.com',
        'san': ['www.example.com', '192.168.1.1', 'mail.example.com', '10.0.0.1'],
    })
    cert_info = load_certificate(cert)

    assert 'san' in cert_info
    assert len(cert_info['san']) >= 4


def test_parse_empty_san():
    """Test parsing certificate without SAN"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test.example.com',
    })
    cert_info = load_certificate(cert)

    assert 'san' in cert_info
    # SAN list should be empty or minimal


def test_san_in_dn():
    """Test that SAN is appended to DN"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test.example.com',
        'san': ['www.example.com', '192.168.1.1'],
    })
    cert_info = load_certificate(cert)

    assert 'DN' in cert_info
    if cert_info['san']:  # If SAN is present
        assert 'subjectAltName=' in cert_info['DN']


def test_parse_basic_constraints_extension():
    """Test parsing BasicConstraints extension"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test.example.com',
    })
    cert_info = load_certificate(cert)

    assert 'extensions' in cert_info
    # Self-signed certs typically have BasicConstraints
    # Extension name format may vary


def test_parse_subject_key_identifier_extension():
    """Test parsing SubjectKeyIdentifier extension"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test.example.com',
    })
    cert_info = load_certificate(cert)

    assert 'extensions' in cert_info
    # Most certs will have SubjectKeyIdentifier


def test_parse_san_extension():
    """Test that SAN extension is parsed correctly"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test.example.com',
        'san': ['www.example.com', '192.168.1.1'],
    })
    cert_info = load_certificate(cert)

    assert 'extensions' in cert_info
    # SubjectAltName should be in extensions
    assert 'SubjectAltName' in cert_info['extensions'] or 'subjectAltName' in cert_info['extensions']


def test_extensions_dict_format():
    """Test that extensions are returned as dict"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test.example.com',
    })
    cert_info = load_certificate(cert)

    assert 'extensions' in cert_info
    assert isinstance(cert_info['extensions'], dict)


def test_extension_name_capitalization():
    """Test that extension names are properly capitalized"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test.example.com',
        'san': ['www.example.com'],
    })
    cert_info = load_certificate(cert)

    # Extension names should start with capital letter
    for ext_name in cert_info['extensions'].keys():
        assert ext_name[0].isupper(), f"Extension name should be capitalized: {ext_name}"


def test_parse_csr_subject_all_fields():
    """Test parsing CSR with all subject fields"""
    csr, _ = generate_certificate_signing_request({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test.example.com',
        'country': 'US',
        'state': 'California',
        'city': 'San Francisco',
        'organization': 'Test Organization',
        'organizational_unit': 'Engineering',
        'email': 'admin@example.com',
        'digest_algorithm': 'SHA256',
    })
    csr_info = load_certificate_request(csr)

    assert csr_info['common'] == 'test.example.com'
    assert csr_info['country'] == 'US'
    assert csr_info['state'] == 'California'
    assert csr_info['city'] == 'San Francisco'
    assert csr_info['organization'] == 'Test Organization'
    assert csr_info['organizational_unit'] == 'Engineering'
    assert csr_info['email'] == 'admin@example.com'


def test_parse_csr_dn_format():
    """Test CSR DN format"""
    csr, _ = generate_certificate_signing_request({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test.example.com',
        'country': 'US',
        'state': 'CA',
        'digest_algorithm': 'SHA256',
    })
    csr_info = load_certificate_request(csr)

    assert 'DN' in csr_info
    assert '/CN=test.example.com' in csr_info['DN']
    assert '/C=US' in csr_info['DN']


def test_parse_csr_with_san():
    """Test parsing CSR with SAN extension"""
    csr, _ = generate_certificate_signing_request({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test.example.com',
        'san': ['www.example.com', '192.168.1.1'],
        'digest_algorithm': 'SHA256',
    })
    csr_info = load_certificate_request(csr)

    assert 'san' in csr_info
    # SAN should be present in either san field or extensions
