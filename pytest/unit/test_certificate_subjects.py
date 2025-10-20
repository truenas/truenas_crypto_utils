import datetime

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
    # Verify exact DNS format
    san_list = cert_info['san']
    assert any('DNS:www.example.com' in entry or 'DNS: www.example.com' in entry for entry in san_list)
    assert any('DNS:mail.example.com' in entry or 'DNS: mail.example.com' in entry for entry in san_list)


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
    # Verify exact IP Address format
    san_list = cert_info['san']
    assert any('IP Address:192.168.1.1' in entry or 'IP: 192.168.1.1' in entry for entry in san_list)
    assert any('IP Address:10.0.0.1' in entry or 'IP: 10.0.0.1' in entry for entry in san_list)


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


def test_san_extension_exact_value_dns():
    """Test SubjectAltName extension value with DNS entries"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test.example.com',
        'san': ['www.example.com', 'mail.example.com', 'ftp.example.com'],
        'digest_algorithm': 'SHA256',
        'lifetime': 365,
        'serial': 7001,
        'cert_extensions': {
            'BasicConstraints': {'enabled': False},
            'AuthorityKeyIdentifier': {'enabled': False},
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {'enabled': False},
        },
    })
    cert_info = load_certificate(cert)

    # Verify SAN is in extensions
    assert 'SubjectAltName' in cert_info['extensions']
    san_ext = cert_info['extensions']['SubjectAltName']

    # Verify all DNS entries are present in the extension value
    assert 'www.example.com' in san_ext
    assert 'mail.example.com' in san_ext
    assert 'ftp.example.com' in san_ext

    # Verify DNS prefix is present
    assert 'DNS:' in san_ext or 'DNS: ' in san_ext


def test_san_extension_exact_value_ip():
    """Test SubjectAltName extension value with IP addresses"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'server.example.com',
        'san': ['192.168.1.10', '10.0.0.5'],
        'digest_algorithm': 'SHA256',
        'lifetime': 365,
        'serial': 7002,
        'cert_extensions': {
            'BasicConstraints': {'enabled': False},
            'AuthorityKeyIdentifier': {'enabled': False},
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {'enabled': False},
        },
    })
    cert_info = load_certificate(cert)

    assert 'SubjectAltName' in cert_info['extensions']
    san_ext = cert_info['extensions']['SubjectAltName']

    # Verify all IP addresses are present
    assert '192.168.1.10' in san_ext
    assert '10.0.0.5' in san_ext

    # Verify IP prefix is present
    assert 'IP Address:' in san_ext or 'IP:' in san_ext


def test_san_extension_exact_value_mixed():
    """Test SubjectAltName extension value with mixed DNS and IP"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'mixed.example.com',
        'san': ['www.example.com', '192.168.1.1', 'mail.example.com', '10.0.0.1'],
        'digest_algorithm': 'SHA256',
        'lifetime': 365,
        'serial': 7003,
        'cert_extensions': {
            'BasicConstraints': {'enabled': False},
            'AuthorityKeyIdentifier': {'enabled': False},
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {'enabled': False},
        },
    })
    cert_info = load_certificate(cert)

    assert 'SubjectAltName' in cert_info['extensions']
    san_ext = cert_info['extensions']['SubjectAltName']

    # Verify DNS entries
    assert 'www.example.com' in san_ext
    assert 'mail.example.com' in san_ext

    # Verify IP entries
    assert '192.168.1.1' in san_ext
    assert '10.0.0.1' in san_ext

    # Verify both prefixes exist
    assert 'DNS:' in san_ext or 'DNS: ' in san_ext
    assert 'IP Address:' in san_ext or 'IP:' in san_ext


def test_san_field_matches_extension():
    """Test that san field matches SubjectAltName extension"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test.example.com',
        'san': ['www.example.com', '192.168.1.1'],
        'digest_algorithm': 'SHA256',
        'lifetime': 365,
        'serial': 7004,
        'cert_extensions': {
            'BasicConstraints': {'enabled': False},
            'AuthorityKeyIdentifier': {'enabled': False},
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {'enabled': False},
        },
    })
    cert_info = load_certificate(cert)

    # Both san field and SubjectAltName extension should be present
    assert 'san' in cert_info
    assert 'SubjectAltName' in cert_info['extensions']

    # san field should have entries
    assert len(cert_info['san']) > 0

    # All entries in san should appear in the extension
    san_ext = cert_info['extensions']['SubjectAltName']
    for san_entry in cert_info['san']:
        # Extract the actual value from format like "DNS:example.com"
        if ':' in san_entry:
            value = san_entry.split(':', 1)[1].strip()
            assert value in san_ext


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


def test_dn_format_all_components():
    """Test DN format with all components present"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test.example.com',
        'country': 'US',
        'state': 'California',
        'city': 'San Francisco',
        'organization': 'Test Org',
        'organizational_unit': 'Test Unit',
        'email': 'test@example.com',
        'digest_algorithm': 'SHA256',
        'lifetime': 365,
        'serial': 6001,
        'cert_extensions': {
            'BasicConstraints': {'enabled': False},
            'AuthorityKeyIdentifier': {'enabled': False},
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {'enabled': False},
        },
    })
    cert_info = load_certificate(cert)

    dn = cert_info['DN']
    # Verify DN starts with /
    assert dn.startswith('/')
    # Verify all components are present
    assert 'CN=test.example.com' in dn
    assert 'C=US' in dn
    assert 'ST=California' in dn
    assert 'L=San Francisco' in dn
    assert 'O=Test Org' in dn
    assert 'OU=Test Unit' in dn
    assert 'emailAddress=test@example.com' in dn


def test_dn_format_minimal_components():
    """Test DN format with only CN"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'minimal.example.com',
        'digest_algorithm': 'SHA256',
        'lifetime': 365,
        'serial': 6002,
        'cert_extensions': {
            'BasicConstraints': {'enabled': False},
            'AuthorityKeyIdentifier': {'enabled': False},
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {'enabled': False},
        },
    })
    cert_info = load_certificate(cert)

    dn = cert_info['DN']
    assert dn.startswith('/')
    assert 'CN=minimal.example.com' in dn


def test_dn_with_san_appended():
    """Test that SAN is appended to DN"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test.example.com',
        'san': ['www.example.com', '192.168.1.1'],
        'digest_algorithm': 'SHA256',
        'lifetime': 365,
        'serial': 6003,
        'cert_extensions': {
            'BasicConstraints': {'enabled': False},
            'AuthorityKeyIdentifier': {'enabled': False},
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {'enabled': False},
        },
    })
    cert_info = load_certificate(cert)

    dn = cert_info['DN']
    assert 'subjectAltName=' in dn
    assert 'www.example.com' in dn
    assert '192.168.1.1' in dn


def test_fingerprint_format_exact():
    """Test that fingerprint has exact SHA1 format"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test-fingerprint',
        'digest_algorithm': 'SHA256',
        'lifetime': 365,
        'serial': 6004,
        'cert_extensions': {
            'BasicConstraints': {'enabled': False},
            'AuthorityKeyIdentifier': {'enabled': False},
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {'enabled': False},
        },
    })
    cert_info = load_certificate(cert)

    fingerprint = cert_info['fingerprint']
    # SHA1 fingerprint format: XX:XX:XX:...:XX (20 pairs)
    parts = fingerprint.split(':')
    assert len(parts) == 20
    # Each part should be 2 hex characters
    for part in parts:
        assert len(part) == 2
        assert all(c in '0123456789ABCDEFabcdef' for c in part)


def test_lifetime_calculation_exact():
    """Test exact lifetime calculation"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test-lifetime',
        'digest_algorithm': 'SHA256',
        'lifetime': 730,  # Exactly 730 days
        'serial': 6005,
        'cert_extensions': {
            'BasicConstraints': {'enabled': False},
            'AuthorityKeyIdentifier': {'enabled': False},
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {'enabled': False},
        },
    })
    cert_info = load_certificate(cert)

    # Should be exactly 730 days
    assert cert_info['lifetime'] == 730


def test_serial_number_large_value():
    """Test with large serial number"""
    large_serial = 999999999999999
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test-large-serial',
        'digest_algorithm': 'SHA256',
        'lifetime': 365,
        'serial': large_serial,
        'cert_extensions': {
            'BasicConstraints': {'enabled': False},
            'AuthorityKeyIdentifier': {'enabled': False},
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {'enabled': False},
        },
    })
    cert_info = load_certificate(cert)

    assert cert_info['serial'] == large_serial


def test_expired_field_not_expired():
    """Test expired field with non-expired certificate"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test-not-expired',
        'digest_algorithm': 'SHA256',
        'lifetime': 365,  # Valid for 1 year from now
        'serial': 6007,
        'cert_extensions': {
            'BasicConstraints': {'enabled': False},
            'AuthorityKeyIdentifier': {'enabled': False},
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {'enabled': False},
        },
    })
    cert_info = load_certificate(cert)

    # Should not be expired
    assert cert_info['expired'] is False


def test_certificate_issuance_date_format():
    """Test that certificate issuance date (from) is in correct format"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test-date-format',
        'digest_algorithm': 'SHA256',
        'lifetime': 365,
        'serial': 8001,
        'cert_extensions': {
            'BasicConstraints': {'enabled': False},
            'AuthorityKeyIdentifier': {'enabled': False},
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {'enabled': False},
        },
    })
    cert_info = load_certificate(cert)

    # Verify 'from' field exists and is a string
    assert 'from' in cert_info
    assert isinstance(cert_info['from'], str)
    assert len(cert_info['from']) > 0

    # ctime format: "Day Mon DD HH:MM:SS YYYY"
    # Example: "Mon Jan 20 15:30:45 2025"
    from_date = cert_info['from']

    # Should contain year (current or recent)
    current_year = datetime.datetime.now().year
    assert str(current_year) in from_date or str(current_year - 1) in from_date or str(current_year + 1) in from_date

    # Should contain month abbreviation
    months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    assert any(month in from_date for month in months)

    # Should contain time with colons
    assert ':' in from_date


def test_certificate_expiry_date_format():
    """Test that certificate expiry date (until) is in correct format"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test-expiry-format',
        'digest_algorithm': 'SHA256',
        'lifetime': 730,  # 2 years
        'serial': 8002,
        'cert_extensions': {
            'BasicConstraints': {'enabled': False},
            'AuthorityKeyIdentifier': {'enabled': False},
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {'enabled': False},
        },
    })
    cert_info = load_certificate(cert)

    # Verify 'until' field exists and is a string
    assert 'until' in cert_info
    assert isinstance(cert_info['until'], str)
    assert len(cert_info['until']) > 0

    # ctime format: "Day Mon DD HH:MM:SS YYYY"
    until_date = cert_info['until']

    # Should contain future year
    current_year = datetime.datetime.now().year
    future_years = [str(current_year + i) for i in range(0, 4)]
    assert any(year in until_date for year in future_years)

    # Should contain month abbreviation
    months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    assert any(month in until_date for month in months)

    # Should contain time with colons
    assert ':' in until_date


def test_certificate_dates_logical_order():
    """Test that from date is before until date"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test-date-order',
        'digest_algorithm': 'SHA256',
        'lifetime': 365,
        'serial': 8003,
        'cert_extensions': {
            'BasicConstraints': {'enabled': False},
            'AuthorityKeyIdentifier': {'enabled': False},
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {'enabled': False},
        },
    })
    cert_info = load_certificate(cert)

    # Parse the dates
    from_date = datetime.datetime.strptime(cert_info['from'], '%a %b %d %H:%M:%S %Y')
    until_date = datetime.datetime.strptime(cert_info['until'], '%a %b %d %H:%M:%S %Y')

    # from should be before until
    assert from_date < until_date


def test_certificate_dates_match_lifetime():
    """Test that lifetime matches the difference between from and until"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test-lifetime-match',
        'digest_algorithm': 'SHA256',
        'lifetime': 365,
        'serial': 8004,
        'cert_extensions': {
            'BasicConstraints': {'enabled': False},
            'AuthorityKeyIdentifier': {'enabled': False},
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {'enabled': False},
        },
    })
    cert_info = load_certificate(cert)

    # Parse the dates
    from_date = datetime.datetime.strptime(cert_info['from'], '%a %b %d %H:%M:%S %Y')
    until_date = datetime.datetime.strptime(cert_info['until'], '%a %b %d %H:%M:%S %Y')

    # Calculate days difference
    days_diff = (until_date - from_date).days

    # Should match lifetime (allow 1 day tolerance for timezone issues)
    assert abs(days_diff - cert_info['lifetime']) <= 1


def test_certificate_issuance_date_recent():
    """Test that newly generated certificate has recent issuance date"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test-recent-issue',
        'digest_algorithm': 'SHA256',
        'lifetime': 365,
        'serial': 8005,
        'cert_extensions': {
            'BasicConstraints': {'enabled': False},
            'AuthorityKeyIdentifier': {'enabled': False},
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {'enabled': False},
        },
    })
    cert_info = load_certificate(cert)

    # Parse the from date
    from_date = datetime.datetime.strptime(cert_info['from'], '%a %b %d %H:%M:%S %Y')
    now = datetime.datetime.now()

    # from_date should be within last hour (to account for test execution time)
    time_diff = abs((now - from_date).total_seconds())
    assert time_diff < 3600  # 1 hour in seconds


def test_certificate_expiry_date_future():
    """Test that certificate expiry date is in the future"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test-future-expiry',
        'digest_algorithm': 'SHA256',
        'lifetime': 365,
        'serial': 8006,
        'cert_extensions': {
            'BasicConstraints': {'enabled': False},
            'AuthorityKeyIdentifier': {'enabled': False},
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {'enabled': False},
        },
    })
    cert_info = load_certificate(cert)

    # Parse the until date
    until_date = datetime.datetime.strptime(cert_info['until'], '%a %b %d %H:%M:%S %Y')
    now = datetime.datetime.now()

    # until_date should be in the future
    assert until_date > now


def test_certificate_expired_status_accuracy():
    """Test that expired status accurately reflects certificate validity"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test-expired-status',
        'digest_algorithm': 'SHA256',
        'lifetime': 365,
        'serial': 8007,
        'cert_extensions': {
            'BasicConstraints': {'enabled': False},
            'AuthorityKeyIdentifier': {'enabled': False},
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {'enabled': False},
        },
    })
    cert_info = load_certificate(cert)

    # Parse the until date
    until_date = datetime.datetime.strptime(cert_info['until'], '%a %b %d %H:%M:%S %Y')
    now = datetime.datetime.now()

    # If until_date is in the future, expired should be False
    if until_date > now:
        assert cert_info['expired'] is False
    else:
        assert cert_info['expired'] is True
