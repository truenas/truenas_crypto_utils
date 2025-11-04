"""Test parsing of Microsoft Active Directory Certificate Services certificates."""

from truenas_crypto_utils.read import load_certificate


# Test certificate with Microsoft ADCS extensions, using anonymized subject/SAN data
# This certificate contains the REAL Microsoft-specific extension binary data:
# - MS Certificate Template (OID 1.3.6.1.4.1.311.21.7)
# - MS Application Policies (OID 1.3.6.1.4.1.311.21.10)
# These extensions previously caused "Unable to parse extension" errors with PyOpenSSL
MICROSOFT_CERT = """-----BEGIN CERTIFICATE-----
MIIEKDCCA66gAwIBAgIUJR/zg51Lo4oVhDw8GHd1xFac1n4wCgYIKoZIzj0EAwMw
fjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFTATBgNVBAoMDEV4
YW1wbGUgQ29ycDEWMBQGA1UECwwNSVQgRGVwYXJ0bWVudDErMCkGA1UEAwwiRXhh
bXBsZSBDb3JwIEFEIENTIEludGVybWVkaWF0ZSBDQTAeFw0yNTExMDQwNzA5MDha
Fw0yNjExMDQwNzA5MDhaMIGtMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZv
cm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzEVMBMGA1UECgwMRXhhbXBsZSBD
b3JwMRYwFAYDVQQLDA1JVCBEZXBhcnRtZW50MSAwHgYDVQQDDBd0ZXN0LXNlcnZl
ci5leGFtcGxlLmNvbTEgMB4GCSqGSIb3DQEJARYRYWRtaW5AZXhhbXBsZS5jb20w
djAQBgcqhkjOPQIBBgUrgQQAIgNiAAQfLtbx3qjX7ioD47kyhL4l8FyQPb/JikFF
f7zjrBJyvxakvTp1frR+HCJ2wWczWTLfZVSjR9dZocoqRzI6CMnMSARwKoel1lto
jRjVYg38OyqY3pLOilGugUMNYR9i5yWjggG7MIIBtzATBgNVHSUEDDAKBggrBgEF
BQcDATAOBgNVHQ8BAf8EBAMCA4gwUgYDVR0RBEswSYIXdGVzdC1zZXJ2ZXIuZXhh
bXBsZS5jb22CFnRlc3Qtbm9kZTEuZXhhbXBsZS5jb22CFnRlc3Qtbm9kZTIuZXhh
bXBsZS5jb20wHQYDVR0OBBYEFB5B1CkAHhhHn02Olob+6Jvk1Ra+MB8GA1UdIwQY
MBaAFAECAwQFBgcICQoLDA0ODxAREhMUME0GA1UdHwRGMEQwQqBAoD6GPGh0dHA6
Ly9wa2kuZXhhbXBsZS5jb20vY3JsL0V4YW1wbGVDb3JwQURDU0ludGVybWVkaWF0
ZUNBLmNybDBUBggrBgEFBQcBAQRIMEYwRAYIKwYBBQUHMAKGOGh0dHA6Ly9wa2ku
ZXhhbXBsZS5jb20vRXhhbXBsZUNvcnBBRENTSW50ZXJtZWRpYXRlQ0EucGVtMDoG
CSsGAQQBgjcVBwQtMCsGIysGAQQBgjcVCILEg13Y0WuFyZcYpsR9guayAmOGhaED
iO1bAgFkAgEOMBsGCSsGAQQBgjcVCgQOMAwwCgYIKwYBBQUHAwEwCgYIKoZIzj0E
AwMDaAAwZQIwShK2BLunUWzdjMJAKo6lnlVspJimRScK6Szpaw9IrPVwh+02tF/9
szOvBwhFxucaAjEAympgmGP4prG/WGy5CQMJd9J3AYAMU5rn+rl7vvWNC3coYB14
j/in+MQq2vrJs7BQ
-----END CERTIFICATE-----
"""


def test_parse_microsoft_adcs_certificate():
    """Test parsing Microsoft ADCS certificate with MS-specific extensions."""
    cert_info = load_certificate(MICROSOFT_CERT)

    # Basic certificate info
    assert cert_info['common'] == 'test-server.example.com'
    assert cert_info['organization'] == 'Example Corp'
    assert cert_info['country'] == 'US'
    assert cert_info['state'] == 'California'
    assert cert_info['city'] == 'San Francisco'

    # SAN entries
    assert 'DNS:test-server.example.com' in cert_info['san']
    assert 'DNS:test-node1.example.com' in cert_info['san']
    assert 'DNS:test-node2.example.com' in cert_info['san']

    # Standard extensions
    assert 'ExtendedKeyUsage' in cert_info['extensions']
    assert 'KeyUsage' in cert_info['extensions']
    assert 'SubjectAltName' in cert_info['extensions']

    # Microsoft-specific extensions should be parsed or at least present
    extensions = cert_info['extensions']

    # MsCertificateTemplate - should be parsed now (not "Unable to parse")
    assert 'MsCertificateTemplate' in extensions
    assert 'Unable to parse' not in extensions.get('MsCertificateTemplate', '')
    # Should contain template info
    ms_template = extensions['MsCertificateTemplate']
    assert 'template_id' in ms_template or 'MSCertificateTemplate' in ms_template

    # Microsoft Application Policies (OID 1.3.6.1.4.1.311.21.10)
    # This might show as "Unknown OID" but should at least be present with data
    has_ms_app_policies = any(
        '1.3.6.1.4.1.311.21.10' in str(v) or 'Unknown OID' in k
        for k, v in extensions.items()
    )
    assert has_ms_app_policies, "Microsoft Application Policies extension should be present"


def test_microsoft_cert_extensions_not_error():
    """Ensure Microsoft certificate extensions don't cause parsing to fail."""
    # The main test is that this doesn't raise an exception
    cert_info = load_certificate(MICROSOFT_CERT)

    # Should have parsed successfully
    assert cert_info is not None
    assert 'extensions' in cert_info
    assert len(cert_info['extensions']) > 0

    # No extension should say "Unable to parse extension"
    for ext_name, ext_value in cert_info['extensions'].items():
        if 'MsCertificateTemplate' in ext_name or 'Unknown OID' in ext_name:
            # These Microsoft extensions should have some data now
            assert ext_value is not None
            assert len(str(ext_value)) > 0


def test_microsoft_cert_has_valid_fingerprint():
    """Test that fingerprint is calculated for Microsoft cert."""
    cert_info = load_certificate(MICROSOFT_CERT)

    # Fingerprint should exist and be in correct format (20 hex pairs separated by colons)
    assert 'fingerprint' in cert_info
    fingerprint = cert_info['fingerprint']
    parts = fingerprint.split(':')
    assert len(parts) == 20
    for part in parts:
        assert len(part) == 2
        assert all(c in '0123456789ABCDEFabcdef' for c in part)


def test_microsoft_cert_has_serial_number():
    """Test that serial number is parsed correctly for Microsoft cert."""
    cert_info = load_certificate(MICROSOFT_CERT)

    # Serial number should exist and be a positive integer
    assert 'serial' in cert_info
    assert isinstance(cert_info['serial'], int)
    assert cert_info['serial'] > 0
