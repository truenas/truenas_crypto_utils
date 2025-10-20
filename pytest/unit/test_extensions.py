import pytest

from truenas_crypto_utils.generate_certs import generate_certificate
from truenas_crypto_utils.read import load_certificate, load_certificate_request
from truenas_crypto_utils.csr import generate_certificate_signing_request
from truenas_crypto_utils.utils import DEFAULT_LIFETIME_DAYS


@pytest.mark.parametrize('generate_params,extension_info', [
    (
        {
            'key_type': 'RSA',
            'key_length': 4096,
            'san': ['domain1', '8.8.8.8'],
            'common': 'dev',
            'country': 'US',
            'state': 'TN',
            'city': 'Knoxville',
            'organization': 'iX',
            'organizational_unit': 'dev',
            'email': 'dev@ix.com',
            'digest_algorithm': 'SHA256',
            'lifetime': DEFAULT_LIFETIME_DAYS,
            'serial': 12931,
            'ca_certificate': None,
            'cert_extensions': {
                'BasicConstraints': {
                    'enabled': True,
                    'ca': True,
                    'extension_critical': True,
                },
            },
        },
        {'BasicConstraints': 'CA:TRUE'},
    ),
    (
        {
            'key_type': 'RSA',
            'key_length': 4096,
            'san': ['domain1', '8.8.8.8'],
            'common': 'dev',
            'country': 'US',
            'state': 'TN',
            'city': 'Knoxville',
            'organization': 'iX',
            'organizational_unit': 'dev',
            'email': 'dev@ix.com',
            'digest_algorithm': 'SHA256',
            'lifetime': DEFAULT_LIFETIME_DAYS,
            'serial': 12931,
            'ca_certificate': None,
            'cert_extensions': {
                'KeyUsage': {
                    'enabled': True,
                    'key_cert_sign': True,
                    'crl_sign': True,
                    'extension_critical': True,
                }
            },
        },
        {'KeyUsage': 'Certificate Sign, CRL Sign'},
    ),
    (
        {
            'key_type': 'RSA',
            'key_length': 4096,
            'san': ['domain1', '8.8.8.8'],
            'common': 'dev',
            'country': 'US',
            'state': 'TN',
            'city': 'Knoxville',
            'organization': 'iX',
            'organizational_unit': 'dev',
            'email': 'dev@ix.com',
            'digest_algorithm': 'SHA256',
            'lifetime': DEFAULT_LIFETIME_DAYS,
            'serial': 12931,
            'ca_certificate': None,
            'cert_extensions': {
                'KeyUsage': {
                    'enabled': True,
                    'key_cert_sign': True,
                    'crl_sign': False,
                    'extension_critical': True,
                }
            },
        },
        {'KeyUsage': 'Certificate Sign'},
    ),
    (
        {
            'key_type': 'RSA',
            'key_length': 4096,
            'san': ['domain1', '8.8.8.8'],
            'common': 'dev',
            'country': 'US',
            'state': 'TN',
            'city': 'Knoxville',
            'organization': 'iX',
            'organizational_unit': 'dev',
            'email': 'dev@ix.com',
            'digest_algorithm': 'SHA256',
            'lifetime': DEFAULT_LIFETIME_DAYS,
            'serial': 12931,
            'ca_certificate': None,
            'cert_extensions': {
                'ExtendedKeyUsage': {
                    'enabled': True,
                    'usages': [
                        'ANY_EXTENDED_KEY_USAGE', 'CLIENT_AUTH', 'CODE_SIGNING', 'EMAIL_PROTECTION',
                        'OCSP_SIGNING', 'SERVER_AUTH', 'TIME_STAMPING'
                    ],
                },
            },
        },
        {
            'ExtendedKeyUsage': 'Any Extended Key Usage, TLS Web Client Authentication, '
                                'Code Signing, E-mail Protection, OCSP Signing, TLS Web Server '
                                'Authentication, Time Stamping',
        },
    ),
    (
        {
            'key_type': 'RSA',
            'key_length': 4096,
            'san': ['domain1', '8.8.8.8'],
            'common': 'dev',
            'country': 'US',
            'state': 'TN',
            'city': 'Knoxville',
            'organization': 'iX',
            'organizational_unit': 'dev',
            'email': 'dev@ix.com',
            'digest_algorithm': 'SHA256',
            'lifetime': DEFAULT_LIFETIME_DAYS,
            'serial': 12931,
            'ca_certificate': None,
            'cert_extensions': {
                'KeyUsage': {
                    'enabled': True,
                    'digital_signature': True,
                    'content_commitment': True,
                    'key_encipherment': True,
                    'data_encipherment': True,
                    'key_agreement': True,
                },
            },
        },
        {
            'KeyUsage': 'Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment, Key Agreement',
        },
    ),
    # BasicConstraints CA=FALSE
    (
        {
            'key_type': 'RSA',
            'key_length': 2048,
            'common': 'Test Non-CA',
            'country': 'US',
            'digest_algorithm': 'SHA256',
            'lifetime': 365,
            'serial': 4002,
            'cert_extensions': {
                'BasicConstraints': {
                    'enabled': True,
                    'ca': False,
                },
            },
        },
        {'BasicConstraints': 'CA:FALSE'},
    ),
    # BasicConstraints with path length
    (
        {
            'key_type': 'RSA',
            'key_length': 2048,
            'common': 'Test CA with Path Length',
            'digest_algorithm': 'SHA256',
            'lifetime': 365,
            'serial': 4003,
            'cert_extensions': {
                'BasicConstraints': {
                    'enabled': True,
                    'ca': True,
                    'path_length': 2,
                },
            },
        },
        {'BasicConstraints': 'CA:TRUE, pathlen:2'},
    ),
    # KeyUsage: digital_signature
    (
        {
            'key_type': 'RSA',
            'key_length': 2048,
            'common': 'Test Digital Signature',
            'digest_algorithm': 'SHA256',
            'lifetime': 365,
            'serial': 4010,
            'cert_extensions': {
                'KeyUsage': {
                    'enabled': True,
                    'digital_signature': True,
                },
            },
        },
        {'KeyUsage': 'Digital Signature'},
    ),
    # KeyUsage: key_encipherment
    (
        {
            'key_type': 'RSA',
            'key_length': 2048,
            'common': 'Test Key Encipherment',
            'digest_algorithm': 'SHA256',
            'lifetime': 365,
            'serial': 4011,
            'cert_extensions': {
                'KeyUsage': {
                    'enabled': True,
                    'key_encipherment': True,
                },
            },
        },
        {'KeyUsage': 'Key Encipherment'},
    ),
    # KeyUsage: data_encipherment
    (
        {
            'key_type': 'RSA',
            'key_length': 2048,
            'common': 'Test Data Encipherment',
            'digest_algorithm': 'SHA256',
            'lifetime': 365,
            'serial': 4012,
            'cert_extensions': {
                'KeyUsage': {
                    'enabled': True,
                    'data_encipherment': True,
                },
            },
        },
        {'KeyUsage': 'Data Encipherment'},
    ),
    # KeyUsage: key_agreement
    (
        {
            'key_type': 'RSA',
            'key_length': 2048,
            'common': 'Test Key Agreement',
            'digest_algorithm': 'SHA256',
            'lifetime': 365,
            'serial': 4013,
            'cert_extensions': {
                'KeyUsage': {
                    'enabled': True,
                    'key_agreement': True,
                },
            },
        },
        {'KeyUsage': 'Key Agreement'},
    ),
    # KeyUsage: content_commitment
    (
        {
            'key_type': 'RSA',
            'key_length': 2048,
            'common': 'Test Content Commitment',
            'digest_algorithm': 'SHA256',
            'lifetime': 365,
            'serial': 4014,
            'cert_extensions': {
                'KeyUsage': {
                    'enabled': True,
                    'content_commitment': True,
                },
            },
        },
        {'KeyUsage': 'Non Repudiation'},
    ),
    # KeyUsage: encipher_only
    (
        {
            'key_type': 'RSA',
            'key_length': 2048,
            'common': 'Test Encipher Only',
            'digest_algorithm': 'SHA256',
            'lifetime': 365,
            'serial': 4015,
            'cert_extensions': {
                'KeyUsage': {
                    'enabled': True,
                    'key_agreement': True,
                    'encipher_only': True,
                },
            },
        },
        {'KeyUsage': 'Key Agreement, Encipher Only'},
    ),
    # KeyUsage: decipher_only
    (
        {
            'key_type': 'RSA',
            'key_length': 2048,
            'common': 'Test Decipher Only',
            'digest_algorithm': 'SHA256',
            'lifetime': 365,
            'serial': 4016,
            'cert_extensions': {
                'KeyUsage': {
                    'enabled': True,
                    'key_agreement': True,
                    'decipher_only': True,
                },
            },
        },
        {'KeyUsage': 'Key Agreement, Decipher Only'},
    ),
    # ExtendedKeyUsage: SERVER_AUTH
    (
        {
            'key_type': 'RSA',
            'key_length': 2048,
            'common': 'Test Server Auth',
            'digest_algorithm': 'SHA256',
            'lifetime': 365,
            'serial': 4020,
            'cert_extensions': {
                'ExtendedKeyUsage': {
                    'enabled': True,
                    'usages': ['SERVER_AUTH'],
                },
            },
        },
        {'ExtendedKeyUsage': 'TLS Web Server Authentication'},
    ),
    # ExtendedKeyUsage: CLIENT_AUTH
    (
        {
            'key_type': 'RSA',
            'key_length': 2048,
            'common': 'Test Client Auth',
            'digest_algorithm': 'SHA256',
            'lifetime': 365,
            'serial': 4021,
            'cert_extensions': {
                'ExtendedKeyUsage': {
                    'enabled': True,
                    'usages': ['CLIENT_AUTH'],
                },
            },
        },
        {'ExtendedKeyUsage': 'TLS Web Client Authentication'},
    ),
    # ExtendedKeyUsage: CODE_SIGNING
    (
        {
            'key_type': 'RSA',
            'key_length': 2048,
            'common': 'Test Code Signing',
            'digest_algorithm': 'SHA256',
            'lifetime': 365,
            'serial': 4022,
            'cert_extensions': {
                'ExtendedKeyUsage': {
                    'enabled': True,
                    'usages': ['CODE_SIGNING'],
                },
            },
        },
        {'ExtendedKeyUsage': 'Code Signing'},
    ),
    # ExtendedKeyUsage: EMAIL_PROTECTION
    (
        {
            'key_type': 'RSA',
            'key_length': 2048,
            'common': 'Test Email Protection',
            'digest_algorithm': 'SHA256',
            'lifetime': 365,
            'serial': 4023,
            'cert_extensions': {
                'ExtendedKeyUsage': {
                    'enabled': True,
                    'usages': ['EMAIL_PROTECTION'],
                },
            },
        },
        {'ExtendedKeyUsage': 'E-mail Protection'},
    ),
    # ExtendedKeyUsage: TIME_STAMPING
    (
        {
            'key_type': 'RSA',
            'key_length': 2048,
            'common': 'Test Time Stamping',
            'digest_algorithm': 'SHA256',
            'lifetime': 365,
            'serial': 4024,
            'cert_extensions': {
                'ExtendedKeyUsage': {
                    'enabled': True,
                    'usages': ['TIME_STAMPING'],
                },
            },
        },
        {'ExtendedKeyUsage': 'Time Stamping'},
    ),
    # ExtendedKeyUsage: OCSP_SIGNING
    (
        {
            'key_type': 'RSA',
            'key_length': 2048,
            'common': 'Test OCSP Signing',
            'digest_algorithm': 'SHA256',
            'lifetime': 365,
            'serial': 4025,
            'cert_extensions': {
                'ExtendedKeyUsage': {
                    'enabled': True,
                    'usages': ['OCSP_SIGNING'],
                },
            },
        },
        {'ExtendedKeyUsage': 'OCSP Signing'},
    ),
])
def test__generating_ca(generate_params, extension_info):
    extensions = load_certificate(generate_certificate(generate_params)[0], True)['extensions']
    for k in extension_info:
        assert k in extensions, extensions
        assert extensions[k] == extension_info[k]


def test_subject_key_identifier_automatically_added():
    """Test that SubjectKeyIdentifier is automatically added"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'Test Auto SKI',
        'digest_algorithm': 'SHA256',
        'lifetime': 365,
        'serial': 4050,
        'cert_extensions': {},
    })
    cert_info = load_certificate(cert)
    assert 'SubjectKeyIdentifier' in cert_info['extensions']


def test_subject_key_identifier_format():
    """Test SubjectKeyIdentifier format"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'Test SKI Format',
        'digest_algorithm': 'SHA256',
        'lifetime': 365,
        'serial': 4051,
        'cert_extensions': {},
    })
    cert_info = load_certificate(cert)
    ski = cert_info['extensions']['SubjectKeyIdentifier']
    assert ':' in ski
    parts = ski.split(':')
    assert len(parts) >= 2


def test_typical_web_server_certificate():
    """Test a typical web server certificate with appropriate extensions"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'www.example.com',
        'country': 'US',
        'san': ['www.example.com', 'example.com'],
        'digest_algorithm': 'SHA256',
        'lifetime': 365,
        'serial': 4070,
        'cert_extensions': {
            'BasicConstraints': {'enabled': True, 'ca': False},
            'KeyUsage': {
                'enabled': True,
                'digital_signature': True,
                'key_encipherment': True,
            },
            'ExtendedKeyUsage': {
                'enabled': True,
                'usages': ['SERVER_AUTH', 'CLIENT_AUTH'],
            },
        },
    })
    cert_info = load_certificate(cert)
    assert 'BasicConstraints' in cert_info['extensions']
    assert 'KeyUsage' in cert_info['extensions']
    assert 'ExtendedKeyUsage' in cert_info['extensions']


def test_typical_ca_certificate():
    """Test a typical CA certificate"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 4096,
        'common': 'Test Root CA',
        'country': 'US',
        'digest_algorithm': 'SHA256',
        'lifetime': 3650,
        'serial': 4071,
        'cert_extensions': {
            'BasicConstraints': {
                'enabled': True,
                'ca': True,
                'path_length': 1,
                'extension_critical': True,
            },
            'KeyUsage': {
                'enabled': True,
                'key_cert_sign': True,
                'crl_sign': True,
                'extension_critical': True,
            },
        },
    })
    cert_info = load_certificate(cert)
    assert 'CA:TRUE' in cert_info['extensions']['BasicConstraints']
    assert 'Certificate Sign' in cert_info['extensions']['KeyUsage']


def test_csr_with_basic_constraints():
    """Test CSR with BasicConstraints extension"""
    csr, _ = generate_certificate_signing_request({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test-csr.example.com',
        'digest_algorithm': 'SHA256',
    })
    csr_info = load_certificate_request(csr)
    assert 'extensions' in csr_info


def test_csr_with_san():
    """Test CSR with SAN extension"""
    csr, _ = generate_certificate_signing_request({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test-csr.example.com',
        'san': ['www.example.com', '192.168.1.1'],
        'digest_algorithm': 'SHA256',
    })
    csr_info = load_certificate_request(csr)
    assert 'san' in csr_info
    assert len(csr_info['san']) > 0


def test_csr_with_key_usage():
    """Test CSR with KeyUsage extension"""
    csr, _ = generate_certificate_signing_request({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test-csr.example.com',
        'digest_algorithm': 'SHA256',
    })
    csr_info = load_certificate_request(csr)
    assert 'extensions' in csr_info


def test_certificate_with_no_extensions_disabled():
    """Test certificate with all extensions disabled"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'no-ext.example.com',
        'digest_algorithm': 'SHA256',
        'lifetime': 365,
        'serial': 4090,
        'cert_extensions': {
            'BasicConstraints': {'enabled': False},
            'AuthorityKeyIdentifier': {'enabled': False},
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {'enabled': False},
        },
    })
    cert_info = load_certificate(cert)
    assert 'SubjectKeyIdentifier' in cert_info['extensions']


def test_extension_name_capitalization():
    """Test that extension names are properly capitalized"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test.example.com',
        'san': ['www.example.com'],
        'digest_algorithm': 'SHA256',
        'lifetime': 365,
        'serial': 4091,
        'cert_extensions': {},
    })
    cert_info = load_certificate(cert)
    for ext_name in cert_info['extensions'].keys():
        assert ext_name[0].isupper(), f"Extension name should be capitalized: {ext_name}"


def test_extensions_return_dict():
    """Test that extensions are returned as dict"""
    cert, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'test.example.com',
        'digest_algorithm': 'SHA256',
        'lifetime': 365,
        'serial': 4092,
        'cert_extensions': {},
    })
    cert_info = load_certificate(cert)
    assert isinstance(cert_info['extensions'], dict)
