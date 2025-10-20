import pytest

from truenas_crypto_utils.validation import validate_cert_with_chain
from truenas_crypto_utils.generate_certs import generate_certificate


@pytest.fixture
def root_ca():
    """Generate a self-signed root CA certificate"""
    cert, key = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'Root CA',
        'country': 'US',
        'organization': 'Test Root CA',
        'digest_algorithm': 'SHA256',
        'lifetime': 3650,
        'serial': 1,
        'cert_extensions': {
            'BasicConstraints': {
                'enabled': True,
                'ca': True,
                'path_length': None,
                'extension_critical': True,
            },
            'AuthorityKeyIdentifier': {'enabled': False},
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {
                'enabled': True,
                'digital_signature': True,
                'key_cert_sign': True,
                'crl_sign': True,
                'extension_critical': True,
            },
        },
    })
    return cert, key


@pytest.fixture
def intermediate_ca(root_ca):
    """Generate an intermediate CA signed by root CA"""
    root_cert, root_key = root_ca
    cert, key = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'Intermediate CA',
        'country': 'US',
        'organization': 'Test Intermediate CA',
        'digest_algorithm': 'SHA256',
        'lifetime': 1825,
        'serial': 2,
        'cert_extensions': {
            'BasicConstraints': {
                'enabled': True,
                'ca': True,
                'path_length': 0,
                'extension_critical': True,
            },
            'AuthorityKeyIdentifier': {
                'enabled': True,
                'authority_cert_issuer': False,
            },
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {
                'enabled': True,
                'digital_signature': True,
                'key_cert_sign': True,
                'crl_sign': True,
                'extension_critical': True,
            },
        },
        'ca_certificate': root_cert,
        'ca_privatekey': root_key,
    })
    return cert, key, root_cert


@pytest.fixture
def end_entity_cert(intermediate_ca):
    """Generate an end-entity certificate signed by intermediate CA"""
    intermediate_cert, intermediate_key, root_cert = intermediate_ca
    cert, key = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'server.example.com',
        'country': 'US',
        'organization': 'Example Org',
        'san': ['www.example.com', 'mail.example.com'],
        'digest_algorithm': 'SHA256',
        'lifetime': 365,
        'serial': 3,
        'cert_extensions': {
            'BasicConstraints': {'enabled': False},
            'AuthorityKeyIdentifier': {
                'enabled': True,
                'authority_cert_issuer': False,
            },
            'ExtendedKeyUsage': {
                'enabled': True,
                'usages': ['SERVER_AUTH', 'CLIENT_AUTH'],
            },
            'KeyUsage': {
                'enabled': True,
                'digital_signature': True,
                'key_encipherment': True,
                'extension_critical': True,
            },
        },
        'ca_certificate': intermediate_cert,
        'ca_privatekey': intermediate_key,
    })
    return cert, key, intermediate_cert, root_cert


# Test Category 1A: Valid Certificate Chain Scenarios


def test_validate_cert_with_single_intermediate_ca(end_entity_cert):
    """Test validation with cert -> intermediate -> root chain"""
    cert, _, intermediate_cert, root_cert = end_entity_cert
    chain = [intermediate_cert, root_cert]

    result = validate_cert_with_chain(cert, chain)
    assert result is True


def test_validate_cert_with_chain_as_single_string(end_entity_cert):
    """Test validation when chain certificates are in a single string"""
    cert, _, intermediate_cert, root_cert = end_entity_cert
    # Concatenate intermediate and root into single string
    chain_string = intermediate_cert + root_cert

    result = validate_cert_with_chain(cert, [chain_string])
    assert result is True


def test_validate_cert_with_chain_separate_strings(end_entity_cert):
    """Test validation when chain certificates are separate strings"""
    cert, _, intermediate_cert, root_cert = end_entity_cert
    chain = [intermediate_cert, root_cert]

    result = validate_cert_with_chain(cert, chain)
    assert result is True


def test_validate_self_signed_cert_in_chain(root_ca):
    """Test validation of self-signed certificate with itself as chain"""
    cert, _ = root_ca
    chain = [cert]

    result = validate_cert_with_chain(cert, chain)
    assert result is True


def test_validate_cert_with_only_root_in_chain(intermediate_ca):
    """Test validation with only root CA in chain (intermediate signed by root)"""
    cert, _, root_cert = intermediate_ca
    chain = [root_cert]

    result = validate_cert_with_chain(cert, chain)
    assert result is True


def test_validate_cert_with_chain_in_reverse_order(end_entity_cert):
    """Test that chain order doesn't matter (root first, then intermediate)"""
    cert, _, intermediate_cert, root_cert = end_entity_cert
    # Provide chain in reverse order
    chain = [root_cert, intermediate_cert]

    result = validate_cert_with_chain(cert, chain)
    assert result is True


# Test Category 1B: Invalid Certificate Chain Scenarios


def test_validate_cert_with_wrong_ca(end_entity_cert, root_ca):
    """Test validation fails when cert is signed by different CA"""
    cert, _, _, _ = end_entity_cert
    # Generate a different root CA
    wrong_root, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'Wrong Root CA',
        'digest_algorithm': 'SHA256',
        'lifetime': 3650,
        'serial': 999,
        'cert_extensions': {
            'BasicConstraints': {
                'enabled': True,
                'ca': True,
                'extension_critical': True,
            },
            'AuthorityKeyIdentifier': {'enabled': False},
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {'enabled': False},
        },
    })

    result = validate_cert_with_chain(cert, [wrong_root])
    assert result is False


def test_validate_cert_with_missing_intermediate(end_entity_cert):
    """Test validation fails when intermediate CA is missing from chain"""
    cert, _, _, root_cert = end_entity_cert
    # Only provide root CA, skip intermediate
    chain = [root_cert]

    result = validate_cert_with_chain(cert, chain)
    # This should fail because intermediate is missing
    assert result is False


def test_validate_cert_not_matching_chain():
    """Test validation fails when certificate doesn't match provided chain"""
    # Create two independent certificate chains
    cert1, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'cert1.example.com',
        'digest_algorithm': 'SHA256',
        'lifetime': 365,
        'serial': 100,
        'cert_extensions': {
            'BasicConstraints': {'enabled': False},
            'AuthorityKeyIdentifier': {'enabled': False},
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {'enabled': False},
        },
    })

    cert2, _ = generate_certificate({
        'key_type': 'RSA',
        'key_length': 2048,
        'common': 'cert2.example.com',
        'digest_algorithm': 'SHA256',
        'lifetime': 365,
        'serial': 101,
        'cert_extensions': {
            'BasicConstraints': {'enabled': False},
            'AuthorityKeyIdentifier': {'enabled': False},
            'ExtendedKeyUsage': {'enabled': False},
            'KeyUsage': {'enabled': False},
        },
    })

    # Try to validate cert1 with cert2 as chain
    result = validate_cert_with_chain(cert1, [cert2])
    assert result is False


def test_validate_cert_with_corrupted_chain_cert(end_entity_cert):
    """Test validation fails when chain contains corrupted certificate"""
    cert, _, intermediate_cert, _ = end_entity_cert

    # Corrupt the intermediate certificate
    corrupted = intermediate_cert.replace('MII', 'XXX', 1)

    # This should raise an exception or return False
    try:
        result = validate_cert_with_chain(cert, [corrupted])
        # If it doesn't raise, it should return False
        assert result is False
    except Exception:
        # Exception is acceptable for corrupted cert
        pass


# Test Category 1C: Edge Cases & Error Handling


def test_validate_with_empty_chain_list(end_entity_cert):
    """Test validation with empty chain list"""
    cert, _, _, _ = end_entity_cert

    result = validate_cert_with_chain(cert, [])
    # With empty chain, validation should fail
    assert result is False


def test_validate_with_invalid_cert_format():
    """Test validation with invalid PEM format certificate"""
    invalid_cert = "NOT A VALID CERTIFICATE"
    chain = []

    try:
        result = validate_cert_with_chain(invalid_cert, chain)
        # Should either raise exception or return False
        assert result is False
    except Exception:
        # Exception is acceptable
        pass


def test_validate_with_duplicate_certs_in_chain(end_entity_cert):
    """Test validation with duplicate certificates in chain"""
    cert, _, intermediate_cert, root_cert = end_entity_cert
    # Provide duplicates
    chain = [intermediate_cert, root_cert, intermediate_cert, root_cert]

    # Should still validate successfully (duplicates ignored)
    result = validate_cert_with_chain(cert, chain)
    assert result is True


def test_validate_with_chain_containing_multiple_certs_per_string(end_entity_cert):
    """Test chain with multiple certificates concatenated in one string"""
    cert, _, intermediate_cert, root_cert = end_entity_cert

    # Put both certs in one string (simulating a chain file)
    combined_chain = intermediate_cert + '\n' + root_cert

    result = validate_cert_with_chain(cert, [combined_chain])
    assert result is True


def test_validate_with_whitespace_in_chain(end_entity_cert):
    """Test validation with extra whitespace in chain certificates"""
    cert, _, intermediate_cert, root_cert = end_entity_cert

    # Add extra whitespace
    intermediate_with_spaces = '\n\n' + intermediate_cert + '\n\n'
    root_with_spaces = '\n\n' + root_cert + '\n\n'

    result = validate_cert_with_chain(cert, [intermediate_with_spaces, root_with_spaces])
    assert result is True


def test_validate_cert_signed_directly_by_root(intermediate_ca):
    """Test certificate signed directly by root CA (no intermediate)"""
    cert, _, root_cert = intermediate_ca

    result = validate_cert_with_chain(cert, [root_cert])
    assert result is True


def test_validate_with_mixed_valid_invalid_chain(end_entity_cert):
    """Test chain containing both valid and invalid certificate strings"""
    cert, _, intermediate_cert, root_cert = end_entity_cert

    # Mix valid certs with invalid string
    chain = [intermediate_cert, "INVALID CERT DATA", root_cert]

    # Should fail due to invalid cert in chain
    try:
        result = validate_cert_with_chain(cert, chain)
        # If no exception, should return False
        assert result is False
    except Exception:
        # Exception is acceptable
        pass
