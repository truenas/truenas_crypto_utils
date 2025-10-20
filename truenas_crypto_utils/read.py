import base64
import hashlib
import datetime
import dateutil
import dateutil.parser
import logging
import re

from contextlib import suppress
from typing import TypeAlias
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.x509 import (
    ExtendedKeyUsage, KeyUsage, BasicConstraints, SubjectKeyIdentifier,
    AuthorityKeyIdentifier, AuthorityInformationAccess, CRLDistributionPoints,
    CertificatePolicies, UnrecognizedExtension
)
from cryptography.x509.oid import ExtensionOID, NameOID, ExtendedKeyUsageOID, AuthorityInformationAccessOID

from .utils import RE_CERTIFICATE


GeneratedPrivateKey: TypeAlias = ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
PrivateKey: TypeAlias = GeneratedPrivateKey | ed448.Ed448PrivateKey | dsa.DSAPrivateKey

logger = logging.getLogger(__name__)


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _serial_value_bytes(n: int) -> bytes:
    # DER INTEGER value bytes for non-negative n
    if n == 0:
        return b'\x00'
    v = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return v if not (v[0] & 0x80) else b'\x00' + v


def _hexlim(data: bytes, limit: int = 256) -> str:
    """
    Hex-encode up to `limit` bytes; indicate truncation and total length if needed.
    """
    if not isinstance(data, (bytes, bytearray)):
        return str(data)
    b = bytes(data)
    if len(b) <= limit:
        return b.hex().upper()

    return f'{b[:limit].hex().upper()}'


def get_cert_id(cert_str: str) -> str:
    """
    ARI cert_id per RFC 9773 §4.1
    format: base64url(AKI.keyIdentifier) + "." + base64url(serial INTEGER value bytes)
    """
    cert = x509.load_pem_x509_certificate(cert_str.encode())
    try:
        aki_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    except x509.ExtensionNotFound as e:
        raise ValueError('Certificate missing Authority Key Identifier (AKI)') from e

    if aki_ext.value.key_identifier is None:
        raise ValueError('AKI keyIdentifier is None')

    aki_b64 = _b64url(aki_ext.value.key_identifier)
    serial_b64 = _b64url(_serial_value_bytes(cert.serial_number))
    return f'{aki_b64}.{serial_b64}'


def parse_cert_date_string(date_value: bytes | str) -> str:
    t1 = dateutil.parser.parse(date_value)
    t2 = t1.astimezone(dateutil.tz.tzlocal())
    return t2.ctime()


def load_certificate(certificate: str, get_issuer: bool = False) -> dict:
    try:
        # digest_algorithm, lifetime, country, state, city, organization, organizational_unit,
        # email, common, san, serial, chain, fingerprint
        cert = x509.load_pem_x509_certificate(certificate.encode())
        from_date = parse_cert_date_string(cert.not_valid_before_utc.strftime('%Y%m%d%H%M%SZ').encode())
        until_date = parse_cert_date_string(cert.not_valid_after_utc.strftime('%Y%m%d%H%M%SZ').encode())
        expired = datetime.datetime.now(datetime.timezone.utc) > cert.not_valid_after_utc
    except (ValueError, OverflowError):
        # Overflow error is raised when the certificate has a lifetime which will never expire
        # and we don't support such certificates
        return {}
    else:
        cert_info = get_x509_subject(cert)
        if get_issuer:
            cert_info['issuer_dn'] = parse_name_components(cert.issuer) if cert.issuer else None

        valid_algos = ('SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512', 'ED25519')
        signature_algorithm = cert.signature_algorithm_oid._name
        # Certs signed with RSA keys will have something like
        # sha256WithRSAEncryption
        # Certs signed with EC keys will have something like
        # ecdsa-with-SHA256
        m = re.match('^(.+)[Ww]ith', signature_algorithm)
        if m:
            cert_info['digest_algorithm'] = m.group(1).upper()

        if cert_info.get('digest_algorithm') not in valid_algos:
            cert_info['digest_algorithm'] = (signature_algorithm or '').split('-')[-1].strip()

        if cert_info['digest_algorithm'] not in valid_algos:
            # Let's log this please
            logger.debug(f'Failed to parse signature algorithm {signature_algorithm} for {certificate}')

        cert_info.update({
            'lifetime': (cert.not_valid_after_utc - cert.not_valid_before_utc).days,
            'from': from_date,
            'until': until_date,
            'serial': cert.serial_number,
            'chain': len(RE_CERTIFICATE.findall(certificate)) > 1,
            'fingerprint': ':'.join(f'{b:02X}' for b in cert.fingerprint(hashes.SHA1())),
            'expired': expired,
        })

        return cert_info


def _get_name_attribute(name: x509.Name, oid) -> str | None:
    """Helper to extract a single attribute from an x509.Name"""
    try:
        attrs = name.get_attributes_for_oid(oid)
        return attrs[0].value if attrs else None
    except (x509.ExtensionNotFound, IndexError):
        return None


def _format_san_entry(entry) -> str:
    """Format a SubjectAlternativeName entry to match OpenSSL-style output and cover all GeneralName variants."""
    if isinstance(entry, x509.DNSName):
        return f'DNS:{entry.value}'
    elif isinstance(entry, x509.IPAddress):
        return f'IP Address:{entry.value}'
    elif isinstance(entry, x509.RFC822Name):
        return f'email:{entry.value}'
    elif isinstance(entry, x509.UniformResourceIdentifier):
        return f'URI:{entry.value}'
    elif isinstance(entry, x509.DirectoryName):
        # Reuse DN formatter for nested names
        return f'DirName:{parse_name_components(entry.value)}'
    elif isinstance(entry, x509.RegisteredID):
        return f'Registered ID:{entry.value.dotted_string}'
    elif isinstance(entry, x509.OtherName):
        # Value is context-specific; represent as hex with OID
        try:
            return f'otherName:{entry.type_id.dotted_string};{_hexlim(entry.value)}'
        except Exception:
            return f'otherName:{entry.type_id.dotted_string};<unprintable>'
    else:
        return str(getattr(entry, 'value', entry))


def _format_extension_value(ext) -> str:
    """Format extension value to match OpenSSL's human-readable format and handle unknown extensions safely."""
    value = ext.value
    # Handle unknown/unregistered extensions explicitly
    if isinstance(value, UnrecognizedExtension):
        raw = getattr(value, 'value', b'')
        return (
            f'Unrecognized (OID {ext.oid.dotted_string})\n'
            f'  critical={getattr(ext, 'critical', False)}\n'
            f'  data(hex)={_hexlim(raw)}'
        )
    elif isinstance(value, (bytes, bytearray)):
        return (
            f'Unrecognized (OID {ext.oid.dotted_string})\n'
            f'  critical={getattr(ext, 'critical', False)}\n'
            f'  data(hex)={_hexlim(value)}'
        )
    elif isinstance(value, CertificatePolicies):
        policies = []
        for policy_info in value:
            policy_oid = policy_info.policy_identifier.dotted_string
            policies.append(f'Policy: {policy_oid}')
        return '\n'.join(policies)
    elif isinstance(value, ExtendedKeyUsage):
        eku_names = {
            ExtendedKeyUsageOID.SERVER_AUTH: 'TLS Web Server Authentication',
            ExtendedKeyUsageOID.CLIENT_AUTH: 'TLS Web Client Authentication',
            ExtendedKeyUsageOID.CODE_SIGNING: 'Code Signing',
            ExtendedKeyUsageOID.EMAIL_PROTECTION: 'E-mail Protection',
            ExtendedKeyUsageOID.TIME_STAMPING: 'Time Stamping',
            ExtendedKeyUsageOID.OCSP_SIGNING: 'OCSP Signing',
            x509.oid.ObjectIdentifier('2.5.29.37.0'): 'Any Extended Key Usage',
        }
        names = [eku_names.get(oid, str(oid)) for oid in value]
        return ', '.join(names)
    elif isinstance(value, KeyUsage):
        usages = []
        if value.digital_signature:
            usages.append('Digital Signature')
        if value.content_commitment:
            usages.append('Non Repudiation')
        if value.key_encipherment:
            usages.append('Key Encipherment')
        if value.data_encipherment:
            usages.append('Data Encipherment')
        if value.key_agreement:
            usages.append('Key Agreement')
            if value.encipher_only:
                usages.append('Encipher Only')
            if value.decipher_only:
                usages.append('Decipher Only')
        if value.key_cert_sign:
            usages.append('Certificate Sign')
        if value.crl_sign:
            usages.append('CRL Sign')
        return ', '.join(usages)
    elif isinstance(value, BasicConstraints):
        parts = [f'CA:{str(value.ca).upper()}']
        if value.path_length is not None:
            parts.append(f'pathlen:{value.path_length}')
        return ', '.join(parts)
    elif isinstance(value, SubjectKeyIdentifier):
        return ':'.join(f'{b:02X}' for b in value.digest)
    elif isinstance(value, AuthorityKeyIdentifier):
        if value.key_identifier:
            return ':'.join(f'{b:02X}' for b in value.key_identifier)
        return ''
    elif isinstance(value, AuthorityInformationAccess):
        lines = []
        aia_names = {
            AuthorityInformationAccessOID.OCSP: 'OCSP',
            AuthorityInformationAccessOID.CA_ISSUERS: 'CA Issuers',
        }
        for desc in value:
            method = aia_names.get(desc.access_method, desc.access_method.dotted_string)
            # Render location using SAN formatter to support non-URI names
            try:
                loc = _format_san_entry(desc.access_location)
            except Exception:
                loc = str(getattr(desc.access_location, "value", desc.access_location))
            lines.append(f'{method} - {loc}')
        return '\n'.join(lines)
    elif isinstance(value, CRLDistributionPoints):
        lines = []
        for dp in value:
            if dp.full_name:
                for name in dp.full_name:
                    lines.append(f'Full Name:\n  {_format_san_entry(name)}')
        return '\n'.join(lines)
    else:
        return str(value)


def get_x509_subject(obj: x509.Certificate | x509.CertificateSigningRequest) -> dict:
    subject = obj.subject
    cert_info = {
        'country': _get_name_attribute(subject, NameOID.COUNTRY_NAME),
        'state': _get_name_attribute(subject, NameOID.STATE_OR_PROVINCE_NAME),
        'city': _get_name_attribute(subject, NameOID.LOCALITY_NAME),
        'organization': _get_name_attribute(subject, NameOID.ORGANIZATION_NAME),
        'organizational_unit': _get_name_attribute(subject, NameOID.ORGANIZATIONAL_UNIT_NAME),
        'common': _get_name_attribute(subject, NameOID.COMMON_NAME),
        'san': [],
        'email': _get_name_attribute(subject, NameOID.EMAIL_ADDRESS),
        'DN': '',
        'subject_name_hash': None,
        'extensions': {},
    }

    # Only calculate subject_name_hash for certificates, not CSRs
    if isinstance(obj, x509.Certificate):
        # Use SHA1 hash of the subject DER encoding, matching OpenSSL's behavior
        subject_der = subject.public_bytes()
        # OpenSSL uses first 4 bytes of SHA1 hash as little-endian integer
        cert_info['subject_name_hash'] = int.from_bytes(hashlib.sha1(subject_der).digest()[:4], byteorder='little')

    # Process extensions
    for ext in obj.extensions:
        try:
            # Prefer friendly name if available; otherwise fall back to dotted OID
            ext_name = ext.oid._name or ext.oid.dotted_string
            if ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                cert_info['san'] = [_format_san_entry(entry) for entry in ext.value]
                cert_info['extensions']['SubjectAltName'] = ', '.join(cert_info['san'])
            else:
                # Capitalize first letter for cosmetic parity with OpenSSL dumps
                ext_title = re.sub(r"^(\S)", lambda m: m.group(1).upper(), ext_name)
                cert_info['extensions'][ext_title] = _format_extension_value(ext)
        except Exception as e:
            # some certificates can have extensions with binary data which we can't parse without
            # explicit mapping for each extension. The current case covers the most of extensions nicely
            # and if it's required to map certain extensions which can't be handled by above we can do
            # so as users request.
            logger.error('Unable to parse extension: %s', e)

    cert_info['DN'] = parse_name_components(subject)

    if cert_info['san']:
        # We should always trust the extension instead of the subject for SAN
        cert_info['DN'] += f'/subjectAltName={", ".join(cert_info["san"])}'

    return cert_info


def parse_name_components(obj: x509.Name) -> str:
    dn = []
    for attr in obj:
        # Map OIDs to their short names
        oid_name_map = {
            NameOID.COMMON_NAME: 'CN',
            NameOID.COUNTRY_NAME: 'C',
            NameOID.STATE_OR_PROVINCE_NAME: 'ST',
            NameOID.LOCALITY_NAME: 'L',
            NameOID.ORGANIZATION_NAME: 'O',
            NameOID.ORGANIZATIONAL_UNIT_NAME: 'OU',
            NameOID.EMAIL_ADDRESS: 'emailAddress',
        }
        name = oid_name_map.get(attr.oid, attr.oid._name)
        if name != 'subjectAltName':
            dn.append(f'{name}={attr.value}')
    return f'/{"/".join(dn)}'


def load_certificate_request(csr: str) -> dict:
    try:
        csr_obj = x509.load_pem_x509_csr(csr.encode())
    except ValueError:
        return {}
    else:
        return get_x509_subject(csr_obj)


def load_private_key(key_string: str, passphrase: str | None = None) -> PrivateKey:
    with suppress(ValueError, TypeError, AttributeError):
        return serialization.load_pem_private_key(
            key_string.encode(),
            password=passphrase.encode() if passphrase else None,
        )


def get_serial_from_certificate_safe(certificate: str | None) -> int | None:
    try:
        cert = x509.load_pem_x509_certificate(certificate.encode())
    except (ValueError, AttributeError):
        return
    else:
        return cert.serial_number
