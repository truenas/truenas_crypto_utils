import datetime

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519, ed448, padding
from cryptography.x509 import verification
from cryptography.x509.oid import ExtensionOID

from .read import load_private_key
from .utils import RE_CERTIFICATE


def _is_self_signed(cert: x509.Certificate) -> bool:
    return cert.issuer == cert.subject


def _verify_cert_signature(issuer_pub, subject_cert: x509.Certificate) -> None:
    """Verify subject_cert's signature using issuer_pub.
    Raises on failure. Supports RSA (PKCS1v15/PSS), ECDSA, Ed25519, Ed448.
    """
    params = getattr(subject_cert, "signature_algorithm_parameters", None)

    if isinstance(issuer_pub, rsa.RSAPublicKey):
        # Use the parameters embedded in the cert when present (handles RSA-PSS),
        # otherwise fall back to PKCS#1 v1.5.
        pad = params if isinstance(params, padding.AsymmetricPadding) else padding.PKCS1v15()
        issuer_pub.verify(
            subject_cert.signature,
            subject_cert.tbs_certificate_bytes,
            pad,
            subject_cert.signature_hash_algorithm,
        )
    elif isinstance(issuer_pub, ec.EllipticCurvePublicKey):
        issuer_pub.verify(
            subject_cert.signature,
            subject_cert.tbs_certificate_bytes,
            ec.ECDSA(subject_cert.signature_hash_algorithm),
        )
    elif isinstance(issuer_pub, ed25519.Ed25519PublicKey):
        issuer_pub.verify(subject_cert.signature, subject_cert.tbs_certificate_bytes)
    elif isinstance(issuer_pub, ed448.Ed448PublicKey):
        issuer_pub.verify(subject_cert.signature, subject_cert.tbs_certificate_bytes)
    else:
        raise ValueError("Unsupported issuer public key type: %r" % type(issuer_pub))


def validate_cert_with_chain(cert: str, chain: list[str]) -> bool:
    """Validate cert against the given chain, mimicking prior PyOpenSSL behavior.

    Behavior notes to match legacy implementation:
    - Treat any provided certificates as trusted roots (anchors) if they are self-signed.
    - If no self-signed certificates are present, treat *all* provided certificates as trust anchors.
    - If the target certificate is self-signed and appears in the chain inputs, accept it as valid.
    - Do not perform revocation (CRL/OCSP) checks.
    """
    try:
        check_cert = x509.load_pem_x509_certificate(cert.encode())
    except Exception:
        return False

    # Build list of certificates extracted from the chain inputs
    chain_certs: list[x509.Certificate] = []
    for chunk in chain:
        for pem in RE_CERTIFICATE.findall(chunk):
            try:
                chain_certs.append(x509.load_pem_x509_certificate(pem.encode()))
            except Exception:
                # Skip malformed certs to mimic OpenSSL's leniency
                pass

    if not chain_certs:
        return False

    # Self-signed special case: leaf appears verbatim in the chain
    if _is_self_signed(check_cert):
        for c in chain_certs:
            if c.public_bytes(serialization.Encoding.PEM) == check_cert.public_bytes(serialization.Encoding.PEM):
                return True

    # Partition into trust anchors (self-signed) and intermediates
    trust_anchors = [c for c in chain_certs if _is_self_signed(c)]
    intermediates = [c for c in chain_certs if not _is_self_signed(c)]

    # If no explicit anchors were provided, mimic OpenSSL by treating all as trusted
    if not trust_anchors:
        trust_anchors = chain_certs
        intermediates = []

    # Prepare store and policy
    store = verification.Store(trust_anchors)

    # Determine if target is a CA cert
    try:
        bc = check_cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        is_ca_cert = bool(bc.ca)
    except x509.ExtensionNotFound:
        is_ca_cert = False

    # Use custom extension policies to avoid EKU requirements on generic EE certs,
    # matching PyOpenSSL which doesn't enforce EKU by default.
    if is_ca_cert:
        ee_policy = verification.ExtensionPolicy.webpki_defaults_ca()
    else:
        ee_policy = verification.ExtensionPolicy.permit_all()
    ca_policy = verification.ExtensionPolicy.webpki_defaults_ca()

    builder = (
        verification.PolicyBuilder()
        .store(store)
        .time(datetime.datetime.now(datetime.timezone.utc))
        .extension_policies(ee_policy=ee_policy, ca_policy=ca_policy)
    )

    try:
        # Prefer the library's path validation when possible.
        verifier = builder.build_client_verifier()
        verifier.verify(check_cert, intermediates)
        return True
    except verification.VerificationError:
        # Fall back for CA-as-leaf and edge cases to preserve legacy behavior
        pass
    except Exception:
        # Any other failure: attempt a manual signature + minimal RFC checks for CA leaf
        pass

    # Manual fallback for CA leaf: check issuer in anchors and verify signature & basic constraints
    if is_ca_cert:
        for ta in trust_anchors:
            if ta.subject == check_cert.issuer:
                try:
                    _verify_cert_signature(ta.public_key(), check_cert)

                    # Minimal validity checks to stay close to OpenSSL defaults
                    now = datetime.datetime.now(datetime.timezone.utc)
                    if now < check_cert.not_valid_before.replace(tzinfo=datetime.timezone.utc):
                        return False
                    if now > check_cert.not_valid_after.replace(tzinfo=datetime.timezone.utc):
                        return False

                    # If KeyUsage is present, require keyCertSign for CA certs
                    try:
                        ku = check_cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
                        if not getattr(ku, "key_cert_sign", False):
                            return False
                    except x509.ExtensionNotFound:
                        pass

                    return True
                except Exception:
                    continue
    return False


def validate_certificate_with_key(
    certificate: str, private_key: str, passphrase: str | None = None
) -> str | None:
    if not certificate or not private_key:
        return None

    try:
        cert = x509.load_pem_x509_certificate(certificate.encode())
        private_key_obj = serialization.load_pem_private_key(
            private_key.encode(),
            password=passphrase.encode() if passphrase else None,
        )
    except Exception as e:
        return str(e)

    # Compare public portions
    try:
        cert_pub = cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_pub = private_key_obj.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if cert_pub != key_pub:
            return "Certificate and private key do not match"
    except Exception as e:
        return str(e)

    return None


def validate_private_key(private_key: str, passphrase: str | None = None) -> str | None:
    private_key_obj = load_private_key(private_key, passphrase)
    if not private_key_obj:
        return 'A valid private key is required, with a passphrase if one has been set.'
    elif (
        isinstance(
            private_key_obj, (ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey),
        ) is False and private_key_obj.key_size < 1024
    ):
        # When a cert/ca is being created, disallow keys with size less then 1024
        # We do not do this check for any EC based key
        return 'Key size must be greater than or equal to 1024 bits.'
