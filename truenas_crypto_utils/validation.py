import itertools

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509 import verification

from .read import load_private_key
from .utils import RE_CERTIFICATE


def validate_cert_with_chain(cert: str, chain: list[str]) -> bool:
    check_cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())

    # Build a list of trusted certificates from the chain
    trusted_certs = []
    for chain_cert in itertools.chain.from_iterable(map(lambda c: RE_CERTIFICATE.findall(c), chain)):
        trusted_certs.append(
            x509.load_pem_x509_certificate(chain_cert.encode(), default_backend())
        )

    try:
        # Create a certificate store and verifier
        # Use build_client_verifier for chain validation without specific server name
        verification.PolicyBuilder().store(
            verification.Store(trusted_certs)
        ).build_client_verifier().verify(check_cert, [])
        return True
    except Exception:
        return False


def validate_certificate_with_key(
    certificate: str, private_key: str, passphrase: str | None = None
) -> str | None:
    if not certificate or not private_key:
        return

    try:
        cert = x509.load_pem_x509_certificate(certificate.encode(), default_backend())
        private_key_obj = serialization.load_pem_private_key(
            private_key.encode(),
            password=passphrase.encode() if passphrase else None,
            backend=default_backend()
        )
    except Exception as e:
        return str(e)

    # Verify that the private key matches the public key in the certificate
    cert_public_key = cert.public_key()
    private_public_key = private_key_obj.public_key()

    # Compare public keys by serializing them
    try:
        cert_public_bytes = cert_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        private_public_bytes = private_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        if cert_public_bytes != private_public_bytes:
            return 'Certificate and private key do not match'
    except Exception as e:
        return str(e)


def validate_private_key(private_key: str, passphrase: str | None = None) -> str | None:
    private_key_obj = load_private_key(private_key, passphrase)
    if not private_key_obj:
        return 'A valid private key is required, with a passphrase if one has been set.'
    elif (
        isinstance(
            private_key_obj, (ec.EllipticCurvePrivateKey, Ed25519PrivateKey),
        ) is False and private_key_obj.key_size < 1024
    ):
        # When a cert/ca is being created, disallow keys with size less then 1024
        # We do not do this check for any EC based key
        return 'Key size must be greater than or equal to 1024 bits.'
