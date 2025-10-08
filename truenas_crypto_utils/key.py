from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization

from .read import load_private_key
from .utils import EC_CURVE_DEFAULT


def retrieve_signing_algorithm(data: dict, signing_key: (
    ed25519.Ed25519PrivateKey |
    ed448.Ed448PrivateKey |
    rsa.RSAPrivateKey |
    dsa.DSAPrivateKey |
    ec.EllipticCurvePrivateKey
)):
    if isinstance(signing_key, Ed25519PrivateKey):
        return None
    else:
        return getattr(hashes, data.get('digest_algorithm') or 'SHA256')()


def generate_private_key(options: dict) -> (
    str,
    ed25519.Ed25519PrivateKey |
    ed448.Ed448PrivateKey |
    rsa.RSAPrivateKey |
    dsa.DSAPrivateKey |
    ec.EllipticCurvePrivateKey
):
    # We should make sure to return in PEM format
    # Reason for using PKCS8
    # https://stackoverflow.com/questions/48958304/pkcs1-and-pkcs8-format-for-rsa-private-key
    options.setdefault('serialize', False)
    options.setdefault('key_length', 2048)
    options.setdefault('type', 'RSA')
    options.setdefault('curve', EC_CURVE_DEFAULT)

    if options.get('type') == 'EC':
        if options['curve'] == 'ed25519':
            key = Ed25519PrivateKey.generate()
        else:
            key = ec.generate_private_key(
                getattr(ec, options.get('curve'))(),
                default_backend()
            )
    else:
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=options.get('key_length'),
            backend=default_backend()
        )

    if options.get('serialize'):
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
    else:
        return key


def export_private_key(buffer: str, passphrase: str | None = None) -> str | None:
    key = load_private_key(buffer, passphrase)
    if key:
        return export_private_key_object(key)


def export_private_key_object(key: (
    ed25519.Ed25519PrivateKey |
    ed448.Ed448PrivateKey |
    rsa.RSAPrivateKey |
    dsa.DSAPrivateKey |
    ec.EllipticCurvePrivateKey
)) -> str:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
