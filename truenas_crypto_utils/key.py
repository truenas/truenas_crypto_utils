from typing import Literal, TypeAlias, overload

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization

from .read import load_private_key
from .utils import EC_CURVE_DEFAULT


GeneratedPrivateKey: TypeAlias = Ed25519PrivateKey | rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
PrivateKey: TypeAlias = GeneratedPrivateKey | Ed448PrivateKey | DSAPrivateKey


def retrieve_signing_algorithm(
    data: dict,
    signing_key: PrivateKey,
):
    if isinstance(signing_key, Ed25519PrivateKey):
        return None
    else:
        return getattr(hashes, data.get('digest_algorithm') or 'SHA256')()


@overload
def generate_private_key(options: dict, *, serialize: Literal[True]) -> str: ...


@overload
def generate_private_key(options: dict, *, serialize: Literal[False] = False) -> GeneratedPrivateKey: ...


def generate_private_key(options: dict, *, serialize: bool = False) -> GeneratedPrivateKey | str:
    # We should make sure to return in PEM format
    # Reason for using PKCS8
    # https://stackoverflow.com/questions/48958304/pkcs1-and-pkcs8-format-for-rsa-private-key
    options.setdefault('key_length', 2048)
    options.setdefault('type', 'RSA')
    options.setdefault('curve', EC_CURVE_DEFAULT)

    if options['type'] == 'EC':
        if options['curve'] == 'ed25519':
            key = Ed25519PrivateKey.generate()
        else:
            key = ec.generate_private_key(
                getattr(ec, options['curve'])(),
                default_backend()
            )
    else:
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=options['key_length'],
            backend=default_backend()
        )

    if serialize:
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


def export_private_key_object(key: PrivateKey) -> str:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
