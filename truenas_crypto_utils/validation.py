import itertools

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from OpenSSL import crypto, SSL

from .read import load_private_key
from .utils import RE_CERTIFICATE


def validate_cert_with_chain(cert: str, chain: list[str]) -> bool:
    check_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
    store = crypto.X509Store()
    for chain_cert in itertools.chain.from_iterable(map(lambda c: RE_CERTIFICATE.findall(c), chain)):
        store.add_cert(
            crypto.load_certificate(crypto.FILETYPE_PEM, chain_cert)
        )

    store_ctx = crypto.X509StoreContext(store, check_cert)
    try:
        store_ctx.verify_certificate()
    except crypto.X509StoreContextError:
        return False
    else:
        return True


def validate_certificate_with_key(
    certificate: str, private_key: str, passphrase: str | None = None
) -> str | None:
    if not certificate or not private_key:
        return

    public_key_obj = crypto.load_certificate(crypto.FILETYPE_PEM, certificate)
    private_key_obj = crypto.load_privatekey(
        crypto.FILETYPE_PEM,
        private_key,
        passphrase=passphrase.encode() if passphrase else None
    )

    try:
        context = SSL.Context(SSL.TLSv1_2_METHOD)
        context.use_certificate(public_key_obj)
        context.use_privatekey(private_key_obj)
        context.check_privatekey()
    except SSL.Error as e:
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
