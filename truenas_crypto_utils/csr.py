from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from .extensions import add_extensions
from .generate_utils import generate_builder, normalize_san
from .key import export_private_key_object, generate_private_key, retrieve_signing_algorithm
from .utils import CERT_BACKEND_MAPPINGS, EC_CURVE_DEFAULT


def generate_certificate_signing_request(data: dict) -> tuple[str, str]:
    key = generate_private_key({
        'type': data.get('key_type') or 'RSA',
        'curve': data.get('ec_curve') or EC_CURVE_DEFAULT,
        'key_length': data.get('key_length') or 2048
    })

    csr = generate_builder({
        'crypto_subject_name': {
            k: data[v] for k, v in CERT_BACKEND_MAPPINGS.items() if data.get(v)
        },
        'san': normalize_san(data.get('san') or []),
        'serial': data.get('serial'),
        'lifetime': data.get('lifetime'),
        'csr': True,
    })

    csr = add_extensions(csr, data.get('cert_extensions', {}), key, None)
    csr = csr.sign(key, retrieve_signing_algorithm(data, key), default_backend())

    return csr.public_bytes(serialization.Encoding.PEM).decode(), export_private_key_object(key)
