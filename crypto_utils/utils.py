import re

CERT_BACKEND_MAPPINGS = {
    'common_name': 'common',
    'country_name': 'country',
    'state_or_province_name': 'state',
    'locality_name': 'city',
    'organization_name': 'organization',
    'organizational_unit_name': 'organizational_unit',
    'email_address': 'email'
}


# This constant defines the default lifetime of certificate ( https://support.apple.com/en-us/HT211025 )
DEFAULT_LIFETIME_DAYS = 397
EC_CURVES = [
    'SECP256R1',
    'SECP384R1',
    'SECP521R1',
    'ed25519',
]
EC_CURVE_DEFAULT = 'SECP384R1'
RE_CERTIFICATE = re.compile(r"(-{5}BEGIN[\s\w]+-{5}[^-]+-{5}END[\s\w]+-{5})+", re.M | re.S)
