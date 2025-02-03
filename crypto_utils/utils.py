import re
from datetime import datetime, UTC


CERT_BACKEND_MAPPINGS = {
    'common_name': 'common',
    'country_name': 'country',
    'state_or_province_name': 'state',
    'locality_name': 'city',
    'organization_name': 'organization',
    'organizational_unit_name': 'organizational_unit',
    'email_address': 'email'
}
RDN_MAPPINGS = {
    'C': 'country_name',
    'country': 'country_name',
    'ST': 'state_or_province_name',
    'state': 'state_or_province_name',
    'L': 'locality_name',
    'city': 'locality_name',
    'O': 'organization_name',
    'organization': 'organization_name',
    'OU': 'organizational_unit_name',
    'organizational_unit': 'organizational_unit_name',
    'CN': 'common_name',
    'common': 'common_name',
    'emailAddress': 'email_address',
    'email': 'email_address'
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


def utc_now(naive=True):
    """Wrapper for `datetime.now(UTC)`. Exclude timezone if `naive=True`."""
    dt = datetime.now(UTC)
    return dt.replace(tzinfo=None) if naive else dt
