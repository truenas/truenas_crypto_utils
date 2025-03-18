from distutils.core import setup
from setuptools import find_packages

VERSION = '0.1'

setup(
    name='truenas_crypto_utils',
    description='TrueNAS Scale System Crypto Utils',
    version=VERSION,
    include_package_data=True,
    packages=find_packages(include=[
        'truenas_acme_utils',
        'truenas_acme_utils.*',
        'truenas_crypto_utils',
        'truenas_crypto_utils.*',
    ]),
    license='GNU3',
    platforms='any',
)
