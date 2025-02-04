from distutils.core import setup
from setuptools import find_packages

VERSION = '0.1'

setup(
    name='crypto_utils',
    description='TrueNAS Scale System Crypto Utils',
    version=VERSION,
    include_package_data=True,
    packages=find_packages(include=[
        'acme_utils',
        'acme_utils.*',
        'crypto_utils',
        'crypto_utils.*',
    ]),
    license='GNU3',
    platforms='any',
)
