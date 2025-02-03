from distutils.core import setup
from setuptools import find_packages

VERSION = '0.1'

setup(
    name='crypto_utils',
    description='Generate TrueNAS Scale System Crypto Utils',
    version=VERSION,
    include_package_data=True,
    packages=find_packages(),
    license='GNU3',
    platforms='any',
)
