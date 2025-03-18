import pytest

from truenas_crypto_utils.generate_certs import normalize_san


@pytest.mark.parametrize("reference,expected_results", [
    (['truenas.domain', '192.168.0.10'], [['DNS', 'truenas.domain'], ['IP', '192.168.0.10']]),
    (['DNS:truenas.domain', '192.168.0.10'], [['DNS', 'truenas.domain'], ['IP', '192.168.0.10']]),
    (['DNS:truenas.domain', 'IP:192.168.0.10'], [['DNS', 'truenas.domain'], ['IP', '192.168.0.10']]),
])
def test_normalize_san(reference, expected_results):
    assert normalize_san(reference) == expected_results
