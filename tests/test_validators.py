import pytest

from conftest import load_fixture
from local_redact.validators import luhn_ok, mod97_ok, verhoeff_ok, validate_iban, validate_ipv6

VECTORS = load_fixture("checksums.json")
FUNCS = {"luhn": luhn_ok, "verhoeff": verhoeff_ok, "mod97": mod97_ok}


@pytest.mark.parametrize(
    "algo,value,ok",
    [(a, v, True) for a in FUNCS for v in VECTORS[a]["valid"]]
    + [(a, v, False) for a in FUNCS for v in VECTORS[a]["invalid"]],
)
def test_checksum_vectors(algo, value, ok):
    assert FUNCS[algo](value) is ok


def test_iban_trims_trailing_text():
    text = "AE07 0331 2345 6789 0123 456 IS"
    assert validate_iban(text, {"lengths": {"AE": 23}}) == len("AE07 0331 2345 6789 0123 456")


@pytest.mark.parametrize(
    "value,ok",
    [
        ("2001:db8::1", True),
        ("2001:0db8:0000:0000:0000:ff00:0042:8329", True),
        ("::ffff:192.0.2.1", True),
        ("2001:db8::1::2", False),
        ("1:2:3:4:5:6:7", False),
        ("1:2:3:4:5:6:7:8:9", False),
        ("12345::1", False),
        ("::1", False),  # fewer than two non-zero groups
    ],
)
def test_ipv6(value, ok):
    assert (validate_ipv6(value, {"min_groups": 2}) is not None) is ok
