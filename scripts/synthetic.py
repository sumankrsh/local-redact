"""Generate synthetic identifiers with valid (or deliberately broken) checksums.

Every ID used in this repo's tests and samples comes from here or from
published test values (card-scheme test numbers, IBAN registry examples).
None is taken from a real person.

The check digits are computed with their own formulas, separately from
src/local_redact/validators.py, so the tests do not just check the
validators against themselves.
"""

from __future__ import annotations

import random
import string

# --- Luhn: check digit = (10 - (sum of the doubled-from-the-right digits) mod 10) mod 10


def luhn_check_digit(body: str) -> str:
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:  # these positions get doubled once the check digit is appended
            d = d * 2
            d = d - 9 if d > 9 else d
        total += d
    return str((10 - total % 10) % 10)


# --- Verhoeff: generate with the inverse table, positions shifted by one.
_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_P = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]]
for _ in range(7):
    _P.append([_P[-1][x] for x in [1, 5, 7, 6, 2, 8, 3, 0, 9, 4]])
_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_check_digit(body: str) -> str:
    c = 0
    for i, ch in enumerate(reversed(body)):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]
    return str(_INV[c])


# --- IBAN: check digits = 98 - (BBAN + country digits + "00") mod 97, using Python big ints.


def iban_check_digits(country: str, bban: str) -> str:
    numeric = "".join(str(int(ch, 36)) for ch in bban + country) + "00"
    return f"{98 - int(numeric) % 97:02d}"


def _digits(rng: random.Random, n: int) -> str:
    return "".join(rng.choice(string.digits) for _ in range(n))


def break_last_digit(value: str) -> str:
    """Change the final digit so the checksum fails (single-digit errors are always caught)."""
    i = max(i for i, ch in enumerate(value) if ch.isdigit())
    new = str((int(value[i]) + 1 + (int(value[i]) * 7) % 9) % 10)
    if new == value[i]:
        new = str((int(value[i]) + 1) % 10)
    return value[:i] + new + value[i + 1 :]


def emirates_id(rng: random.Random, sep: str = "-") -> str:
    year = str(rng.randint(1960, 2010))
    body = "784" + year + _digits(rng, 7)
    check = luhn_check_digit(body)
    return sep.join([body[:3], body[3:7], body[7:14], check])


def saudi_id(rng: random.Random, first: str = "1") -> str:
    body = first + _digits(rng, 8)
    return body + luhn_check_digit(body)


def aadhaar(rng: random.Random, sep: str = " ") -> str:
    while True:
        body = rng.choice("23456789") + _digits(rng, 10)
        full = body + verhoeff_check_digit(body)
        if full != full[::-1]:
            return sep.join([full[:4], full[4:8], full[8:]])


def pan(rng: random.Random) -> str:
    letters = string.ascii_uppercase
    return (
        "".join(rng.choice(letters) for _ in range(3))
        + rng.choice("PCHFATBLJG")
        + rng.choice(letters)
        + _digits(rng, 4)
        + rng.choice(letters)
    )


def card(rng: random.Random, prefix: str, length: int, sep: str = " ") -> str:
    body = prefix + _digits(rng, length - len(prefix) - 1)
    full = body + luhn_check_digit(body)
    if length == 15 and sep:
        return sep.join([full[:4], full[4:10], full[10:]])
    if sep:
        return sep.join(full[i : i + 4] for i in range(0, len(full), 4))
    return full


def iban(rng: random.Random, country: str, length: int, spaced: bool = True) -> str:
    bban = _digits(rng, length - 4)
    full = country + iban_check_digits(country, bban) + bban
    if spaced:
        return " ".join(full[i : i + 4] for i in range(0, len(full), 4))
    return full


def ipv4(rng: random.Random) -> str:
    return ".".join(str(rng.randint(1, 254)) for _ in range(4))


def ipv6(rng: random.Random) -> str:
    groups = [f"{rng.randint(1, 0xFFFF):x}" for _ in range(8)]
    return ":".join(groups)
