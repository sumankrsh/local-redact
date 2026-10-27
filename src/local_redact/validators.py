"""Checksum and format validators.

Each validator takes the matched text and the pattern's ``params`` from the
JSON spec. It returns the number of characters to keep (usually the whole
match) or ``None`` to reject the match.

web/engine.js has a line-for-line JavaScript copy of every function here.
If you change one, change the other; the shared fixtures in tests/fixtures
will catch any difference.
"""

from __future__ import annotations

import base64
import json
from typing import Callable, Dict, Optional


def digits_only(text: str) -> str:
    return "".join(ch for ch in text if "0" <= ch <= "9")


def has_prefix(digits: str, prefixes) -> bool:
    """True if ``digits`` starts with one of ``prefixes``.

    A prefix is either a digit string ("4") or an inclusive range of equal-length
    digit strings ("2221-2720").
    """
    for prefix in prefixes:
        if "-" in prefix:
            low, high = prefix.split("-")
            head = digits[: len(low)]
            if len(head) == len(low) and int(low) <= int(head) <= int(high):
                return True
        elif digits.startswith(prefix):
            return True
    return False


def luhn_ok(digits: str) -> bool:
    """Luhn (mod 10) check, as defined in ISO/IEC 7812-1 Annex B.

    Reference: https://en.wikipedia.org/wiki/Luhn_algorithm
    """
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# Verhoeff tables: multiplication in the dihedral group D5 and the permutation
# table. Reference: https://en.wikipedia.org/wiki/Verhoeff_algorithm
# (same tables as python-stdnum's stdnum/verhoeff.py).
_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def verhoeff_ok(digits: str) -> bool:
    check = 0
    for i, ch in enumerate(reversed(digits)):
        check = _VERHOEFF_D[check][_VERHOEFF_P[i % 8][ord(ch) - 48]]
    return check == 0


def mod97_ok(iban: str) -> bool:
    """ISO 13616 / ISO 7064 MOD 97-10: move the first four characters to the
    end, turn letters into numbers (A=10 ... Z=35) and check the remainder is 1.
    """
    rearranged = iban[4:] + iban[:4]
    remainder = 0
    for ch in rearranged:
        value = int(ch, 36)
        remainder = (remainder * (100 if value > 9 else 10) + value) % 97
    return remainder == 1


def _length_ok(digits: str, params: dict) -> bool:
    return params.get("min_length", 0) <= len(digits) <= params.get("max_length", 10**6)


def validate_luhn(text: str, params: dict) -> Optional[int]:
    digits = digits_only(text)
    if not _length_ok(digits, params):
        return None
    if "prefixes" in params and not has_prefix(digits, params["prefixes"]):
        return None
    return len(text) if luhn_ok(digits) else None


def validate_verhoeff(text: str, params: dict) -> Optional[int]:
    digits = digits_only(text)
    if not _length_ok(digits, params):
        return None
    if "prefixes" in params and not has_prefix(digits, params["prefixes"]):
        return None
    if params.get("reject_palindromes") and digits == digits[::-1]:
        return None
    return len(text) if verhoeff_ok(digits) else None


def validate_iban(text: str, params: dict) -> Optional[int]:
    """Country length from the registry table, then MOD 97-10.

    The regex can run past the end of a spaced IBAN ("AE07 0331 ... 456 IS"),
    so we keep only as many characters as the country's IBAN length and
    require a space or the end of the match right after them.
    """
    lengths = params["lengths"]
    country = text[:2]
    if country not in lengths:
        return None
    want = lengths[country]
    compact = []
    keep = 0
    for i, ch in enumerate(text):
        if ch != " ":
            compact.append(ch)
            if len(compact) == want:
                keep = i + 1
                break
    if len(compact) < want:
        return None
    if keep < len(text) and text[keep] != " ":
        return None
    return keep if mod97_ok("".join(compact)) else None


def validate_e164(text: str, params: dict) -> Optional[int]:
    """ITU-T E.164 allows at most 15 digits including the country code."""
    digits = digits_only(text)
    if text.startswith("00"):
        digits = digits[2:]
    if params.get("min_digits", 0) <= len(digits) <= params.get("max_digits", 15):
        return len(text)
    return None


def ipv4_ok(text: str) -> bool:
    parts = text.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part or len(part) > 3 or not all("0" <= c <= "9" for c in part):
            return False
        if len(part) > 1 and part[0] == "0":  # leading zeros are ambiguous (octal)
            return False
        if int(part) > 255:
            return False
    return True


def validate_ipv4(text: str, params: dict) -> Optional[int]:
    return len(text) if ipv4_ok(text) else None


_HEX = set("0123456789abcdefABCDEF")


def validate_ipv6(text: str, params: dict) -> Optional[int]:
    """Text form from RFC 4291 section 2.2, including "::" and a trailing
    dotted IPv4 part. ``min_groups`` drops very short forms such as "::1".
    """
    if ":::" in text or text.count("::") > 1:
        return None
    compressed = "::" in text
    if compressed:
        head, tail = text.split("::")
        groups = (head.split(":") if head else []) + (tail.split(":") if tail else [])
    else:
        groups = text.split(":")
    width = len(groups)
    non_empty = len(groups)
    if groups and "." in groups[-1]:
        if not ipv4_ok(groups[-1]):
            return None
        groups = groups[:-1]
        width += 1  # a dotted IPv4 tail fills two 16-bit groups
        non_empty += 1
    for group in groups:
        if not (1 <= len(group) <= 4) or not all(c in _HEX for c in group):
            return None
    if compressed and width > 7:
        return None
    if not compressed and width != 8:
        return None
    if non_empty < params.get("min_groups", 0):
        return None
    return len(text)


def validate_jwt(text: str, params: dict) -> Optional[int]:
    """RFC 7519 compact form: the first part must decode to a JSON object
    with an "alg" member (the JOSE header)."""
    header = text.split(".")[0]
    try:
        raw = base64.urlsafe_b64decode(header + "=" * (-len(header) % 4))
        decoded = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if isinstance(decoded, dict) and isinstance(decoded.get("alg"), str):
        return len(text)
    return None


VALIDATORS: Dict[str, Callable[[str, dict], Optional[int]]] = {
    "luhn": validate_luhn,
    "verhoeff": validate_verhoeff,
    "iban": validate_iban,
    "e164": validate_e164,
    "ipv4": validate_ipv4,
    "ipv6": validate_ipv6,
    "jwt": validate_jwt,
}


def run_validator(name: Optional[str], text: str, params: dict) -> Optional[int]:
    if not name:
        return len(text)
    return VALIDATORS[name](text, params or {})
