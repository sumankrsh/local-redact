"""Write the shared test corpus used by both the Python and the JS test suites.

    python scripts/generate_fixtures.py

Writes:
  tests/fixtures/generated.json        seeded synthetic cases; expectations come
                                       from the generator (it knows what it inserted)
  tests/fixtures/samples.expected.json snapshot of the Python engine on samples/;
                                       the JS suite must produce the same output

CI regenerates both and fails if they change, so the files cannot drift.
"""

from __future__ import annotations

import base64
import json
import random
import string
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))

import synthetic as s  # noqa: E402

SEED = 20261028
CONTEXTS = [" {v} ", "({v})", "{v}.", "id={v};", "'{v}'", "{v},", "\t{v}\n", "رقم {v} شكرا"]

CARD_SHAPES = [("4", 16), ("4", 13), ("51", 16), ("55", 16), ("2221", 16), ("2720", 16), ("34", 15), ("37", 15),
               ("6011", 16), ("65", 16), ("3530", 16), ("36", 14), ("62", 16), ("60", 16), ("508", 16)]


def iban_lengths():
    spec = json.loads((ROOT / "patterns" / "iban.json").read_text(encoding="utf-8"))
    return spec["patterns"][0]["params"]["lengths"]


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def jwt(rng: random.Random) -> str:
    header = b64url(json.dumps({"alg": rng.choice(["HS256", "RS256", "ES256"]), "typ": "JWT"}).encode())
    payload = b64url(json.dumps({"sub": f"user-{rng.randint(1, 99999)}"}).encode())
    return f"{header}.{payload}.{b64url(bytes(rng.randrange(256) for _ in range(24)))}"


def rand(rng, alphabet, n):
    return "".join(rng.choice(alphabet) for _ in range(n))


def valid_value(rng: random.Random, type_: str, lengths: dict) -> str:
    if type_ == "EMIRATES_ID":
        return s.emirates_id(rng, sep=rng.choice(["-", "", " "]))
    if type_ == "SAUDI_ID":
        return s.saudi_id(rng, first=rng.choice("12"))
    if type_ == "AADHAAR":
        return s.aadhaar(rng, sep=rng.choice([" ", "", "-"]))
    if type_ == "CARD":
        prefix, length = rng.choice(CARD_SHAPES)
        return s.card(rng, prefix, length, sep=rng.choice([" ", "-", ""]))
    if type_ == "IBAN":
        country = rng.choice(sorted(lengths))
        return s.iban(rng, country, lengths[country], spaced=rng.random() < 0.5)
    if type_ == "IN_PAN":
        return s.pan(rng)
    if type_ == "PHONE":
        d = lambda n: rand(rng, string.digits, n)  # noqa: E731
        return rng.choice([
            f"+971 5{rng.choice('024568')} {d(3)} {d(4)}",
            f"+9715{rng.choice('024568')}{d(7)}",
            f"+966 5{rng.choice('03456789')} {d(3)} {d(4)}",
            f"00974 {rng.choice('3567')}{d(3)} {d(4)}",
            f"+965 {rng.choice('569')}{d(3)} {d(4)}",
            f"+91 {rng.choice('6789')}{d(4)} {d(5)}",
            f"+91-{rng.choice('6789')}{d(9)}",
            f"05{rng.choice('024568')} {d(3)} {d(4)}",
            f"05{rng.choice('024568')}{d(7)}",
            f"{rng.choice('6789')}{d(9)}",
            f"0{rng.choice('6789')}{d(4)} {d(5)}",
        ])
    if type_ == "IP_ADDRESS":
        return s.ipv4(rng) if rng.random() < 0.5 else s.ipv6(rng)
    if type_ == "EMAIL":
        local = rand(rng, string.ascii_lowercase, rng.randint(3, 8)) + rng.choice(["", ".", "_", "+"]) + rand(rng, string.ascii_lowercase, 3)
        return f"{local}@{rng.choice(['example.com', 'example.org', 'mail.example.ae', 'example.co.in'])}"
    if type_ == "SECRET":
        kind = rng.choice(["aws", "github", "jwt"])
        if kind == "aws":
            return "AKIA" + rand(rng, string.ascii_uppercase + string.digits, 9) + "EXAMPLE"
        if kind == "github":
            return "ghp_EXAMPLE" + rand(rng, string.ascii_letters + string.digits, 29)
        return jwt(rng)
    raise ValueError(type_)


def invalid_value(rng: random.Random, type_: str, lengths: dict) -> str:
    """Values with the right shape but a failing check, which must not be flagged."""
    if type_ in ("EMIRATES_ID", "SAUDI_ID", "AADHAAR", "CARD", "IBAN"):
        return s.break_last_digit(valid_value(rng, type_, lengths))
    if type_ == "IN_PAN":
        p = s.pan(rng)
        return p[:3] + rng.choice("DEIKMNOQRSUVWXYZ") + p[4:]
    if type_ == "IP_ADDRESS":
        return f"{rng.randint(256, 999)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}"
    if type_ == "EMAIL":
        return rand(rng, string.ascii_lowercase, 6) + "@example"
    if type_ == "PHONE":
        return "+" + rand(rng, "123456789", 1) + " " + rand(rng, string.digits, 4)
    if type_ == "SECRET":
        return "AKIA" + rand(rng, string.ascii_uppercase, 8)
    raise ValueError(type_)


TYPES = ["EMAIL", "PHONE", "IBAN", "CARD", "EMIRATES_ID", "SAUDI_ID", "AADHAAR", "IN_PAN", "IP_ADDRESS", "SECRET"]


def generated_cases():
    rng = random.Random(SEED)
    lengths = iban_lengths()
    cases = []
    for type_ in TYPES:
        for i in range(24):
            v = valid_value(rng, type_, lengths)
            ctx = CONTEXTS[i % len(CONTEXTS)]
            cases.append({"name": f"{type_.lower()}-valid-{i}", "text": ctx.format(v=v), "expect": [[type_, v]]})
        for i in range(8):
            v = invalid_value(rng, type_, lengths)
            cases.append({"name": f"{type_.lower()}-invalid-{i}", "text": f" {v} ", "expect": []})
    # Mixed documents: several values in one text, in order.
    for i in range(30):
        picks = [rng.choice(TYPES) for _ in range(rng.randint(3, 6))]
        values = [(t, valid_value(rng, t, lengths)) for t in picks]
        text = "Note: " + "; then ".join(v for _, v in values) + ". End."
        cases.append({"name": f"mixed-{i}", "text": text, "expect": [[t, v] for t, v in values]})
    return cases


def samples_snapshot():
    from local_redact import redact

    index = json.loads((ROOT / "samples" / "index.json").read_text(encoding="utf-8"))
    out = []
    for sample in index:
        text = (ROOT / "samples" / sample["file"]).read_text(encoding="utf-8")
        result = redact(text, custom=sample.get("custom", []))
        out.append({
            "id": sample["id"],
            "detections": [[d.type, d.text, d.pattern] for d in result.detections],
            "redacted": result.text,
        })
    return out


def write(path: Path, data) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {path.relative_to(ROOT)}")


if __name__ == "__main__":
    write(ROOT / "tests" / "fixtures" / "generated.json", generated_cases())
    write(ROOT / "tests" / "fixtures" / "samples.expected.json", samples_snapshot())
