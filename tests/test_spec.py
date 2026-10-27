"""The pattern spec must use regex syntax that means the same in Python and JavaScript."""

import re

import pytest

from local_redact import load_spec
from local_redact.validators import VALIDATORS

# Constructs that differ between Python's re and JavaScript RegExp (or that one lacks):
# \d \w \s \b match Unicode in Python but ASCII in JS; named groups and inline flags differ.
FORBIDDEN = [r"\d", r"\D", r"\w", r"\W", r"\b", r"\B", r"(?P", r"(?i", r"(?m", r"(?s", r"(?x", r"(?#", r"\Z", r"\A"]

PATTERNS = [(d["id"], p) for d in load_spec() for p in d["patterns"]]


def test_ids_and_orders_unique():
    spec = load_spec()
    assert len({d["id"] for d in spec}) == len(spec)
    assert len({d["order"] for d in spec}) == len(spec)


@pytest.mark.parametrize("det_id,pattern", PATTERNS, ids=[f"{d}:{p['name']}" for d, p in PATTERNS])
def test_portable_regex(det_id, pattern):
    regex = pattern["regex"].replace(r"[\s\S]", "")  # the one allowed use of \s
    for token in FORBIDDEN:
        assert token not in regex, f"{det_id}/{pattern['name']} uses {token}"
    assert not re.search(r"\(\?<[A-Za-z]", regex), "named groups differ between Python and JS"
    assert "." not in re.sub(r"\\.|\[[^\]]*\]", "", regex), "bare . differs on line breaks; use a class"
    re.compile(pattern["regex"])


@pytest.mark.parametrize("det_id,pattern", PATTERNS, ids=[f"{d}:{p['name']}" for d, p in PATTERNS])
def test_validator_known(det_id, pattern):
    name = pattern.get("validator")
    assert name is None or name in VALIDATORS


def test_every_detector_documents_sources():
    for d in load_spec():
        assert d["validation"], d["id"]
        assert d["sources"], d["id"]
        assert d["examples"]["valid"] and d["examples"]["invalid"], d["id"]
