"""Run the shared fixture corpus. tests/js/engine.test.js runs the same files."""

import json

import pytest

from conftest import ROOT, load_fixture
from local_redact import Mapping, detect, load_spec, redact, restore

CASES = load_fixture("cases.json") + load_fixture("generated.json")


def _options(case):
    opts = case.get("options", {})
    return {"types": opts.get("types"), "allowlist": opts.get("allowlist", []), "custom": opts.get("custom", [])}


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_case(case):
    found = [[d.type, d.text] for d in detect(case["text"], **_options(case))]
    assert found == case["expect"]

    mapping = Mapping(dict(case.get("mapping", {})))
    result = redact(case["text"], mapping=mapping, **_options(case))
    if "redacted" in case:
        assert result.text == case["redacted"]
    # Restoring the redacted text must give back the original exactly.
    assert restore(result.text, result.mapping).text == case["text"]


SAMPLES = load_fixture("samples.expected.json")


@pytest.mark.parametrize("expected", SAMPLES, ids=[s["id"] for s in SAMPLES])
def test_samples_snapshot(expected):
    index = {s["id"]: s for s in json.loads((ROOT / "samples" / "index.json").read_text(encoding="utf-8"))}
    sample = index[expected["id"]]
    text = (ROOT / "samples" / sample["file"]).read_text(encoding="utf-8")
    result = redact(text, custom=sample.get("custom", []))
    assert [[d.type, d.text, d.pattern] for d in result.detections] == expected["detections"]
    assert result.text == expected["redacted"]


EXAMPLES = [(d["id"], v, True) for d in load_spec() for v in d["examples"]["valid"]] + [
    (d["id"], v, False) for d in load_spec() for v in d["examples"]["invalid"]
]


@pytest.mark.parametrize("type_,value,valid", EXAMPLES)
def test_spec_examples(type_, value, valid):
    found = [(d.type, d.text) for d in detect(f"x {value} y")]
    if valid:
        assert found == [(type_, value)]
    else:
        assert type_ not in [t for t, _ in found]
