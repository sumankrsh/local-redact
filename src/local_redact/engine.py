"""Detect, redact and restore.

The algorithm here is mirrored in web/engine.js. Both read the same pattern
spec (patterns/*.json) and are tested against the same fixtures, so the
browser app and the CLI find the same things.
"""

from __future__ import annotations

import bisect
import json
import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

from .validators import run_validator

CUSTOM_PRIORITY = 100
TYPE_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,31}$")
PLACEHOLDER_RE = re.compile(r"<[A-Z][A-Z0-9_]*_[0-9]+>")


# ---------------------------------------------------------------- spec loading


def _spec_files():
    packaged = resources.files("local_redact") / "patterns"
    if packaged.is_dir():
        return [p for p in packaged.iterdir() if p.name.endswith(".json")]
    # Running from a source checkout (editable install or tests).
    repo = Path(__file__).resolve().parents[2] / "patterns"
    return sorted(repo.glob("*.json"))


_SPEC_CACHE: Optional[List[dict]] = None


def load_spec() -> List[dict]:
    """Return the built-in detectors, sorted by their ``order`` field."""
    global _SPEC_CACHE
    if _SPEC_CACHE is None:
        detectors = [json.loads(p.read_text(encoding="utf-8")) for p in _spec_files()]
        detectors.sort(key=lambda d: d["order"])
        _SPEC_CACHE = detectors
    return _SPEC_CACHE


def detector_ids() -> List[str]:
    return [d["id"] for d in load_spec()]


# ------------------------------------------------------------------ detection


@dataclass(frozen=True)
class Detection:
    type: str
    start: int
    end: int
    text: str
    pattern: str


@dataclass
class _Compiled:
    id: str
    priority: int
    patterns: list  # (name, compiled regex, validator, params)


def _compile(detectors: Sequence[dict]) -> List[_Compiled]:
    out = []
    for det in detectors:
        pats = [
            (p["name"], re.compile(p["regex"]), p.get("validator"), p.get("params", {}))
            for p in det["patterns"]
        ]
        out.append(_Compiled(det["id"], det["priority"], pats))
    return out


_BUILTIN: Optional[List[_Compiled]] = None


def _builtin() -> List[_Compiled]:
    global _BUILTIN
    if _BUILTIN is None:
        _BUILTIN = _compile(load_spec())
    return _BUILTIN


def compile_custom(custom: Iterable[dict]) -> List[_Compiled]:
    """Compile user patterns: ``[{"type": "POLICY_NO", "regex": "POL-[0-9]{6}"}]``."""
    out = []
    builtin = set(detector_ids())
    for item in custom or ():
        name = item["type"]
        if not TYPE_NAME_RE.match(name):
            raise ValueError(
                f"Custom type name {name!r} must be capitals, digits and _, starting with a letter"
            )
        if name in builtin:
            raise ValueError(f"Custom type name {name!r} clashes with a built-in type")
        try:
            regex = re.compile(item["regex"])
        except re.error as exc:
            raise ValueError(f"Custom pattern {name}: {exc}") from None
        out.append(_Compiled(name, CUSTOM_PRIORITY, [(name, regex, None, {})]))
    return out


def detect(
    text: str,
    types: Optional[Iterable[str]] = None,
    allowlist: Iterable[str] = (),
    custom: Iterable[dict] = (),
) -> List[Detection]:
    """Find sensitive values in ``text``.

    ``types``: built-in type ids to use (default: all). Custom patterns always run.
    ``allowlist``: values never to redact (case-insensitive, exact match).
    ``custom``: extra patterns, see :func:`compile_custom`.
    """
    wanted = None if types is None else set(types)
    allowed = {a.strip().lower() for a in allowlist if a.strip()}
    detectors = [d for d in _builtin() if wanted is None or d.id in wanted]
    detectors += compile_custom(custom)

    candidates = []
    for d_index, det in enumerate(detectors):
        for p_index, (name, regex, validator, params) in enumerate(det.patterns):
            for m in regex.finditer(text):
                start, end = m.start(), m.end()
                if end == start:
                    continue
                keep = run_validator(validator, m.group(0), params)
                if keep is None:
                    continue
                end = start + keep
                value = text[start:end]
                if value.strip().lower() in allowed:
                    continue
                candidates.append(
                    (-(end - start), -det.priority, start, d_index, p_index, det.id, end, value, name)
                )

    # Overlaps: the longest match wins, then the higher priority, then the earliest.
    candidates.sort(key=lambda c: c[:5])
    starts: List[int] = []
    accepted: List[Detection] = []
    for _, _, start, _, _, type_, end, value, name in candidates:
        i = bisect.bisect_left(starts, start)
        if i > 0 and accepted[i - 1].end > start:
            continue
        if i < len(accepted) and accepted[i].start < end:
            continue
        starts.insert(i, start)
        accepted.insert(i, Detection(type_, start, end, value, name))
    return accepted


# ------------------------------------------------------- redaction and restore


@dataclass
class Mapping:
    """Placeholder -> original value. Keep this file private: it holds the real data."""

    placeholders: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        self._reverse = {}
        self._next = {}
        for ph, value in self.placeholders.items():
            type_, number = ph[1:-1].rsplit("_", 1)
            self._reverse[(type_, value)] = ph
            self._next[type_] = max(self._next.get(type_, 1), int(number) + 1)

    def placeholder_for(self, type_: str, value: str, source_text: str) -> str:
        key = (type_, value)
        if key in self._reverse:
            return self._reverse[key]
        n = self._next.get(type_, 1)
        # Never reuse a placeholder that already appears in the input text.
        while f"<{type_}_{n}>" in source_text:
            n += 1
        ph = f"<{type_}_{n}>"
        self._next[type_] = n + 1
        self._reverse[key] = ph
        self.placeholders[ph] = value
        return ph

    def to_json(self) -> dict:
        return {"format": "local-redact-mapping", "version": 1, "placeholders": self.placeholders}

    @classmethod
    def from_json(cls, data: dict) -> "Mapping":
        if data.get("format") != "local-redact-mapping":
            raise ValueError("Not a local-redact mapping file")
        placeholders = data.get("placeholders", {})
        for ph in placeholders:
            if not PLACEHOLDER_RE.fullmatch(ph):
                raise ValueError(f"Bad placeholder in mapping: {ph!r}")
        return cls(dict(placeholders))


@dataclass
class RedactResult:
    text: str
    detections: List[Detection]
    placeholders: List[str]  # one per detection, same order
    mapping: Mapping


def redact(
    text: str,
    mapping: Optional[Mapping] = None,
    types: Optional[Iterable[str]] = None,
    allowlist: Iterable[str] = (),
    custom: Iterable[dict] = (),
) -> RedactResult:
    """Replace each detection with a numbered placeholder such as ``<EMAIL_1>``.

    The same value always gets the same placeholder. Pass an existing
    ``mapping`` to keep numbering consistent across several texts.
    """
    mapping = mapping if mapping is not None else Mapping()
    detections = detect(text, types=types, allowlist=allowlist, custom=custom)
    parts = []
    placeholders = []
    last = 0
    for det in detections:
        ph = mapping.placeholder_for(det.type, det.text, text)
        placeholders.append(ph)
        parts.append(text[last : det.start])
        parts.append(ph)
        last = det.end
    parts.append(text[last:])
    return RedactResult("".join(parts), detections, placeholders, mapping)


@dataclass
class RestoreResult:
    text: str
    restored: int
    unknown: List[str]  # placeholders in the text that the mapping does not know
    unused: List[str]  # mapping entries that did not appear in the text


def restore(text: str, mapping: Mapping) -> RestoreResult:
    """Put the original values back in place of placeholders."""
    used = set()
    unknown: List[str] = []
    count = 0

    def swap(m):
        nonlocal count
        ph = m.group(0)
        if ph in mapping.placeholders:
            used.add(ph)
            count += 1
            return mapping.placeholders[ph]
        if ph not in unknown:
            unknown.append(ph)
        return ph

    out = PLACEHOLDER_RE.sub(swap, text)
    unused = [ph for ph in mapping.placeholders if ph not in used]
    return RestoreResult(out, count, unknown, unused)
