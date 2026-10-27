"""Command-line interface: ``local-redact redact``, ``restore`` and ``types``."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .engine import Mapping, detector_ids, load_spec, redact, restore


def _read_text(source: str) -> str:
    try:
        if source == "-":
            return sys.stdin.buffer.read().decode("utf-8")
        return Path(source).read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        raise SystemExit(f"local-redact: {source} is not UTF-8 text")
    except OSError as exc:
        raise SystemExit(f"local-redact: cannot read {source}: {exc.strerror}")


def _write_text(path: Path, text: str, private: bool = False) -> None:
    data = text.encode("utf-8")
    if private:
        # The mapping holds the real values: create it readable by the owner only.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
    else:
        path.write_bytes(data)


def _load_config(path: Optional[str]) -> dict:
    if not path:
        return {}
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit(f"local-redact: cannot read config {path}: {exc}")
    if not isinstance(data, dict):
        raise SystemExit("local-redact: config must be a JSON object")
    return data


def _parse_types(value: Optional[str]) -> Optional[List[str]]:
    if value is None:
        return None
    types = [t.strip().upper() for t in value.split(",") if t.strip()]
    unknown = [t for t in types if t not in detector_ids()]
    if unknown:
        raise SystemExit(f"local-redact: unknown type(s): {', '.join(unknown)} (see 'local-redact types')")
    return types


def _cmd_redact(args) -> int:
    config = _load_config(args.config)

    types = _parse_types(args.types) if args.types else config.get("types")
    if args.skip:
        skip = set(_parse_types(args.skip) or [])
        types = [t for t in (types or detector_ids()) if t not in skip]

    allowlist = list(config.get("allowlist", [])) + list(args.allow or [])
    for path in args.allow_file or []:
        allowlist += [line.strip() for line in _read_text(path).splitlines() if line.strip()]

    custom = list(config.get("custom", []))
    for item in args.pattern or []:
        name, sep, regex = item.partition("=")
        if not sep or not regex:
            raise SystemExit(f"local-redact: --pattern needs NAME=REGEX, got {item!r}")
        custom.append({"type": name.strip().upper(), "regex": regex})

    sources = args.inputs or ["-"]
    if len(sources) > 1 and not args.out_dir:
        raise SystemExit("local-redact: use --out-dir when redacting more than one file")
    if args.output and len(sources) > 1:
        raise SystemExit("local-redact: -o works with a single input; use --out-dir")

    mapping = Mapping()
    map_path = Path(args.map) if args.map else None
    if map_path and map_path.exists():
        try:
            mapping = Mapping.from_json(json.loads(map_path.read_text(encoding="utf-8")))
        except ValueError as exc:
            raise SystemExit(f"local-redact: {map_path}: {exc}")

    results = []
    total = 0
    for source in sources:
        text = _read_text(source)
        try:
            result = redact(text, mapping=mapping, types=types, allowlist=allowlist, custom=custom)
        except ValueError as exc:
            raise SystemExit(f"local-redact: {exc}")
        total += len(result.detections)

        out_path = None
        if args.out_dir:
            out_dir = Path(args.out_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / (Path(source).name if source != "-" else "stdin.txt")
        elif args.output:
            out_path = Path(args.output)
        if out_path:
            _write_text(out_path, result.text)

        counts = {}
        detections = []
        for det, ph in zip(result.detections, result.placeholders):
            counts[det.type] = counts.get(det.type, 0) + 1
            item = {"type": det.type, "start": det.start, "end": det.end, "placeholder": ph, "pattern": det.pattern}
            if args.include_values:
                item["value"] = det.text
            detections.append(item)
        results.append(
            {
                "source": source,
                "output": str(out_path) if out_path else None,
                "counts": counts,
                "detections": detections,
                "text": None if out_path else result.text,
            }
        )
        if not args.json and not out_path:
            sys.stdout.write(result.text)

    if map_path:
        _write_text(map_path, json.dumps(mapping.to_json(), indent=2, ensure_ascii=False) + "\n", private=True)

    if args.json:
        report = {"tool": "local-redact", "version": __version__, "results": results}
        if map_path:
            report["map"] = str(map_path)
        sys.stdout.write(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    elif not args.quiet:
        counts_all = {}
        for r in results:
            for k, v in r["counts"].items():
                counts_all[k] = counts_all.get(k, 0) + v
        summary = ", ".join(f"{k} {v}" for k, v in sorted(counts_all.items())) or "nothing found"
        print(f"local-redact: {total} redacted ({summary})", file=sys.stderr)
        if map_path:
            print(f"local-redact: mapping saved to {map_path} (keep it private)", file=sys.stderr)

    if args.check and total:
        return 1
    return 0


def _cmd_restore(args) -> int:
    try:
        mapping = Mapping.from_json(json.loads(Path(args.map).read_text(encoding="utf-8")))
    except (OSError, ValueError) as exc:
        raise SystemExit(f"local-redact: cannot read mapping {args.map}: {exc}")
    result = restore(_read_text(args.input), mapping)
    if args.output:
        _write_text(Path(args.output), result.text)
    else:
        sys.stdout.write(result.text)
    if not args.quiet:
        print(f"local-redact: {result.restored} placeholder(s) restored", file=sys.stderr)
        if result.unknown:
            print(f"local-redact: not in the mapping, left as is: {', '.join(result.unknown)}", file=sys.stderr)
    if args.strict and result.unknown:
        return 1
    return 0


def _cmd_types(args) -> int:
    spec = load_spec()
    if args.json:
        rows = [{k: d[k] for k in ("id", "label", "region", "validation")} for d in spec]
        print(json.dumps(rows, indent=2))
        return 0
    width = max(len(d["id"]) for d in spec)
    for d in spec:
        print(f"{d['id']:<{width}}  {d['label']} ({d['region']})")
        print(f"{'':<{width}}  {d['validation']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="local-redact",
        description="Remove sensitive data from text before you paste it into an LLM. Runs locally.",
    )
    parser.add_argument("--version", action="version", version=f"local-redact {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    r = sub.add_parser("redact", help="replace sensitive values with placeholders such as <EMAIL_1>")
    r.add_argument("inputs", nargs="*", help="text files to redact (default: stdin)")
    r.add_argument("-o", "--output", help="write the redacted text here instead of stdout")
    r.add_argument("--out-dir", help="write each redacted file into this folder")
    r.add_argument("--map", help="save placeholder -> value mapping here, for 'restore' (extends an existing file)")
    r.add_argument("--json", action="store_true", help="print a JSON report of detections instead of the text")
    r.add_argument("--include-values", action="store_true", help="include the original values in the JSON report")
    r.add_argument("--types", help="only these types, comma-separated (see 'local-redact types')")
    r.add_argument("--skip", help="skip these types, comma-separated")
    r.add_argument("--allow", action="append", metavar="VALUE", help="never redact this value (repeatable)")
    r.add_argument("--allow-file", action="append", metavar="FILE", help="never redact values listed in FILE, one per line")
    r.add_argument("--pattern", action="append", metavar="NAME=REGEX", help="extra pattern, e.g. POLICY_NO=POL-[0-9]{6}")
    r.add_argument("--config", help="JSON settings file with 'types', 'allowlist' and 'custom' (as exported by the web app)")
    r.add_argument("--check", action="store_true", help="exit with status 1 if anything was found")
    r.add_argument("-q", "--quiet", action="store_true", help="no summary on stderr")
    r.set_defaults(func=_cmd_redact)

    s = sub.add_parser("restore", help="put the original values back into text that has placeholders")
    s.add_argument("input", nargs="?", default="-", help="text with placeholders, e.g. an LLM answer (default: stdin)")
    s.add_argument("--map", required=True, help="mapping file written by 'redact --map'")
    s.add_argument("-o", "--output", help="write the restored text here instead of stdout")
    s.add_argument("--strict", action="store_true", help="exit with status 1 if a placeholder is not in the mapping")
    s.add_argument("-q", "--quiet", action="store_true", help="no summary on stderr")
    s.set_defaults(func=_cmd_restore)

    t = sub.add_parser("types", help="list the built-in detectors")
    t.add_argument("--json", action="store_true")
    t.set_defaults(func=_cmd_types)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
