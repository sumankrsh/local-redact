import json
import os
import stat
import subprocess
import sys

import pytest

from conftest import ROOT
from local_redact import Mapping, redact, restore
from local_redact.cli import main

CLAIM = (ROOT / "samples" / "claim-note.txt").read_text(encoding="utf-8")


def test_redact_file_to_stdout(capsys):
    assert main(["redact", str(ROOT / "samples" / "claim-note.txt"), "-q"]) == 0
    out = capsys.readouterr().out
    assert "<EMIRATES_ID_1>" in out and "784-1990-1234567-6" not in out
    assert "<IBAN_1>" in out and "<SAUDI_ID_1>" in out and "<AADHAAR_1>" in out


def test_redact_stdin(monkeypatch, capsys):
    class FakeStdin:
        buffer = __import__("io").BytesIO("mail layla@example.com\n".encode())

    monkeypatch.setattr(sys, "stdin", FakeStdin)
    assert main(["redact", "-q"]) == 0
    assert capsys.readouterr().out == "mail <EMAIL_1>\n"


def test_json_report_hides_values_by_default(tmp_path, capsys):
    src = tmp_path / "note.txt"
    src.write_text("Emirates ID 784-1990-1234567-6", encoding="utf-8")
    main(["redact", str(src), "--json"])
    report = json.loads(capsys.readouterr().out)
    det = report["results"][0]["detections"][0]
    assert det == {"type": "EMIRATES_ID", "start": 12, "end": 30, "placeholder": "<EMIRATES_ID_1>", "pattern": "emirates_id"}
    assert report["results"][0]["text"] == "Emirates ID <EMIRATES_ID_1>"
    main(["redact", str(src), "--json", "--include-values"])
    assert json.loads(capsys.readouterr().out)["results"][0]["detections"][0]["value"] == "784-1990-1234567-6"


def test_map_and_restore_round_trip(tmp_path, capsys):
    src = tmp_path / "claim.txt"
    src.write_text(CLAIM, encoding="utf-8")
    map_path = tmp_path / "claim.map.json"
    out_path = tmp_path / "claim.redacted.txt"
    assert main(["redact", str(src), "-o", str(out_path), "--map", str(map_path), "-q"]) == 0
    if os.name == "posix":
        assert stat.S_IMODE(map_path.stat().st_mode) == 0o600

    # Pretend an LLM answered using the placeholders.
    answer = tmp_path / "answer.txt"
    answer.write_text("Pay <IBAN_1> and text <PHONE_1>. Unknown: <EMAIL_9>.", encoding="utf-8")
    assert main(["restore", str(answer), "--map", str(map_path), "-q"]) == 0
    restored = capsys.readouterr().out
    assert restored == "Pay AE07 0331 2345 6789 0123 456 and text 050 000 1234. Unknown: <EMAIL_9>."
    assert main(["restore", str(answer), "--map", str(map_path), "--strict", "-q"]) == 1
    capsys.readouterr()

    # The redacted file restores to the original byte for byte.
    assert main(["restore", str(out_path), "--map", str(map_path), "-q"]) == 0
    assert capsys.readouterr().out == CLAIM


def test_map_is_extended_across_runs(tmp_path, capsys):
    a, b, m = tmp_path / "a.txt", tmp_path / "b.txt", tmp_path / "m.json"
    a.write_text("x@example.com", encoding="utf-8")
    b.write_text("y@example.com and x@example.com", encoding="utf-8")
    main(["redact", str(a), "--map", str(m), "-q"])
    main(["redact", str(b), "--map", str(m), "-q"])
    assert capsys.readouterr().out == "<EMAIL_1><EMAIL_2> and <EMAIL_1>"


def test_out_dir_and_shared_numbering(tmp_path):
    a, b = tmp_path / "a.txt", tmp_path / "b.txt"
    a.write_text("x@example.com", encoding="utf-8")
    b.write_text("x@example.com y@example.com", encoding="utf-8")
    assert main(["redact", str(a), str(b), "--out-dir", str(tmp_path / "out"), "-q"]) == 0
    assert (tmp_path / "out" / "a.txt").read_text() == "<EMAIL_1>"
    assert (tmp_path / "out" / "b.txt").read_text() == "<EMAIL_1> <EMAIL_2>"


def test_multiple_inputs_need_out_dir(tmp_path):
    with pytest.raises(SystemExit):
        main(["redact", "a.txt", "b.txt"])


def test_types_skip_allow_pattern_and_check(tmp_path, capsys):
    src = tmp_path / "n.txt"
    src.write_text("POL-2025-118204 layla@example.com ops@example.com +971 50 000 1234", encoding="utf-8")
    code = main([
        "redact", str(src), "-q", "--check", "--skip", "phone",
        "--allow", "ops@example.com", "--pattern", "policy_no=POL-[0-9]{4}-[0-9]{6}",
    ])
    assert code == 1
    assert capsys.readouterr().out == "<POLICY_NO_1> <EMAIL_1> ops@example.com +971 50 000 1234"
    src.write_text("nothing here", encoding="utf-8")
    assert main(["redact", str(src), "-q", "--check"]) == 0


def test_config_file_from_web_app(tmp_path, capsys):
    cfg = tmp_path / "settings.json"
    cfg.write_text(json.dumps({
        "types": ["EMAIL"],
        "allowlist": ["ops@example.com"],
        "custom": [{"type": "CLAIM_NO", "regex": "CLM-[0-9]{4}-[0-9]{7}"}],
    }), encoding="utf-8")
    src = tmp_path / "n.txt"
    src.write_text("CLM-2026-0004417 ops@example.com a@example.com 784-1990-1234567-6", encoding="utf-8")
    main(["redact", str(src), "--config", str(cfg), "-q"])
    assert capsys.readouterr().out == "<CLAIM_NO_1> ops@example.com <EMAIL_1> 784-1990-1234567-6"


def test_bad_inputs_give_clear_errors(tmp_path):
    with pytest.raises(SystemExit, match="unknown type"):
        main(["redact", "--types", "NOPE"])
    with pytest.raises(SystemExit, match="NAME=REGEX"):
        main(["redact", "--pattern", "oops"])
    binary = tmp_path / "x.bin"
    binary.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(SystemExit, match="not UTF-8"):
        main(["redact", str(binary)])


def test_types_command(capsys):
    assert main(["types"]) == 0
    out = capsys.readouterr().out
    for t in ("EMAIL", "PHONE", "IBAN", "CARD", "EMIRATES_ID", "SAUDI_ID", "AADHAAR", "IN_PAN", "IP_ADDRESS", "SECRET"):
        assert t in out


def test_module_entry_point():
    env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
    run = subprocess.run(
        [sys.executable, "-m", "local_redact", "redact", "-q"],
        input="ID 2987654320".encode(), capture_output=True, env=env, check=True,
    )
    assert run.stdout.decode() == "ID <SAUDI_ID_1>"


def test_mapping_rejects_other_files():
    with pytest.raises(ValueError):
        Mapping.from_json({"format": "something-else"})
    with pytest.raises(ValueError):
        Mapping.from_json({"format": "local-redact-mapping", "placeholders": {"EMAIL_1": "x"}})


def test_restore_reports_unknown_and_unused():
    m = Mapping({"<EMAIL_1>": "a@example.com", "<PHONE_1>": "+971 50 000 1234"})
    r = restore("Reply to <EMAIL_1> and <EMAIL_9>", m)
    assert (r.text, r.restored, r.unknown, r.unused) == ("Reply to a@example.com and <EMAIL_9>", 1, ["<EMAIL_9>"], ["<PHONE_1>"])


def test_custom_errors():
    for bad, msg in ([{"type": "bad name", "regex": "x"}], "capitals"), ([{"type": "EMAIL", "regex": "x"}], "clashes"), ([{"type": "OK", "regex": "("}], "Custom pattern OK"):
        with pytest.raises(ValueError, match=msg):
            redact("x", custom=bad)
