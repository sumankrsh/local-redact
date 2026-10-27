import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"

# Allow running the tests from a source checkout without installing.
src = str(ROOT / "src")
if src not in sys.path:
    sys.path.insert(0, src)


def load_fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))
