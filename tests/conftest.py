import json
from pathlib import Path

SAMPLES = Path(__file__).parent.parent / "data" / "samples"
FIXTURES = Path(__file__).parent / "fixtures"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sample(relative_path: str) -> dict:
    """A real API response saved in data/samples/."""
    return load_json(SAMPLES / relative_path)
