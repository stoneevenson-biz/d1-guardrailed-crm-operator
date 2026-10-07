"""D1 demo: a guardrailed AI CRM operator over a mock CRM. Synthetic scenario — not a client deployment."""

import json
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
LABEL = "Illustrative synthetic scenario. Not a real client, result, or testimonial."


def load_json(name):
    return json.loads((FIXTURES / name).read_text())
