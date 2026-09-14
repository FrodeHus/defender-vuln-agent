from __future__ import annotations
import json


def render(doc: dict) -> str:
    return json.dumps(doc, indent=2, sort_keys=True)
