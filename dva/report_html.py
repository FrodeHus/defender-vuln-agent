from __future__ import annotations
import html, json
from pathlib import Path

TEMPLATE = Path(__file__).parent / "report_template.html"


def render(doc: dict) -> str:
    payload = json.dumps(doc).replace("</", "<\\/")
    tenant = html.escape(str(doc.get("summary", {}).get("tenant", "tenant")))
    return TEMPLATE.read_text(encoding="utf-8").replace("__TITLE__", tenant).replace("__FINDINGS_JSON__", payload)
