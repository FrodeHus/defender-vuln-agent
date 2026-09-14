"""Resolve a tenant's display name.

Order: DVA_TENANT_NAME (tenant .env / shell) → cached Graph lookup → Graph
`findTenantInformationByTenantId` (needs the optional application permission
CrossTenantInformation.ReadBasic.All) → the tenant directory name → the tenant id.
Microsoft's public .well-known/openid-configuration endpoint does not expose the display name,
which is why the Graph call is used.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from dva.errors import DvaError

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
CACHE_FILE = "tenant-info.json"


def lookup_display_name(client, tenant_id: str) -> str | None:
    """Graph lookup; returns None when the permission is missing or the call fails."""
    try:
        data = client.get_json(f"/tenantRelationships/findTenantInformationByTenantId(tenantId='{tenant_id}')")
    except DvaError:
        return None
    name = data.get("displayName") if isinstance(data, dict) else None
    return name or None


def resolve_display_name(cache_dir: Path, client_factory=None, log=None) -> str:
    explicit = os.environ.get("DVA_TENANT_NAME")
    if explicit:
        return explicit
    tenant_id = os.environ.get("DVA_TENANT_ID")
    fallback = os.environ.get("DVA_TENANT") or tenant_id or "unknown"
    if not tenant_id:
        return fallback
    cache_path = Path(cache_dir) / CACHE_FILE
    try:
        cached = json.loads(cache_path.read_text()) if cache_path.exists() else {}
    except (OSError, json.JSONDecodeError):
        cached = {}
    if isinstance(cached, dict) and cached.get("tenant_id") == tenant_id and cached.get("display_name"):
        return cached["display_name"]
    if client_factory is None:
        return fallback
    try:
        client = client_factory()
    except DvaError as exc:
        if log:
            log(f"tenant name lookup skipped: {exc}")
        return fallback
    name = lookup_display_name(client, tenant_id)
    if not name:
        if log:
            log("tenant name lookup failed (grant CrossTenantInformation.ReadBasic.All or set DVA_TENANT_NAME); using fallback")
        return fallback
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps({"tenant_id": tenant_id, "display_name": name, "fetched_at": datetime.now(timezone.utc).isoformat()}))
    except OSError:
        pass
    return name
