"""Persist scan results for history and side-by-side comparison."""

import json
import uuid
from datetime import datetime
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data" / "scans"


def _ensure_dir():
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def save_scan(scan_type: str, target: str, data: dict, label: str = None) -> dict:
    _ensure_dir()
    scan_id = str(uuid.uuid4())[:12]
    record = {
        "id": scan_id,
        "type": scan_type,
        "target": target,
        "label": label or target,
        "created_at": datetime.now().isoformat(),
        "data": data,
    }
    path = DATA_DIR / f"{scan_id}.json"
    path.write_text(json.dumps(record, default=str), encoding="utf-8")
    return {
        "id": scan_id,
        "type": scan_type,
        "target": target,
        "label": record["label"],
        "created_at": record["created_at"],
    }


def list_scans(limit: int = 50, scan_type: str = None) -> list:
    _ensure_dir()
    items = []
    for path in sorted(DATA_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if scan_type and record.get("type") != scan_type:
            continue
        items.append({
            "id": record.get("id", path.stem),
            "type": record.get("type"),
            "target": record.get("target"),
            "label": record.get("label"),
            "created_at": record.get("created_at"),
        })
        if len(items) >= limit:
            break
    return items


def get_scan(scan_id: str) -> dict | None:
    path = DATA_DIR / f"{scan_id}.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _port_set(scan_data: dict) -> dict:
    tcp = scan_data.get("data", {}).get("tcp") or scan_data.get("tcp") or {}
    return {int(p): info for p, info in tcp.items()}


def compare_port_scans(a: dict, b: dict) -> dict:
    ports_a = _port_set(a)
    ports_b = _port_set(b)
    keys_a, keys_b = set(ports_a), set(ports_b)
    added = sorted(keys_b - keys_a)
    removed = sorted(keys_a - keys_b)
    changed = []
    for p in keys_a & keys_b:
        ia, ib = ports_a[p], ports_b[p]
        if ia.get("product") != ib.get("product") or ia.get("version") != ib.get("version"):
            changed.append({
                "port": p,
                "before": {"service": ia.get("name"), "product": ia.get("product"), "version": ia.get("version")},
                "after": {"service": ib.get("name"), "product": ib.get("product"), "version": ib.get("version")},
            })
    unchanged = sorted((keys_a & keys_b) - {c["port"] for c in changed})
    return {
        "type": "port",
        "scan_a": {"id": a["id"], "label": a.get("label"), "created_at": a.get("created_at")},
        "scan_b": {"id": b["id"], "label": b.get("label"), "created_at": b.get("created_at")},
        "added": [{"port": p, **ports_b[p]} for p in added],
        "removed": [{"port": p, **ports_a[p]} for p in removed],
        "changed": changed,
        "unchanged_count": len(unchanged),
    }


def compare_network_scans(a: dict, b: dict) -> dict:
    data_a = a.get("data", a)
    data_b = b.get("data", b)
    hosts_a = set(data_a.get("hosts") or [])
    hosts_b = set(data_b.get("hosts") or [])
    return {
        "type": "network",
        "scan_a": {"id": a["id"], "label": a.get("label"), "created_at": a.get("created_at")},
        "scan_b": {"id": b["id"], "label": b.get("label"), "created_at": b.get("created_at")},
        "added_hosts": sorted(hosts_b - hosts_a),
        "removed_hosts": sorted(hosts_a - hosts_b),
        "unchanged_hosts": sorted(hosts_a & hosts_b),
    }


def compare_scans(scan_id_a: str, scan_id_b: str) -> dict:
    a = get_scan(scan_id_a)
    b = get_scan(scan_id_b)
    if not a or not b:
        return {"error": "One or both scans not found"}
    if a.get("type") != b.get("type"):
        return {"error": f"Cannot compare {a.get('type')} with {b.get('type')}. Use the same scan type."}
    if a["type"] == "port":
        return compare_port_scans(a, b)
    if a["type"] == "network":
        return compare_network_scans(a, b)
    return {"error": f"Comparison not supported for type: {a.get('type')}"}
