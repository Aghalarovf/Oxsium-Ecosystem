import json
from datetime import datetime
from pathlib import Path

DOMAIN_ACES_FILE = "domain_aces.jsonl"


def _write_acl_jsonl_snapshot(out_path: Path, meta_line: dict, records: list[dict]) -> None:
    lines = [json.dumps(meta_line, ensure_ascii=False, default=str)]
    lines.extend(json.dumps(r, ensure_ascii=False, default=str) for r in records)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_domain_aces_snapshot(result: dict, output_dir: Path, is_local: bool = False) -> Path:
    out_path = Path(output_dir) / DOMAIN_ACES_FILE
    aces = list(result.get("acls") or result.get("aces") or [])

    out_path.parent.mkdir(parents=True, exist_ok=True)

    generated_at = datetime.utcnow().isoformat() + "Z"
    source = "local" if is_local else "domain"
    success = bool(result.get("success"))
    count = int(result.get("count") or 0)
    error = result.get("error") if not success else None

    meta_line = {
        "generated_at": generated_at,
        "source": source,
        "success": success,
        "count": count,
        "error": error,
        "meta": result.get("meta") or {},
    }

    _write_acl_jsonl_snapshot(out_path, meta_line, aces)
    return out_path


def write_acl_snapshots(result: dict, output_dir: Path) -> dict[str, Path]:
    return {
        "aces": write_domain_aces_snapshot(result, output_dir),
    }