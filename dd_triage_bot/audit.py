from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

class AuditLogger:
    def __init__(self, path: str = "triage-audit.jsonl"):
        self.path = Path(path)
    def write(self, record: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        record = {"timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"), **record}
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
