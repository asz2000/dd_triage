from __future__ import annotations
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

class FindingKind(StrEnum):
    SCA = "sca_package_vulnerability"
    SECRET = "secret"
    OTHER = "other"

@dataclass
class Finding:
    id: int
    title: str = ""
    description: str = ""
    scan_type: str = ""
    severity: str = ""
    active: bool = True
    verified: bool = False
    false_p: bool = False
    risk_accepted: bool = False
    tags: list[str] = field(default_factory=list)
    product_id: int | None = None
    test_id: int | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_api(cls, data: dict[str, Any], product_id: int | None = None) -> "Finding":
        test = data.get("test") if isinstance(data.get("test"), dict) else {}
        scan_type = data.get("scan_type") or test.get("scan_type") or data.get("test__scan_type") or ""
        pid = product_id or data.get("product") or data.get("product_id") or test.get("product")
        tid = data.get("test") if isinstance(data.get("test"), int) else test.get("id") or data.get("test_id")
        tags = data.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        return cls(
            id=int(data.get("id", 0)), title=data.get("title") or data.get("name") or "",
            description=data.get("description") or data.get("mitigation") or "", scan_type=scan_type,
            severity=data.get("severity") or "", active=bool(data.get("active", True)),
            verified=bool(data.get("verified", False)), false_p=bool(data.get("false_p", False)),
            risk_accepted=bool(data.get("risk_accepted", False) or data.get("is_risk_accepted", False)),
            tags=list(tags), product_id=pid, test_id=tid, raw=data)

    def get(self, *names: str, default: Any = "") -> Any:
        for name in names:
            if hasattr(self, name):
                value = getattr(self, name)
            else:
                value = self.raw.get(name)
            if value not in (None, "", []):
                return value
        return default

@dataclass
class TriageAction:
    finding: Finding
    kind: FindingKind
    action: str
    patch: dict[str, Any] = field(default_factory=dict)
    tags_to_add: list[str] = field(default_factory=list)
    note: str | None = None
    rule_id: str | None = None
    reason: str | None = None
    masked_secret: str | None = None
    skipped: bool = False
    skip_reason: str | None = None
