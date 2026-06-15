from __future__ import annotations
import re
from .config import ClassificationSettings
from .models import Finding, FindingKind

DEFAULT_SECRET_RULE_RE = re.compile(r"(?i)(secret|token|api[-_ ]?key|password|credential|private[-_ ]?key|gitleaks|trufflehog)")
VULN_RE = re.compile(r"(?i)(CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|OSV-\d+)")

def _any(patterns: list[str], text: str) -> bool:
    return any(re.search(p, text or "") for p in patterns)

def is_secret(f: Finding, cfg: ClassificationSettings) -> bool:
    blob = f"{f.title}\n{f.description}"
    tags = {str(t).lower() for t in f.tags}
    rule = str(f.get("scanner_rule_id", "rule_id", "vulnerability_id", default=""))
    return (f.scan_type in cfg.secret_scan_types or _any(cfg.secret_title_patterns, blob)
            or bool(tags & {"secret", "credential", "leak"}) or bool(DEFAULT_SECRET_RULE_RE.search(rule)))

def is_sca(f: Finding, cfg: ClassificationSettings) -> bool:
    blob = f"{f.title}\n{f.description}"
    tags = {str(t).lower() for t in f.tags}
    vuln = f.get("vulnerability_id", "cve", "cwe", default="")
    has_pkg = bool(f.get("component_name", "package_name", default="")) and bool(vuln)
    return (f.scan_type in cfg.sca_scan_types or bool(VULN_RE.search(blob))
            or _any(cfg.sca_title_patterns + cfg.sca_description_patterns, blob)
            or has_pkg or bool(tags & {"sca", "dependency", "package", "vulnerable-package"}))

def classify_finding(f: Finding, cfg: ClassificationSettings) -> FindingKind:
    if is_secret(f, cfg):
        return FindingKind.SECRET
    if is_sca(f, cfg):
        return FindingKind.SCA
    return FindingKind.OTHER
