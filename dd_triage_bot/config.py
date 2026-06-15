from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
try:
    import yaml
except Exception:
    from . import simple_yaml as yaml

@dataclass
class DefectDojoSettings:
    page_size:int=100; request_timeout_seconds:int=30; verify_tls:bool=True
@dataclass
class ClassificationSettings:
    sca_scan_types:list[str]=field(default_factory=list); secret_scan_types:list[str]=field(default_factory=list); sca_title_patterns:list[str]=field(default_factory=list); sca_description_patterns:list[str]=field(default_factory=list); secret_title_patterns:list[str]=field(default_factory=list)
@dataclass
class TagSettings:
    auto_verified_sca:str='auto-verified-sca'; auto_verified_secret:str='auto-verified-secret'; auto_fp_secret:str='auto-fp-secret'; manual_triage_required:str='manual-triage-required'
@dataclass
class SafetySettings:
    do_not_override_manual_false_positive:bool=True; do_not_override_risk_accepted:bool=True; do_not_reopen_inactive_findings:bool=True; add_audit_note:bool=True
@dataclass
class AppConfig:
    defectdojo:DefectDojoSettings=field(default_factory=DefectDojoSettings); classification:ClassificationSettings=field(default_factory=ClassificationSettings); tags:TagSettings=field(default_factory=TagSettings); safety:SafetySettings=field(default_factory=SafetySettings)

def load_config(path: str|Path)->AppConfig:
    data=yaml.safe_load(Path(path).read_text(encoding='utf-8')) or {}
    return AppConfig(DefectDojoSettings(**data.get('defectdojo',{})), ClassificationSettings(**data.get('classification',{})), TagSettings(**data.get('tags',{})), SafetySettings(**data.get('safety',{})))
