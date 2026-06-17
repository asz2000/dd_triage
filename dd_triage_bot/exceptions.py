from __future__ import annotations
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
import re
try:
    import yaml
except Exception:
    from . import simple_yaml as yaml
from .models import Finding

@dataclass
class MatchCriteria:
    condition:str='AND'; path_regex:list[str]=field(default_factory=list); line_regex:list[str]=field(default_factory=list); secret_regex:list[str]=field(default_factory=list); title_regex:list[str]=field(default_factory=list)
@dataclass
class ExceptionRule:
    id:str; enabled:bool=True; provider:str='generic'; scanner_rule_ids:list[str]=field(default_factory=list); decision:str='false_positive'; reason:str=''; owner:str=''; created_at:date|str|None=None; expires_at:date|str|None=None; match:MatchCriteria|dict=field(default_factory=MatchCriteria); tags:list[str]=field(default_factory=list)
    def __post_init__(self):
        if isinstance(self.match, dict): self.match=MatchCriteria(**self.match)
        for attr in ('created_at','expires_at'):
            v=getattr(self,attr)
            if isinstance(v,str):
                try: setattr(self,attr,date.fromisoformat(v))
                except ValueError: pass
    def expired(self,today:date|None=None)->bool:
        return isinstance(self.expires_at,date) and self.expires_at < (today or date.today())
@dataclass
class ExceptionPolicy:
    version:int=1; rules:list[ExceptionRule]=field(default_factory=list)
    def __post_init__(self): self.rules=[r if isinstance(r,ExceptionRule) else ExceptionRule(**r) for r in self.rules]

def load_exception_policy(path: str|Path)->ExceptionPolicy:
    return ExceptionPolicy(**(yaml.safe_load(Path(path).read_text(encoding='utf-8')) or {}))
def _matches_any(patterns:list[str], value:str)->bool: return any(re.search(p,value or '') for p in patterns)
def find_matching_exception(f:Finding, policy:ExceptionPolicy, today:date|None=None)->ExceptionRule|None:
    rid=str(f.get('scanner_rule_id','rule_id',default='')); path=str(f.get('file_path','file','path',default='')); line=str(f.get('line','line_text','matched_line',default='')); secret=str(f.get('secret','secret_value','matched_secret','raw_secret',default='')); title=str(f.get('title', default=''))
    for r in policy.rules:
        if not r.enabled or r.expired(today) or r.decision!='false_positive': continue
        if r.scanner_rule_ids and rid not in r.scanner_rule_ids: continue
        groups=[]
        if r.match.path_regex: groups.append(_matches_any(r.match.path_regex,path))
        if r.match.line_regex: groups.append(_matches_any(r.match.line_regex,line))
        if r.match.secret_regex: groups.append(_matches_any(r.match.secret_regex,secret))
        if r.match.title_regex: groups.append(_matches_any(r.match.title_regex,title))
        if groups and ((r.match.condition.upper()=='OR' and any(groups)) or (r.match.condition.upper()!='OR' and all(groups))): return r
    return None
