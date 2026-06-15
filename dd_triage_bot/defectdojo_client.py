from __future__ import annotations
import os, json, urllib.request
from typing import Any, Iterator

class DefectDojoClient:
    def __init__(self, base_url: str | None = None, token: str | None = None, timeout: int = 30, verify_tls: bool = True, page_size: int = 100):
        self.base_url=(base_url or os.environ.get('DEFECTDOJO_URL') or '').rstrip('/'); self.token=token or os.environ.get('DEFECTDOJO_TOKEN') or ''; self.timeout=timeout; self.page_size=page_size; self.false_positive_field='false_p'
    def _request(self, method:str, path:str, payload:dict[str,Any]|None=None)->dict[str,Any]:
        if not self.base_url: raise RuntimeError('DEFECTDOJO_URL is not set')
        url=path if path.startswith('http') else self.base_url+path
        data=json.dumps(payload).encode() if payload is not None else None
        req=urllib.request.Request(url,data=data,method=method,headers={'Accept':'application/json','Content-Type':'application/json', **({'Authorization':f'Token {self.token}'} if self.token else {})})
        with urllib.request.urlopen(req,timeout=self.timeout) as r: return json.loads(r.read() or b'{}')
    def validate_schema(self)->None:
        if not self.base_url: return
        try:
            text=str(self._request('GET','/api/v2/oa3/schema/')); self.false_positive_field='false_p' if 'false_p' in text else 'is_false_positive'
        except Exception: self.false_positive_field='false_p'
    def iter_findings(self, product_id:int|None=None)->Iterator[dict[str,Any]]:
        if not self.base_url: return iter(())
        sep='&' if '?' in '/api/v2/findings/' else '?'
        url=f'/api/v2/findings/{sep}limit={self.page_size}' + (f'&test__engagement__product={product_id}' if product_id else '')
        while url:
            data=self._request('GET',url); items=data.get('results', data if isinstance(data,list) else [])
            for item in items: yield item
            url=data.get('next') if isinstance(data,dict) else None
    def patch_finding(self,finding_id:int,payload:dict[str,Any])->dict[str,Any]:
        if 'false_p' in payload and self.false_positive_field!='false_p': payload={self.false_positive_field if k=='false_p' else k:v for k,v in payload.items()}
        return self._request('PATCH',f'/api/v2/findings/{finding_id}/',payload)
    def add_note(self,finding_id:int,text:str)->None:
        self._request('POST','/api/v2/notes/',{'entry':text,'finding':finding_id})
