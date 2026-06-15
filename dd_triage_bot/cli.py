from __future__ import annotations
from pathlib import Path
import argparse
from .audit import AuditLogger
from .config import load_config
from .defectdojo_client import DefectDojoClient
from .exceptions import load_exception_policy, ExceptionPolicy
from .models import Finding
from .triage import desired_change, apply_action
from .reports import write_csv, write_json

def _client(cfg):
    c=DefectDojoClient(timeout=cfg.defectdojo.request_timeout_seconds, verify_tls=cfg.defectdojo.verify_tls, page_size=cfg.defectdojo.page_size); c.validate_schema(); return c

def cmd_triage(args):
    if args.dry_run == args.apply: raise SystemExit('Choose exactly one of --dry-run or --apply')
    cfg=load_config(args.config); policy=load_exception_policy(args.exceptions); client=_client(cfg); audit=AuditLogger(args.audit_log); total=0
    for raw in client.iter_findings(args.product_id):
        total+=1; a=desired_change(Finding.from_api(raw,args.product_id),cfg,policy); apply_action(a,client,audit,args.product_id,args.dry_run); print(f'{a.finding.id}: {a.action}')
    print(f"Processed {total} findings; mode={'dry-run' if args.dry_run else 'apply'}")

def cmd_export(args):
    cfg=load_config(args.config); client=_client(cfg); rows=[]
    for raw in client.iter_findings(args.product_id):
        f=Finding.from_api(raw,args.product_id); a=desired_change(f,cfg,ExceptionPolicy()); rows.append({'finding_id':f.id,'product_id':args.product_id,'test_id':f.test_id,'scan_type':f.scan_type,'title':f.title,'severity':f.severity,'action':a.action})
    write_json(args.output,rows) if args.format=='json' else write_csv(args.output,rows); print(f'Wrote {len(rows)} rows to {args.output}')

def main():
    p=argparse.ArgumentParser(); sub=p.add_subparsers(dest='cmd',required=True)
    t=sub.add_parser('triage'); t.add_argument('--config',required=True); t.add_argument('--exceptions',required=True); t.add_argument('--product-id',type=int,required=True); t.add_argument('--dry-run',action='store_true'); t.add_argument('--apply',action='store_true'); t.add_argument('--audit-log',default='triage-audit.jsonl'); t.set_defaults(func=cmd_triage)
    e=sub.add_parser('export'); e.add_argument('--config',required=True); e.add_argument('--product-id',type=int,required=True); e.add_argument('--format',choices=['csv','json'],default='csv'); e.add_argument('--output',required=True); e.set_defaults(func=cmd_export)
    a=p.parse_args(); a.func(a)
if __name__=='__main__': main()
