from datetime import date
from dd_triage_bot.exceptions import ExceptionPolicy, ExceptionRule, MatchCriteria, find_matching_exception
from dd_triage_bot.models import Finding

def finding(**raw): return Finding.from_api({'id':1, **raw})
def rule(**kw):
    base=dict(id='r1', scanner_rule_ids=['generic-api-key'], match=MatchCriteria(condition='AND', path_regex=['docs/'], secret_regex=['dummy']))
    base.update(kw); return ExceptionRule(**base)
def test_match_rule_id_path_secret():
    p=ExceptionPolicy(rules=[rule()]); f=finding(scanner_rule_id='generic-api-key', file_path='docs/a.md', secret='dummy')
    assert find_matching_exception(f,p,date(2026,1,1)).id=='r1'
def test_expired_not_applied():
    p=ExceptionPolicy(rules=[rule(expires_at=date(2025,1,1))]); assert find_matching_exception(finding(scanner_rule_id='generic-api-key', file_path='docs/a', secret='dummy'),p,date(2026,1,1)) is None
def test_disabled_not_applied():
    p=ExceptionPolicy(rules=[rule(enabled=False)]); assert find_matching_exception(finding(scanner_rule_id='generic-api-key', file_path='docs/a', secret='dummy'),p) is None
def test_and_requires_all_groups():
    p=ExceptionPolicy(rules=[rule()]); assert find_matching_exception(finding(scanner_rule_id='generic-api-key', file_path='src/a', secret='dummy'),p) is None
def test_or_requires_one_group():
    p=ExceptionPolicy(rules=[rule(match=MatchCriteria(condition='OR', path_regex=['docs/'], secret_regex=['dummy']))])
    assert find_matching_exception(finding(scanner_rule_id='generic-api-key', file_path='src/a', secret='dummy'),p).id=='r1'
