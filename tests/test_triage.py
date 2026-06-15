from dd_triage_bot.config import load_config
from dd_triage_bot.exceptions import ExceptionPolicy
from dd_triage_bot.models import Finding
from dd_triage_bot.triage import desired_change, needs_update
cfg=load_config('examples/config.yaml')
def test_risk_accepted_skip(): assert desired_change(Finding(1,title='CVE-2024-1',risk_accepted=True),cfg,ExceptionPolicy()).skipped
def test_manual_false_positive_skip(): assert desired_change(Finding(1,title='API Key',false_p=True),cfg,ExceptionPolicy()).action=='skip_manual_false_positive'
def test_inactive_not_reopened(): assert desired_change(Finding(1,title='CVE-2024-1',active=False),cfg,ExceptionPolicy()).action=='skip_inactive'
def test_idempotent_existing_tags_no_update():
    f=Finding(1,title='CVE-2024-1',active=True,verified=True,false_p=False,tags=['auto-verified-sca'])
    assert needs_update(desired_change(f,cfg,ExceptionPolicy())) is False
