from dd_triage_bot.classifier import classify_finding
from dd_triage_bot.config import load_config
from dd_triage_bot.models import Finding, FindingKind
cfg=load_config('examples/config.yaml')
def test_sca_cve_title(): assert classify_finding(Finding(1,title='CVE-2024-1234'),cfg.classification)==FindingKind.SCA
def test_sca_ghsa_desc(): assert classify_finding(Finding(1,description='GHSA-abcd-1234-efgh'),cfg.classification)==FindingKind.SCA
def test_sca_osv(): assert classify_finding(Finding(1,title='OSV-2023-1'),cfg.classification)==FindingKind.SCA
def test_sca_trivy(): assert classify_finding(Finding(1,scan_type='Trivy Scan'),cfg.classification)==FindingKind.SCA
def test_sca_osv_scan(): assert classify_finding(Finding(1,scan_type='OSV Scanner'),cfg.classification)==FindingKind.SCA
def test_secret_gitleaks(): assert classify_finding(Finding(1,scan_type='Gitleaks Scan'),cfg.classification)==FindingKind.SECRET
def test_secret_trufflehog(): assert classify_finding(Finding(1,scan_type='TruffleHog Scan'),cfg.classification)==FindingKind.SECRET
def test_secret_api_key_title(): assert classify_finding(Finding(1,title='API Key leaked'),cfg.classification)==FindingKind.SECRET
def test_secret_tag(): assert classify_finding(Finding(1,tags=['secret']),cfg.classification)==FindingKind.SECRET
def test_secret_priority(): assert classify_finding(Finding(1,title='CVE token leak'),cfg.classification)==FindingKind.SECRET
