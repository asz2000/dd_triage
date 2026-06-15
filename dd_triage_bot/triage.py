from __future__ import annotations
from typing import Any
from .audit import AuditLogger
from .classifier import classify_finding
from .config import AppConfig
from .exceptions import ExceptionPolicy, find_matching_exception
from .models import Finding, FindingKind, TriageAction
from .reports import mask_secret

STATE = {"active", "verified", "false_p"}

def desired_change(f: Finding, cfg: AppConfig, policy: ExceptionPolicy | None = None) -> TriageAction:
    kind = classify_finding(f, cfg.classification)
    if cfg.safety.do_not_override_risk_accepted and f.risk_accepted:
        return TriageAction(f, kind, "skip_risk_accepted", skipped=True, skip_reason="risk accepted")
    if cfg.safety.do_not_override_manual_false_positive and f.false_p and not any(t.startswith("exception:") or t == cfg.tags.auto_fp_secret for t in f.tags):
        return TriageAction(f, kind, "skip_manual_false_positive", skipped=True, skip_reason="manual false positive")
    if cfg.safety.do_not_reopen_inactive_findings and not f.active:
        return TriageAction(f, kind, "skip_inactive", skipped=True, skip_reason="inactive")
    if kind == FindingKind.SCA:
        return TriageAction(f, kind, "mark_sca_verified", {"active": True, "verified": True, "false_p": False}, [cfg.tags.auto_verified_sca])
    if kind == FindingKind.SECRET:
        rule = find_matching_exception(f, policy) if policy else None
        secret = str(f.get("secret", "secret_value", "matched_secret", "raw_secret", default=""))
        if rule:
            return TriageAction(f, kind, "mark_secret_false_positive", {"active": False, "verified": False, "false_p": True}, [cfg.tags.auto_fp_secret, f"exception:{rule.id}"], f"Auto false positive by exception {rule.id}: {rule.reason}", rule.id, rule.reason, mask_secret(secret))
        return TriageAction(f, kind, "mark_secret_verified", {"active": True, "verified": True, "false_p": False}, [cfg.tags.auto_verified_secret], masked_secret=mask_secret(secret))
    return TriageAction(f, kind, "manual_triage_required", tags_to_add=[cfg.tags.manual_triage_required])

def needs_update(a: TriageAction) -> bool:
    if a.skipped or not a.patch: return False
    state_diff = any(getattr(a.finding, k) != v for k, v in a.patch.items() if k in STATE)
    tag_diff = any(t not in a.finding.tags for t in a.tags_to_add)
    # already same FP exception => no update/note duplication
    if a.rule_id and a.finding.false_p and f"exception:{a.rule_id}" in a.finding.tags and not state_diff and not tag_diff:
        return False
    return state_diff or tag_diff or bool(a.note and a.rule_id and f"exception:{a.rule_id}" not in a.finding.tags)

def apply_action(a: TriageAction, client: Any, audit: AuditLogger, product_id: int | None, dry_run: bool) -> None:
    if not needs_update(a): return
    new_tags = list(dict.fromkeys([*a.finding.tags, *a.tags_to_add]))
    payload = dict(a.patch)
    if a.tags_to_add: payload["tags"] = new_tags
    old_state = {k: getattr(a.finding, k) for k in STATE}
    new_state = {**old_state, **a.patch}
    audit.write({"finding_id": a.finding.id, "product_id": product_id or a.finding.product_id, "action": a.action, "old_state": old_state, "new_state": new_state, "rule_id": a.rule_id, "reason": a.reason, "masked_secret": a.masked_secret, "dry_run": dry_run})
    if not dry_run:
        client.patch_finding(a.finding.id, payload)
        if a.note:
            client.add_note(a.finding.id, a.note)
