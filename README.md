# dd_triage_bot

`dd_triage_bot` is a Python 3.12 CLI service for automatic post-triage of DefectDojo API v2 findings after scanner reimport. It classifies findings as SCA package vulnerabilities, secrets, or manual-triage items; then applies safe, auditable state changes.

## Process

1. CI imports scanner results into DefectDojo.
2. The bot reads `/api/v2/findings/` for a product.
3. SCA findings are marked `active=true`, `verified=true`, `false_p=false` and tagged `auto-verified-sca`.
4. Secret findings are matched against a reviewed YAML exception allowlist. Matching, unexpired false-positive rules are marked inactive/unverified/false-positive and tagged with `auto-fp-secret` plus `exception:<rule_id>`; unmatched secrets are verified.
5. Other findings are exported as `manual_triage_required`.
6. Each actual or dry-run change is written to `triage-audit.jsonl` with masked secrets only.

## Usage

Set `DEFECTDOJO_URL` and `DEFECTDOJO_TOKEN`.

```bash
python -m dd_triage_bot.cli triage --config examples/config.yaml --exceptions examples/secret_exceptions.yaml --product-id 10 --dry-run
python -m dd_triage_bot.cli triage --config examples/config.yaml --exceptions examples/secret_exceptions.yaml --product-id 10 --apply
python -m dd_triage_bot.cli export --config examples/config.yaml --product-id 10 --format csv --output triage-report.csv
```

`--dry-run` records what would change without PATCHing DefectDojo. `--apply` sends PATCH requests only when state or tags differ, preventing duplicate tags and repeated exception notes.

## Exceptions

See `examples/secret_exceptions.yaml`. Add exceptions only after confirming the provider, scanner rule, file path context, line context, and secret pattern are all constrained. **`provider-not-used` must never be the only false-positive criterion**; require fixture/docs/test path and placeholder value evidence.

## DefectDojo API notes

The client checks `/api/v2/oa3/schema/` before PATCH and adapts the false-positive field if needed. The note adapter currently posts to `/api/v2/notes/` with `{entry, finding}`; if your DefectDojo version uses a different notes/comments endpoint, change `DefectDojoClient.add_note` in `dd_triage_bot/defectdojo_client.py`.

## CI/CD example

```yaml
triage-defectdojo:
  stage: security
  script:
    - python -m pip install .
    - python -m dd_triage_bot.cli triage --config examples/config.yaml --exceptions examples/secret_exceptions.yaml --product-id "$DD_PRODUCT_ID" --apply
  needs: [defectdojo-reimport]
```
