from dd_triage_bot.reports import mask_secret
def test_short_masked_all(): assert mask_secret('short')=='***'
def test_long_masked_edges(): assert mask_secret('AKIAIOSFODNN7EXAMPLE')=='AKIA***MPLE'
