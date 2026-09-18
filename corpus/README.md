# Verdict corpus

Committed PEMs and CSRs plus the expected gate outcome. CI fails if a fixture
stops matching this file.

```bash
pytest tests/test_verdict_corpus.py -q
```

`evaluate: inside_window` uses the midpoint of the certificate's validity so
regenerated fixtures stay stable. `after_not_after` is for artefacts that must
fail expiry (including the 0.2.0 expired-cert false negative).
