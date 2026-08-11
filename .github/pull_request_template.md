**What does this change?**

**Checklist**

- [ ] `pytest` passes locally
- [ ] `ruff check .` and `ruff format --check .` pass
- [ ] No new runtime dependencies (stdlib only — this is a hard rule)
- [ ] Nothing added reads prompt content or `/proc/PID/environ`
- [ ] User-visible change noted under `[Unreleased]` in CHANGELOG.md

**If this adds or changes an agent fingerprint**

- [ ] `redact` rules cover every position that agent puts a prompt in
- [ ] A case added to `tests/test_redact.py` with a realistic command line
      containing an obviously-secret string, asserting it does not survive
- [ ] `flags_verified` is honest: `true` only if checked against the binary,
      and `notes` says which version
