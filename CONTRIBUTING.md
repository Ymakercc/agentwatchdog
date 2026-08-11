# Contributing

Thanks for considering a contribution.

## The easiest useful contribution: a new agent fingerprint

Support for an agent CLI is a JSON file in `agents.d/`, not code. If you use an
agent that isn't supported yet, adding it is a small, self-contained PR:

1. Copy an existing file in `agents.d/` as a starting point.
2. Fill in how the agent is recognised (`comms`, `path_markers`).
3. **Fill in `redact` carefully.** This is the part that matters. Work out where
   that CLI puts the prompt — a flag value, a positional argument after a
   subcommand, or both — and make sure every such position is covered.
4. Add a case to `tests/test_redact.py` using a realistic command line that
   contains an obviously-secret string, and assert it does not survive redaction.

A fingerprint PR without a redaction test will not be merged. An incorrect
fingerprint doesn't just fail to detect — it writes someone's prompt to disk.

## Development setup

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest
ruff check .
```

Tests must run without root and without a real agent installed; that's what
`tests/fixtures/` is for. If you find yourself needing a live process to test
something, add a fixture instead.

## Ground rules

- **Zero runtime dependencies.** Standard library only. A PR that adds a
  dependency needs to justify why the tool is still droppable onto a bare server.
- **Never read prompt content.** See [SECURITY.md](SECURITY.md). Features that
  collect what a user asked an agent are out of scope, permanently.
- Keep Python 3.9 compatibility.
- Conventional commit subjects (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`).
- Add a `CHANGELOG.md` entry under `[Unreleased]` for anything user-visible.

## Reporting bugs

Include your distro, `python3 --version`, the agent CLI and version involved, and
the output of `agentwatchdog selftest`. Never paste a raw `events.jsonl` line
without checking it first — it should already be redacted, and if it isn't, that
is itself the bug and should be reported privately per SECURITY.md.
