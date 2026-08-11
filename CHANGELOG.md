# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `/proc`-based collector: identifies agent processes from outside the agent,
  with no hooks, wrappers or exporters to bypass. No `ps` dependency.
- Agent fingerprints as data (`agents.d/*.json`) for Claude Code, OpenAI Codex
  CLI, aider (all verified against real binaries), Gemini CLI and OpenCode
  (best-effort). Operators can add or override fingerprints in
  `/etc/agentwatchdog/agents.d/`.
- Default-deny redaction: positional arguments are masked unless a fingerprint
  vouches for them; unknown flags are treated as boolean so their neighbours
  are masked too; credential-shaped values are masked in any position.
  `/proc/PID/environ` is never opened, enforced by test.
- Detectors: `unexpected_user` (with loginuid attribution), `parent_spawn_storm`,
  `user_high_frequency`, `long_running_process`, `high_cpu` (lifetime average
  with a minimum sample age), `high_mem`, `agents_during_high_load`.
  Per-situation alert cooldowns.
- Delivery: local `alerts.jsonl` by default; opt-in `exec` (no shell) and
  `webhook` (HTTPS only) notifiers. Nothing leaves the host unconfigured.
- Anonymized aggregate `export`, validated against a key allowlist at runtime.
- CLI: `scan`, `dry-run` (writes nothing at all), `status`, `selftest` (proves
  redaction on the installed host), `agents`, `export`, `install`, `uninstall`.
- Hardened systemd timer install with logrotate; single-file zipapp build
  (~110 KB, python3-only) exercised by CI in a bare environment.

[Unreleased]: https://github.com/Ymakercc/agentwatchdog/compare/main...HEAD
