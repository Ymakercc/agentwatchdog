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
- `parent_spawn_storm` identifies a restart loop by *consecutive scans* on which
  a parent starts a fresh agent (`MIN_SPAWN_STREAK`), not by counting starts
  inside a window. Counting cannot work: only agents alive at scan time are
  counted, so a serial loop contributes at most one per scan and can never reach
  a volume threshold however fast it runs. The window count is kept for the
  other shape — a parent launching many agents that all stay up. The host's
  kernel fork rate is attached to the alert as corroboration.
- Command-line correlation digests are HMAC under a per-host key
  (`DIGEST_KEY_PATH`, created at install, 0600, outside the log directory and
  never exported). An unkeyed hash beside a redacted command line is a
  guess-and-compare oracle for the redacted part; without a readable key the
  digest is omitted rather than downgraded.
- Delivery: local `alerts.jsonl` by default; opt-in `exec` (no shell) and
  `webhook` (HTTPS only) notifiers. Nothing leaves the host unconfigured.
- Anonymized aggregate `export`, validated against a key allowlist at runtime.
- CLI: `scan`, `dry-run` (writes nothing at all), `status`, `selftest` (proves
  redaction on the installed host), `agents`, `export`, `install`, `uninstall`.
- Hardened systemd timer install with logrotate. The timer is anchored to the
  clock (`OnCalendar`, `AccuracySec=1s`) rather than relative to the previous
  run: the relative form stretched a 60s interval to roughly 65s and drifted,
  measured at 1334 scans a day instead of 1440 over an eight-day burn-in.
- Single-file zipapp build
  (~110 KB, python3-only) exercised by CI in a bare environment.

[Unreleased]: https://github.com/Ymakercc/agentwatchdog/compare/main...HEAD
