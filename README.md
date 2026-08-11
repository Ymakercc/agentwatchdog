# agentwatchdog

**Host-side runtime audit for terminal AI coding agents. No hooks, no wrappers, no opt-out — it reads `/proc`, never your prompts.**

> ⚠️ Early development (`0.1.0.dev0`). Linux only. Not yet released.
> [中文文档](README.zh-CN.md)

---

## The problem

You run AI coding agents on a server — under cron, in CI, over SSH, in a shared
account. Sooner or later you want to answer questions like:

- Who spawned an agent on this box at 3am, and from what parent process?
- Is something stuck in a loop re-spawning agents and burning API spend?
- Is an agent process still running after four hours because it hung?
- Did a user who has no business running agents here just run one?

Every existing tool answers a different question ("how many tokens did I spend?")
and answers it from *inside* the agent — via an OpenTelemetry exporter, a hook, a
wrapper command, or an API proxy.

That has a structural weakness: **the thing being watched has to cooperate.**
Don't set the env var, don't install the hook, don't use the wrapper — and the
tool goes blind. A runaway cron job, a misconfigured service, or a user who
simply invokes the binary directly is invisible to all of them.

## The approach

agentwatchdog watches from **outside the agent**, at the operating system level.
It polls `/proc` and `ps` on a systemd timer and reports on every agent process
on the host.

- **Cannot be opted out of.** If the process exists, it is seen. No cooperation
  from the agent is required or possible.
- **Zero dependencies.** Python 3 standard library and systemd. No Docker, no
  OTLP collector, no Grafana, no Node packages.
- **Never reads your prompts.** This is a hard constraint enforced in code and in
  tests, not a promise:
  - never reads `/proc/PID/environ` — environment variables and API keys are
    never touched
  - command lines are **redacted before they are written to disk**; prompts,
    session ids, tokens and secret-looking values become `<redacted>`
  - a SHA-256 digest of the raw command line is stored instead, so identical
    invocations can be correlated without revealing content
  - nothing leaves the host by default

## What it detects

| Alert | Meaning |
|---|---|
| `long_running_process` | A non-interactive agent process has outlived its threshold — likely hung |
| `parent_spawn_storm` | One parent process is repeatedly spawning agents — a restart loop burning spend |
| `user_high_frequency` | A single user is starting agents far faster than expected |
| `unexpected_user` | An account outside the allow-list ran an agent on this host |
| `high_cpu` / `high_mem` | An agent process is consuming abnormal resources |
| `agents_during_high_load` | Several agents running concurrently while the host is already overloaded |

## Supported agents

Detection is driven by a fingerprint table (`agents.d/*.json`), so adding an
agent is a config change, not a code change.

| Agent | Status |
|---|---|
| Claude Code | planned for 0.1.0 |
| OpenAI Codex CLI | planned for 0.1.0 |
| Gemini CLI | planned for 0.1.0 |
| aider | planned for 0.1.0 |
| OpenCode | planned for 0.1.0 |

Each fingerprint also carries that agent's **redaction rules**, because every CLI
puts the prompt somewhere different — `claude -p "…"`, `codex exec "…"`,
`aider -m "…"`. Getting this right per-agent is the difference between an audit
log and an accidental prompt archive.

## Scope and limits

- **Linux only.** The design reads `/proc`. macOS support (via `libproc`) is on
  the roadmap; there is no Windows plan.
- **Process-level, not content-level.** It tells you *that* an agent ran, who ran
  it and how it behaved. It deliberately cannot tell you *what* it was asked.
- **For hosts you own or are authorized to audit.** See [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE).

agentwatchdog is an independent project. It is not affiliated with, endorsed by,
or sponsored by Anthropic, OpenAI, Google, or any other agent vendor. Product
names are used only to identify the software being observed.
