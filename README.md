# agentwatchdog

**Host-side runtime audit for terminal AI coding agents. No hooks, no wrappers, no opt-out — it reads `/proc`, never your prompts.**

> **Status:** feature-complete, currently in a burn-in period running side by side
> with its predecessor on a production VPS. `v0.1.0` will be tagged when that
> soak completes. Linux only.
>
> [31582749.xyz](https://31582749.xyz/) &middot; [中文文档](README.zh-CN.md)

---

## The problem

You run AI coding agents on a server — under cron, in CI, over SSH, in a shared
account. Sooner or later you are asking one of these questions:

- Who started an agent on this box at 3am, and from what parent process?
- Is something stuck in a loop re-spawning agents and burning API spend?
- Is that non-interactive agent from six hours ago hung, or still working?
- Did an account that has no business running agents here just run one?

The existing observability tools answer a different question — *how many tokens
did I spend?* — and they answer it from **inside the agent**: an OpenTelemetry
exporter you enable, a hook you install, a wrapper command you remember to use,
a proxy you route through.

That has a structural weakness: **the thing being watched has to cooperate.**
Don't set the env var, don't install the hook, invoke the binary directly — and
the tool is blind. The runaway cron job, the misconfigured service, and the
unexpected user are exactly the cases that never cooperate.

## The approach

agentwatchdog watches from **outside the agent**, at the operating system level.
A systemd timer runs a one-shot scan every minute; the scan reads `/proc`,
identifies agent processes by fingerprint, and records who is running what.

| | in-agent tools (OTel / hooks / wrappers) | agentwatchdog |
|---|---|---|
| Vantage point | inside the agent process | the host's `/proc` |
| Can be bypassed | yes — by not cooperating | no — a process that exists is seen |
| Dependencies | collector / Docker / Node packages | none: Python 3 stdlib + systemd |
| Prompt content | some tools read session transcripts | never read, redacted before write |
| Question answered | tokens, cost, session detail | who / what / spawned by / behaving? |
| Meant for | the developer at the keyboard | the operator of the host |

The two views complement each other. If you want per-token cost dashboards, use
an OTel-based tool — this is not that. This is the audit trail for the host.

## Quick start

One file, no dependencies beyond `python3`:

```sh
curl -fsSLO https://github.com/Ymakercc/agentwatchdog/releases/latest/download/agentwatchdog.pyz
chmod +x agentwatchdog.pyz

# See exactly what it would record before it records anything:
./agentwatchdog.pyz dry-run

# Prove the redaction promise on your own host:
./agentwatchdog.pyz selftest

# Then, if you like what you see:
sudo mv agentwatchdog.pyz /usr/local/bin/agentwatchdog
sudo agentwatchdog install        # systemd timer + config + logrotate
```

Or from a checkout: `pip install .` (PyPI release follows `v0.1.0`).

`dry-run` writes nothing — not even the log directory — and sends nothing. It
exists so you can point this at a production host and see its complete output
before trusting it with anything.

What a scan sees (real output, this repository's build host):

```
agent processes running: 7
agents seen            : claude-code, codex

--- what is running ---
  [codex] pid=821321 user=root persistent 964.6h
      .../bin/codex app-server --listen <redacted>
  [claude-code] pid=2759430 user=root persistent 28.8h
      claude remote-control --name <redacted> --permission-mode default
  [claude-code] pid=2760702 user=root persistent 28.7h
      .../claude.exe --print --sdk-url <redacted> --session-id <redacted> ...
```

## What it detects

| Alert | Severity | Meaning |
|---|---|---|
| `unexpected_user` | critical | An account outside `ALLOWED_USERS` ran an agent. Reports `loginuid`, so "alice ran an agent as root via sudo" is one alert, not a mystery. |
| `parent_spawn_storm` | critical | One parent process keeps spawning agents. No human does this — it is a restart loop billing you for every attempt. Found by *consecutive scans*, not by counting starts, so a loop faster than the scan interval is still caught. The alert carries the parent's ancestry. |
| `user_high_frequency` | warning | One account is starting agents far faster than people type. |
| `long_running_process` | warning | A non-interactive agent outlived its limit — probably hung. |
| `high_cpu` / `high_mem` | warning | Sustained abnormal resource use (lifetime average, so launch spikes don't false-positive). |
| `agents_during_high_load` | warning | Several agents piling onto a host that is already struggling. |

Alerts are appended to a local `alerts.jsonl` and **go nowhere else by
default**. To deliver them somewhere, opt in via `NOTIFY`:

- `exec` — pipe the alert JSON into any command you already have (a Telegram
  bot, `mail`, your incident tooling). Runs without a shell, by design.
- `webhook` — POST JSON to an HTTPS endpoint. Plain HTTP is refused, not warned
  about: alerts name users, paths and process trees.

## Privacy: enforced, not promised

This tool reads command lines for a living, so the constraints are load-bearing
and tested in CI as a separate job that blocks release:

1. **`/proc/PID/environ` is never opened.** A test records every `open()`
   during a scan and fails if that file appears. API keys in the environment
   cannot pass through this tool.
2. **Prompts never reach disk.** Command lines are redacted *before* being
   written, using per-agent rules — because every CLI puts the prompt somewhere
   different (`claude -p "…"`, `codex exec "…"`, `aider -m "…"`).
3. **Positional arguments are denied by default.** An argument is redacted
   unless the fingerprint explicitly lists it as a safe literal (a subcommand
   name). An unknown flag is assumed boolean, so the token after it is redacted
   too. A new agent, or a new release that moves the prompt, leaks nothing.
4. **Credential-shaped values are masked anywhere they appear** — provider key
   prefixes, JWTs, long opaque tokens — even in positions no rule anticipated.
5. **What may leave the host is anonymous by construction.** `export` produces
   counts and time buckets assembled into a fixed shape and checked against a
   key allowlist *at runtime* — an export that cannot be proven anonymous is
   refused, not published.

A digest of the command line is stored so identical invocations can be
correlated. It is an HMAC under a key generated per host, kept outside the log
directory and never exported — because a plain hash sitting next to
`codex exec <redacted>` tells an attacker the shape and leaves only the prompt
to guess, and one hash of a guess would confirm it. No key, no digest: the
unkeyed fallback is the one thing this must not do.

Run `agentwatchdog selftest` on your own host to watch these hold against the
agents actually running there.

## Supported agents

Detection is data, not code: each agent is a JSON fingerprint in `agents.d/`,
and operators can add or override fingerprints in `/etc/agentwatchdog/agents.d/`
without waiting for a release.

| Agent | Detection | Flag table |
|---|---|---|
| Claude Code | ✅ | **verified** against the binary |
| OpenAI Codex CLI | ✅ | **verified** against the binary |
| aider | ✅ | **verified** against 0.86.2 |
| Gemini CLI | ✅ | best-effort, from documentation |
| OpenCode | ✅ | best-effort, from documentation |

"Best-effort" costs detail, never privacy: unrecognised arguments are redacted,
not printed. Two real traps the verified tables caught, as a caution against
writing these from memory: Codex takes a prompt as a positional at the *top*
level, not only after `exec`; and Codex's `-p` is `--profile`, while Claude
Code's `-p` is the prompt. Porting one agent's rules to the other silently
leaks. See [CONTRIBUTING.md](CONTRIBUTING.md) to add or correct a fingerprint —
it is the easiest useful PR this project accepts.

## Configuration

`/etc/agentwatchdog.conf`, flat `KEY=VALUE`, re-read every scan, editable with
`vi` over SSH. Defaults are chosen so a fresh install is quiet: no outbound
delivery, no user allow-list (you enable that check by writing down who belongs
on the host), thresholds loose enough not to cry wolf.

The settings you are most likely to touch:

```ini
ALLOWED_USERS=root deploy          # empty = unexpected_user check off
PERSISTENT_REGEX=remote-control    # extra long-lived sessions to exempt
MAX_RUNTIME_SEC=14400              # 4h before a one-shot agent counts as hung
NOTIFY=jsonl                       # add exec and/or webhook to deliver
```

## Scope and honest limits

- **Linux only.** The design *is* `/proc`. macOS (`libproc`) is on the roadmap;
  Windows is not planned.
- **Process-level, not content-level.** It tells you *that* an agent ran, who
  ran it, and how it behaved — deliberately never *what it was asked*.
- **It samples.** A scan is a snapshot every `--interval` seconds (60 by
  default, anchored to the clock). An agent that starts and exits between two
  scans is never seen, so counts of short one-shot invocations are a lower
  bound. Detection of a restart loop does not depend on catching any particular
  attempt, and the host's kernel fork rate is attached to storm alerts so you
  can see the magnitude the process list cannot show.
- **It observes; it does not block.** This is an audit aid, not a sandbox, and
  not a containment boundary: root can disable it like any systemd unit.
- **For hosts you own or are authorized to audit.** It is unsuitable for covert
  surveillance of people by design — no prompts, no keystrokes, no file
  contents — and contributions that change that will be declined. See
  [SECURITY.md](SECURITY.md).

## License

Apache-2.0. agentwatchdog is an independent project, not affiliated with or
endorsed by Anthropic, OpenAI, Google, or any other agent vendor; product names
identify the software being observed.
