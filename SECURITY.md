# Security Policy

## Reporting a vulnerability

Please report security issues privately through GitHub's
[private vulnerability reporting](https://github.com/Ymakercc/AgentWatchDog/security/advisories/new)
rather than opening a public issue. Expect an acknowledgement within a few days.

## Intended use

agentwatchdog is an operations and defensive-security tool. It is meant to be run
by an administrator **on hosts they own or are explicitly authorized to audit**,
to answer questions about automated agent processes running on that host.

It is not intended for, and is deliberately unsuitable for, covert surveillance of
people. It records no prompt content, no keystrokes and no file contents — only
process-level facts (which agent, which account, which parent process, how long,
how much CPU). If your goal is to read what someone typed, this is the wrong tool
and we will not accept contributions that make it the right one.

## Privacy guarantees

These are enforced by code and by tests in `tests/test_redact.py` and
`tests/test_export_anon.py`. A failure of either test blocks a release.

1. **Environment variables are never read.** The collector does not open
   `/proc/PID/environ` under any code path. API keys living in the environment
   cannot leak through this tool.
2. **Prompts are never written to disk.** Command lines are redacted before being
   persisted. Redaction is driven per-agent, because each CLI carries the prompt
   in a different position.
3. **Secrets are redacted defensively.** Values that look like API keys, bearer
   tokens or JWTs are replaced even when they appear in an unexpected position.
4. **Nothing leaves the host by default.** Alerts are written to a local JSONL
   file. Outbound delivery (webhook, exec) is opt-in and off unless configured.
5. **Exported aggregates are anonymous.** The `export` subcommand emits counts and
   time buckets only — no users, uids, pids, paths, hostnames or command lines.

## Threat model

agentwatchdog assumes it runs as root on a host where the agent processes are
**not** trusted to report on themselves. It does not assume the agents are
malicious, but it does assume they may be misconfigured, looping, or invoked by
someone who did not expect to be logged.

It is **not** a sandbox and does not block anything. It observes and reports.
An attacker who already has root on the host can disable it like any other
systemd unit; it is an audit aid, not a containment boundary.
