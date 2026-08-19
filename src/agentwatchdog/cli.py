"""Command line entry point.

Hand-rolled dispatch rather than argparse, for one reason: this module also has
to work when the whole package has been flattened into a single file and dropped
onto a host with nothing installed. Keeping the surface small keeps that build
honest.

``scan`` is the default because that is what the timer runs. Everything else
exists for a human at a prompt.
"""

import json
import os
import sys
import time

from . import __version__, agents, collector, config, digest, export, install, redact, state

USAGE = f"""\
agentwatchdog - host-side runtime audit for terminal AI coding agents

usage: agentwatchdog <command> [options]

  scan                 run one scan and record what it finds (what the timer runs)
  dry-run              run one scan and print it; write nothing, send nothing
  status               timer state and what has been recorded so far
  selftest             check this host: tools, agents, and that redaction works
  agents               list the agent fingerprints in effect
  export [PATH]        write the anonymized aggregate summary (stdout if no PATH)
  install [--interval N]   set up the systemd timer, config and log rotation
  uninstall [--purge]  remove the timer; --purge also removes logs and config
  version

Alerts are written to the local alerts.jsonl and go nowhere else unless NOTIFY
is configured. See {config.CONFIG_PATH}
"""


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    command = argv[0] if argv else "scan"
    rest = argv[1:]

    if command in ("-h", "--help", "help"):
        print(USAGE)
        return 0
    if command in ("-V", "--version", "version"):
        print(f"agentwatchdog {__version__}")
        return 0

    cfg = config.load()

    if command in ("scan", "run"):
        return _scan(cfg)
    if command in ("dry-run", "--dry-run", "dry"):
        return _dry_run(cfg)
    if command == "status":
        return _status(cfg)
    if command == "selftest":
        return _selftest(cfg)
    if command == "agents":
        return _agents(cfg)
    if command == "export":
        return _export(cfg, rest)
    if command == "install":
        return _install(cfg, rest)
    if command == "uninstall":
        return install.uninstall(cfg, purge="--purge" in rest)

    sys.stderr.write(f"agentwatchdog: unknown command {command!r}\n\n{USAGE}")
    return 2


def _scan(cfg):
    """Run one scan, recording results. Never raises: the timer must keep firing."""

    def log(message):
        try:
            os.makedirs(cfg["LOG_DIR"], exist_ok=True)
            with open(os.path.join(cfg["LOG_DIR"], "agentwatchdog.log"), "a") as fh:
                fh.write(f"{time.strftime('%F %T')} {message}\n")
        except OSError:
            pass

    try:
        collector.scan(cfg, log=log)
    except Exception as exc:  # noqa: BLE001 - one bad scan must not stop the timer
        log(f"scan failed: {exc!r}")
        sys.stderr.write(f"agentwatchdog: scan failed: {exc}\n")
        return 1
    return 0


def _dry_run(cfg):
    """Show what a scan would record, without touching anything.

    The point is to be runnable on a production host by someone deciding whether
    to trust this tool with their command lines. It writes nothing, sends
    nothing and updates no state.
    """
    summary, new_events, alerts, all_events = collector.scan(cfg, dry_run=True)

    print("dry run - nothing written, nothing sent\n")
    print(f"agent processes running: {summary['agent_processes']}")
    print(f"agents seen            : {', '.join(summary['agents_seen']) or '(none)'}")
    if summary["unavailable_fields"]:
        print(f"unavailable            : {', '.join(summary['unavailable_fields'])}")

    if all_events:
        print("\n--- what is running ---")
        for event in all_events:
            flag = "persistent" if event["persistent"] else "one-shot  "
            print(
                f"  [{event['agent']}] pid={event['pid']} user={event['user']} "
                f"{flag} {_duration(event['duration_sec'])}"
            )
            print(f"      {event['cmdline_sanitized'][:140]}")

    print(f"\n--- would record {len(new_events)} event(s) ---")
    if not new_events:
        print("  (none new; already-running processes were recorded on an earlier scan)")

    print(f"\n--- would raise {len(alerts)} alert(s) ---")
    for alert in alerts:
        print(f"  [{alert['severity']}] {alert['alert_type']}: {alert['reason']}")
        print(f"      -> {alert['suggested_action']}")
    if not alerts:
        print("  (none)")
    return 0


def _duration(seconds):
    if not seconds:
        return "0s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    return f"{seconds / 3600:.1f}h"


def _status(cfg):
    log_dir = cfg["LOG_DIR"]
    code, output = install._run(["systemctl", "is-active", "agentwatchdog.timer"])
    print(f"timer     {output or 'unknown'}")
    print(f"log dir   {log_dir}")

    for name in ("events.jsonl", "alerts.jsonl"):
        path = os.path.join(log_dir, name)
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                count = sum(1 for _ in fh)
            print(f"{name:<14} {count} record(s)")
        except OSError:
            print(f"{name:<14} (none yet)")

    current = state.load(os.path.join(log_dir, collector.STATE_FILENAME))
    last = current.get("last_summary")
    if last:
        print(f"last scan {json.dumps(last, ensure_ascii=False)}")
    else:
        print("last scan (never)")

    print(f"delivery  {cfg.get('NOTIFY')}")
    return 0


def _agents(cfg):
    fingerprints = agents.load(
        cfg.get("AGENTS_DIR"), enabled=config.get_list(cfg, "ENABLED_AGENTS")
    )
    print(f"{len(fingerprints)} fingerprint(s) in effect\n")
    for fingerprint in sorted(fingerprints, key=lambda fp: fp["id"]):
        verified = "verified" if fingerprint.get("flags_verified") else "best-effort"
        print(f"  {fingerprint['id']:<14} {fingerprint['name']}  [{verified}]")
        print(f"                 comm: {', '.join(fingerprint.get('comms', [])) or '-'}")
    print(
        "\n'best-effort' means the flag table was written from documentation rather "
        "than\nchecked against the binary. Prompts are still redacted either way - "
        "positional\narguments are denied by default. See CONTRIBUTING.md to correct one."
    )
    return 0


def _export(cfg, rest):
    path = rest[0] if rest and not rest[0].startswith("-") else None
    if path:
        export.write(cfg, path, version=__version__)
        print(f"wrote anonymized summary to {path}")
    else:
        print(export.render(cfg, version=__version__))
    return 0


def _install(cfg, rest):
    interval = 60
    if "--interval" in rest:
        try:
            interval = int(rest[rest.index("--interval") + 1])
        except (IndexError, ValueError):
            sys.stderr.write("agentwatchdog: --interval needs a number of seconds\n")
            return 2
    if os.geteuid() != 0:
        sys.stderr.write("agentwatchdog: install needs root\n")
        return 1
    return install.install(cfg, interval=interval)


def _selftest(cfg):
    """Prove on this host that the thing we promise not to do, we do not do."""
    print(f"agentwatchdog {__version__} selftest\n")
    ok = True

    print(f"python            {sys.version.split()[0]}")
    import shutil

    for tool in ("ss", "systemctl", "logrotate"):
        found = shutil.which(tool)
        note = found or "missing (degrades gracefully)"
        print(f"{tool:<18}{note}")

    fingerprints = agents.load(
        cfg.get("AGENTS_DIR"), enabled=config.get_list(cfg, "ENABLED_AGENTS")
    )
    print(f"fingerprints      {len(fingerprints)}")

    key_path = cfg.get("DIGEST_KEY_PATH") or config.DEFAULTS["DIGEST_KEY_PATH"]
    if digest.load_key(key_path) is None:
        print(f"digest key        {key_path} (absent, digests omitted)")
    else:
        print(f"digest key        {key_path} (present)")

    now = int(time.time())
    events, unavailable = collector.observe(cfg, now)
    print(f"agents running    {len(events)}")
    if unavailable:
        print(f"unavailable       {', '.join(unavailable)}")

    print("\nredaction, against every built-in fingerprint:")
    probe = "THIS-IS-A-PRIVATE-PROMPT"
    key = "sk-ant-THIS-IS-A-FAKE-KEY-000000000000"
    for fingerprint in sorted(fingerprints, key=lambda fp: fp["id"]):
        comm = (fingerprint.get("comms") or ["agent"])[0]
        for argv in ([comm, probe], [comm, "exec", probe], [comm, "--model", key]):
            result = redact.sanitize(argv, fingerprint.get("redact"))
            if probe in result or key in result:
                print(f"  FAIL {fingerprint['id']}: {result}")
                ok = False
                break
        else:
            print(f"  ok   {fingerprint['id']}")

    print("\nlive command lines on this host, after redaction:")
    for event in events[:5]:
        leaked = redact.contains_secret(event["cmdline_sanitized"])
        print(f"  {'LEAK' if leaked else 'ok  '} {event['cmdline_sanitized'][:100]}")
        ok = ok and not leaked
    if not events:
        print("  (no agents running right now)")

    print("\n" + ("PASS" if ok else "FAIL - do not install until this passes"))
    return 0 if ok else 1
