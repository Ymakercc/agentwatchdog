"""One scan: look at the host, decide what is new, decide what is wrong.

This is the module the systemd timer runs. It is deliberately a one-shot rather
than a daemon — a scan that crashes is retried in sixty seconds by something
better at supervision than we are, and there is no long-lived process to leak,
wedge, or have to restart after an upgrade.

The ordering matters in one place. An event is written the first time a process
is *seen*, not while it runs, so a session that stays up for a week produces one
event rather than ten thousand. State carries the set of processes already
reported; :func:`agentwatchdog.state.process_key` is what makes that survive pid
reuse.
"""

import hashlib
import os
import re
import time

from . import agents, config, detect, notify, procfs, redact, state

EVENTS_FILENAME = "events.jsonl"
STATE_FILENAME = "state.json"


def _compile(pattern):
    if not pattern:
        return None
    try:
        return re.compile(pattern)
    except re.error:
        return None


def build_event(info, fingerprint, now, persistent, net_established, unavailable):
    """Assemble the record written for a newly seen agent process.

    The command line is redacted here, before it is ever part of a value that
    could be written or delivered, and checked again afterwards. The digest of
    the raw command line is kept so identical invocations can be correlated
    without storing what they said.
    """
    sanitized = redact.sanitize(info.get("argv") or [], fingerprint.get("redact"))
    if redact.contains_secret(sanitized):
        # Belt and braces. Reaching this means a fingerprint is wrong, and the
        # right response is to lose the detail rather than write the secret.
        sanitized = "<redaction-failed-suppressed>"

    raw = info.get("raw_cmdline")
    digest = hashlib.sha256(raw).hexdigest()[:32] if raw else None

    return {
        "ts": now,
        "datetime": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(now)),
        "kind": "agent_process",
        "agent": fingerprint.get("id"),
        "agent_name": fingerprint.get("name"),
        "pid": info.get("pid"),
        "ppid": info.get("ppid"),
        "user": info.get("user"),
        "uid": info.get("uid"),
        "loginuid": info.get("loginuid"),
        "sessionid": info.get("sessionid"),
        "tty": info.get("tty"),
        "cwd": procfs.read_cwd(info.get("pid")),
        "abs_start": info.get("abs_start"),
        "starttime_ticks": info.get("starttime_ticks"),
        "duration_sec": info.get("duration_sec"),
        "pcpu": info.get("pcpu"),
        "pmem": info.get("pmem"),
        "rss_kb": info.get("rss_kb"),
        "net_established": net_established,
        "persistent": persistent,
        "cmdline_sanitized": sanitized,
        "cmdline_sha256": digest,
        "process_tree": procfs.process_tree(info.get("pid")),
        "unavailable_fields": unavailable,
    }


def observe(cfg, now):
    """Return ``(events, unavailable)`` for every agent process on the host.

    Every agent process is described, whether or not it is new; the caller
    decides which ones are worth recording. The detectors need the full picture
    — concurrency and resource use are properties of what is running now, not of
    what started this minute.
    """
    fingerprints = agents.load(
        cfg.get("AGENTS_DIR"), enabled=config.get_list(cfg, "ENABLED_AGENTS")
    )
    ignore = _compile(cfg.get("IGNORE_REGEX"))
    persistent_extra = _compile(cfg.get("PERSISTENT_REGEX"))

    net_counts = None
    if config.get_bool(cfg, "COLLECT_NET", True):
        net_counts = procfs.established_conn_counts()

    unavailable = []
    if net_counts is None and config.get_bool(cfg, "COLLECT_NET", True):
        unavailable.append("net_established")

    events = []
    for info in procfs.snapshot(now).values():
        if ignore is not None and ignore.search(info.get("args") or ""):
            continue
        fingerprint = agents.identify(info, fingerprints)
        if fingerprint is None:
            continue
        events.append(
            build_event(
                info,
                fingerprint,
                now,
                agents.is_persistent(info, fingerprint, persistent_extra),
                (net_counts or {}).get(info.get("pid")),
                unavailable,
            )
        )
    return events, unavailable


def scan(cfg, now=None, dry_run=False, log=None):
    """Run one scan. Returns a summary dict.

    With ``dry_run`` nothing is written: no events, no alerts, no state, no
    delivery. That makes it safe to run against a production host to see what
    the tool would record before installing it, which is a reasonable thing to
    want to do before letting something read every command line on your server.
    """
    now = int(time.time()) if now is None else now
    log_dir = cfg["LOG_DIR"]
    window = config.get_int(cfg, "WINDOW_SEC", 300)
    cooldown = config.get_int(cfg, "ALERT_COOLDOWN_SEC", 3600)

    events, unavailable = observe(cfg, now)

    state_path = os.path.join(log_dir, STATE_FILENAME)
    current = state.load(state_path)

    new_events = []
    live_keys = set()
    for event in events:
        key = state.process_key(event["pid"], event["starttime_ticks"])
        live_keys.add(key)
        if key in current["seen"]:
            continue
        current["seen"][key] = {"first_ts": now, "user": event["user"], "agent": event["agent"]}
        new_events.append(event)
        if not event["persistent"]:
            state.record_invocation(current, now, event["user"], event["ppid"], event["agent"])

    state.prune(current, now, window, cooldown, live_keys)

    _, load5, _ = procfs.load_avg()
    context = detect.Context(
        now=now,
        cfg=cfg,
        processes=events,
        invocations=current["invocations"],
        cores=os.cpu_count() or 1,
        load5=load5,
    )
    alerts = detect.run(context, current, cooldown)

    summary = {
        "ts": now,
        "agent_processes": len(events),
        "new_events": len(new_events),
        "alerts": len(alerts),
        "window_invocations": len(current["invocations"]),
        "agents_seen": sorted({event["agent"] for event in events}),
        "unavailable_fields": unavailable,
    }

    if dry_run:
        return summary, new_events, alerts, events

    os.makedirs(log_dir, exist_ok=True)
    _append_jsonl(os.path.join(log_dir, EVENTS_FILENAME), new_events)
    notify.dispatch(cfg, alerts, log_dir, on_error=log)

    state.touch(current, summary)
    state.save(state_path, current)

    if log is not None:
        log(f"scan ok: {summary}")
    return summary, new_events, alerts, events


def _append_jsonl(path, records):
    if not records:
        return
    import json

    with open(path, "a", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
