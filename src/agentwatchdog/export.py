"""Anonymized aggregate export.

The event log is deliberately host-private: it names users, pids, working
directories and parent processes. This module produces the opposite — a summary
safe to publish on a status page, paste into a ticket, or ship off the box.

The safety property is enforced by construction rather than by review. The
summary is assembled from scratch into a fixed shape, never by filtering fields
out of an event, so a field added to events later cannot leak here by default.
:func:`assert_anonymous` then re-checks the finished document against a key
allowlist before it is returned, which is also what ``tests/test_export_anon.py``
asserts on.
"""

import json
import os
import re
import time

from . import agents, config, procfs

SCHEMA = "agentwatchdog-summary/1"

DAY = 86400
HOUR = 3600

#: Every key permitted anywhere in the exported document. Anything else is a bug
#: in this module, and :func:`assert_anonymous` refuses to return the document.
ALLOWED_KEYS = frozenset(
    {
        "schema",
        "generated_at",
        "generated_iso",
        "monitor_version",
        "interval_hint_sec",
        "privacy",
        "current",
        "active_sessions",
        "agent_processes",
        "host_under_load",
        "totals",
        "events_24h",
        "events_7d",
        "alerts_24h",
        "alerts_7d",
        "invocations_by_hour",
        "events_by_day",
        "alerts_by_type",
        "alerts_by_severity",
        "agents_seen",
        "h",
        "d",
        "c",
    }
)

#: Values are counts, labels and timestamps. Anything that looks like a path, an
#: address or a long opaque string has no business in an anonymous aggregate.
_FORBIDDEN_VALUE_RE = re.compile(
    r"(/[A-Za-z0-9._\-]+/)"  # filesystem paths
    r"|(\b\d{1,3}(\.\d{1,3}){3}\b)"  # IPv4 addresses
    r"|(@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})"  # email-ish
)


def read_jsonl(path):
    """Return the parsable records in a JSONL file; skip anything malformed."""
    records = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        pass
    return records


def _within(records, now, seconds):
    return [r for r in records if isinstance(r.get("ts"), int) and now - r["ts"] <= seconds]


def _hour_buckets(records, now, count=24):
    buckets = []
    base = now - (now % HOUR)
    for offset in range(count - 1, -1, -1):
        start = base - offset * HOUR
        buckets.append(
            {
                "h": time.strftime("%Y-%m-%dT%H:00", time.localtime(start)),
                "c": sum(1 for r in records if start <= r["ts"] < start + HOUR),
            }
        )
    return buckets


def _day_buckets(records, now, count=7):
    local = time.localtime(now)
    midnight = now - (local.tm_hour * HOUR + local.tm_min * 60 + local.tm_sec)
    buckets = []
    for offset in range(count - 1, -1, -1):
        start = midnight - offset * DAY
        buckets.append(
            {
                "d": time.strftime("%Y-%m-%d", time.localtime(start)),
                "c": sum(1 for r in records if start <= r["ts"] < start + DAY),
            }
        )
    return buckets


def _tally(records, key, default="unknown"):
    counts = {}
    for record in records:
        label = str(record.get(key, default))
        counts[label] = counts.get(label, 0) + 1
    return counts


def _current_state(cfg, now):
    """Count what is running right now, without recording anything about it."""
    fingerprints = agents.load(
        cfg.get("AGENTS_DIR"), enabled=config.get_list(cfg, "ENABLED_AGENTS")
    )
    persistent = 0
    total = 0
    for info in procfs.snapshot(now).values():
        fingerprint = agents.identify(info, fingerprints)
        if fingerprint is None:
            continue
        total += 1
        if agents.is_persistent(info, fingerprint):
            persistent += 1

    cores = os.cpu_count() or 1
    _, load5, _ = procfs.load_avg()
    factor = config.get_float(cfg, "LOAD_FACTOR", 1.5)
    under_load = None if load5 is None else bool(load5 > cores * factor)

    return {
        "active_sessions": persistent,
        "agent_processes": total,
        "host_under_load": under_load,
    }


def build(cfg, now=None, version="0"):
    """Return the anonymized summary document."""
    now = int(time.time()) if now is None else now
    log_dir = cfg["LOG_DIR"]
    events = read_jsonl(os.path.join(log_dir, "events.jsonl"))
    alerts = read_jsonl(os.path.join(log_dir, "alerts.jsonl"))

    events_24h = _within(events, now, DAY)
    events_7d = _within(events, now, 7 * DAY)
    alerts_24h = _within(alerts, now, DAY)
    alerts_7d = _within(alerts, now, 7 * DAY)

    summary = {
        "schema": SCHEMA,
        "generated_at": now,
        "generated_iso": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(now)),
        "monitor_version": version,
        "interval_hint_sec": 60,
        "current": _current_state(cfg, now),
        "totals": {
            "events_24h": len(events_24h),
            "events_7d": len(events_7d),
            "alerts_24h": len(alerts_24h),
            "alerts_7d": len(alerts_7d),
        },
        "invocations_by_hour": _hour_buckets(events_24h, now),
        "events_by_day": _day_buckets(events_7d, now),
        "alerts_by_type": _tally(alerts_7d, "alert_type"),
        "alerts_by_severity": _tally(alerts_7d, "severity", default="info"),
        # Which agents are in use is a fact about tooling, not about people.
        "agents_seen": _tally(events_7d, "agent"),
        "privacy": "anonymized aggregate only - no users, pids, paths or command lines",
    }
    assert_anonymous(summary)
    return summary


def assert_anonymous(document):
    """Raise if the document contains anything that could identify a host or user.

    This runs in production, not only in tests. An export that cannot be proven
    anonymous is not published at all.
    """
    _walk(document, ())


def _walk(node, path):
    if isinstance(node, dict):
        for key, value in node.items():
            if key not in ALLOWED_KEYS and not _is_label_key(path):
                raise ValueError(f"export contains disallowed key {'.'.join((*path, key))!r}")
            _walk(value, (*path, key))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _walk(value, (*path, str(index)))
    elif isinstance(node, str) and _FORBIDDEN_VALUE_RE.search(node):
        raise ValueError(f"export contains an identifying value at {'.'.join(path)!r}")


def _is_label_key(path):
    """Return True where the *keys* are data: alert types, severities, agent ids.

    These maps are keyed by labels the tool itself defines, so their keys cannot
    be enumerated in the allowlist. Their values are counts and are still walked.
    """
    return bool(path) and path[-1] in ("alerts_by_type", "alerts_by_severity", "agents_seen")


def render(cfg, now=None, version="0"):
    """Return the summary as the JSON text that gets written or printed."""
    return json.dumps(build(cfg, now=now, version=version), ensure_ascii=False, indent=2)


def write(cfg, path, now=None, version="0"):
    """Write the summary atomically to ``path``."""
    text = render(cfg, now=now, version=version)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text + "\n")
    os.replace(tmp, path)
