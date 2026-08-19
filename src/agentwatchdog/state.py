"""Persistent state carried between scans.

The collector is a series of independent one-shot runs on a timer, not a daemon,
so anything it needs to remember across runs lives in one small JSON file:

* ``seen`` — processes already reported, so a long-lived agent produces one event
  rather than one per minute. Keyed by ``pid:starttime_ticks``; the start time is
  what makes the key immune to pid reuse.
* ``invocations`` — recent starts, used by the sliding-window frequency
  detectors. Trimmed to the window on every run.
* ``spawn_streaks`` — per parent process, how many *consecutive* scans have
  found it starting fresh agents. Counting starts within a window undercounts a
  restart loop badly (see :mod:`agentwatchdog.detect.frequency`); counting
  consecutive scans does not.
* ``fork_counter`` — the previous reading of the kernel's cumulative fork count,
  so each scan can derive the host's process-creation rate.
* ``alert_cooldown`` — when each alert last fired, so a stuck condition does not
  page every 60 seconds.
"""

import json
import os
import time

STATE_VERSION = 1


def load(path):
    """Return the stored state, or an empty one if it is missing or corrupt.

    A corrupt state file must not wedge the timer. Losing it costs one duplicate
    event per running agent and one duplicate alert, which is a far better
    failure than a monitor that stops running.
    """
    state = None
    try:
        with open(path, encoding="utf-8") as fh:
            state = json.load(fh)
    except (OSError, ValueError):
        state = None
    if not isinstance(state, dict):
        state = {}
    state.setdefault("version", STATE_VERSION)
    state.setdefault("seen", {})
    state.setdefault("invocations", [])
    state.setdefault("spawn_streaks", {})
    state.setdefault("fork_counter", {})
    state.setdefault("alert_cooldown", {})
    return state


def save(path, state):
    """Write state atomically, so a killed scan cannot leave a truncated file."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh)
    os.replace(tmp, path)


def process_key(pid, starttime_ticks):
    """Return the identity used to tell "still running" from "started again"."""
    return f"{pid}:{starttime_ticks if starttime_ticks is not None else 'x'}"


def prune(state, now, window_sec, cooldown_sec, live_keys):
    """Drop everything the next scan cannot use.

    Without this the state file grows without bound on a long-lived host: the
    cooldown map in particular accumulates an entry per alerting pid forever.
    """
    for key in list(state["seen"]):
        if key not in live_keys:
            del state["seen"][key]

    state["invocations"] = [
        record
        for record in state["invocations"]
        if isinstance(record.get("ts"), int) and now - record["ts"] <= window_sec
    ]

    # An expired cooldown entry has no effect on future decisions, so it is safe
    # to forget. Keep a margin so a scan running slightly late still suppresses.
    horizon = max(cooldown_sec * 2, window_sec)
    for key, last in list(state["alert_cooldown"].items()):
        if not isinstance(last, int) or now - last > horizon:
            del state["alert_cooldown"][key]


def in_cooldown(state, alert_type, key, now, cooldown_sec):
    """Return ``True`` if this alert fired recently enough to stay quiet."""
    last = state["alert_cooldown"].get(f"{alert_type}:{key}", 0)
    return isinstance(last, int) and now - last < cooldown_sec


def mark_fired(state, alert_type, key, now):
    """Record that an alert fired, starting its cooldown."""
    state["alert_cooldown"][f"{alert_type}:{key}"] = now


def record_invocation(state, now, user, ppid, agent_id):
    """Note a newly started agent process for the frequency detectors."""
    state["invocations"].append({"ts": now, "user": user, "ppid": ppid, "agent": agent_id})


def update_spawn_streaks(state, now, parents):
    """Advance each parent's consecutive-scan streak and return the current ones.

    ``parents`` maps a parent pid to a sample of what it started on *this* scan.
    A parent absent from it has its streak dropped, so the count only ever
    describes scans that ran back to back: one gap and the evidence is gone,
    which is the property that makes a long streak mean something.
    """
    streaks = state["spawn_streaks"]
    for key in list(streaks):
        if key not in {str(ppid) for ppid in parents}:
            del streaks[key]

    current = []
    for ppid, sample in parents.items():
        key = str(ppid)
        record = streaks.get(key)
        if not isinstance(record, dict) or not isinstance(record.get("count"), int):
            record = {"count": 0, "first_ts": now}
        record = {
            "count": record["count"] + 1,
            "first_ts": record.get("first_ts", now),
            "last_ts": now,
            "user": sample.get("user"),
            "agent": sample.get("agent"),
        }
        streaks[key] = record
        current.append(dict(record, ppid=ppid))
    return current


def record_fork_count(state, now, value):
    """Store the kernel fork counter and return ``(forks, seconds)`` since last scan.

    Returns ``None`` on the first scan, when the counter is unavailable, and
    after a reboot — the counter restarts at boot, so a decrease is not a rate.
    """
    previous = state.get("fork_counter") or {}
    state["fork_counter"] = {"value": value, "ts": now} if isinstance(value, int) else {}
    if not isinstance(value, int):
        return None
    last_value = previous.get("value")
    last_ts = previous.get("ts")
    if not isinstance(last_value, int) or not isinstance(last_ts, int):
        return None
    elapsed = now - last_ts
    if elapsed <= 0 or value < last_value:
        return None
    return value - last_value, elapsed


def touch(state, summary=None):
    """Stamp the state with the time of this run and its summary."""
    state["updated"] = int(time.time())
    if summary is not None:
        state["last_summary"] = summary
