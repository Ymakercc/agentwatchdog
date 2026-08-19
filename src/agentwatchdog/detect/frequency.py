"""Agents being started faster than any human is starting them.

Two shapes, and the distinction matters for what an operator does next:

``user_high_frequency``
    One account is starting a lot of agents. Could be a busy person, could be a
    script in a loop. Worth a look.
``parent_spawn_storm``
    One *parent process* is starting them, which no human does — it is a
    supervisor restarting a crashing unit, or a loop with no backoff. This is
    the expensive one: it will keep going all night and bill for every attempt.
    Reported as critical, with the ancestry, because the agent process is the
    symptom and the parent is the bug.

Only non-persistent starts are counted. A long-lived session that the collector
sees on every scan is one invocation, not one per minute.

Counting starts inside a window cannot find the storm it was written for
-------------------------------------------------------------------------
A start is only counted if the process was still alive when a scan looked. In a
serial restart loop exactly one instance is alive at a time, so a scan can
contribute at most one start, and a 300s window holding five 60s scans can never
count more than five — below any threshold worth setting, no matter how fast the
loop actually is. Measured on a real host: a loop restarting every two seconds
performs 150 starts in five minutes and is counted as five.

So the storm is found by *consecutive scans* instead. A parent that has started
a fresh agent on every one of the last N scans is looping, and that holds however
short-lived the individual attempts are, because it does not depend on catching
any particular one of them. The window count is kept as well: it still finds the
other shape, a parent firing off many agents at once that all stay alive.

Both are sampled signals, and a loop whose attempts die between scans can evade
both. The kernel's cumulative fork count does not miss those, so the host's
process-creation rate is attached to the alert as corroboration — it cannot be
attributed to a particular parent, which is why it informs rather than fires.
"""

from .. import config, procfs
from .base import Finding


def detect(context):
    window = config.get_int(context.cfg, "WINDOW_SEC", 300)
    minutes = window / 60.0

    by_user = {}
    by_parent = {}
    for record in context.invocations:
        user = record.get("user")
        parent = record.get("ppid")
        if user:
            by_user[user] = by_user.get(user, 0) + 1
        if parent:
            by_parent[parent] = by_parent.get(parent, 0) + 1

    user_limit = config.get_int(context.cfg, "MAX_PER_USER_WINDOW", 10)
    for user, count in sorted(by_user.items()):
        if count <= user_limit:
            continue
        yield Finding(
            type="user_high_frequency",
            severity="warning",
            key=f"user:{user}",
            reason=(
                f"account {user!r} started {count} agents in {minutes:.0f} minutes "
                f"(threshold {user_limit})"
            ),
            action=(
                "Check whether a script is looping. Sustained at this rate the API "
                "spend is the thing to worry about, not the process count."
            ),
            extra={"user": user, "count": count, "window_sec": window},
        )

    yield from _spawn_storms(context, by_parent, window)


def _spawn_storms(context, by_parent, window):
    """Yield one finding per parent that is looping, by streak or by volume."""
    parent_limit = config.get_int(context.cfg, "MAX_PER_PARENT_WINDOW", 8)
    streak_limit = config.get_int(context.cfg, "MIN_SPAWN_STREAK", 3)

    streaks = {}
    if streak_limit > 0:
        for record in context.spawn_streaks or ():
            count = record.get("count") or 0
            span = (record.get("last_ts") or 0) - (record.get("first_ts") or 0)
            # A streak spanning far more than the window is not consecutive in any
            # useful sense: the timer was stopped, or the host was asleep.
            if count >= streak_limit and span <= max(window, count * 60):
                streaks[record.get("ppid")] = record

    for parent in sorted(set(streaks) | {p for p, c in by_parent.items() if c > parent_limit}):
        streak = streaks.get(parent)
        counted = by_parent.get(parent, 0)
        tree = procfs.process_tree(parent)
        ancestry = " <- ".join(node["comm"] for node in tree) or "unknown"

        if streak:
            scans = streak["count"]
            reason = (
                f"process {parent} has started a new agent on {scans} consecutive scans "
                f"(threshold {streak_limit}); ancestry: {ancestry}. Only {counted} "
                f"start{'' if counted == 1 else 's'} could be counted directly — attempts "
                "that finish between scans are not visible, so the real rate is higher"
            )
        else:
            reason = (
                f"process {parent} spawned {counted} agents in {window / 60.0:.0f} minutes "
                f"(threshold {parent_limit}); ancestry: {ancestry}"
            )

        extra = {
            "ppid": parent,
            "count": counted,
            "consecutive_scans": streak["count"] if streak else 1,
            "window_sec": window,
            "process_tree": tree,
        }
        if streak and streak.get("agent"):
            extra["agent"] = streak["agent"]
        if streak and streak.get("user"):
            extra["user"] = streak["user"]
        if context.fork_rate is not None:
            # Corroboration, not evidence: this counts every fork on the host.
            extra["host_fork_rate_per_sec"] = round(context.fork_rate, 2)

        yield Finding(
            type="parent_spawn_storm",
            severity="critical",
            key=f"ppid:{parent}",
            reason=reason,
            action=(
                f"This is a loop, not a person. Inspect the parent: ps -fp {parent}. "
                "If it is a systemd unit, check its restart policy before restarting it "
                "again."
            ),
            extra=extra,
        )
