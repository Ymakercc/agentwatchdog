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

    parent_limit = config.get_int(context.cfg, "MAX_PER_PARENT_WINDOW", 8)
    for parent, count in sorted(by_parent.items()):
        if count <= parent_limit:
            continue
        tree = procfs.process_tree(parent)
        ancestry = " <- ".join(node["comm"] for node in tree) or "unknown"
        yield Finding(
            type="parent_spawn_storm",
            severity="critical",
            key=f"ppid:{parent}",
            reason=(
                f"process {parent} spawned {count} agents in {minutes:.0f} minutes "
                f"(threshold {parent_limit}); ancestry: {ancestry}"
            ),
            action=(
                f"This is a loop, not a person. Inspect the parent: ps -fp {parent}. "
                "If it is a systemd unit, check its restart policy before restarting it "
                "again."
            ),
            extra={
                "ppid": parent,
                "count": count,
                "window_sec": window,
                "process_tree": tree,
            },
        )
