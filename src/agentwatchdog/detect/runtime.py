"""Agents that have been running far longer than they should have been.

The failure this catches is mundane and expensive: a non-interactive agent that
hung — waiting on a network call, a prompt nobody will answer, a lock — and will
sit there until someone notices. On a server, nobody notices.

Sessions the fingerprint or the operator marked persistent are exempt. An
interactive session someone is sitting in front of is not a hung process, and
treating it as one makes this detector useless on exactly the hosts it is for.
"""

from .. import config
from .base import Finding


def detect(context):
    limit = config.get_int(context.cfg, "MAX_RUNTIME_SEC", 14400)
    if limit <= 0:
        return

    for event in context.processes:
        if event.get("persistent"):
            continue
        duration = event.get("duration_sec")
        if not duration or duration <= limit:
            continue

        hours = duration / 3600.0
        yield Finding(
            type="long_running_process",
            severity="warning",
            key=f"pid{event.get('pid')}:{event.get('starttime_ticks')}",
            reason=(
                f"{event.get('agent_name')} process has been running for {hours:.1f}h "
                f"without being marked as a persistent session (limit "
                f"{limit / 3600.0:.1f}h)"
            ),
            action=(
                f"Check whether it is stuck: ps -fp {event.get('pid')}. If this is a "
                "legitimate long-lived session, add a matching pattern to "
                "PERSISTENT_REGEX so it stops being reported."
            ),
            extra={
                "agent": event.get("agent"),
                "user": event.get("user"),
                "pid": event.get("pid"),
                "ppid": event.get("ppid"),
                "duration_sec": duration,
                "cwd": event.get("cwd"),
                "process_tree": event.get("process_tree"),
            },
        )
