"""Agents piling onto a host that is already struggling.

None of the individual processes has to be misbehaving for this to matter. The
case it catches is several one-shot agents landing at once — a cron fan-out, a
CI matrix, a person retrying — on a box that is also serving something else.
Each looks reasonable alone; together they are why the service got slow.

The predecessor to this detector asked systemd whether a specific set of
services on the author's own machine were healthy. That is not a thing anyone
else can use. Load average against CPU count says the same thing about any host
and needs no configuration to be roughly right.

Persistent sessions are excluded: an idle interactive session sitting open is
not contributing to load, and counting it would make this fire on any host where
someone left a terminal attached.
"""

from .. import config
from .base import Finding


def detect(context):
    if context.load5 is None:
        return

    factor = config.get_float(context.cfg, "LOAD_FACTOR", 1.5)
    threshold = (context.cores or 1) * factor
    if context.load5 <= threshold:
        return

    concurrent = [event for event in context.processes if not event.get("persistent")]
    minimum = config.get_int(context.cfg, "HIGH_LOAD_AGENT_MIN", 3)
    if len(concurrent) < minimum:
        return

    yield Finding(
        type="agents_during_high_load",
        severity="warning",
        # One situation for the host, not one per process involved.
        key="host",
        reason=(
            f"{len(concurrent)} agents running concurrently while the host is loaded "
            f"(load5 {context.load5:.2f} over {context.cores} cores, threshold "
            f"{threshold:.2f})"
        ),
        action=(
            "No single process is necessarily at fault. Consider staggering whatever "
            "schedules these, or capping concurrency, before anything sharing this host "
            "starts timing out."
        ),
        extra={
            "load5": context.load5,
            "cores": context.cores,
            "threshold": round(threshold, 2),
            "concurrent_agents": len(concurrent),
            "agents": sorted({event.get("agent") for event in concurrent if event.get("agent")}),
            "pids": [event.get("pid") for event in concurrent],
        },
    )
