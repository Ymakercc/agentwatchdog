"""Agent processes consuming an abnormal share of the host.

``pcpu`` is the process's average CPU over its whole lifetime, not an
instantaneous sample. That is deliberate — it is the measure that distinguishes
a process which has been pegged for an hour from one that is briefly busy — but
it has a consequence: a process that is two seconds old and spent both of them
starting up reads as 100%. Every agent looks like that at launch.

So the CPU check does not apply until a process has been alive long enough for
the average to mean something. Without that floor this detector fires on
essentially every agent invocation, and an operator learns to ignore it.
"""

from .. import config
from .base import Finding


def detect(context):
    cpu_limit = config.get_float(context.cfg, "CPU_ALERT_PCT", 85)
    mem_limit = config.get_float(context.cfg, "MEM_ALERT_PCT", 50)
    rss_limit_kb = config.get_int(context.cfg, "RSS_ALERT_MB", 2000) * 1024
    min_age = config.get_int(context.cfg, "MIN_CPU_SAMPLE_SEC", 300)

    for event in context.processes:
        pid = event.get("pid")
        pcpu = event.get("pcpu")
        duration = event.get("duration_sec") or 0

        if pcpu is not None and pcpu > cpu_limit and duration >= min_age:
            minutes = duration / 60.0
            yield Finding(
                type="high_cpu",
                severity="warning",
                key=f"pid{pid}:{event.get('starttime_ticks')}",
                reason=(
                    f"{event.get('agent_name')} has averaged {pcpu:.0f}% CPU over "
                    f"{minutes:.0f} minutes (threshold {cpu_limit:.0f}%)"
                ),
                action=(
                    f"Sustained rather than a burst, so look at what it is doing: top -p {pid}."
                ),
                extra={
                    "agent": event.get("agent"),
                    "user": event.get("user"),
                    "pid": pid,
                    "ppid": event.get("ppid"),
                    "pcpu": pcpu,
                    "duration_sec": duration,
                },
            )

        rss_kb = event.get("rss_kb") or 0
        pmem = event.get("pmem")
        over_share = pmem is not None and pmem > mem_limit
        over_absolute = rss_limit_kb > 0 and rss_kb > rss_limit_kb
        if over_share or over_absolute:
            yield Finding(
                type="high_mem",
                severity="warning",
                key=f"pid{pid}:{event.get('starttime_ticks')}",
                reason=(
                    f"{event.get('agent_name')} is holding {rss_kb // 1024} MB "
                    f"({pmem or 0:.0f}% of host memory)"
                ),
                action=(
                    f"Check whether it is still growing: ps -o rss,vsz -p {pid}. On a "
                    "host without swap this is what precedes the OOM killer."
                ),
                extra={
                    "agent": event.get("agent"),
                    "user": event.get("user"),
                    "pid": pid,
                    "rss_mb": rss_kb // 1024,
                    "pmem": pmem,
                },
            )
