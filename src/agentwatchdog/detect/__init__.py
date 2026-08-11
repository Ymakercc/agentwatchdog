"""Detectors: turn a scan into a short list of things worth waking someone for.

A detector is a plain function over a :class:`Context` that yields
:class:`Finding` objects. It does not know about cooldowns, log files, state or
delivery — the runner in this module applies all of that. Two reasons:

* A detector becomes testable by calling it with a hand-built context and
  reading what comes back, which is why ``tests/test_detect.py`` needs no
  filesystem and no clock.
* Suppression policy stays in one place. Getting it wrong in one detector out
  of six is how a monitor ends up firing every sixty seconds until someone
  turns it off for good.
"""

import time

from .. import state
from . import frequency, identity, load, resource, runtime
from .base import Context, Finding

#: Order determines the order alerts appear in a scan's output. Identity first:
#: an unexpected account is the finding an operator should read before the
#: resource noise it probably also generated.
DETECTORS = (
    identity.detect,
    frequency.detect,
    runtime.detect,
    resource.detect,
    load.detect,
)


def run(context, current_state, cooldown_sec):
    """Return the alerts to record, applying suppression.

    A finding still in cooldown is dropped silently rather than downgraded or
    counted, because the condition it describes is already represented by the
    alert that started the cooldown.
    """
    alerts = []
    for detector in DETECTORS:
        for finding in detector(context) or ():
            if state.in_cooldown(
                current_state, finding.type, finding.key, context.now, cooldown_sec
            ):
                continue
            state.mark_fired(current_state, finding.type, finding.key, context.now)
            alerts.append(materialize(finding, context.now))
    return alerts


def materialize(finding, now):
    """Render a finding as the alert record that gets written and delivered."""
    alert = {
        "ts": now,
        "datetime": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(now)),
        "alert_type": finding.type,
        "severity": finding.severity,
        "reason": finding.reason,
        "suggested_action": finding.action,
    }
    alert.update(finding.extra)
    return alert


__all__ = ["Context", "DETECTORS", "Finding", "materialize", "run"]
