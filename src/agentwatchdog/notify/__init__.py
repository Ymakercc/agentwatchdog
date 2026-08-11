"""Where alerts go.

Only ``jsonl`` is on by default, and it writes to a file on the same host. That
is the whole default configuration: **nothing leaves the machine unless someone
asks for it**. A monitoring tool that phones somewhere out of the box is one
nobody should install on a server they care about, and this one reads process
command lines for a living.

The other two exist so an operator can wire alerts into whatever they already
run — a Telegram bot, PagerDuty, an internal webhook — without this project
growing an integration for each. ``exec`` hands the alert to a command on
stdin; ``webhook`` posts it. Both take a target the operator has to supply.

A failing notifier is logged and stepped over. Losing an alert is bad; losing
the scan that would have produced the next hundred is worse.
"""

from .. import config
from . import command, jsonl, webhook

NOTIFIERS = {
    "jsonl": jsonl.send,
    "exec": command.send,
    "webhook": webhook.send,
}


def dispatch(cfg, alerts, log_dir, on_error=None):
    """Deliver ``alerts`` through every configured notifier.

    Returns the ids that ran successfully. An unknown id in ``NOTIFY`` is
    reported rather than ignored, since a typo there means alerts silently go
    nowhere — the exact failure a monitor must not have.
    """
    if not alerts:
        return []

    delivered = []
    for name in config.get_list(cfg, "NOTIFY"):
        sender = NOTIFIERS.get(name)
        if sender is None:
            _report(on_error, f"unknown notifier {name!r}; alerts not delivered through it")
            continue
        try:
            sender(cfg, alerts, log_dir)
        except Exception as exc:  # noqa: BLE001 - a notifier must not kill the scan
            _report(on_error, f"notifier {name!r} failed: {exc}")
            continue
        delivered.append(name)
    return delivered


def _report(on_error, message):
    if on_error is not None:
        on_error(message)


__all__ = ["NOTIFIERS", "dispatch"]
