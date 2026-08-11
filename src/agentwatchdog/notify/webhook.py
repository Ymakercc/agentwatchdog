"""POST alerts as JSON to a URL.

Written against ``urllib`` rather than ``requests`` to keep the tool
dependency-free — it has to stay droppable onto a server with nothing but
python3 installed.

Note what this sends: alert records, which name users, pids, working directories
and process ancestry. That is host-private information, so plain HTTP is
refused. If alerts need to leave the machine, they leave it over TLS.
"""

import json
import urllib.error
import urllib.request

USER_AGENT = "agentwatchdog"


def send(cfg, alerts, log_dir):  # noqa: ARG001 - log_dir is part of the notifier contract
    """POST ``{"alerts": [...]}`` to ``NOTIFY_WEBHOOK_URL``."""
    url = (cfg.get("NOTIFY_WEBHOOK_URL") or "").strip()
    if not url:
        raise ValueError("NOTIFY includes 'webhook' but NOTIFY_WEBHOOK_URL is empty")
    if not url.startswith("https://"):
        # Alerts carry usernames, paths and process trees. Refusing rather than
        # warning, because a warning in a timer's output is a warning nobody reads.
        raise ValueError(f"NOTIFY_WEBHOOK_URL must be https, got {url.split(':', 1)[0]!r}")

    try:
        timeout = int(cfg.get("NOTIFY_WEBHOOK_TIMEOUT_SEC", 10))
    except (TypeError, ValueError):
        timeout = 10

    body = json.dumps({"alerts": alerts}, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(  # noqa: S310 - scheme is checked above
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        return response.status
