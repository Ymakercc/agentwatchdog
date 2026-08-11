"""Hand alerts to a local command on stdin.

This is the escape hatch that keeps the project from growing an integration per
chat service. Whatever an operator already uses to get paged — a Telegram bot, a
mail script, a wrapper around their incident tool — can be pointed at from
here without this codebase knowing anything about it.

The command is run with a fixed argument list and **no shell**. That is not
incidental: ``NOTIFY_EXEC_CMD`` comes from a config file, and alert payloads
contain command lines observed on the host. Handing either to a shell would turn
an audit tool into a way to run whatever an agent happened to be invoked with.
"""

import json
import shlex
import subprocess

DEFAULT_TIMEOUT_SEC = 30


def send(cfg, alerts, log_dir):  # noqa: ARG001 - log_dir is part of the notifier contract
    """Run ``NOTIFY_EXEC_CMD``, passing the alerts as JSON on stdin."""
    raw = (cfg.get("NOTIFY_EXEC_CMD") or "").strip()
    if not raw:
        raise ValueError("NOTIFY includes 'exec' but NOTIFY_EXEC_CMD is empty")

    argv = shlex.split(raw)
    if not argv:
        raise ValueError(f"NOTIFY_EXEC_CMD is not a runnable command: {raw!r}")

    payload = json.dumps({"alerts": alerts}, ensure_ascii=False)
    result = subprocess.run(
        argv,
        input=payload,
        text=True,
        capture_output=True,
        timeout=DEFAULT_TIMEOUT_SEC,
        check=False,
        shell=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()[:200]
        raise RuntimeError(f"{argv[0]} exited {result.returncode}: {detail}")
    return result.returncode
