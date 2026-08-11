"""Append alerts to a local JSONL file. The default, and the only one on by default."""

import json
import os

FILENAME = "alerts.jsonl"


def send(cfg, alerts, log_dir):
    """Append each alert as one JSON object per line.

    One object per line rather than a JSON array so the file can be tailed,
    grepped and rotated while it is being written, and so a truncated write
    costs one alert instead of the whole file.
    """
    path = os.path.join(log_dir, FILENAME)
    with open(path, "a", encoding="utf-8") as fh:
        for alert in alerts:
            fh.write(json.dumps(alert, ensure_ascii=False) + "\n")
    return path
