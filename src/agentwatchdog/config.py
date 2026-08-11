"""Configuration loading.

The config file is a flat ``KEY=VALUE`` text file, deliberately not YAML or TOML:
it has to be editable over a bare SSH session with ``vi`` and parsable with no
third-party libraries. It is re-read on every run, so changing a threshold does
not require reloading anything.

Values are read with the ``get_*`` helpers rather than accessed directly, so a
malformed line in the file degrades to the default instead of crashing the timer.
"""

import os

CONFIG_PATH = "/etc/agentwatchdog.conf"

#: Every setting the tool understands, with its default.
#:
#: Defaults are chosen so that a fresh install on an unknown host is quiet and
#: safe: no outbound delivery, no user allow-list (so no false "unexpected user"
#: alerts), and thresholds loose enough not to cry wolf on a busy machine.
DEFAULTS = {
    # --- what counts as an agent ---------------------------------------------
    # Directory of extra fingerprint files, merged over the built-in ones.
    "AGENTS_DIR": "/etc/agentwatchdog/agents.d",
    # Space-separated agent ids to watch; empty means "every known agent".
    "ENABLED_AGENTS": "",
    # Processes whose command line matches this regex are skipped entirely.
    "IGNORE_REGEX": "",
    # Command lines matching this are treated as legitimate long-lived sessions
    # and exempted from the runtime and frequency detectors. Interactive shells
    # and SDK-driven sessions belong here.
    "PERSISTENT_REGEX": "",
    # Accounts expected to run agents here. Empty disables the check entirely,
    # which is the right default: on an unknown host we have no basis to call
    # any account unexpected, and a monitor that cries wolf gets switched off.
    "ALLOWED_USERS": "",
    # --- detection thresholds ------------------------------------------------
    "MAX_RUNTIME_SEC": "14400",  # 4h; a non-interactive agent past this is hung
    "WINDOW_SEC": "300",  # sliding window for the frequency detectors
    "MAX_PER_USER_WINDOW": "10",
    "MAX_PER_PARENT_WINDOW": "8",
    "CPU_ALERT_PCT": "85",
    "MEM_ALERT_PCT": "50",
    "RSS_ALERT_MB": "2000",
    "ALERT_COOLDOWN_SEC": "3600",  # minimum gap before re-firing the same alert
    # Host is "under load" when loadavg(5m) exceeds cores * LOAD_FACTOR.
    "LOAD_FACTOR": "1.5",
    # Concurrent non-persistent agents needed to alert while under load.
    "HIGH_LOAD_AGENT_MIN": "3",
    # --- collection ----------------------------------------------------------
    # Established-connection counts per process. Cheap, but needs `ss`.
    "COLLECT_NET": "1",
    # --- output --------------------------------------------------------------
    # Comma-separated notifier ids. "jsonl" writes alerts.jsonl locally and is
    # the only one enabled by default: nothing leaves the host unless asked.
    "NOTIFY": "jsonl",
    "NOTIFY_EXEC_CMD": "",  # command receiving the alert JSON on stdin
    "NOTIFY_WEBHOOK_URL": "",  # endpoint receiving a JSON POST
    "NOTIFY_WEBHOOK_TIMEOUT_SEC": "10",
    "LOG_DIR": "/var/log/agentwatchdog",
}

#: Settings renamed since the tool's pre-release ancestor. Old names keep working.
ALIASES = {
    "MAX_PER_USER_5MIN": "MAX_PER_USER_WINDOW",
    "MAX_PER_PARENT_5MIN": "MAX_PER_PARENT_WINDOW",
}


def load(path=None):
    """Return the effective configuration as a ``dict`` of strings.

    An unreadable or missing config file is not an error: the defaults are a
    working configuration. A malformed line is skipped with a warning rather
    than aborting the scan, because this runs unattended on a timer.
    """
    if path is None:
        path = os.environ.get("AGENTWATCHDOG_CONFIG", CONFIG_PATH)
    cfg = dict(DEFAULTS)
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if not key:
                    continue
                cfg[ALIASES.get(key, key)] = value
    except FileNotFoundError:
        pass
    except OSError as exc:
        # Degrade to defaults rather than leaving the host unmonitored.
        import sys

        sys.stderr.write(f"agentwatchdog: cannot read {path}: {exc}\n")
    return cfg


def get_int(cfg, key, default=0):
    """Read an integer setting, falling back to ``default`` if it is malformed."""
    try:
        return int(str(cfg.get(key, default)).strip())
    except (TypeError, ValueError):
        return int(default)


def get_float(cfg, key, default=0.0):
    """Read a float setting, falling back to ``default`` if it is malformed."""
    try:
        return float(str(cfg.get(key, default)).strip())
    except (TypeError, ValueError):
        return float(default)


def get_bool(cfg, key, default=False):
    """Read a boolean setting. Accepts 1/true/yes/on, case-insensitively."""
    raw = str(cfg.get(key, default)).strip().lower()
    return raw in ("1", "true", "yes", "on")


def get_list(cfg, key):
    """Read a whitespace- or comma-separated setting as a list of strings."""
    raw = str(cfg.get(key, "") or "")
    return [item for item in raw.replace(",", " ").split() if item]
