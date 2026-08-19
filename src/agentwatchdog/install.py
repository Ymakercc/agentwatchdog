"""Install and remove the systemd timer, config and log rotation.

Bundling this into the tool rather than shipping a distro package is a
deliberate trade: the audience is people putting this on a server they already
have, over SSH, and ``agentwatchdog install`` is a shorter conversation than a
repository and a package name. Every step is idempotent, because the realistic
usage is running it again after an upgrade without thinking about it.

The unit is hardened as far as the job allows. It reads the whole of ``/proc``,
so it runs as root, but it needs to write exactly one directory and never needs
to gain privileges.
"""

import os
import shutil
import subprocess
import sys

from . import config, digest

SERVICE_PATH = "/etc/systemd/system/agentwatchdog.service"
TIMER_PATH = "/etc/systemd/system/agentwatchdog.timer"
LOGROTATE_PATH = "/etc/logrotate.d/agentwatchdog"

SERVICE_TEMPLATE = """\
[Unit]
Description=agentwatchdog - one scan for AI coding agent processes
Documentation=https://github.com/Ymakercc/agentwatchdog
After=multi-user.target

[Service]
Type=oneshot
ExecStart={executable} scan
# Never compete with the workload being observed.
Nice=10
IOSchedulingClass=idle
# Reads all of /proc; writes only its own log directory.
ProtectSystem=strict
ReadWritePaths={log_dir}
ProtectHome=read-only
NoNewPrivileges=yes
PrivateTmp=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
"""

TIMER_TEMPLATE = """\
[Unit]
Description=Run agentwatchdog every {interval}s

[Timer]
{schedule}
# systemd is allowed to defer a timer to batch wakeups; at the default accuracy
# that alone stretches a 60s interval to roughly 65s.
AccuracySec=1s
Unit=agentwatchdog.service

[Install]
WantedBy=timers.target
"""


def timer_schedule(interval):
    """Return the activation directive for a scan every ``interval`` seconds.

    ``OnUnitActiveSec`` measures from the last activation and accumulates
    whatever systemd added on top, so the interval it produces is longer than
    the one asked for and drifts around the clock: measured over eight days on a
    real host, ``OnUnitActiveSec=60`` with the previous ``AccuracySec=5s`` ran
    1334 times a day instead of 1440. That 7% is not cosmetic — the detectors
    count in scans, and short-lived agent processes are missed in proportion.

    A calendar schedule is anchored to the clock, so the interval holds. It only
    expresses intervals that divide a minute or an hour evenly; anything else
    falls back to the relative form, which is at least no longer blurred by the
    accuracy window.
    """
    # A repetition equal to the whole field is not a valid step ("0/60" is
    # rejected outright), so the exact minute and hour are spelled out.
    if interval == 60:
        return "OnCalendar=*:*:00"
    if interval == 3600:
        return "OnCalendar=*:00:00"
    if 0 < interval < 60 and 60 % interval == 0:
        return f"OnCalendar=*:*:0/{interval}"
    minutes = interval // 60
    if 60 < interval < 3600 and interval % 60 == 0 and 60 % minutes == 0:
        return f"OnCalendar=*:0/{minutes}:00"
    return f"OnBootSec={interval}\nOnUnitActiveSec={interval}"


LOGROTATE_TEMPLATE = """\
# Rotated daily, kept for a month, and also cut at 50M so one noisy day cannot
# fill the disk of the host we are supposed to be looking after.
{log_dir}/*.jsonl {log_dir}/agentwatchdog.log {{
    daily
    rotate 30
    maxsize 50M
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
}}
"""


def config_template():
    """Render a commented config file from the defaults, so the two cannot drift."""
    lines = [
        "# agentwatchdog configuration.",
        "# Re-read on every scan; there is nothing to reload after editing.",
        "# Every setting below is shown at its default value.",
        "",
        "# Accounts expected to run agents here, space separated. Empty disables",
        "# the check - set it once you know what belongs on this host.",
        "",
    ]
    for key, value in config.DEFAULTS.items():
        lines.append(f"{key}={value}")
    return "\n".join(lines) + "\n"


def _executable():
    """Return the command systemd should run.

    Prefers the installed console script; falls back to the interpreter and
    module so a checkout or a single-file drop-in also produces a working unit.
    """
    found = shutil.which("agentwatchdog")
    if found:
        return found
    script = os.path.realpath(sys.argv[0])
    if script.endswith(".py"):
        return f"{sys.executable} {script}"
    return f"{sys.executable} -m agentwatchdog"


def _run(argv):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, str(exc)
    return result.returncode, (result.stdout + result.stderr).strip()


def install(cfg, interval=60, config_path=None, out=print):
    """Create the log directory, config, units and rotation, then start the timer."""
    log_dir = cfg["LOG_DIR"]
    config_path = config_path or config.CONFIG_PATH

    out(f"log directory   {log_dir}")
    os.makedirs(log_dir, exist_ok=True)
    # Alert and event records name users, paths and process ancestry. Not world
    # readable, on a host where the point is that other accounts exist.
    os.chmod(log_dir, 0o750)  # noqa: S103 - root-owned and group-readable, not world

    if os.path.exists(config_path):
        out(f"config          {config_path} (kept, not overwritten)")
    else:
        with open(config_path, "w", encoding="utf-8") as fh:
            fh.write(config_template())
        os.chmod(config_path, 0o640)
        out(f"config          {config_path} (written)")

    executable = _executable()
    with open(SERVICE_PATH, "w", encoding="utf-8") as fh:
        fh.write(SERVICE_TEMPLATE.format(executable=executable, log_dir=log_dir))
    out(f"service         {SERVICE_PATH}")

    with open(TIMER_PATH, "w", encoding="utf-8") as fh:
        fh.write(TIMER_TEMPLATE.format(interval=interval, schedule=timer_schedule(interval)))
    out(f"timer           {TIMER_PATH} (every {interval}s)")

    key_path = cfg.get("DIGEST_KEY_PATH") or config.DEFAULTS["DIGEST_KEY_PATH"]
    if digest.create_key(key_path) is None:
        out(f"digest key      {key_path} (could not be created; digests disabled)")
    else:
        out(f"digest key      {key_path} (0600, never leaves this host)")

    with open(LOGROTATE_PATH, "w", encoding="utf-8") as fh:
        fh.write(LOGROTATE_TEMPLATE.format(log_dir=log_dir))
    out(f"log rotation    {LOGROTATE_PATH}")

    code, message = _run(["systemctl", "daemon-reload"])
    if code != 0:
        out(f"\nsystemctl daemon-reload failed: {message}")
        out("Units are written; start them yourself once systemd is available.")
        return 1
    code, message = _run(["systemctl", "enable", "--now", "agentwatchdog.timer"])
    if code != 0:
        out(f"\nsystemctl enable failed: {message}")
        return 1

    out("\nInstalled. Nothing is sent anywhere: alerts go to")
    out(f"  {os.path.join(log_dir, 'alerts.jsonl')}")
    out("until NOTIFY says otherwise.\n")
    out("  agentwatchdog status     what it has seen so far")
    out(f"  {config_path}   thresholds and delivery")
    return 0


def uninstall(cfg, purge=False, config_path=None, out=print):
    """Stop and remove the timer. Keeps logs and config unless ``purge``."""
    config_path = config_path or config.CONFIG_PATH
    _run(["systemctl", "disable", "--now", "agentwatchdog.timer"])

    for path in (TIMER_PATH, SERVICE_PATH, LOGROTATE_PATH):
        if os.path.exists(path):
            os.remove(path)
            out(f"removed         {path}")
    _run(["systemctl", "daemon-reload"])

    if purge:
        log_dir = cfg["LOG_DIR"]
        if os.path.isdir(log_dir):
            shutil.rmtree(log_dir, ignore_errors=True)
            out(f"removed         {log_dir}")
        key_path = cfg.get("DIGEST_KEY_PATH") or config.DEFAULTS["DIGEST_KEY_PATH"]
        for path in (config_path, key_path):
            if os.path.exists(path):
                os.remove(path)
                out(f"removed         {path}")
    else:
        out(f"kept            {cfg['LOG_DIR']} and {config_path} (use --purge to remove)")
    return 0
