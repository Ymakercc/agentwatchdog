"""Read process facts from ``/proc``.

Everything the collector knows comes from this module, and this module reads
only ``/proc``. Two consequences are load-bearing:

* **No subprocess is required.** An earlier version of this code shelled out to
  ``ps`` for its snapshot, which made the tool blind on hosts without procps and
  impossible to test without live processes. Deriving the same fields from
  ``/proc`` directly removes both problems.
* **``/proc/PID/environ`` is never opened.** Not on any code path, not behind a
  flag. That file is where API keys live; see SECURITY.md.

``PROC`` is a module-level constant rather than a parameter threaded through
every call, so tests can point the whole module at a fixture tree in one place.
"""

import os
import pwd
import re
import shutil
import subprocess

#: Root of the proc filesystem. Overridable for tests and offline analysis.
PROC = os.environ.get("AGENTWATCHDOG_PROC_ROOT", "/proc")

CLK_TCK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
PAGE_SIZE = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096

_UID_CACHE = {}


def _path(pid, *parts):
    return os.path.join(PROC, str(pid), *parts)


def _read_text(path):
    """Return the contents of ``path``, or ``None`` if it cannot be read.

    Processes exit while we are walking them; a vanished pid is normal operation,
    not an error worth propagating.
    """
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def read_comm(pid):
    """Return the process's ``comm`` (the truncated executable name)."""
    text = _read_text(_path(pid, "comm"))
    return text.strip() if text else ""


def read_cmdline(pid):
    """Return ``(argv, raw_bytes)`` for a process, or ``(None, None)``.

    ``raw_bytes`` is kept only long enough to hash it. Kernel threads and
    zombies have an empty cmdline, which is reported as ``(None, None)``.
    """
    try:
        with open(_path(pid, "cmdline"), "rb") as fh:
            raw = fh.read()
    except OSError:
        return None, None
    if not raw:
        return None, None
    argv = [part.decode("utf-8", "replace") for part in raw.split(b"\x00") if part != b""]
    return argv, raw


def read_line(path):
    """Return the stripped contents of a small single-value proc file."""
    text = _read_text(path)
    return text.strip() if text is not None else None


def _parse_stat(pid):
    """Parse ``/proc/PID/stat`` into the handful of fields we use.

    ``comm`` may itself contain spaces and parentheses, so the fixed fields are
    located from the *last* closing paren rather than by splitting the line.
    """
    data = _read_text(_path(pid, "stat"))
    if not data:
        return None
    close = data.rfind(")")
    if close < 0:
        return None
    rest = data[close + 2 :].split()
    # rest[0] is field 3 (state), so proc field N lives at rest[N - 3].
    if len(rest) < 20:
        return None
    try:
        return {
            "ppid": int(rest[1]),  # field 4
            "tty_nr": int(rest[4]),  # field 7
            "utime": int(rest[11]),  # field 14
            "stime": int(rest[12]),  # field 15
            "starttime": int(rest[19]),  # field 22
        }
    except (TypeError, ValueError):
        return None


def read_starttime_ticks(pid):
    """Return the process start time in clock ticks since boot, or ``None``.

    Paired with the pid this forms a key that survives pid reuse, which matters
    because the collector remembers which processes it has already reported.
    """
    stat = _parse_stat(pid)
    return stat["starttime"] if stat else None


def get_ppid(pid):
    """Return the parent pid, or ``None`` if the process is gone."""
    stat = _parse_stat(pid)
    return stat["ppid"] if stat else None


def boot_time():
    """Return the host boot time as a unix timestamp, or ``None``."""
    text = _read_text(os.path.join(PROC, "stat"))
    if not text:
        return None
    for line in text.splitlines():
        if line.startswith("btime"):
            try:
                return int(line.split()[1])
            except (IndexError, ValueError):
                return None
    return None


def load_avg():
    """Return the 1/5/15-minute load averages, or ``(None, None, None)``."""
    text = _read_text(os.path.join(PROC, "loadavg"))
    if not text:
        return None, None, None
    parts = text.split()
    try:
        return float(parts[0]), float(parts[1]), float(parts[2])
    except (IndexError, ValueError):
        return None, None, None


def total_memory_kb():
    """Return ``MemTotal`` in kB, or ``None``. Used to express RSS as a percentage."""
    text = _read_text(os.path.join(PROC, "meminfo"))
    if not text:
        return None
    for line in text.splitlines():
        if line.startswith("MemTotal:"):
            try:
                return int(line.split()[1])
            except (IndexError, ValueError):
                return None
    return None


def _uid_name(uid):
    """Resolve a uid to a username, falling back to the numeric form."""
    if uid in _UID_CACHE:
        return _UID_CACHE[uid]
    try:
        name = pwd.getpwuid(uid).pw_name
    except KeyError:
        name = str(uid)
    _UID_CACHE[uid] = name
    return name


def _tty_name(tty_nr):
    """Render ``tty_nr`` from ``/proc/PID/stat`` as a device name.

    Only the two device families that matter for auditing an interactive session
    are decoded; anything else is reported by number rather than guessed at.
    """
    if not tty_nr:
        return "?"
    major = (tty_nr >> 8) & 0xFFF
    minor = (tty_nr & 0xFF) | ((tty_nr >> 12) & 0xFFF00)
    if major == 136:
        return f"pts/{minor}"
    if major == 4:
        return f"tty{minor}"
    return f"dev({major},{minor})"


def read_uid(pid):
    """Return the process's real uid, or ``None`` if the process is gone.

    ``/proc/PID/status`` is preferred over ``stat()`` on the directory because it
    is a plain text field we can reproduce in a fixture tree; test coverage of
    the identity detector would otherwise require root to chown fixtures.
    """
    text = _read_text(_path(pid, "status"))
    if text:
        for line in text.splitlines():
            if line.startswith("Uid:"):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        return int(parts[1])
                    except ValueError:
                        break
                break
    try:
        return os.stat(_path(pid)).st_uid
    except OSError:
        return None


#: What the kernel writes in loginuid when no audit login uid has been set.
_LOGINUID_UNSET = "4294967295"


def read_loginuid(pid):
    """Return the audit login uid, or ``None`` if unset.

    This is the account that originally logged in, and it survives ``su`` and
    ``sudo``. When it disagrees with the effective user, it answers "who really
    started this" — the single most useful field in an unexpected-user alert.
    """
    value = read_line(_path(pid, "loginuid"))
    if value in (None, "", _LOGINUID_UNSET):
        return None
    return value


def _rss_kb(pid):
    """Return resident set size in kB from ``/proc/PID/statm``."""
    text = _read_text(_path(pid, "statm"))
    if not text:
        return None
    parts = text.split()
    if len(parts) < 2:
        return None
    try:
        return int(parts[1]) * PAGE_SIZE // 1024
    except (TypeError, ValueError):
        return None


def list_pids():
    """Return every pid currently present under ``PROC``."""
    pids = []
    try:
        entries = os.listdir(PROC)
    except OSError:
        return pids
    for entry in entries:
        if entry.isdigit():
            pids.append(int(entry))
    return pids


def process_info(pid, now, btime=None, mem_total_kb=None):
    """Return a dict of facts about one process, or ``None`` if it is gone.

    ``pcpu`` is the process's average CPU usage over its whole lifetime, which is
    the same quantity ``ps`` reports as ``%CPU`` — not an instantaneous sample.
    That is the right measure here: the detector is looking for a process that
    has been pegged for a long time, not for a momentary inference spike.
    """
    stat = _parse_stat(pid)
    if stat is None:
        return None
    argv, raw = read_cmdline(pid)

    uid = read_uid(pid)
    if uid is None:
        return None

    abs_start = None
    duration = None
    if btime is not None:
        abs_start = int(btime + stat["starttime"] / CLK_TCK)
        duration = max(0, now - abs_start)

    pcpu = None
    if duration:
        cpu_seconds = (stat["utime"] + stat["stime"]) / CLK_TCK
        pcpu = round(cpu_seconds / duration * 100.0, 1)

    rss_kb = _rss_kb(pid)
    pmem = None
    if rss_kb is not None and mem_total_kb:
        pmem = round(rss_kb / mem_total_kb * 100.0, 1)

    return {
        "pid": pid,
        "ppid": stat["ppid"],
        "uid": uid,
        "user": _uid_name(uid),
        "comm": read_comm(pid),
        "argv": argv or [],
        "raw_cmdline": raw,
        "args": " ".join(argv) if argv else "",
        "tty": _tty_name(stat["tty_nr"]),
        "loginuid": read_loginuid(pid),
        "sessionid": read_line(_path(pid, "sessionid")),
        "starttime_ticks": stat["starttime"],
        "abs_start": abs_start,
        "duration_sec": duration,
        "pcpu": pcpu,
        "pmem": pmem,
        "rss_kb": rss_kb,
    }


def snapshot(now):
    """Return ``{pid: process_info}`` for every readable process on the host."""
    btime = boot_time()
    mem_total_kb = total_memory_kb()
    result = {}
    for pid in list_pids():
        info = process_info(pid, now, btime=btime, mem_total_kb=mem_total_kb)
        if info is not None:
            result[pid] = info
    return result


def process_tree(pid, max_depth=12):
    """Walk from ``pid`` up to init, returning one entry per ancestor.

    The chain is what makes a spawn storm diagnosable: it shows the cron job or
    supervisor actually responsible, not just the agent process it produced. It
    carries ``comm`` only — no arguments — so no redaction is needed here.
    """
    chain = []
    seen = set()
    current = pid
    while current and current > 0 and current not in seen and len(chain) < max_depth:
        seen.add(current)
        chain.append({"pid": current, "comm": read_comm(current)})
        if current == 1:
            break
        current = get_ppid(current)
    return chain


_SS_PID_RE = re.compile(r"pid=(\d+)")


def established_conn_counts():
    """Return ``{pid: established_connection_count}``, or ``None`` if unavailable.

    This is the one optional external command. ``ss`` is not required; when it is
    missing the field is simply absent from events and reported in
    ``unavailable_fields`` so the gap is visible rather than silent.
    """
    if not shutil.which("ss"):
        return None
    try:
        proc = subprocess.run(
            ["ss", "-tnpH", "state", "established"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    counts = {}
    for line in proc.stdout.splitlines():
        for match in _SS_PID_RE.finditer(line):
            pid = int(match.group(1))
            counts[pid] = counts.get(pid, 0) + 1
    return counts
