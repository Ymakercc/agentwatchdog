"""Shared fixtures: a synthetic ``/proc`` tree.

The collector's whole job is to interpret ``/proc``, so the tests need to be able
to state "here is a host with these processes on it" and assert on what comes
out. Doing that against real processes would make the suite unrunnable in CI,
dependent on which agents happen to be installed, and unable to cover the cases
that matter most — a spawn storm, an unexpected user, a four-hour hang.

``fake_proc`` builds exactly the files ``procfs`` reads, with the same field
layout the kernel uses, and repoints the module at them. Nothing here needs root.
"""

import pytest

from agentwatchdog import procfs

#: Ticks per second assumed when writing fixture stat files. Matches the value
#: procfs reads from sysconf on every mainstream Linux build.
FIXTURE_CLK_TCK = 100

#: Fixture hosts boot at a fixed instant so elapsed times are deterministic.
FIXTURE_BTIME = 1_700_000_000

FIXTURE_MEM_TOTAL_KB = 4_000_000

PAGE_SIZE = 4096


class FakeProc:
    """Builder for a synthetic ``/proc`` tree."""

    def __init__(self, root):
        self.root = root
        self.btime = FIXTURE_BTIME
        #: "Now" for this fixture host, i.e. it has been up for 100_000 seconds.
        #: Tests pass this to the collector so elapsed times are reproducible.
        self.now = FIXTURE_BTIME + 100_000
        self._write_host_files()

    def _write_host_files(self):
        (self.root / "stat").write_text(
            f"cpu  1 2 3 4 5 6 7 8 9 10\nbtime {self.btime}\nprocesses 12345\n"
        )
        (self.root / "loadavg").write_text("0.50 0.40 0.30 2/300 12345\n")
        (self.root / "meminfo").write_text(
            f"MemTotal:       {FIXTURE_MEM_TOTAL_KB} kB\nMemFree:         100000 kB\n"
        )

    def set_load(self, one, five, fifteen):
        """Set the host load averages reported by the fixture."""
        (self.root / "loadavg").write_text(f"{one} {five} {fifteen} 2/300 12345\n")

    def add(
        self,
        pid,
        argv,
        comm=None,
        ppid=1,
        uid=0,
        age_sec=60,
        cpu_seconds=1.0,
        rss_kb=100_000,
        tty="pts/0",
        loginuid=None,
        sessionid="1",
    ):
        """Add one process to the tree.

        ``age_sec`` and ``cpu_seconds`` are given in the terms a test wants to
        reason about; they are converted here into the clock-tick fields the
        kernel actually exposes.
        """
        directory = self.root / str(pid)
        directory.mkdir(parents=True, exist_ok=True)

        if comm is None:
            comm = argv[0].rsplit("/", 1)[-1][:15] if argv else ""
        (directory / "comm").write_text(comm + "\n")
        (directory / "cmdline").write_bytes(
            b"".join(arg.encode() + b"\x00" for arg in argv) if argv else b""
        )

        starttime_ticks = int((self.now - self.btime - age_sec) * FIXTURE_CLK_TCK)
        cpu_ticks = int(cpu_seconds * FIXTURE_CLK_TCK)
        utime = cpu_ticks // 2
        stime = cpu_ticks - utime

        # /proc/PID/stat: pid (comm) state ppid pgrp session tty_nr tpgid ...
        # Fields 3..22 follow the closing paren; everything we do not use is
        # filled with zeroes, matching the shape but not the values.
        fields = ["0"] * 50
        fields[0] = "S"  # field 3, state
        fields[1] = str(ppid)  # field 4
        fields[4] = str(_tty_nr(tty))  # field 7
        fields[11] = str(utime)  # field 14
        fields[12] = str(stime)  # field 15
        fields[19] = str(starttime_ticks)  # field 22
        (directory / "stat").write_text(f"{pid} ({comm}) " + " ".join(fields) + "\n")

        (directory / "statm").write_text(f"0 {rss_kb * 1024 // PAGE_SIZE} 0 0 0 0 0\n")
        (directory / "status").write_text(
            f"Name:\t{comm}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nPPid:\t{ppid}\n"
        )
        (directory / "loginuid").write_text("4294967295" if loginuid is None else str(loginuid))
        (directory / "sessionid").write_text(str(sessionid))
        return pid


def _tty_nr(tty):
    """Encode a device name back into the ``tty_nr`` field's packed form."""
    if not tty or tty == "?":
        return 0
    if tty.startswith("pts/"):
        major, minor = 136, int(tty[4:])
    elif tty.startswith("tty"):
        major, minor = 4, int(tty[3:])
    else:
        return 0
    return (major << 8) | (minor & 0xFF) | ((minor & 0xFFF00) << 12)


@pytest.fixture
def fake_proc(tmp_path, monkeypatch):
    """Yield a :class:`FakeProc` with ``procfs`` pointed at it.

    ``procfs.PROC`` is patched rather than passed as an argument so that every
    layer above it — detectors, exporter, CLI — exercises the same code path in
    tests that it uses in production.
    """
    root = tmp_path / "proc"
    root.mkdir()
    monkeypatch.setattr(procfs, "PROC", str(root))
    monkeypatch.setattr(procfs, "CLK_TCK", FIXTURE_CLK_TCK)
    monkeypatch.setattr(procfs, "PAGE_SIZE", PAGE_SIZE)
    # Usernames must not depend on the accounts of whichever machine runs the
    # suite; map fixture uids to stable names instead.
    monkeypatch.setattr(procfs, "_UID_CACHE", {0: "root", 1000: "alice", 1001: "mallory"})

    return FakeProc(root)
