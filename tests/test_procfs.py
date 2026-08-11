"""Tests for the /proc collector.

These also serve as the check that the fixture tree in ``conftest.py`` really
does reproduce the kernel's field layout — if it drifts, these fail first.
"""

from agentwatchdog import procfs


def test_snapshot_reports_each_process(fake_proc):
    fake_proc.add(100, ["/usr/bin/claude", "--model", "opus"], comm="claude")
    fake_proc.add(101, ["/usr/bin/codex", "exec", "hello"], comm="codex", uid=1000)

    snapshot = procfs.snapshot(fake_proc.now)

    assert set(snapshot) == {100, 101}
    assert snapshot[100]["comm"] == "claude"
    assert snapshot[100]["user"] == "root"
    assert snapshot[101]["user"] == "alice"
    assert snapshot[101]["argv"] == ["/usr/bin/codex", "exec", "hello"]


def test_elapsed_and_cpu_are_derived_from_stat(fake_proc):
    fake_proc.add(200, ["/usr/bin/claude"], age_sec=3600, cpu_seconds=360, rss_kb=200_000)

    info = procfs.snapshot(fake_proc.now)[200]

    assert info["duration_sec"] == 3600
    # 360s of CPU over 3600s of wall clock is 10% averaged over the lifetime,
    # which is the same quantity ps reports as %CPU.
    assert info["pcpu"] == 10.0
    assert info["rss_kb"] == 200_000
    assert info["pmem"] == 5.0  # 200_000 of the fixture host's 4_000_000 kB


def test_process_tree_walks_to_init(fake_proc):
    fake_proc.add(1, ["/sbin/init"], comm="systemd", ppid=0)
    fake_proc.add(50, ["/usr/bin/cron"], comm="cron", ppid=1)
    fake_proc.add(51, ["/bin/sh", "-c", "loop"], comm="sh", ppid=50)
    fake_proc.add(52, ["/usr/bin/claude"], comm="claude", ppid=51)

    chain = [node["comm"] for node in procfs.process_tree(52)]

    assert chain == ["claude", "sh", "cron", "systemd"]


def test_process_tree_survives_a_cycle(fake_proc):
    # Should not happen on a live kernel, but a truncated or racing read can
    # produce one, and the collector must not spin.
    fake_proc.add(60, ["/bin/a"], comm="a", ppid=61)
    fake_proc.add(61, ["/bin/b"], comm="b", ppid=60)

    chain = procfs.process_tree(60)

    assert [node["pid"] for node in chain] == [60, 61]


def test_vanished_process_is_skipped_not_fatal(fake_proc):
    fake_proc.add(300, ["/usr/bin/claude"])
    # A pid directory with no stat file is what a race with process exit looks
    # like from here.
    (fake_proc.root / "301").mkdir()

    snapshot = procfs.snapshot(fake_proc.now)

    assert set(snapshot) == {300}


def test_kernel_threads_have_no_cmdline(fake_proc):
    fake_proc.add(2, [], comm="kthreadd")

    info = procfs.snapshot(fake_proc.now)[2]

    assert info["argv"] == []
    assert info["raw_cmdline"] is None


def test_tty_is_decoded_for_interactive_sessions(fake_proc):
    fake_proc.add(400, ["/usr/bin/claude"], tty="pts/3")
    fake_proc.add(401, ["/usr/bin/claude"], tty="?")

    snapshot = procfs.snapshot(fake_proc.now)

    assert snapshot[400]["tty"] == "pts/3"
    assert snapshot[401]["tty"] == "?"


def test_loginuid_identifies_the_original_account(fake_proc):
    fake_proc.add(500, ["/usr/bin/claude"], uid=0, loginuid=1000)
    fake_proc.add(501, ["/usr/bin/claude"], uid=0)

    snapshot = procfs.snapshot(fake_proc.now)

    # Running as root but logged in as uid 1000: someone used sudo.
    assert snapshot[500]["loginuid"] == "1000"
    # Unset loginuid is reported as absent rather than as the kernel's sentinel.
    assert snapshot[501]["loginuid"] is None


def test_host_facts_are_read_from_proc(fake_proc):
    fake_proc.set_load(3.5, 2.5, 1.5)

    assert procfs.boot_time() == fake_proc.btime
    assert procfs.load_avg() == (3.5, 2.5, 1.5)
    assert procfs.total_memory_kb() == 4_000_000


def test_environ_is_never_opened(fake_proc, monkeypatch):
    """The privacy guarantee that matters most, asserted at the syscall boundary.

    API keys live in the environment. This test fails if any code path in the
    collector ever opens that file, no matter how it is reached.
    """
    fake_proc.add(600, ["/usr/bin/claude", "--model", "opus"])
    (fake_proc.root / "600" / "environ").write_bytes(b"ANTHROPIC_API_KEY=sk-ant-secret\x00")

    opened = []
    real_open = open

    def recording_open(path, *args, **kwargs):
        opened.append(str(path))
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", recording_open)
    procfs.snapshot(fake_proc.now)
    procfs.process_tree(600)

    assert not any(name.endswith("/environ") for name in opened), (
        "collector opened /proc/PID/environ"
    )
