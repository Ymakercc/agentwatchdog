"""Tests for the state carried between scans."""

from agentwatchdog import state


def test_missing_state_file_yields_a_usable_state(tmp_path):
    loaded = state.load(str(tmp_path / "absent.json"))

    assert loaded["seen"] == {}
    assert loaded["invocations"] == []
    assert loaded["alert_cooldown"] == {}


def test_corrupt_state_file_does_not_wedge_the_scan(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("{ this is not json")

    loaded = state.load(str(path))

    # Losing state costs one duplicate event per running agent. Refusing to run
    # costs all monitoring, which is the worse failure.
    assert loaded["seen"] == {}


def test_save_is_atomic(tmp_path):
    path = str(tmp_path / "state.json")
    state.save(path, {"seen": {"1:2": {}}})

    assert state.load(path)["seen"] == {"1:2": {}}
    assert not (tmp_path / "state.json.tmp").exists()


def test_process_key_distinguishes_a_reused_pid():
    # Same pid, different start time: a different process, and it must be
    # reported as a new invocation rather than silently treated as the old one.
    assert state.process_key(1234, 5000) != state.process_key(1234, 9000)


def test_prune_drops_dead_processes_and_stale_records():
    now = 1_000_000
    current = {
        "version": 1,
        "seen": {"1:1": {}, "2:2": {}},
        "invocations": [{"ts": now - 10}, {"ts": now - 9999}],
        "alert_cooldown": {"high_cpu:pid1": now - 10, "high_cpu:pid2": now - 999_999},
    }

    state.prune(current, now, window_sec=300, cooldown_sec=3600, live_keys={"1:1"})

    assert set(current["seen"]) == {"1:1"}
    assert current["invocations"] == [{"ts": now - 10}]
    # An expired cooldown cannot suppress anything, so keeping it would only
    # grow the file forever.
    assert set(current["alert_cooldown"]) == {"high_cpu:pid1"}


def test_cooldown_suppresses_then_releases():
    now = 1_000_000
    current = state.load("/nonexistent")

    assert not state.in_cooldown(current, "high_cpu", "pid1", now, 3600)

    state.mark_fired(current, "high_cpu", "pid1", now)

    assert state.in_cooldown(current, "high_cpu", "pid1", now + 60, 3600)
    assert not state.in_cooldown(current, "high_cpu", "pid1", now + 3601, 3600)
    # Cooldown is per alert type and per subject, not global.
    assert not state.in_cooldown(current, "high_cpu", "pid2", now + 60, 3600)
    assert not state.in_cooldown(current, "high_mem", "pid1", now + 60, 3600)


def test_a_streak_counts_consecutive_scans_and_resets_on_a_quiet_one():
    """One quiet scan has to erase the streak.

    The streak stands in for "this parent is in a loop right now". If a gap did
    not reset it, a parent that starts one agent a day would eventually look
    identical to a crash loop.
    """
    current = state.load("/nonexistent")
    sample = {"user": "root", "agent": "codex"}

    for index in range(3):
        streaks = state.update_spawn_streaks(current, 1000 + index * 60, {900: sample})
    assert streaks[0]["count"] == 3
    assert streaks[0]["ppid"] == 900

    assert state.update_spawn_streaks(current, 1300, {}) == []
    assert current["spawn_streaks"] == {}

    streaks = state.update_spawn_streaks(current, 1360, {900: sample})
    assert streaks[0]["count"] == 1


def test_streaks_are_kept_per_parent():
    current = state.load("/nonexistent")
    sample = {"user": "root", "agent": "codex"}

    state.update_spawn_streaks(current, 1000, {900: sample, 901: sample})
    streaks = {
        record["ppid"]: record
        for record in state.update_spawn_streaks(current, 1060, {900: sample})
    }

    assert streaks[900]["count"] == 2
    assert 901 not in streaks


def test_the_fork_counter_yields_a_rate_only_once_it_has_a_previous_reading():
    current = state.load("/nonexistent")

    assert state.record_fork_count(current, 1000, 500) is None
    assert state.record_fork_count(current, 1060, 800) == (300, 60)


def test_a_reboot_does_not_look_like_a_negative_fork_rate():
    """The kernel counter restarts at boot; a decrease is not a measurement."""
    current = state.load("/nonexistent")
    state.record_fork_count(current, 1000, 900_000)

    assert state.record_fork_count(current, 1060, 12) is None
    # The new reading still becomes the baseline for the scan after it.
    assert state.record_fork_count(current, 1120, 40) == (28, 60)


def test_an_unavailable_fork_counter_is_not_an_error():
    current = state.load("/nonexistent")

    assert state.record_fork_count(current, 1000, None) is None
    assert state.record_fork_count(current, 1060, None) is None
