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
