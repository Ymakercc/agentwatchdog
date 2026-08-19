"""End-to-end tests for a scan, against a synthetic host.

These are the tests that would catch a mistake in how the pieces fit together
rather than in any one of them: a session recorded once a minute forever, a
prompt reaching disk because redaction was wired up after the write, a dry run
that turns out not to be dry.
"""

import hashlib
import json

from agentwatchdog import collector, config, state

PROMPT = "the quarterly numbers are not to leave this room"


def cfg(log_dir, **overrides):
    settings = config.load("/nonexistent")
    settings["LOG_DIR"] = str(log_dir)
    # Keep the suite off the real host's network tooling.
    settings["COLLECT_NET"] = "0"
    settings.update(overrides)
    return settings


def read_events(log_dir):
    path = log_dir / collector.EVENTS_FILENAME
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_scan_records_agents_and_ignores_everything_else(fake_proc, tmp_path):
    fake_proc.add(100, ["/usr/bin/claude", "--model", "opus"], comm="claude")
    fake_proc.add(101, ["/usr/bin/codex", "exec", PROMPT], comm="codex")
    fake_proc.add(102, ["/usr/sbin/sshd", "-D"], comm="sshd")
    fake_proc.add(103, ["/usr/bin/postgres"], comm="postgres")

    summary, *_ = collector.scan(cfg(tmp_path), now=fake_proc.now)

    assert summary["agent_processes"] == 2
    assert summary["agents_seen"] == ["claude-code", "codex"]
    assert len(read_events(tmp_path)) == 2


def test_a_prompt_never_reaches_the_event_log(fake_proc, tmp_path):
    """The one that matters. Redaction has to happen before anything is written."""
    fake_proc.add(100, ["/usr/bin/codex", "exec", PROMPT], comm="codex")
    fake_proc.add(101, ["/usr/bin/claude", PROMPT], comm="claude")

    collector.scan(cfg(tmp_path), now=fake_proc.now)

    written = (tmp_path / collector.EVENTS_FILENAME).read_text()
    assert PROMPT not in written
    assert "quarterly" not in written


def test_the_raw_command_line_is_kept_only_as_a_digest(fake_proc, tmp_path):
    fake_proc.add(100, ["/usr/bin/codex", "exec", PROMPT], comm="codex")

    collector.scan(cfg(tmp_path), now=fake_proc.now)
    event = read_events(tmp_path)[0]

    # Enough to correlate identical invocations, not enough to read them.
    assert len(event["cmdline_digest"]) == 32
    assert PROMPT not in event["cmdline_digest"]


def test_the_digest_cannot_be_reproduced_from_the_command_line_alone(fake_proc, tmp_path):
    """Without this the digest is a guess-and-compare oracle for the prompt.

    The redacted command line sits in the same record, so anyone holding the log
    knows the shape and has only the prompt to guess. If the digest were a plain
    hash, one hash of a guess would confirm it.
    """
    argv = ["/usr/bin/codex", "exec", PROMPT]
    fake_proc.add(100, argv, comm="codex")

    collector.scan(cfg(tmp_path), now=fake_proc.now)
    digest_value = read_events(tmp_path)[0]["cmdline_digest"]

    raw = b"".join(arg.encode() + b"\x00" for arg in argv)
    for guess in (raw, raw.rstrip(b"\x00"), " ".join(argv).encode()):
        assert not hashlib.sha256(guess).hexdigest().startswith(digest_value)
        assert not hashlib.md5(guess).hexdigest().startswith(digest_value)  # noqa: S324


def test_the_same_invocation_digests_the_same_and_a_different_host_does_not(fake_proc, tmp_path):
    argv = ["/usr/bin/codex", "exec", PROMPT]
    fake_proc.add(100, argv, comm="codex")
    fake_proc.add(101, argv, comm="codex")

    collector.scan(cfg(tmp_path), now=fake_proc.now)
    first, second = (event["cmdline_digest"] for event in read_events(tmp_path))
    assert first == second

    other_host = cfg(tmp_path, DIGEST_KEY_PATH=str(tmp_path / "other.key"))
    fake_proc.add(102, argv, comm="codex")
    collector.scan(other_host, now=fake_proc.now + 60)
    assert read_events(tmp_path)[-1]["cmdline_digest"] != first


def test_without_a_key_the_digest_is_omitted_rather_than_unkeyed(fake_proc, tmp_path):
    """Degrading to a plain hash would silently restore the oracle."""
    fake_proc.add(100, ["/usr/bin/codex", "exec", PROMPT], comm="codex")
    unwritable = cfg(tmp_path, DIGEST_KEY_PATH="/proc/nonexistent/agentwatchdog.key")

    summary, *_ = collector.scan(unwritable, now=fake_proc.now)
    event = read_events(tmp_path)[0]

    assert event["cmdline_digest"] is None
    assert "cmdline_digest" in event["unavailable_fields"]
    assert summary["agent_processes"] == 1


def test_a_restart_loop_faster_than_the_scan_interval_is_still_found(fake_proc, tmp_path):
    """The storm the previous release could not see.

    A supervisor restarting a crashing agent has one instance alive at a time,
    so a scan can count at most one start and a five-minute window holds at most
    five scans — never reaching a threshold of eight, however fast the loop runs.
    What gives it away is that every scan finds a *different* fresh instance.
    """
    settings = cfg(tmp_path)
    fake_proc.add(900, ["/usr/bin/supervisord"], comm="supervisord")

    alerts = []
    for index in range(4):
        fake_proc.remove(1000 + index - 1)
        fake_proc.add(
            1000 + index,
            ["/usr/bin/codex", "exec", PROMPT],
            comm="codex",
            ppid=900,
            age_sec=2,
        )
        _, _, scan_alerts, _ = collector.scan(settings, now=fake_proc.now + index * 60)
        alerts.extend(scan_alerts)

    storms = [alert for alert in alerts if alert["alert_type"] == "parent_spawn_storm"]
    assert len(storms) == 1, "fired once, then held by the cooldown"
    storm = storms[0]
    assert storm["ppid"] == 900
    assert storm["severity"] == "critical"
    assert storm["consecutive_scans"] >= 3
    # The counting path could not have produced this: it never got near its own
    # threshold, which is the whole reason the streak exists.
    assert storm["count"] < config.get_int(settings, "MAX_PER_PARENT_WINDOW", 8)
    assert "supervisord" in storm["reason"]


def test_a_person_starting_an_agent_now_and_then_is_not_a_storm(fake_proc, tmp_path):
    """One start, then quiet scans. The streak has to reset, or everyone alerts."""
    settings = cfg(tmp_path)
    fake_proc.add(900, ["/usr/bin/bash"], comm="bash")

    alerts = []
    for index in range(6):
        if index % 3 == 0:
            fake_proc.remove(1000 + index - 3)
            fake_proc.add(1000 + index, ["/usr/bin/codex", "exec", PROMPT], comm="codex", ppid=900)
        _, _, scan_alerts, _ = collector.scan(settings, now=fake_proc.now + index * 60)
        alerts.extend(scan_alerts)

    assert [alert for alert in alerts if alert["alert_type"] == "parent_spawn_storm"] == []


def test_a_running_session_is_recorded_once_not_once_per_scan(fake_proc, tmp_path):
    fake_proc.add(100, ["/usr/bin/claude", "--model", "opus"], comm="claude")
    settings = cfg(tmp_path)

    collector.scan(settings, now=fake_proc.now)
    collector.scan(settings, now=fake_proc.now + 60)
    collector.scan(settings, now=fake_proc.now + 120)

    # Otherwise a week-long session produces ten thousand identical events.
    assert len(read_events(tmp_path)) == 1


def test_a_restarted_process_reusing_a_pid_is_a_new_event(fake_proc, tmp_path):
    settings = cfg(tmp_path)
    fake_proc.add(100, ["/usr/bin/claude"], comm="claude", age_sec=100)
    collector.scan(settings, now=fake_proc.now)

    # Same pid, started later: a different process, and hiding it would hide a
    # crash loop.
    fake_proc.add(100, ["/usr/bin/claude"], comm="claude", age_sec=1)
    collector.scan(settings, now=fake_proc.now)

    assert len(read_events(tmp_path)) == 2


def test_dry_run_touches_nothing(fake_proc, tmp_path):
    fake_proc.add(100, ["/usr/bin/claude", PROMPT], comm="claude")
    log_dir = tmp_path / "logs"

    summary, new_events, _, _ = collector.scan(cfg(log_dir), now=fake_proc.now, dry_run=True)

    assert summary["agent_processes"] == 1
    assert len(new_events) == 1
    # Someone evaluating this tool on a production host must be able to see what
    # it would do without it having done anything. Not even the log directory
    # gets created.
    assert not log_dir.exists()


def test_alerts_are_written_and_events_recorded_together(fake_proc, tmp_path):
    fake_proc.add(100, ["/usr/bin/claude"], comm="claude", uid=1001, age_sec=100)

    summary, _, alerts, _ = collector.scan(cfg(tmp_path, ALLOWED_USERS="root"), now=fake_proc.now)

    assert summary["alerts"] == 1
    assert alerts[0]["alert_type"] == "unexpected_user"
    assert (tmp_path / "alerts.jsonl").exists()


def test_persistent_sessions_do_not_count_as_invocations(fake_proc, tmp_path):
    # A long-lived session seen on every scan is one session, not a flood.
    for pid in range(20):
        fake_proc.add(
            200 + pid,
            ["/usr/bin/claude", "--input-format", "stream-json"],
            comm="claude.exe",
        )

    summary, *_ = collector.scan(cfg(tmp_path), now=fake_proc.now)

    assert summary["agent_processes"] == 20
    assert summary["window_invocations"] == 0
    assert summary["alerts"] == 0


def test_ignore_regex_excludes_a_process_entirely(fake_proc, tmp_path):
    fake_proc.add(100, ["/usr/bin/claude", "--model", "opus"], comm="claude")
    fake_proc.add(101, ["/usr/bin/claude", "--model", "haiku"], comm="claude")

    summary, *_ = collector.scan(cfg(tmp_path, IGNORE_REGEX="haiku"), now=fake_proc.now)

    assert summary["agent_processes"] == 1


def test_operator_regex_marks_a_session_persistent(fake_proc, tmp_path):
    fake_proc.add(100, ["/usr/bin/claude", "--model", "opus"], comm="claude", age_sec=99_999)

    summary, _, alerts, _ = collector.scan(
        cfg(tmp_path, PERSISTENT_REGEX="opus"), now=fake_proc.now
    )

    # Without the exemption this would be reported as a hung process.
    assert summary["alerts"] == 0
    assert alerts == []


def test_state_survives_between_scans(fake_proc, tmp_path):
    fake_proc.add(100, ["/usr/bin/claude"], comm="claude")
    settings = cfg(tmp_path)

    collector.scan(settings, now=fake_proc.now)
    saved = state.load(str(tmp_path / collector.STATE_FILENAME))

    assert saved["seen"]
    assert saved["last_summary"]["agent_processes"] == 1


def test_a_process_that_exits_is_forgotten(fake_proc, tmp_path):
    import shutil

    settings = cfg(tmp_path)
    fake_proc.add(100, ["/usr/bin/claude"], comm="claude")
    collector.scan(settings, now=fake_proc.now)

    shutil.rmtree(fake_proc.root / "100")
    collector.scan(settings, now=fake_proc.now + 60)

    # Otherwise state grows without bound on a long-lived host.
    assert state.load(str(tmp_path / collector.STATE_FILENAME))["seen"] == {}


def test_an_empty_host_produces_an_empty_scan(fake_proc, tmp_path):
    summary, *_ = collector.scan(cfg(tmp_path), now=fake_proc.now)

    assert summary["agent_processes"] == 0
    assert summary["alerts"] == 0
    assert read_events(tmp_path) == []
