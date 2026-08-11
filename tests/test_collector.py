"""End-to-end tests for a scan, against a synthetic host.

These are the tests that would catch a mistake in how the pieces fit together
rather than in any one of them: a session recorded once a minute forever, a
prompt reaching disk because redaction was wired up after the write, a dry run
that turns out not to be dry.
"""

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
    assert len(event["cmdline_sha256"]) == 32
    assert PROMPT not in event["cmdline_sha256"]


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
