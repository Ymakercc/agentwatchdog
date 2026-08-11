"""The second privacy guarantee: what leaves the host carries nothing about it.

The event log is host-private by design — it names users, pids, working
directories and parent processes, because that is what makes an alert
actionable. The exported summary is the artefact that may be published, so it
has to be provably free of all of it.

These tests feed the exporter an event log full of identifying material and
assert that none of it appears in the output.
"""

import json

import pytest

from agentwatchdog import export

#: A realistic event, carrying everything the exporter must not pass on.
LOADED_EVENT = {
    "ts": 1_000_000,
    "kind": "agent_process",
    "agent": "claude-code",
    "pid": 4242,
    "ppid": 4241,
    "user": "deploy",
    # Chosen not to appear as a substring of any timestamp in these tests, so a
    # match below means a real leak rather than a coincidence.
    "uid": 1507,
    "loginuid": "1509",
    "sessionid": "77",
    "tty": "pts/3",
    "cwd": "/srv/customer-portal/checkout",
    "cmdline_sanitized": "claude --model opus <redacted>",
    "cmdline_sha256": "deadbeefdeadbeefdeadbeefdeadbeef",
    "process_tree": [{"pid": 4242, "comm": "claude"}, {"pid": 1, "comm": "systemd"}],
    "duration_sec": 30,
}

LOADED_ALERT = {
    "ts": 1_000_000,
    "alert_type": "unexpected_user",
    "severity": "critical",
    "agent": "codex",
    "user": "mallory",
    "pid": 9999,
    "reason": "user mallory ran an agent on prod-db-07",
    "process_tree": [{"pid": 9999, "comm": "codex"}],
}


@pytest.fixture
def exported(tmp_path, monkeypatch):
    """Return the summary built from a log full of identifying material."""
    (tmp_path / "events.jsonl").write_text(
        "\n".join(json.dumps(LOADED_EVENT) for _ in range(3)) + "\n"
    )
    (tmp_path / "alerts.jsonl").write_text(json.dumps(LOADED_ALERT) + "\n")
    # The exporter counts what is running now; keep that out of these tests by
    # pointing it at an empty process tree.
    empty = tmp_path / "proc"
    empty.mkdir()
    monkeypatch.setattr("agentwatchdog.procfs.PROC", str(empty))

    cfg = {"LOG_DIR": str(tmp_path), "AGENTS_DIR": "", "ENABLED_AGENTS": "", "LOAD_FACTOR": "1.5"}
    return export.build(cfg, now=1_000_100, version="9.9.9")


IDENTIFYING_STRINGS = [
    "deploy",
    "mallory",
    "4242",
    "9999",
    "1507",
    "1509",
    "pts/3",
    "/srv/customer-portal/checkout",
    "customer-portal",
    "systemd",
    "deadbeef",
    "prod-db-07",
    "<redacted>",
]


@pytest.mark.parametrize("needle", IDENTIFYING_STRINGS)
def test_no_identifying_string_survives_export(exported, needle):
    assert needle not in json.dumps(exported)


def test_export_reports_only_permitted_keys(exported):
    # Assembled from scratch into a fixed shape, so a field added to events
    # later cannot appear here by default.
    export.assert_anonymous(exported)


def test_a_leak_is_refused_rather_than_published():
    """The allowlist runs in production, not only under test."""
    with pytest.raises(ValueError, match="disallowed key"):
        export.assert_anonymous({"schema": export.SCHEMA, "hostname": "prod-db-07"})


def test_a_path_shaped_value_is_refused():
    with pytest.raises(ValueError, match="identifying value"):
        export.assert_anonymous({"schema": "/srv/customer-portal/app"})


def test_an_ip_shaped_value_is_refused():
    with pytest.raises(ValueError, match="identifying value"):
        export.assert_anonymous({"schema": "reached 10.0.13.7 successfully"})


def test_counts_and_shape_are_still_useful(exported):
    # Anonymous has to remain informative, or nobody publishes it.
    assert exported["schema"] == export.SCHEMA
    assert exported["totals"]["events_24h"] == 3
    assert exported["totals"]["alerts_24h"] == 1
    assert exported["alerts_by_type"] == {"unexpected_user": 1}
    assert exported["alerts_by_severity"] == {"critical": 1}
    assert len(exported["invocations_by_hour"]) == 24
    assert len(exported["events_by_day"]) == 7


def test_agent_mix_is_reported_because_tooling_is_not_a_person(exported):
    assert exported["agents_seen"] == {"claude-code": 3}


def test_old_records_fall_out_of_the_windows(tmp_path, monkeypatch):
    stale = dict(LOADED_EVENT, ts=1_000_000 - 40 * 86400)
    (tmp_path / "events.jsonl").write_text(json.dumps(stale) + "\n")
    empty = tmp_path / "proc"
    empty.mkdir()
    monkeypatch.setattr("agentwatchdog.procfs.PROC", str(empty))

    summary = export.build({"LOG_DIR": str(tmp_path), "LOAD_FACTOR": "1.5"}, now=1_000_100)

    assert summary["totals"]["events_7d"] == 0


def test_a_corrupt_log_line_does_not_stop_the_export(tmp_path, monkeypatch):
    (tmp_path / "events.jsonl").write_text(
        json.dumps(LOADED_EVENT) + "\nthis line is not json\n" + json.dumps(LOADED_EVENT) + "\n"
    )
    empty = tmp_path / "proc"
    empty.mkdir()
    monkeypatch.setattr("agentwatchdog.procfs.PROC", str(empty))

    summary = export.build({"LOG_DIR": str(tmp_path), "LOAD_FACTOR": "1.5"}, now=1_000_100)

    assert summary["totals"]["events_24h"] == 2


def test_missing_logs_export_as_zeroes(tmp_path, monkeypatch):
    empty = tmp_path / "proc"
    empty.mkdir()
    monkeypatch.setattr("agentwatchdog.procfs.PROC", str(empty))

    summary = export.build({"LOG_DIR": str(tmp_path), "LOAD_FACTOR": "1.5"}, now=1_000_100)

    assert summary["totals"]["events_7d"] == 0
    assert summary["current"]["agent_processes"] == 0
