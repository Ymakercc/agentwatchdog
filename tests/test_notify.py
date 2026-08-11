"""Tests for alert delivery.

Two properties matter more than the mechanics: nothing leaves the host unless
someone configured it to, and a broken notifier does not take the scan with it.
"""

import json
import os
import sys

import pytest

from agentwatchdog import config, notify

ALERTS = [{"alert_type": "high_cpu", "severity": "warning", "reason": "hot", "pid": 1}]


def cfg(**overrides):
    settings = config.load("/nonexistent")
    settings.update(overrides)
    return settings


def test_default_configuration_writes_locally_and_nowhere_else():
    # The whole default posture, asserted: alerts land in a file on this host.
    assert config.get_list(cfg(), "NOTIFY") == ["jsonl"]


def test_jsonl_appends_one_object_per_line(tmp_path):
    notify.dispatch(cfg(), ALERTS, str(tmp_path))
    notify.dispatch(cfg(), ALERTS, str(tmp_path))

    lines = (tmp_path / "alerts.jsonl").read_text().strip().splitlines()

    assert len(lines) == 2
    assert json.loads(lines[0])["alert_type"] == "high_cpu"


def test_nothing_is_written_when_there_is_nothing_to_report(tmp_path):
    assert notify.dispatch(cfg(), [], str(tmp_path)) == []
    assert not (tmp_path / "alerts.jsonl").exists()


def test_unknown_notifier_is_reported_not_ignored(tmp_path):
    # A typo in NOTIFY means alerts silently go nowhere, which is the one
    # failure a monitor must never have quietly.
    errors = []
    notify.dispatch(cfg(NOTIFY="jsonl,tlegram"), ALERTS, str(tmp_path), on_error=errors.append)

    assert any("tlegram" in message for message in errors)
    # The working notifier still ran.
    assert (tmp_path / "alerts.jsonl").exists()


def test_a_failing_notifier_does_not_stop_the_others(tmp_path):
    errors = []
    delivered = notify.dispatch(
        cfg(NOTIFY="webhook,jsonl", NOTIFY_WEBHOOK_URL=""),
        ALERTS,
        str(tmp_path),
        on_error=errors.append,
    )

    assert delivered == ["jsonl"]
    assert errors


# --------------------------------------------------------------------------
# exec
# --------------------------------------------------------------------------


def test_exec_hands_the_alerts_to_a_command_on_stdin(tmp_path):
    sink = tmp_path / "received.json"
    script = tmp_path / "sink.py"
    script.write_text(
        f"import sys, pathlib\npathlib.Path({str(sink)!r}).write_text(sys.stdin.read())\n"
    )

    delivered = notify.dispatch(
        cfg(NOTIFY="exec", NOTIFY_EXEC_CMD=f"{sys.executable} {script}"),
        ALERTS,
        str(tmp_path),
    )

    assert delivered == ["exec"]
    assert json.loads(sink.read_text())["alerts"][0]["alert_type"] == "high_cpu"


def test_exec_without_a_command_is_an_error_not_a_silent_no_op(tmp_path):
    errors = []
    notify.dispatch(
        cfg(NOTIFY="exec", NOTIFY_EXEC_CMD=""), ALERTS, str(tmp_path), on_error=errors.append
    )

    assert any("NOTIFY_EXEC_CMD" in message for message in errors)


def test_exec_reports_a_failing_command(tmp_path):
    errors = []
    notify.dispatch(
        cfg(NOTIFY="exec", NOTIFY_EXEC_CMD=f"{sys.executable} -c 'import sys; sys.exit(3)'"),
        ALERTS,
        str(tmp_path),
        on_error=errors.append,
    )

    assert any("exited 3" in message for message in errors)


def test_exec_does_not_go_through_a_shell(tmp_path):
    """Alert payloads contain command lines observed on the host.

    If delivery went through a shell, an audit tool would become a way to run
    whatever an agent happened to be invoked with.
    """
    marker = tmp_path / "should-not-exist"
    errors = []
    notify.dispatch(
        cfg(NOTIFY="exec", NOTIFY_EXEC_CMD=f"true; touch {marker}"),
        ALERTS,
        str(tmp_path),
        on_error=errors.append,
    )

    assert not marker.exists()


# --------------------------------------------------------------------------
# webhook
# --------------------------------------------------------------------------


def test_webhook_refuses_plain_http(tmp_path):
    # Alerts name users, paths and process ancestry. Refused rather than warned
    # about, because a warning in a timer's output is a warning nobody reads.
    errors = []
    notify.dispatch(
        cfg(NOTIFY="webhook", NOTIFY_WEBHOOK_URL="http://example.com/hook"),
        ALERTS,
        str(tmp_path),
        on_error=errors.append,
    )

    assert any("https" in message for message in errors)


def test_webhook_posts_json(monkeypatch, tmp_path):
    sent = {}

    class FakeResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def fake_urlopen(request, timeout=None):
        sent["url"] = request.full_url
        sent["body"] = json.loads(request.data.decode())
        sent["content_type"] = request.headers.get("Content-type")
        return FakeResponse()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    delivered = notify.dispatch(
        cfg(NOTIFY="webhook", NOTIFY_WEBHOOK_URL="https://example.com/hook"),
        ALERTS,
        str(tmp_path),
    )

    assert delivered == ["webhook"]
    assert sent["url"] == "https://example.com/hook"
    assert sent["content_type"] == "application/json"
    assert sent["body"]["alerts"][0]["pid"] == 1


@pytest.mark.parametrize("name", ["jsonl", "exec", "webhook"])
def test_every_documented_notifier_exists(name):
    assert name in notify.NOTIFIERS
    assert os.path.exists  # sanity, keeps the import used
