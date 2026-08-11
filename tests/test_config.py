"""Tests for configuration loading."""

from agentwatchdog import config


def test_defaults_are_safe_on_an_unknown_host():
    cfg = config.load("/nonexistent")

    # Nothing leaves the host unless explicitly configured.
    assert cfg["NOTIFY"] == "jsonl"
    assert cfg["NOTIFY_WEBHOOK_URL"] == ""
    assert cfg["NOTIFY_EXEC_CMD"] == ""
    # No allow-list means the unexpected-user check is off, so a fresh install
    # cannot alert on accounts it has no basis to judge.
    assert cfg["ALLOWED_USERS"] == ""


def test_file_values_override_defaults(tmp_path):
    path = tmp_path / "agentwatchdog.conf"
    path.write_text(
        '# a comment\n\nMAX_RUNTIME_SEC=60\nALLOWED_USERS="root deploy"\nNOTIFY = jsonl,webhook\n'
    )

    cfg = config.load(str(path))

    assert config.get_int(cfg, "MAX_RUNTIME_SEC") == 60
    assert config.get_list(cfg, "ALLOWED_USERS") == ["root", "deploy"]
    assert config.get_list(cfg, "NOTIFY") == ["jsonl", "webhook"]


def test_renamed_settings_keep_working(tmp_path):
    path = tmp_path / "agentwatchdog.conf"
    path.write_text("MAX_PER_USER_5MIN=42\n")

    cfg = config.load(str(path))

    assert config.get_int(cfg, "MAX_PER_USER_WINDOW") == 42


def test_malformed_values_fall_back_instead_of_crashing(tmp_path):
    path = tmp_path / "agentwatchdog.conf"
    path.write_text("MAX_RUNTIME_SEC=not-a-number\nCPU_ALERT_PCT=\nthis line has no equals\n")

    cfg = config.load(str(path))

    # This runs unattended on a timer; a typo in the config must not stop it.
    assert config.get_int(cfg, "MAX_RUNTIME_SEC", 14400) == 14400
    assert config.get_float(cfg, "CPU_ALERT_PCT", 85) == 85.0


def test_get_bool_accepts_the_usual_spellings():
    cfg = {"A": "1", "B": "true", "C": "YES", "D": "on", "E": "0", "F": "false", "G": ""}

    assert [config.get_bool(cfg, key) for key in "ABCD"] == [True] * 4
    assert [config.get_bool(cfg, key) for key in "EFG"] == [False] * 3
