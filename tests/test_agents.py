"""Tests for agent fingerprints and process identification."""

import json

import pytest

from agentwatchdog import agents, redact


def info(comm="", argv=(), args=None):
    argv = list(argv)
    return {
        "comm": comm,
        "argv": argv,
        "args": " ".join(argv) if args is None else args,
    }


# --------------------------------------------------------------------------
# Identification
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("comm", "expected"),
    [
        ("claude", "claude-code"),
        ("claude.exe", "claude-code"),
        ("codex", "codex"),
        ("gemini", "gemini-cli"),
        ("aider", "aider"),
        ("opencode", "opencode"),
    ],
)
def test_agents_are_identified_by_comm(comm, expected):
    match = agents.identify(info(comm=comm, argv=[f"/usr/bin/{comm}"]), agents.load())

    assert match is not None
    assert match["id"] == expected


def test_agent_is_identified_by_executable_path_under_a_generic_comm():
    # Agents shipped as npm packages often run with comm "node".
    match = agents.identify(
        info(comm="node", argv=["/usr/lib/node_modules/@openai/codex/bin/codex.js"]),
        agents.load(),
    )

    assert match["id"] == "codex"


def test_path_markers_are_matched_against_argv0_only():
    """A command that merely mentions an agent is not an agent.

    Matching markers against the whole command line — which the predecessor did
    — reports `grep @openai/codex .` as a running Codex session, and worse,
    subjects an unrelated process to agent-specific redaction rules.
    """
    match = agents.identify(
        info(comm="grep", argv=["/bin/grep", "-r", "@openai/codex", "/srv"]),
        agents.load(),
    )

    assert match is None


def test_unrelated_processes_are_not_identified():
    assert agents.identify(info(comm="sshd", argv=["/usr/sbin/sshd", "-D"]), agents.load()) is None
    assert agents.identify(info(comm="", argv=[]), agents.load()) is None


def test_enabled_list_restricts_what_is_watched():
    loaded = agents.load(enabled=["codex"])

    assert [fp["id"] for fp in loaded] == ["codex"]
    assert agents.identify(info(comm="claude", argv=["/usr/bin/claude"]), loaded) is None


# --------------------------------------------------------------------------
# Operator-supplied fingerprints
# --------------------------------------------------------------------------


def test_custom_fingerprint_is_added(tmp_path):
    (tmp_path / "inhouse.json").write_text(
        json.dumps(
            {
                "id": "inhouse",
                "name": "In-house agent",
                "comms": ["ourbot"],
                "redact": {"safe_words": ["run"]},
            }
        )
    )

    match = agents.identify(info(comm="ourbot", argv=["/opt/ourbot"]), agents.load(str(tmp_path)))

    assert match["id"] == "inhouse"


def test_custom_fingerprint_overrides_a_builtin(tmp_path):
    # An operator must be able to correct a wrong fingerprint immediately,
    # rather than wait for a release — a wrong one can mean a leaked prompt.
    (tmp_path / "codex.json").write_text(
        json.dumps({"id": "codex", "name": "Patched", "comms": ["codex-next"], "redact": {}})
    )

    loaded = agents.load(str(tmp_path))

    assert agents.identify(info(comm="codex-next", argv=["/x"]), loaded)["id"] == "codex"
    assert agents.identify(info(comm="codex", argv=["/x"]), loaded) is None


def test_malformed_custom_fingerprint_is_skipped_not_fatal(tmp_path):
    (tmp_path / "broken.json").write_text("{ not json")
    (tmp_path / "fine.json").write_text(json.dumps({"id": "fine", "comms": ["fine"]}))

    loaded = agents.load(str(tmp_path))

    # One bad file must not stop the other agents from being watched.
    ids = {fp["id"] for fp in loaded}
    assert "fine" in ids
    assert "claude-code" in ids


def test_missing_agents_dir_is_not_an_error():
    assert agents.load("/nonexistent/agents.d")


# --------------------------------------------------------------------------
# Persistent sessions
# --------------------------------------------------------------------------


def test_sdk_and_remote_sessions_are_treated_as_persistent():
    fingerprint = next(fp for fp in agents.load() if fp["id"] == "claude-code")
    sdk = info(comm="claude.exe", argv=["claude", "--input-format", "stream-json"])

    assert agents.is_persistent(sdk, fingerprint)


def test_one_shot_invocation_is_not_persistent():
    fingerprint = next(fp for fp in agents.load() if fp["id"] == "claude-code")
    one_shot = info(comm="claude", argv=["claude", "-p", "do a thing"])

    assert not agents.is_persistent(one_shot, fingerprint)


def test_operator_regex_can_mark_extra_sessions_persistent():
    import re

    fingerprint = next(fp for fp in agents.load() if fp["id"] == "codex")
    proc = info(comm="codex", argv=["codex", "exec", "x"], args="codex --profile nightly")

    assert agents.is_persistent(proc, fingerprint, re.compile("nightly"))


# --------------------------------------------------------------------------
# Fingerprint file hygiene
# --------------------------------------------------------------------------


def test_builtin_fingerprints_are_well_formed():
    loaded = agents.load()

    assert len(loaded) >= 5
    for fingerprint in loaded:
        assert fingerprint["id"] and fingerprint["name"]
        assert fingerprint["comms"], f"{fingerprint['id']} has no comm to match on"
        rules = fingerprint.get("redact", {})
        # A flag cannot be both redacted and preserved.
        overlap = set(rules.get("secret_flags", ())) & set(rules.get("keep_flags", ()))
        assert not overlap, f"{fingerprint['id']} lists {overlap} as both secret and keep"
        # A "safe" word that looks like a credential would be printed verbatim.
        for word in rules.get("safe_words", ()):
            assert redact.scrub_value(word) == word, f"{fingerprint['id']}: unsafe safe_word {word}"


def test_fingerprints_declare_whether_their_flags_were_verified():
    # Honesty about which tables were checked against a real binary is what
    # tells a user how much to trust the non-prompt detail in their logs.
    for fingerprint in agents.load():
        assert isinstance(fingerprint.get("flags_verified"), bool)
        assert fingerprint.get("notes")
