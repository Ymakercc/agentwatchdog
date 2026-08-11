"""The privacy red line, in executable form.

A failure in this file means the tool would write someone's prompt or credential
to disk. It is wired to its own CI job for that reason.

The organising idea being tested is default-deny: a positional argument is
redacted unless a fingerprint explicitly vouches for it. That is what stops a
leak when an agent moves its prompt, adds a subcommand, or is one we have never
seen before.
"""

import pytest

from agentwatchdog import agents, redact

#: Stand-in for a user's prompt. Every test here asserts it does not survive.
SECRET = "refactor the billing module and do not tell anyone"  # noqa: S105


def rules_for(agent_id):
    for fingerprint in agents.load():
        if fingerprint["id"] == agent_id:
            return fingerprint["redact"]
    raise AssertionError(f"no built-in fingerprint for {agent_id}")


# --------------------------------------------------------------------------
# Prompts, in every position the real CLIs put them
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("agent_id", "argv"),
    [
        # claude [options] [command] [prompt] — bare positional
        ("claude-code", ["claude", SECRET]),
        ("claude-code", ["claude", "-p", SECRET]),
        ("claude-code", ["claude", "--print", SECRET]),
        ("claude-code", ["claude", "--append-system-prompt", SECRET]),
        ("claude-code", ["claude", "--model", "opus", SECRET]),
        # codex [OPTIONS] [PROMPT] — positional at the top level, not only
        # after `exec`. Missing this is how a redactor written for one agent
        # leaks on another.
        ("codex", ["codex", SECRET]),
        ("codex", ["codex", "exec", SECRET]),
        ("codex", ["codex", "e", SECRET]),
        ("codex", ["codex", "exec", "--model", "o3", SECRET]),
        ("codex", ["codex", "-m", "o3", SECRET]),
        # In codex, -p is --profile. A prompt still follows as a positional.
        ("codex", ["codex", "-p", "work", SECRET]),
        ("gemini-cli", ["gemini", "-p", SECRET]),
        ("gemini-cli", ["gemini", SECRET]),
        ("aider", ["aider", "-m", SECRET]),
        ("aider", ["aider", "--message", SECRET]),
        ("opencode", ["opencode", "run", SECRET]),
    ],
)
def test_prompt_never_survives_redaction(agent_id, argv):
    result = redact.sanitize(argv, rules_for(agent_id))

    assert SECRET not in result
    assert "refactor" not in result
    assert "billing" not in result


def test_unknown_agent_redacts_everything_positional():
    """The case that matters most: an agent released after this version.

    With no fingerprint there is nothing to consult, so every positional has to
    be assumed to be a prompt.
    """
    result = redact.sanitize(["some-new-agent", "chat", SECRET], agents.UNKNOWN["redact"])

    assert SECRET not in result
    assert "chat" not in result


def test_unknown_flag_is_assumed_boolean_so_its_neighbour_is_redacted():
    """A flag we have never seen must not be allowed to vouch for what follows.

    If an agent adds `--task "<prompt>"` in a future release, treating the
    unknown flag as value-taking would print the prompt. Treating it as boolean
    makes the prompt a positional, and positionals are denied by default.
    """
    result = redact.sanitize(["claude", "--newly-added-flag", SECRET], rules_for("claude-code"))

    assert SECRET not in result
    assert "--newly-added-flag" in result


def test_unknown_long_flag_with_inline_value_is_redacted():
    result = redact.sanitize(["claude", f"--newly-added-flag={SECRET}"], rules_for("claude-code"))

    assert SECRET not in result
    assert "--newly-added-flag=<redacted>" in result


# --------------------------------------------------------------------------
# Credentials, wherever they turn up
# --------------------------------------------------------------------------


# These are shaped like real credentials so the detector is genuinely exercised,
# but deliberately spelled so that no secret scanner mistakes them for live keys.
# A fixture that trips GitHub's push protection blocks every contributor's fork,
# not just ours.
@pytest.mark.parametrize(
    "secret",
    [
        "sk-ant-api03-EXAMPLE-NOT-A-REAL-KEY-000000000",
        "sk-proj-EXAMPLE-NOT-A-REAL-KEY-00000000",
        "ghp_EXAMPLENOTAREALTOKEN000000000000",
        "AIzaEXAMPLENOTAREALKEY00000000000000",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJleGFtcGxlIn0.not-a-signature",
        "xoxb-EXAMPLE-NOT-A-REAL-TOKEN-00000000",
    ],
)
def test_credentials_are_redacted_in_any_position(secret):
    # Not after a flag that declares it a secret — as a bare positional, which
    # is where a credential ends up when someone pastes a command wrong.
    result = redact.sanitize(["claude", "--model", secret], rules_for("claude-code"))

    assert secret not in result
    assert not redact.contains_secret(result)


def test_secret_looking_assignments_are_redacted():
    result = redact.sanitize(["codex", "-c", "api_key=hunter2hunter2hunter2"], rules_for("codex"))

    assert "hunter2" not in result


def test_urls_keep_the_endpoint_and_lose_the_path():
    result = redact.sanitize(
        ["claude", "--sdk-url", "https://api.anthropic.com/v1/code/sessions/cse_01SECRET"],
        rules_for("claude-code"),
    )

    assert "cse_01SECRET" not in result
    assert "sessions" not in result


def test_url_endpoint_is_preserved_when_it_is_the_audit_signal():
    # Which host an agent was pointed at is exactly what an auditor wants; the
    # path after it is where the session ids live.
    result = redact.scrub_value("https://api.example.com/v1/messages?token=abc")

    assert result == "https://api.example.com/<redacted-path>"


# --------------------------------------------------------------------------
# The audit trail has to stay useful, or nobody keeps the tool installed
# --------------------------------------------------------------------------


def test_operationally_useful_flags_are_preserved():
    result = redact.sanitize(
        ["claude", "--model", "opus", "--permission-mode", "acceptEdits", "-p", SECRET],
        rules_for("claude-code"),
    )

    assert "--model opus" in result
    assert "--permission-mode acceptEdits" in result
    assert SECRET not in result


def test_subcommands_are_preserved():
    # `claude mcp list` should read as itself, not as three redactions.
    result = redact.sanitize(["claude", "mcp", "list"], rules_for("claude-code"))

    assert result == "claude mcp list"


def test_codex_subcommand_and_model_survive():
    result = redact.sanitize(["codex", "exec", "--model", "o3", SECRET], rules_for("codex"))

    assert "exec" in result
    assert "--model o3" in result


def test_boolean_flag_does_not_swallow_the_next_flag():
    # `--print` is boolean in SDK mode. If it consumed the following token,
    # --output-format would vanish from every SDK session's audit record.
    result = redact.sanitize(
        ["claude", "--print", "--output-format", "stream-json"], rules_for("claude-code")
    )

    assert "--output-format stream-json" in result


# --------------------------------------------------------------------------
# Robustness
# --------------------------------------------------------------------------


def test_empty_and_degenerate_argv():
    assert redact.sanitize([]) == ""
    assert redact.sanitize(["claude"]) == "claude"
    assert redact.sanitize(["claude", "-"]) == "claude <redacted>"


def test_trailing_secret_flag_without_a_value():
    assert redact.sanitize(["claude", "-p"], rules_for("claude-code")) == "claude -p"


def test_output_is_length_capped():
    result = redact.sanitize(["claude"] + ["x" * 100] * 50, rules_for("claude-code"))

    assert len(result) <= redact.MAX_LENGTH


def test_every_builtin_fingerprint_is_tested_here():
    """Guard against a fingerprint being added without a redaction test.

    CONTRIBUTING.md promises this is enforced rather than merely requested.
    """
    covered = {argv[0] for _, argv in _parametrized_cases()}
    for fingerprint in agents.load():
        comms = fingerprint.get("comms", [])
        assert any(comm in covered for comm in comms), (
            f"fingerprint {fingerprint['id']} has no case in test_prompt_never_survives_redaction"
        )


def _parametrized_cases():
    marker = test_prompt_never_survives_redaction.pytestmark[0]
    return list(marker.args[1])
