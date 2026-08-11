"""Regression tests for path-marker precision, from findings on a live host."""

from agentwatchdog import agents


def info(comm, argv):
    return {"comm": comm, "argv": argv, "args": " ".join(argv)}


def test_a_venv_interpreter_is_not_the_agent_installed_in_it():
    """Found live: 'pip install aider-chat' running as /tmp/aider-venv/bin/python3
    was reported as aider, because the marker '/aider' matched 'aider-venv'.

    A marker has to match the agent's own entry point, not any path that
    happens to contain the agent's name.
    """
    # The path is data being matched against, not a file being opened.
    interpreter = "/tmp/aider-venv/bin/python3"  # noqa: S108
    pip = "/tmp/aider-venv/bin/pip"  # noqa: S108
    match = agents.identify(
        info("python3", [interpreter, pip, "install", "x"]),
        agents.load(),
    )

    assert match is None


def test_the_real_aider_entry_point_still_matches():
    match = agents.identify(
        info("python3", ["/home/dev/.venvs/tools/bin/aider", "--model", "gpt-4o"]),
        agents.load(),
    )

    assert match is not None
    assert match["id"] == "aider"


def test_aider_by_comm_still_matches():
    match = agents.identify(info("aider", ["/usr/local/bin/aider"]), agents.load())

    assert match["id"] == "aider"
