"""Who ran an agent here.

Off by default. On an unfamiliar host there is no basis for calling any account
unexpected, and a monitor whose first act is a false critical gets uninstalled.
It becomes useful the moment an operator writes down who is supposed to be
running agents, which is a thing worth being made to think about.
"""

from .. import config
from .base import Finding


def detect(context):
    allowed = set(config.get_list(context.cfg, "ALLOWED_USERS"))
    if not allowed:
        return

    for event in context.processes:
        user = event.get("user")
        if not user or user in allowed:
            continue

        yield _finding(event, user, allowed)


def _finding(event, user, allowed):
    # loginuid survives su and sudo, so when it disagrees with the effective
    # user it names the human actually responsible. That is the difference
    # between "root ran an agent" — useless — and "alice ran an agent as root".
    login = event.get("loginuid")
    via_sudo = login is not None and login != str(event.get("uid"))
    if via_sudo:
        reason = (
            f"account {user!r} is not in ALLOWED_USERS and ran {event.get('agent_name')}; "
            f"the session was opened by login uid {login}, so this was reached via su or sudo"
        )
    else:
        reason = (
            f"account {user!r} is not in ALLOWED_USERS and ran {event.get('agent_name')} "
            f"(allowed: {', '.join(sorted(allowed))})"
        )

    return Finding(
        type="unexpected_user",
        severity="critical",
        # Per user and per agent, not per pid: one account running a hundred
        # agents is one situation, and should not produce a hundred alerts.
        key=f"{user}:{event.get('agent')}",
        reason=reason,
        action=(
            f"Confirm who this is: ps -fp {event.get('pid')}. If the invocation was not "
            "authorised, stop the process and review the account's access."
        ),
        extra={
            "agent": event.get("agent"),
            "user": user,
            "uid": event.get("uid"),
            "loginuid": login,
            "pid": event.get("pid"),
            "ppid": event.get("ppid"),
            "tty": event.get("tty"),
            "cwd": event.get("cwd"),
            "process_tree": event.get("process_tree"),
        },
    )
