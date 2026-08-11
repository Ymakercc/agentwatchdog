"""Turn a raw command line into something safe to write to disk.

This is the module the project's privacy promise rests on. Everything else can
be rebuilt; a prompt written to a log file cannot be unwritten.

The design is **default-deny on positional arguments**. Every terminal agent
accepts a prompt as a bare argument in at least one form — ``claude "…"``,
``codex exec "…"``, ``opencode run "…"`` — so a scheme that only redacts the
values of known flags leaks by construction the moment a new agent or a new
release moves the prompt somewhere it wasn't. Here, a positional argument is
redacted unless it is a literal word the fingerprint explicitly lists as safe,
such as a subcommand name.

Flags are classified per agent:

``secret_flags``
    Consume the next argument and redact it. ``--session-id``, ``-p``.
``keep_flags``
    Consume the next argument and keep it, because knowing it is the point of
    the audit trail. ``--model``, ``--permission-mode``.
Anything else
    Assumed to be boolean. The token after it is therefore treated as a
    positional, which means it is redacted unless explicitly safe. An unknown
    flag can cost some detail in the log; it cannot cost a prompt.

On top of that, three checks run on every value that survives, whatever position
it came from, so a secret in an unexpected place is still caught.
"""

import re

REDACTED = "<redacted>"
REDACTED_TOKEN = "<redacted-token>"  # noqa: S105 — a placeholder, not a credential
REDACTED_SECRETISH = "<redacted-secretish>"
REDACTED_URL = "<redacted-url>"

#: Cap on the stored command line. Long enough to stay diagnostic, short enough
#: that a pathological argv cannot bloat every event.
MAX_LENGTH = 600

#: Values shaped like credentials: provider key prefixes, JWTs, and any long
#: opaque blob. The last alternative is deliberately broad — a 40-character
#: unbroken token is not something worth preserving in an audit log.
TOKEN_RE = re.compile(
    r"(sk-ant[A-Za-z0-9_\-]{8,}"
    r"|sk-[A-Za-z0-9_\-]{8,}"
    r"|ghp_[A-Za-z0-9]{20,}"
    r"|gho_[A-Za-z0-9]{20,}"
    r"|xox[baprs]-[A-Za-z0-9\-]{10,}"
    r"|AIza[A-Za-z0-9_\-]{20,}"
    r"|eyJ[A-Za-z0-9_\-]{10,}"
    r"|[A-Za-z0-9_\-]{40,})"
)

#: An argument that names a secret and then supplies one.
SECRETISH_RE = re.compile(r"(?i)(token|secret|password|passwd|api[_-]?key|bearer)\s*[=:]")

_URL_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*://[^/\s]+)")


def scrub_value(value):
    """Apply the checks that run regardless of where an argument appeared.

    A URL keeps its scheme and host — that is the part with audit value, since it
    says which endpoint an agent was pointed at — and loses its path, which is
    where session ids and tokens tend to live.
    """
    match = _URL_RE.match(value)
    if match:
        return match.group(1) + "/<redacted-path>"
    if "://" in value:
        return REDACTED_URL
    if SECRETISH_RE.search(value):
        return REDACTED_SECRETISH
    if TOKEN_RE.fullmatch(value) or (len(value) >= 40 and TOKEN_RE.search(value)):
        return REDACTED_TOKEN
    return value


def sanitize(argv, rules=None):
    """Return a redacted, printable rendering of ``argv``.

    ``rules`` is the ``redact`` section of an agent fingerprint. With no rules at
    all the result is maximally conservative: every positional is redacted and
    every flag is treated as boolean, which is the correct behaviour for an agent
    we do not recognise.
    """
    if not argv:
        return ""

    rules = rules or {}
    secret_flags = set(rules.get("secret_flags", ()))
    keep_flags = set(rules.get("keep_flags", ()))
    safe_words = set(rules.get("safe_words", ()))

    out = [scrub_value(argv[0])]
    index = 1
    while index < len(argv):
        argument = argv[index]

        if argument.startswith("--") and "=" in argument:
            flag, _, value = argument.partition("=")
            if flag in keep_flags and not SECRETISH_RE.search(argument):
                out.append(f"{flag}={scrub_value(value)}")
            else:
                # Unknown --flag=value is redacted rather than kept: we cannot
                # know that the value is not a prompt or a key.
                out.append(f"{flag}={REDACTED}")
            index += 1
            continue

        if argument.startswith("-") and argument != "-":
            out.append(argument)
            takes_value = argument in secret_flags or argument in keep_flags
            has_value = index + 1 < len(argv) and not argv[index + 1].startswith("-")
            if takes_value and has_value:
                value = argv[index + 1]
                out.append(REDACTED if argument in secret_flags else scrub_value(value))
                index += 2
            else:
                index += 1
            continue

        # Positional. Default-deny: safe only if the fingerprint says so, and
        # even then only if it does not itself look like a credential.
        if argument in safe_words and scrub_value(argument) == argument:
            out.append(argument)
        else:
            out.append(REDACTED)
        index += 1

    return " ".join(out)[:MAX_LENGTH]


def contains_secret(text):
    """Return ``True`` if ``text`` still looks like it carries a credential.

    Used as a last-line assertion before writing, and by ``selftest`` to prove
    the redaction path works on the host it was installed on.
    """
    return bool(TOKEN_RE.search(text) or SECRETISH_RE.search(text))
