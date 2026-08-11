"""Which processes are AI coding agents, and how to redact each one.

Support for an agent is data, not code: a JSON file describing how to recognise
it and where it carries its prompt. Built-in fingerprints ship in
``agents.d/`` inside the package; an operator can add or override them by
dropping files into the directory named by the ``AGENTS_DIR`` setting.

A fingerprint has:

``id``, ``name``
    Identity. A file whose ``id`` matches a built-in one replaces it entirely,
    so an operator can correct a fingerprint without waiting for a release.
``comms``
    Exact matches against ``/proc/PID/comm``. This is the primary signal.
``path_markers``
    Substrings matched **against argv[0] only**, never the whole command line —
    otherwise ``grep @openai/codex`` would be reported as a running agent.
``persistent_markers``
    Substrings that mark a legitimately long-lived session, exempting the
    process from the runtime and frequency detectors.
``redact``
    Rules handed to :mod:`agentwatchdog.redact`. See that module for the model.
"""

import json
import os

BUILTIN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agents.d")

#: Fingerprint used for a process that matched nothing. Its empty rule set makes
#: :func:`agentwatchdog.redact.sanitize` maximally conservative.
UNKNOWN = {
    "id": "unknown",
    "name": "Unknown agent",
    "comms": [],
    "path_markers": [],
    "persistent_markers": [],
    "redact": {},
}


def _valid(data, found):
    if isinstance(data, dict) and data.get("id"):
        found.append(data)


def _load_builtin():
    """Return the fingerprints shipped inside the package.

    Read through ``importlib.resources`` rather than by path, because the
    single-file build is a zipapp: there is no directory to list, and
    ``__file__`` points inside an archive. Falls back to the filesystem so a
    plain source checkout keeps working.
    """
    found = []
    try:
        from importlib.resources import files

        for entry in sorted(files(__package__).joinpath("agents.d").iterdir(), key=_name):
            if entry.name.endswith(".json"):
                try:
                    _valid(json.loads(entry.read_text(encoding="utf-8")), found)
                except (OSError, ValueError):
                    continue
        if found:
            return found
    except (ImportError, AttributeError, FileNotFoundError, ModuleNotFoundError):
        pass
    return _load_dir(BUILTIN_DIR)


def _name(entry):
    return entry.name


def _load_dir(directory):
    """Return the fingerprints in a filesystem ``directory``, skipping bad files."""
    found = []
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return found
    for name in names:
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(directory, name), encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            # A malformed custom fingerprint must not take the monitor down; the
            # remaining agents still get watched.
            continue
        _valid(data, found)
    return found


def load(extra_dir=None, enabled=None):
    """Return the active fingerprints, newest definition of each id winning.

    ``enabled`` restricts the result to the given ids; an empty or ``None``
    value means every known agent is watched.
    """
    by_id = {}
    for fingerprint in _load_builtin():
        by_id[fingerprint["id"]] = fingerprint
    if extra_dir:
        for fingerprint in _load_dir(extra_dir):
            by_id[fingerprint["id"]] = fingerprint
    fingerprints = list(by_id.values())
    if enabled:
        wanted = set(enabled)
        fingerprints = [fp for fp in fingerprints if fp["id"] in wanted]
    return fingerprints


def identify(info, fingerprints):
    """Return the fingerprint matching this process, or ``None``.

    ``comm`` is checked before ``path_markers`` because it is the cheaper and
    more precise signal; the markers exist for the case where the agent runs
    under a generic interpreter name such as ``node`` or ``python3``.
    """
    comm = info.get("comm") or ""
    argv = info.get("argv") or []
    argv0 = argv[0] if argv else ""

    for fingerprint in fingerprints:
        if comm and comm in fingerprint.get("comms", ()):
            return fingerprint
    for fingerprint in fingerprints:
        for marker in fingerprint.get("path_markers", ()):
            if marker and marker in argv0:
                return fingerprint
    return None


def is_persistent(info, fingerprint, extra_regex=None):
    """Return ``True`` for a session that is meant to stay up.

    An interactive session an operator is sitting in front of, or a long-lived
    SDK session, is not a hung process and not a spawn storm. Treating them the
    same way would make the runtime and frequency detectors useless on exactly
    the hosts this tool is for.
    """
    args = info.get("args") or ""
    for marker in fingerprint.get("persistent_markers", ()):
        if marker and marker in args:
            return True
    if extra_regex is not None and extra_regex.search(args):
        return True
    return False
