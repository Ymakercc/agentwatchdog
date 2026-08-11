"""Types shared by the detectors.

Kept apart from ``detect/__init__.py`` so that a detector can import what it
needs without the package importing it back — the alternative is deferred
imports inside functions, which hide the dependency and break in ways that only
show up at runtime.
"""

from typing import NamedTuple


class Finding(NamedTuple):
    """A candidate alert, before cooldown and formatting are applied."""

    #: Stable machine-readable name, e.g. ``"long_running_process"``.
    type: str
    #: ``"warning"`` or ``"critical"``.
    severity: str
    #: Identity of *the situation*, not the occurrence. The same hung process
    #: must produce the same key on every scan, or its cooldown never applies.
    key: str
    #: What was observed, in a sentence an operator can act on at 3am.
    reason: str
    #: What to do about it, including the command to run.
    action: str
    #: Detector-specific fields attached to the emitted alert.
    extra: dict


class Context(NamedTuple):
    """Everything the detectors are allowed to look at."""

    #: Unix timestamp of this scan.
    now: int
    #: Effective configuration.
    cfg: dict
    #: Agent process events observed in this scan.
    processes: list
    #: Recent agent starts within ``WINDOW_SEC``, from persisted state.
    invocations: list
    #: CPU count, for judging what "loaded" means on this host.
    cores: int
    #: Five-minute load average, or ``None`` if unavailable.
    load5: float
