"""Host-side runtime audit for terminal AI coding agents.

agentwatchdog observes AI coding agent processes from outside the agent, by
reading /proc and ps. It never reads prompt content and never opens
/proc/PID/environ; see SECURITY.md for the guarantees this package is built to
keep.
"""

__version__ = "0.1.0.dev0"

__all__ = ["__version__"]
