#!/usr/bin/env python3
"""Build the single-file distribution.

The audience for this tool is someone on a server they already have, over SSH,
who does not want to install a package manager's opinion of anything. So there
has to be a form of this that is one file you can copy across and run.

Built with :mod:`zipapp` rather than by concatenating modules into one ``.py``.
Concatenation means rewriting every relative import and inlining the fingerprint
JSON, which breaks quietly whenever the package is reorganised. A zipapp is the
package as it actually is, with a shebang on the front — and the same code paths
run in it as in an installed copy, so testing one tests the other.

Usage:
    python3 scripts/build_singlefile.py [OUTPUT]
"""

import pathlib
import sys
import zipapp

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE = ROOT / "src"
DEFAULT_OUTPUT = ROOT / "agentwatchdog.pyz"


def build(output=DEFAULT_OUTPUT):
    output = pathlib.Path(output)
    zipapp.create_archive(
        SOURCE,
        target=output,
        interpreter="/usr/bin/env python3",
        main="agentwatchdog.cli:main",
        compressed=True,
    )
    output.chmod(0o755)
    return output


if __name__ == "__main__":
    destination = build(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_OUTPUT)
    size_kb = destination.stat().st_size / 1024
    print(f"built {destination} ({size_kb:.0f} KB)")
    print("Copy it to a host with python3 and run it directly:")
    print(f"  ./{destination.name} selftest")
