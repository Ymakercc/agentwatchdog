"""Allow ``python3 -m agentwatchdog`` for checkouts and single-file drops."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
