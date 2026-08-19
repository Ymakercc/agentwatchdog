"""Correlation digests for command lines, keyed per host.

The collector stores a digest of each command line so that identical invocations
can be recognised as identical without keeping what they said. A plain hash does
not achieve that. The event record next to it says exactly what the command
looked like — ``codex exec <redacted>`` — so anyone holding the log knows the
shape and has to guess only the redacted part, then hash their guess and compare.
For prompts, which are short and often guessable, that is a confirmation oracle:
"did they ask about the incident on the 14th?" is one hash away from an answer.

So the digest is an HMAC under a key that is generated per host, stored outside
the log directory, and never included in anything the tool ships or exports.
Correlation still works — the same command line on the same host always produces
the same digest — but a copy of the logs on its own proves nothing about content.

If the key cannot be read, the digest is omitted. Losing correlation is a small
loss; falling back to an unkeyed hash would quietly reinstate the oracle, which
is the one outcome this module exists to prevent.
"""

import hmac
import os
from hashlib import sha256

#: Length of the hex digest kept. 128 bits is far past collision concerns for
#: per-host correlation, and the shorter field keeps the event records readable.
DIGEST_HEX_LEN = 32

KEY_BYTES = 32


def load_key(path):
    """Return the host's digest key, or ``None`` if it cannot be read.

    Not an error: a checkout being exercised before ``install`` has no key, and
    the correct behaviour there is to record no digest.
    """
    try:
        with open(path, "rb") as fh:
            key = fh.read().strip()
    except OSError:
        return None
    return key or None


def create_key(path):
    """Create the key if absent and return it, or ``None`` if the path is not writable.

    Written 0600 before any content reaches it, so the key is never briefly
    readable by other accounts on the host.
    """
    existing = load_key(path)
    if existing is not None:
        return existing

    key = os.urandom(KEY_BYTES).hex().encode("ascii")
    tmp = path + ".tmp"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, key + b"\n")
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return None
    return key


def compute(raw, key):
    """Return the keyed digest of ``raw``, or ``None`` without a key or content."""
    if not raw or not key:
        return None
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "replace")
    return hmac.new(key, raw, sha256).hexdigest()[:DIGEST_HEX_LEN]
