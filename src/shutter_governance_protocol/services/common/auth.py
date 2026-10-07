"""Shared bearer-token comparison for the service HTTP surfaces.

Exists so the constant-time compare is written once and the same way everywhere:
a plain ``!=`` on a secret short-circuits at the first differing byte
and leaks a token prefix through response timing.
"""

from __future__ import annotations

import hmac


def tokens_equal(presented: object, expected: object) -> bool:
    """Constant-time equality for two bearer tokens. Never raises.

    Compares **bytes**, not str. ``hmac.compare_digest`` raises TypeError on a str
    containing non-ASCII characters, and the presented token is attacker-controlled —
    comparing str directly would turn `Authorization: Bearer tök` into a 500 instead of
    a 401, which is a worse bug than the timing leak this function exists to close.
    A missing or non-string token is simply unequal.
    """
    if not isinstance(presented, (str, bytes)) or not isinstance(expected, (str, bytes)):
        return False
    # surrogateescape, not strict: a header can decode to a lone surrogate, and
    # str.encode("utf-8") raises UnicodeEncodeError on those. This function is on the
    # auth path for attacker-controlled input, so it must never raise.
    p = presented.encode("utf-8", "surrogateescape") if isinstance(presented, str) else presented
    e = expected.encode("utf-8", "surrogateescape") if isinstance(expected, str) else expected
    if not p or not e:  # an empty token never authenticates
        return False
    return hmac.compare_digest(p, e)
