"""Retention default for a keyper's per-election secrets.

Retention itself is deliberate — operators need the secret for late or repeated
decryption — so the 90-day window is unchanged. What the fix changes is the *fallback*:
an unset `KEYPER_SECRET_TTL_S` used to produce `expires_at=None` and nothing was ever
pruned, so safe behaviour depended on the compose file passing the variable and a bare
`python -m geg.services.keyper` kept every historical share for ever.
"""

from __future__ import annotations

import pytest

from geg.services.keyper.keyper_server import _DEFAULT_SECRET_RETENTION_S, _parse_secret_ttl


def test_code_default_matches_the_compose_default():
    """Pinned so the two cannot drift apart (docker-compose.keyper.yml passes 7776000)."""
    assert _DEFAULT_SECRET_RETENTION_S == 7_776_000 == 90 * 24 * 3600


@pytest.mark.parametrize("raw", [None, "", "  "])
def test_unset_or_blank_is_finite_not_forever(raw):
    """The regression this closes. Blank matters as much as unset: a compose var or env
    file entry that is set-but-empty arrives as "", which a plain getenv default misses."""
    assert _parse_secret_ttl(raw) == _DEFAULT_SECRET_RETENTION_S


@pytest.mark.parametrize("raw,want", [("3600", 3600), (" 60 ", 60), ("0", 0)])
def test_explicit_values_keep_their_meaning(raw, want):
    assert _parse_secret_ttl(raw) == want


def test_indefinite_retention_stays_available_but_must_be_stated():
    assert _parse_secret_ttl("never") is None
    assert _parse_secret_ttl("NEVER") is None


def test_malformed_value_raises_rather_than_retaining_forever():
    """Silently falling back to indefinite retention is the failure mode being closed."""
    with pytest.raises(ValueError):
        _parse_secret_ttl("90d")
