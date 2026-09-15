"""Bearer-token comparison on the service HTTP surfaces.

The timing property itself is not assertable in a unit test — what is assertable is
that the comparison is the constant-time one, and that hardening it did not change the
*behaviour* of a bad token. That second half matters: `hmac.compare_digest` raises
TypeError on non-ASCII str input, so comparing header strings directly turns an
attacker-controlled header into a 500. These tests pin 401.
"""

from __future__ import annotations

import inspect

import pytest

from geg.services.common.auth import tokens_equal


# --- the helper ------------------------------------------------------------ #

@pytest.mark.parametrize(
    "presented,expected,want",
    [
        ("tok", "tok", True),
        ("tok", "tok2", False),
        ("to", "tok", False),           # prefix must not match
        ("tokk", "tok", False),
        ("tök", "tok", False),          # non-ASCII presented: unequal, NOT an exception
        ("tok", "tök", False),
        (None, "tok", False),           # missing header
        ("tok", None, False),           # peer token not installed yet
        (None, None, False),
        ("", "tok", False),             # empty never authenticates...
        ("tok", "", False),
        ("", "", False),                # ...even against an empty expected
        (b"tok", "tok", True),          # bytes/str mix
    ],
)
def test_tokens_equal(presented, expected, want):
    assert tokens_equal(presented, expected) is want


def test_tokens_equal_never_raises_on_hostile_input():
    for hostile in ["\udcff", "ö" * 100, "\x00tok", 12345, [], {"a": 1}]:
        assert tokens_equal(hostile, "tok") is False


def test_auth_paths_use_the_constant_time_helper():
    """Regression guard: a future refactor must not quietly go back to `!=`.

    A source assertion, deliberately — the timing behaviour it protects cannot be
    observed reliably from a test, so what we pin is that the plain compare is gone.
    """
    from geg.services.coordinator import coordinator
    from geg.services.keyper import keyper_server

    # The exact pre-fix expressions, so the check cannot be tripped by an unrelated
    # `!=` elsewhere in the module (e.g. a length or address comparison).
    for mod, old_compare in (
        (keyper_server, "tok != expected"),
        (coordinator, "presented != api_token"),
    ):
        src = inspect.getsource(mod)
        assert "tokens_equal" in src, f"{mod.__name__} no longer uses tokens_equal"
        assert old_compare not in src, f"{mod.__name__} reintroduced a plain != token compare"
