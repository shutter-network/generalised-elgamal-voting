from __future__ import annotations

import json

import pytest

from geg.services.common.token_store import TokenStore, derive_fernet

SK = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
OTHER_SK = 0x0FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA098765432
URL = "http://keyper1:8101"


def test_round_trips_through_disk(tmp_path):
    store = TokenStore(tmp_path / "s", SK)
    store.put(URL, "api-aaa", "peer-bbb")
    assert TokenStore(tmp_path / "s", SK).get(URL) == {
        "api_token": "api-aaa",
        "peer_token": "peer-bbb",
    }


def test_merges_rather_than_replacing(tmp_path):
    """Two keypers share one file; recording the second must not drop the first."""
    store = TokenStore(tmp_path / "s", SK)
    store.put(URL, "api-1", "peer-1")
    store.put("http://keyper2:8102", "api-2", "peer-2")
    assert store.get(URL)["api_token"] == "api-1"
    assert store.get("http://keyper2:8102")["api_token"] == "api-2"


# --------------------------------------------------------------------------- #
#  The property the change exists for
# --------------------------------------------------------------------------- #

def test_the_file_reveals_nothing(tmp_path):
    """No token, URL, or field name is legible on disk.

    Asserted against the raw bytes rather than "is it valid JSON", because the
    failure that matters is a human reading the file, not a parser.
    """
    store = TokenStore(tmp_path / "s", SK)
    store.put(URL, "api-SECRET-TOKEN", "peer-SECRET-TOKEN")

    raw = (tmp_path / "s" / "keyper_tokens.enc").read_bytes()
    for needle in [b"api-SECRET-TOKEN", b"peer-SECRET-TOKEN", URL.encode(),
                   b"api_token", b"peer_token"]:
        assert needle not in raw
    with pytest.raises(ValueError):
        json.loads(raw)


def test_never_falls_back_to_plaintext(tmp_path):
    """The one outcome that would make this worse than not doing it."""
    store = TokenStore(tmp_path / "s", SK)
    store.put(URL, "api-aaa", "peer-bbb")
    files = sorted(f.name for f in (tmp_path / "s").iterdir())
    assert files == ["keyper_tokens.enc"]  # no .json, no stray .tmp


# --------------------------------------------------------------------------- #
#  Degradation
# --------------------------------------------------------------------------- #

def test_a_wrong_key_reads_as_empty_rather_than_raising(tmp_path, caplog):
    """A rotated signing key must degrade to a re-bootstrap, not an outage.

    "No tokens" is the coordinator's ordinary cold-start path, so returning empty
    puts it back on a path it already handles. Raising would turn a recoverable
    key change into a crash loop — and the tokens are re-mintable, unlike a keyper
    share, so there is nothing here worth failing hard to protect.
    """
    TokenStore(tmp_path / "s", SK).put(URL, "api-aaa", "peer-bbb")
    with caplog.at_level("WARNING"):
        assert TokenStore(tmp_path / "s", OTHER_SK).get(URL) is None
    # Silently re-minting credentials must still be visible to an operator.
    assert any("unreadable" in r.message for r in caplog.records)


def test_a_corrupt_file_reads_as_empty(tmp_path):
    store = TokenStore(tmp_path / "s", SK)
    store.put(URL, "api-aaa", "peer-bbb")
    (tmp_path / "s" / "keyper_tokens.enc").write_bytes(b"not a fernet token")
    assert store.get(URL) is None


def test_a_missing_file_reads_as_empty(tmp_path):
    assert TokenStore(tmp_path / "s", SK).get(URL) is None


def test_recovers_by_re_minting_after_a_key_change(tmp_path):
    """The whole degradation story, end to end: unreadable, then writable again."""
    TokenStore(tmp_path / "s", SK).put(URL, "api-old", "peer-old")
    fresh = TokenStore(tmp_path / "s", OTHER_SK)
    assert fresh.get(URL) is None
    fresh.put(URL, "api-new", "peer-new")
    assert fresh.get(URL)["api_token"] == "api-new"


# --------------------------------------------------------------------------- #
#  Domain separation
# --------------------------------------------------------------------------- #

def test_a_keyper_key_cannot_decrypt_a_coordinator_store(tmp_path):
    """Same construction, different label — so the two file families stay disjoint
    even if two services were somehow configured with the same signing key."""
    from geg.services.keyper.keyper_persistence import derive_fernet as keyper_fernet
    from cryptography.fernet import InvalidToken

    TokenStore(tmp_path / "s", SK).put(URL, "api-aaa", "peer-bbb")
    raw = (tmp_path / "s" / "keyper_tokens.enc").read_bytes()
    with pytest.raises(InvalidToken):
        keyper_fernet(SK).decrypt(raw)


def test_the_two_derivations_differ_for_one_key():
    from geg.services.keyper.keyper_persistence import derive_fernet as keyper_fernet

    probe = b"same plaintext"
    coordinator_ct = derive_fernet(SK).encrypt(probe)
    # Fernet is randomised, so compare by cross-decryption rather than by bytes.
    from cryptography.fernet import InvalidToken

    with pytest.raises(InvalidToken):
        keyper_fernet(SK).decrypt(coordinator_ct)
    assert derive_fernet(SK).decrypt(coordinator_ct) == probe


def test_different_keys_give_different_stores():
    """Two coordinators with different keys cannot read each other's stores."""
    from cryptography.fernet import InvalidToken

    ct = derive_fernet(SK).encrypt(b"probe")
    with pytest.raises(InvalidToken):
        derive_fernet(OTHER_SK).decrypt(ct)
