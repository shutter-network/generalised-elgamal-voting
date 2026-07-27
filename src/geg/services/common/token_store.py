"""Shared keyper-token store (coordinator writes, tally-aggregator reads).

The keyper bootstrap api-tokens are minted by the **coordinator** (the sole
bootstrapper) and installed on the keypers. Other admin-plane services that must
call keyper endpoints — today the tally aggregator's ``/decrypt`` trigger — need
those same tokens, but they run in separate processes with no access to the
coordinator's in-memory cache.

This is a tiny file-backed hand-off over a **shared volume**: the coordinator
writes the tokens keyed by committee (the keyper URL set), and readers look them
up by the same committee. Because the coordinator is the *only* bootstrapper, the
keyper's single token slot is never overwritten by anyone else, so the stored
token always matches what the keyper currently accepts — no re-bootstrap, no churn.

Tokens are stored in plaintext on an internal, non-committed volume (consistent
with ``COORDINATOR_API_TOKEN`` living in ``.env``). Encrypt-at-rest is a possible
future hardening.
"""

from __future__ import annotations

import json
import os
import pathlib


def _committee_key(urls: dict[int, str]) -> str:
    """Stable string key for a committee (its index→URL map)."""
    return "|".join(f"{i}={urls[i]}" for i in sorted(urls))


class TokenStore:
    """File-backed committee→api-tokens map on a shared volume."""

    def __init__(self, directory: str | os.PathLike):
        self._dir = pathlib.Path(directory)
        self._file = self._dir / "keyper_tokens.json"

    def _load(self) -> dict:
        try:
            return json.loads(self._file.read_text())
        except (FileNotFoundError, ValueError):
            return {}

    def write(self, urls: dict[int, str], api_tokens: dict[int, str]) -> None:
        """Record this committee's api-tokens (atomic; merges with other committees)."""
        self._dir.mkdir(parents=True, exist_ok=True)
        data = self._load()
        data[_committee_key(urls)] = {str(i): t for i, t in api_tokens.items()}
        tmp = self._file.with_suffix(".tmp")
        tmp.write_text(json.dumps(data))
        tmp.replace(self._file)  # atomic on the same filesystem

    def read(self, urls: dict[int, str]) -> dict[int, str] | None:
        """Return this committee's api-tokens, or ``None`` if not yet written."""
        entry = self._load().get(_committee_key(urls))
        return {int(i): t for i, t in entry.items()} if entry else None
