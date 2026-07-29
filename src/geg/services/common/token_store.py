"""Coordinator-private keyper-credential persistence.

The keyper bootstrap tokens are minted by the **coordinator** (the sole
bootstrapper) and installed on the keypers. This file-backed store persists them to
the coordinator's private volume, keyed by **keyper URL** — the stable identity of a
keyper endpoint.

Each entry is a per-``(coordinator, keyper)`` **channel credential**
(``{api_token, peer_token}``): minted once and reused across every committee/election
that keyper joins, never rotated by a new committee. This is what keeps two
overlapping concurrent committees (e.g. ``{k1,k2,k3}`` then ``{k2,k3,k4}``) from
churning a shared keyper's single token slot — the shared keyper keeps the same
token, so the first election's coordinator→keyper calls keep authenticating. On
restart the coordinator reloads these instead of re-bootstrapping.

Tokens are stored in plaintext on an internal, non-committed volume (consistent
with ``COORDINATOR_API_TOKEN`` living in ``.env``). Encrypt-at-rest is a possible
future hardening.
"""

from __future__ import annotations

import json
import os
import pathlib


class TokenStore:
    """File-backed ``keyper-URL → {api_token, peer_token}`` map on the coordinator's
    private volume."""

    def __init__(self, directory: str | os.PathLike):
        self._dir = pathlib.Path(directory)
        self._file = self._dir / "keyper_tokens.json"

    def _load(self) -> dict:
        try:
            return json.loads(self._file.read_text())
        except (FileNotFoundError, ValueError):
            return {}

    def get(self, url: str) -> dict | None:
        """Return this keyper's ``{api_token, peer_token}``, or ``None`` if unminted."""
        entry = self._load().get(url)
        return dict(entry) if entry else None

    def put(self, url: str, api_token: str, peer_token: str) -> None:
        """Record this keyper's stable credential (atomic; merges with other keypers)."""
        self._dir.mkdir(parents=True, exist_ok=True)
        data = self._load()
        data[url] = {"api_token": api_token, "peer_token": peer_token}
        tmp = self._file.with_suffix(".tmp")
        tmp.write_text(json.dumps(data))
        tmp.replace(self._file)  # atomic on the same filesystem
