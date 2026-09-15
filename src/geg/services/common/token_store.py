"""Coordinator-private keyper-credential persistence.

The keyper bootstrap tokens are minted by the **coordinator** (the sole
bootstrapper) and installed on the keypers. This encrypted file-backed store persists
them to the coordinator's private volume, keyed by **keyper URL** — the stable
identity of a keyper.

Each entry is a per-``(coordinator, keyper)`` **channel credential**
(``{api_token, peer_token}``): minted once and reused across every committee/election
that keyper joins, never rotated by a new committee. This is what keeps two
overlapping concurrent committees (e.g. ``{k1,k2,k3}`` then ``{k2,k3,k4}``) from
churning a shared keyper's single token slot — the shared keyper keeps the same
token, so the first election's coordinator→keyper calls keep authenticating. On
restart the coordinator reloads these instead of re-bootstrapping.

## Encryption at rest

The file is Fernet-encrypted with a key derived from the coordinator's signing key,
mirroring ``keyper_persistence`` so that **every** state directory in this system is
opaque. That uniformity is most of the point: an operator should have one rule
("state dirs are not readable") rather than an exception they have to remember, and a
plaintext file full of fields named ``api_token`` is the one that ends up pasted into
a bug report.

Be clear about what this does *not* buy. The key derives from
``COORDINATOR_SIGNING_KEY``, which lives in the same environment, so anyone who can
read this file can almost certainly read that too — this is no defence against host
compromise. What it defends is *partial* disclosure: a backup, a tarball, a copied
directory, a terminal share.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import pathlib

from cryptography.fernet import Fernet, InvalidToken
from eth_utils import keccak

_LOG = logging.getLogger("geg.coordinator")

# Distinct from ``KEYPER-FERNET-v1`` on purpose — see the module docstring.
_FERNET_INFO = b"COORDINATOR-FERNET-v1"


def derive_fernet(signing_sk: int) -> Fernet:
    """Derive the store-encryption key from the coordinator's signing key."""
    material = keccak(_FERNET_INFO + int(signing_sk).to_bytes(32, "big"))
    return Fernet(base64.urlsafe_b64encode(material))


class TokenStore:
    """File-backed ``keyper-URL → {api_token, peer_token}`` map on the coordinator's
    private volume."""

    def __init__(self, directory: str | os.PathLike, signing_sk: int):
        self._dir = pathlib.Path(directory)
        self._file = self._dir / "keyper_tokens.enc"
        # Fail closed. A store that could not derive a key must refuse to exist
        # rather than quietly fall back to plaintext, which is the one outcome
        # that would make this change worse than not making it.
        self._fernet = derive_fernet(signing_sk)

    def _load(self) -> dict:
        """The stored map, or empty when there is nothing readable.

        An undecryptable file is treated as absent rather than fatal: it means the
        signing key changed, and the coordinator's cold-start path already handles
        "no tokens" by re-bootstrapping the committee. Crashing instead would turn a
        recoverable key rotation into an outage. Logged at warning, because silently
        re-minting credentials should still be visible in an operator's logs.
        """
        try:
            raw = self._file.read_bytes()
        except FileNotFoundError:
            return {}
        try:
            return json.loads(self._fernet.decrypt(raw))
        except (InvalidToken, ValueError):
            _LOG.warning(
                "op=token_store status=unreadable file=%s — the signing key does not "
                "match the one that wrote it; treating as empty and re-bootstrapping",
                self._file,
            )
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
        tmp.write_bytes(self._fernet.encrypt(json.dumps(data).encode()))
        tmp.replace(self._file)  # atomic on the same filesystem
