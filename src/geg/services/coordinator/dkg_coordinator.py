"""DKG coordinator daemon.

A standing watcher that drives the keyper ceremony for ``Registered`` elections
lacking a finalized key, sequencing ``round1 → distribute_commitments →
distribute_shares → round2 → submit_dkg_result``. It holds no secrets; its
compromise affects liveness only.

Retry/backoff to a hard lead-time deadline: attempts are bounded and must complete before
``voting_start`` minus a margin. Sleeping is injected (``sleep``) so tests drive
the schedule deterministically; wall-clock is read via ``clock``.
"""

from __future__ import annotations

import logging
import secrets
import time

import requests

from geg.crypto.dkg import derive_joint_mpk
from geg.crypto.points import g2_to_compressed
from geg.ports.data_layer import ElectionDataLayer
from geg.services.keyper import keyper_bootstrap as boot
from geg.services.keyper import KeyperService

# Shared with AutoDKG (same logger name), so the ceremony/trigger driver and the
# lifecycle watcher interleave under one "geg.coordinator" stream — the operator sees
# per-phase progress and *which* keyper/phase failed, not just a terminal error.
_LOG = logging.getLogger("geg.coordinator")


class DKGError(RuntimeError):
    pass


class DKGComplaint(DKGError):
    """A committee member reported a Feldman-VSS complaint against a dealer during
    round2. Terminal for this ceremony: a divergent transcript can never finalize, so
    the coordinator halts *before* publishing and surfaces the signed accusations for
    manual resolution (see DKG_SECURITY_HARDENING_PLAN.md). Carries the accusations."""

    def __init__(self, message: str, accusations: list[dict]):
        super().__init__(message)
        self.accusations = accusations


def keyper_urls_from(config, overrides: dict[str, str] | None = None) -> dict[int, str]:
    """Map keyper index (1-based) → HTTP URL for the ceremony/trigger.

    URLs come from the election config on every backend — including blockchain,
    where the KeyperSet contract stores per-member URLs (read back via the port).
    ``overrides`` (address-keyed, lowercase hex) is a vestigial escape hatch and is
    normally empty.
    """
    overrides = overrides or {}
    return {
        i: (k.url or overrides.get(bytes(k.signing_key).hex().lower(), ""))
        for i, k in enumerate(config.keypers, start=1)
    }


def run_dkg_once(election_id: bytes, keypers: list[KeyperService], n: int, t: int) -> bool:
    """One full ceremony attempt over the given keypers, **in-process (single-process
    test/simulation transport only)**.

    This is the DKG twin of ``tally_aggregator.run_tally``: it drives live
    ``KeyperService`` objects in the same process (rounds + submit) instead of the
    deployed HTTP path (:func:`run_dkg_http`, keyper ``/dkg/*`` endpoints, confidential
    keyper→keyper share exchange). Used only by the protocol-level e2e tests via
    :func:`ensure_dkg`; no production caller. The multi-operator deployment always uses
    :func:`run_dkg_http`.

    Returns whether the data layer's quorum rule now reports a finalized key.
    """
    if len(keypers) != n:
        raise DKGError(f"expected {n} keypers, got {len(keypers)}")

    # Round 1: each keyper produces commitments + shares for every recipient.
    all_commitments: dict[int, list] = {}
    all_shares: dict[int, dict[int, int]] = {}
    for k in keypers:
        comms, shares = k.dkg_round1(n, t)
        all_commitments[k.index] = comms
        all_shares[k.index] = shares

    # Distribute + Round 2: each keyper verifies the shares addressed to it.
    for k in keypers:
        received = {dealer: all_shares[dealer][k.index] for dealer in all_commitments}
        k.dkg_round2(all_commitments, received)

    # Submit: each keyper derives and submits the (byte-identical) joint result.
    for k in keypers:
        k.submit_dkg_result(election_id, all_commitments)

    return keypers[0].dl.get_finalized_key(election_id) is not None


def ensure_dkg(
    election_id: bytes,
    keypers: list[KeyperService],
    data_layer: ElectionDataLayer,
    *,
    n: int,
    t: int,
    clock,
    deadline: int,
    max_attempts: int = 5,
    sleep=lambda _s: None,
    backoff_base: float = 10.0,
) -> bool:
    """Drive the ceremony with retry/backoff until finalized or the deadline.

    **In-process test/simulation harness only** (wraps :func:`run_dkg_once`); the
    deployed coordinator uses the HTTP watcher (:class:`AutoDKG` → :func:`run_dkg_http`).

    ``deadline`` is the hard cutoff (e.g. ``voting_start - margin``). Returns
    ``True`` if the key finalized in time; ``False`` if attempts/ deadline were
    exhausted (the election then derives to ``DKGFailed`` at ``voting_start``).
    """
    if data_layer.get_finalized_key(election_id) is not None:
        return True
    for attempt in range(max_attempts):
        if clock() >= deadline:
            return False
        try:
            if run_dkg_once(election_id, keypers, n, t):
                return True
        except Exception:  # noqa: BLE001 — a failed attempt is retried, not fatal
            pass
        if attempt < max_attempts - 1:
            sleep(backoff_base * (2 ** attempt))
    return data_layer.get_finalized_key(election_id) is not None


# --------------------------------------------------------------------------- #
#  HTTP driver — drive a multi-operator keyper deployment over the wire
# --------------------------------------------------------------------------- #

def bootstrap_keypers(coordinator, keyper_urls: dict[int, str], *, member_addrs: dict[int, bytes],
                      relay_token: str | None = None, token_store=None, install: set[int] | None = None,
                      timeout: float = 10.0):
    """Install per-keyper channel credentials via each keyper's /auth/bootstrap.

    Each keyper's ``{api_token, peer_token}`` is a **stable per-(coordinator, keyper)
    credential**: reused from ``token_store`` if present, else freshly minted and
    persisted. Only the per-committee peer *map* differs between bootstraps — so a
    keyper that sits in two overlapping committees keeps the same token slot and never
    gets churned (the concurrent-election bug). Tokens for *every* member are computed
    (the peer map needs them), but /auth/bootstrap is POSTed only to the members in
    ``install`` (default: all) — pass a subset to re-install a single keyper on a 401.

    Fetches each keyper's X25519 encryption pubkey (/status) and VERIFIES it against
    that keyper's ``member_addrs`` entry (its config signing address) before use, then
    seals a per-keyper token bundle to the verified key, signs it with the coordinator
    identity, and posts it. Every *other* keyper's verified ``{enc_pubkey,
    enc_pubkey_sig}`` is embedded in the peer map so dealers can seal shares to it.
    ``relay_token`` (the coordinator's write-relay bearer) rides inside the same
    sealed+signed payload so keypers need not pre-share it. Returns
    ``(api_tokens, peer_tokens)`` keyed by keyper index (all members).
    """
    api_tokens: dict[int, str] = {}
    peer_tokens: dict[int, str] = {}
    reused: dict[int, bool] = {}
    for i, url in keyper_urls.items():
        cred = token_store.get(url) if token_store is not None else None
        reused[i] = cred is not None
        if cred is None:  # first time this keyper is seen by this coordinator → mint + persist
            cred = {"api_token": secrets.token_urlsafe(32), "peer_token": secrets.token_urlsafe(32)}
            if token_store is not None:
                token_store.put(url, cred["api_token"], cred["peer_token"])
        api_tokens[i] = cred["api_token"]
        peer_tokens[i] = cred["peer_token"]

    # Fetch every keyper's X25519 encryption pubkey (+ self-binding signature) and VERIFY
    # it against that keyper's config member address before use. The verified key object
    # seals the keyper's own bootstrap bundle (closing a blind-trust MITM on /status); the
    # raw {enc_pubkey, enc_pubkey_sig} rides in every *other* keyper's peer map so dealers
    # can seal shares to it (re-verifying against the peer's member address at send time).
    enc_raw: dict[int, dict[str, str]] = {}
    enc_pub: dict[int, object] = {}
    for i, url in keyper_urls.items():
        try:
            st = requests.get(url.rstrip("/") + "/status", timeout=timeout).json()
            enc_hex, enc_sig = st["encryptionPubkey"], st["encryptionPubkeySig"]
            enc_pub[i] = boot.verify_encryption_pubkey(member_addrs[i], enc_hex, enc_sig)
            enc_raw[i] = {"enc_pubkey": enc_hex, "enc_pubkey_sig": enc_sig}
        except Exception as err:  # noqa: BLE001 — re-raised; caller backs off and retries
            _LOG.error("op=bootstrap keyper=%d url=%s status=enc_pubkey_error err=%s", i, url, err)
            raise

    targets = keyper_urls if install is None else {i: keyper_urls[i] for i in install}
    for i, url in targets.items():
        # Seal+sign this keyper's bundle and install it — attributing any failure to the
        # specific keyper so a stuck committee names the culprit, not a generic error.
        try:
            payload = {
                "api_token": api_tokens[i],
                "peer_token": peer_tokens[i],
                "relay_token": relay_token,
                # Each peer entry: where to reach it, what to authenticate with, and the
                # X25519 key to seal shares to (the dealer re-verifies it before sealing).
                "peers": {str(j): {"url": keyper_urls[j], "token": peer_tokens[j], **enc_raw[j]}
                          for j in keyper_urls if j != i},
                "nonce": secrets.token_hex(16),
                "timestamp": int(time.time()),
            }
            sig = boot.sign_payload(coordinator, payload)
            sealed = boot.x25519_seal(boot.canonical_payload_bytes(payload), enc_pub[i])
            requests.post(url.rstrip("/") + "/auth/bootstrap",
                          json={"sealed": sealed.hex(), "signature": sig.hex()}, timeout=timeout).raise_for_status()
        except Exception as err:  # noqa: BLE001 — re-raised; caller backs off and retries
            _LOG.error("op=bootstrap keyper=%d url=%s status=error err=%s", i, url, err)
            raise
        _LOG.debug("op=bootstrap keyper=%d url=%s status=installed token=%s",
                   i, url, "reused" if reused[i] else "minted")
    return api_tokens, peer_tokens


def _post_keyper(url: str, path: str, election_id: bytes, api_tokens: dict[int, str], i: int,
                 *, rebootstrap=None, timeout: float, op: str | None = None):
    """POST a coordinator→keyper trigger, recovering from a stale-token 401.

    On ``401`` — the keyper doesn't hold the token we presented (state loss, or a
    credential the coordinator minted but never installed on this keyper) — call
    ``rebootstrap(i)`` to re-install this keyper's *stable* credential and retry once
    with the returned token. Because credentials are per-keyper (Option D), re-installing
    keyper ``i`` never disturbs any other keyper, so this can't ping-pong between
    concurrent elections. Returns the response, or ``None`` if the call errored out.

    A trigger is best-effort (the data-layer quorum is the real success gate and the
    next poll retries), but failures are **logged** — an unreachable keyper or a 5xx
    during tally would otherwise be invisible, leaving the operator staring at a stalled
    election with no clue which keyper is down.
    """
    op = op or path.lstrip("/")
    eid_hex = election_id.hex()
    body = {"electionId": eid_hex}
    try:
        r = requests.post(url.rstrip("/") + path, json=body,
                          headers={"Authorization": f"Bearer {api_tokens[i]}"}, timeout=timeout)
        if r.status_code == 401 and rebootstrap is not None:
            _LOG.info("op=%s keyper=%d status=reauth election=%s (401 → re-bootstrap + retry)", op, i, eid_hex)
            token = rebootstrap(i)  # re-install stable token; returns it (unchanged) or None
            if token:
                api_tokens[i] = token
                r = requests.post(url.rstrip("/") + path, json=body,
                                  headers={"Authorization": f"Bearer {token}"}, timeout=timeout)
        if r.status_code >= 500:
            _LOG.warning("op=%s keyper=%d status=error http=%d election=%s", op, i, r.status_code, eid_hex)
        return r
    except Exception as err:  # noqa: BLE001 — best-effort; retried next poll
        _LOG.warning("op=%s keyper=%d status=unreachable election=%s err=%s", op, i, eid_hex, err)
        return None


def run_dkg_http(election_id: bytes, keyper_urls: dict[int, str], api_tokens: dict[int, str],
                 data_layer: ElectionDataLayer, *, rebootstrap=None, timeout: float = 30.0) -> bool:
    """Sequence the DKG ceremony over HTTP; return whether the key finalized.

    ``rebootstrap(i)`` (optional) re-installs keyper ``i``'s stable credential and
    returns its token; used to recover a phase call that comes back ``401``."""
    eid_hex = election_id.hex()

    def call(i: int, phase: str):
        path = "/dkg/" + phase
        try:
            r = requests.post(keyper_urls[i].rstrip("/") + path, json={"electionId": eid_hex},
                              headers={"Authorization": f"Bearer {api_tokens[i]}"}, timeout=timeout)
            if r.status_code == 401 and rebootstrap is not None:
                _LOG.info("op=dkg phase=%s keyper=%d status=reauth election=%s", phase, i, eid_hex)
                token = rebootstrap(i)
                if token:
                    api_tokens[i] = token
                    r = requests.post(keyper_urls[i].rstrip("/") + path, json={"electionId": eid_hex},
                                      headers={"Authorization": f"Bearer {token}"}, timeout=timeout)
            r.raise_for_status()
            return r.json()
        except Exception as err:  # noqa: BLE001 — re-raised; _drive_dkg backs off + retries
            _LOG.error("op=dkg phase=%s keyper=%d status=error election=%s err=%s", phase, i, eid_hex, err)
            raise

    idxs = sorted(keyper_urls)
    for phase in ("round1", "distribute_commitments", "distribute_shares"):
        for i in idxs:
            call(i, phase)
        _LOG.info("op=dkg phase=%s status=ok election=%s keypers=%d", phase, eid_hex, len(idxs))

    # round2 — collect complaints. A verified:false response carries recipient-signed
    # accusations (DKG-ACCUSE-v1). If ANY keyper complains we HALT before publishing (a
    # divergent transcript would never finalize) and surface the signed evidence for
    # manual resolution. Automated adjudicate → exclude → re-round2 is future work.
    complaints = [(i, resp) for i in idxs
                  if isinstance(resp := call(i, "round2"), dict) and resp.get("verified") is False]
    _LOG.info("op=dkg phase=round2 status=ok election=%s keypers=%d", eid_hex, len(idxs))
    if complaints:
        accusations = [acc for _i, resp in complaints for acc in resp.get("accusations", [])]
        for acc in accusations:
            _LOG.error("op=dkg_complaint accuser_kid=%s accused_dealer=%s election=%s signature=%s",
                       acc.get("recipientIndex"), acc.get("accusedDealerIndex"),
                       acc.get("electionId"), acc.get("signature"))
        accused = sorted({acc.get("accusedDealerIndex") for acc in accusations})
        raise DKGComplaint(
            f"DKG halted: complaint(s) against dealer(s) {accused}; not publishing on chain. "
            f"Signed accusations logged above; resolve manually (see DKG_SECURITY_HARDENING_PLAN.md).",
            accusations)

    for i in idxs:
        call(i, "publish")
    _LOG.info("op=dkg phase=publish status=ok election=%s keypers=%d", eid_hex, len(idxs))
    return data_layer.get_finalized_key(election_id) is not None


def trigger_decrypt_http(election_id: bytes, keyper_urls: dict[int, str], api_tokens: dict[int, str],
                         *, rebootstrap=None, timeout: float = 30.0) -> None:
    """Trigger each keyper's /decrypt (keypers self-guard on their preconditions). A ``401`` is
    recovered via ``rebootstrap`` (Option D safety net); other failures are best-effort
    (the share-count quorum is the real gate and the next poll retries)."""
    for i, url in keyper_urls.items():
        _post_keyper(url, "/decrypt", election_id, api_tokens, i, rebootstrap=rebootstrap, timeout=timeout, op="decrypt")


def trigger_aggregate_http(election_id: bytes, keyper_urls: dict[int, str], api_tokens: dict[int, str],
                           *, rebootstrap=None, timeout: float = 30.0) -> None:
    """Trigger each keyper's /aggregate (keypers self-guard on votingEnd). A ``401`` is
    recovered via ``rebootstrap`` (Option D safety net); other failures are best-effort.

    Each keyper re-derives the same deterministic aggregate from the ordered ballots
    and submits it signed; the data layer makes it canonical at the t+1 quorum."""
    for i, url in keyper_urls.items():
        _post_keyper(url, "/aggregate", election_id, api_tokens, i, rebootstrap=rebootstrap, timeout=timeout, op="aggregate")
