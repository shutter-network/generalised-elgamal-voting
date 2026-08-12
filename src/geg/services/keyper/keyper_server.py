"""Deployable keyper HTTP service (geg ports).

One process per committee member. Wraps the keyper crypto (`KeyperDKGState`,
partial decryption) behind an authenticated HTTP API the DKG coordinator drives,
with confidential round-2 shares travelling **directly keyper→keyper**. Secrets
persist encrypted at rest (:mod:`geg.services.keyper_persistence`) so the process
survives the gap between DKG and decryption.

Auth (fail-closed until bootstrapped): coordinator→keyper endpoints require the
``api_token``; keyper→keyper (`/dkg/receive_*`) require the callee's ``peer_token``;
``/status``, ``/health``, ``/auth/bootstrap`` are open. Tokens are installed via a
one-time X25519-sealed + coordinator-signed :func:`/auth/bootstrap` and persisted.

DKG peer-to-peer traffic is authenticated **and** confidential: dealers EIP-191-sign
their commitments and shares (verified against the dealer's config member address), and
each secret share travels **sealed** to the recipient's X25519 key — published and
self-bound on ``/status`` as ``encryptionPubkey`` / ``encryptionPubkeySig`` so a relayed
key is verified against the member address before anyone seals to it. A Feldman-VSS
complaint at ``/dkg/round2`` returns recipient-signed ``DKG-ACCUSE-v1`` accusations; the
accused dealer's ``/dkg/reveal_share`` discloses a share **only** on such an accusation
from that share's own recipient (so a caller can never harvest others' shares), and the
coordinator halts the ceremony before publishing if any keyper complains.

The server never trusts a decryption trigger — `/publish_decr_share` re-checks the
preconditions against the data layer (via :class:`KeyperService`). There is deliberately
no oracle that partial-decrypts a caller-supplied ciphertext.
"""

from __future__ import annotations

import json
import logging
import os
import threading

import requests
from flask import Flask, abort, jsonify, request

from geg.core import write_auth
from geg.crypto.dkg import KeyperDKGState, derive_joint_mpk, derive_mpk_share
from geg.crypto.points import g2_from_compressed, g2_to_compressed
from geg.ports.data_layer import ImmutabilityError
from geg.services.data_layer.data_layer import PORT_READ_PREFIX
from . import keyper_bootstrap as boot
from . import keyper_persistence as persist
from .keyper import KeyperService

_OPEN = {"/status", "/health", "/auth/bootstrap"}
_PEER = {"/dkg/receive_commitments", "/dkg/receive_share"}
# Retention TTL for a keyper's per-election secrets, measured from voting_end (there is no
# tally deadline any more — a keyper can decrypt however late, up to this bound). The default
# is owned by the deployment (compose `KEYPER_SECRET_TTL_S`); when unset the secret is kept
# indefinitely (expires_at=None → never pruned) rather than baking a default value in here.
_ttl = os.environ.get("KEYPER_SECRET_TTL_S")
_SECRET_RETENTION_S = int(_ttl) if _ttl else None


def _is_benign_write_conflict(err: Exception) -> bool:
    """True if a keyper write lost a benign race: the artifact it is submitting is
    already canonical/recorded, so its (byte-identical) contribution wasn't needed.

    Happens when the ``t+1`` quorum finalizes the aggregate (or enough decryption
    shares land) just before this keyper's submission — expected with a committee
    larger than the threshold. A **direct** write raises :class:`ImmutabilityError`;
    a write **via the coordinator relay** surfaces the same as an HTTP ``409``. Either
    way it is not a fault — distinct from a real 4xx/5xx, which still propagates."""
    if isinstance(err, ImmutabilityError):
        return True
    resp = getattr(err, "response", None)  # requests.HTTPError from the relay
    return resp is not None and resp.status_code == 409


def build_keyper_app(signer, data_layer, trusted_identities, *, clock, state_dir,
                     submitter=None, logger=None):
    """Build a keyper Flask app bound to one committee identity (`signer`).

    ``trusted_identities`` is the pinned set of bootstrapper addresses the keyper
    accepts on ``/auth/bootstrap`` — a single 20-byte address or an iterable (the
    coordinator, the sole keyper bootstrapper). ``state_dir`` is this keyper's private
    encrypted-state directory. Reads go to
    ``data_layer``; **writes** (DKG result, aggregate, decryption shares) go to ``submitter`` —
    which defaults to ``data_layer`` (direct write, in-process/simple deployments) or
    is a :class:`~geg.services.coordinator.CoordinatorClient` that POSTs the signed
    artifacts to the coordinator relay (the multi-operator path). Either way the
    keyper only ever *signs* — the data layer / contract verifies authorship.
    """
    import pathlib

    submitter = submitter or data_layer
    trusted_identities = boot.as_identity_set(trusted_identities)
    log = logger or logging.getLogger("geg.keyper")
    state_dir = pathlib.Path(state_dir)
    app = Flask(__name__)
    lock = threading.Lock()

    @app.after_request
    def _cors(resp):
        # The admin browser app reads the open /status (GET, no custom headers → a
        # "simple" request, so no preflight) to resolve this keyper's address at
        # registration time. Expose it cross-origin. Auth'd routes still require the
        # bearer regardless of origin, so this only widens read access to /status,
        # /health, /auth/bootstrap.
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return resp

    fernet = persist.derive_fernet(signer.private_key)
    x25519 = persist.load_or_create_x25519(fernet, state_dir, log)
    # Self-sign this keyper's X25519 encryption pubkey, binding it to the keyper's
    # secp256k1 identity. Published on /status so the coordinator (before sealing a
    # bootstrap bundle) and dealers (before sealing a share) can verify a relayed key
    # against this keyper's config member address instead of trusting it blindly.
    enc_pubkey_bytes = x25519.public_key().public_bytes_raw()
    enc_pubkey_sig_hex = boot.sign_encryption_pubkey(signer, enc_pubkey_bytes).hex()
    completed: dict[str, persist.DkgEntry] = {}
    persist.load_dkg_secrets(fernet, completed, state_dir, log)
    dkg_states: dict[str, KeyperDKGState] = {}
    inbox: dict[str, dict] = {}
    nonce_tracker = boot.NonceTracker()

    tokens = persist.load_bootstrap_tokens(fernet, state_dir, log) or {}
    installed = {
        "api_token": tokens.get("api_token"),
        "peer_token": tokens.get("peer_token"),
        "relay_token": tokens.get("relay_token"),  # keyper→coordinator relay bearer (pushed via bootstrap)
        "peers": tokens.get("peers", {}),
    }

    def _apply_relay_token() -> None:
        # The relay bearer is pushed over /auth/bootstrap (not pre-shared), so point
        # the write client (CoordinatorClient) at it. Reloaded from state on restart.
        if submitter is not data_layer and hasattr(submitter, "token") and installed["relay_token"]:
            submitter.token = installed["relay_token"]

    _apply_relay_token()
    persist.start_prune_loop(completed, fernet, state_dir, log, lock)

    # -- helpers ------------------------------------------------------------ #

    def _eid(body) -> bytes:
        return bytes.fromhex(body["electionId"])

    def _config(election_id: bytes):
        return data_layer.get_election(election_id).config

    def _my_index(config) -> int:
        for i, k in enumerate(config.keypers, start=1):
            if k.signing_key == signer.identity:
                return i
        abort(403, "this keyper is not in the election's keyper set")

    def _members_addr(config, index: int) -> bytes | None:
        """The config member (signing) address for a 1-based keyper index — the trust
        anchor for verifying peer enc pubkeys and dealer/accuser signatures. Sourced
        from the data-layer config, so it is identical on the db and chain backends."""
        if 1 <= index <= len(config.keypers):
            return bytes(config.keypers[index - 1].signing_key)
        return None

    def _inbox(eid_hex: str) -> dict:
        return inbox.setdefault(eid_hex, {"commitments": {}, "shares": {}})

    def _peer(index: int) -> dict:
        return installed["peers"][str(index)]

    def _post_peer(index: int, path: str, body: dict) -> None:
        p = _peer(index)
        requests.post(p["url"].rstrip("/") + path, json=body,
                      headers={"Authorization": f"Bearer {p['token']}"}, timeout=10).raise_for_status()

    # -- auth --------------------------------------------------------------- #

    @app.before_request
    def _require_bearer():
        if request.path in _OPEN:
            return
        if installed["api_token"] is None:
            abort(503, "keyper not bootstrapped")
        tok = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        expected = installed["peer_token"] if request.path in _PEER else installed["api_token"]
        if not tok or tok != expected:
            abort(401, "bad bearer token")

    # -- status + bootstrap ------------------------------------------------- #

    @app.get("/health")
    def health():
        return jsonify(ok=True)

    @app.get("/status")
    def status():
        return jsonify(
            address="0x" + signer.identity.hex(),
            bootstrapped=installed["api_token"] is not None,
            encryptionPubkey=enc_pubkey_bytes.hex(),
            encryptionPubkeySig=enc_pubkey_sig_hex,  # binds the enc pubkey to this keyper's address
            elections=sorted(completed.keys()),
        )

    @app.post("/auth/bootstrap")
    def bootstrap():
        body = request.get_json(force=True)
        try:
            payload = json.loads(boot.x25519_unseal(bytes.fromhex(body["sealed"]), x25519).decode())
        except Exception:  # noqa: BLE001
            abort(400, "cannot unseal bootstrap payload")
        if not boot.verify_payload(trusted_identities, payload, bytes.fromhex(body["signature"])):
            abort(401, "untrusted bootstrapper signature")
        if not nonce_tracker.check_and_record(payload.get("nonce", ""), int(payload.get("timestamp", 0))):
            abort(401, "stale or replayed bootstrap")
        with lock:
            installed["api_token"] = str(payload["api_token"])
            installed["peer_token"] = str(payload["peer_token"])
            installed["peers"] = dict(payload["peers"])
            relay = payload.get("relay_token")
            if relay:  # pushed by the coordinator so keypers need no pre-shared relay token
                installed["relay_token"] = str(relay)
                _apply_relay_token()
            persist.save_bootstrap_tokens(fernet, installed["api_token"], installed["peer_token"],
                                          installed["peers"], state_dir, relay_token=installed["relay_token"])
        log.info("op=bootstrap status=installed peers=%d", len(installed["peers"]))
        return jsonify(ok=True)

    # -- DKG ---------------------------------------------------------------- #

    @app.post("/dkg/round1")
    def dkg_round1():
        body = request.get_json(force=True)
        eid = _eid(body); eid_hex = eid.hex()
        config = _config(eid)
        idx = _my_index(config)
        n, t = config.threshold.n, config.threshold.t
        with lock:
            st = KeyperDKGState()
            st.round1(idx, n, t)
            dkg_states[eid_hex] = st
            _inbox(eid_hex)  # reset/init
            inbox[eid_hex] = {"commitments": {idx: st.commitments}, "shares": {idx: st.shares_for_others[idx]}}
        return jsonify(ok=True, index=idx)

    @app.post("/dkg/distribute_commitments")
    def dkg_distribute_commitments():
        body = request.get_json(force=True)
        eid = _eid(body); eid_hex = eid.hex()
        config = _config(eid)
        idx = _my_index(config)
        commitments_c = [g2_to_compressed(c) for c in dkg_states[eid_hex].commitments]
        commitments_hex = [c.hex() for c in commitments_c]
        # Sign the commitments so a recipient can bind them to this dealer's member
        # address (defeats a peer injecting forged commitments for another dealer).
        sig = write_auth.sign_digest(signer.private_key, write_auth.dkg_commitments_digest(eid, idx, commitments_c))
        for peer_index in range(1, config.threshold.n + 1):
            if peer_index == idx:
                continue
            _post_peer(peer_index, "/dkg/receive_commitments",
                       {"electionId": eid_hex, "dealerIndex": idx, "commitments": commitments_hex,
                        "signature": "0x" + sig.hex()})
        return jsonify(ok=True)

    @app.post("/dkg/receive_commitments")
    def dkg_receive_commitments():
        body = request.get_json(force=True)
        eid_hex = body["electionId"]
        eid = bytes.fromhex(eid_hex)
        dealer = int(body["dealerIndex"])
        incoming = [bytes.fromhex(h) for h in body["commitments"]]
        # Verify the dealer's signature against its config member address before storing.
        config = _config(eid)
        dealer_addr = _members_addr(config, dealer)
        try:
            sig = bytes.fromhex(str(body["signature"]).removeprefix("0x"))
            ok = dealer_addr is not None and \
                write_auth.recover_digest(write_auth.dkg_commitments_digest(eid, dealer, incoming), sig) == dealer_addr
        except (KeyError, ValueError, TypeError):
            ok = False
        if not ok:
            log.warning("op=dkg phase=receive_commitments status=rejected election=%s dealer=%s reason=bad_signature",
                        eid_hex, dealer)
            abort(401, "bad dealer commitments signature")
        with lock:
            box = _inbox(eid_hex)["commitments"]
            if dealer in box:
                if [g2_to_compressed(c) for c in box[dealer]] != incoming:
                    abort(409, "different commitments already received from this dealer")
            else:
                box[dealer] = [g2_from_compressed(b) for b in incoming]
        return jsonify(ok=True)

    @app.post("/dkg/distribute_shares")
    def dkg_distribute_shares():
        body = request.get_json(force=True)
        eid = _eid(body); eid_hex = eid.hex()
        config = _config(eid)
        idx = _my_index(config)
        st = dkg_states[eid_hex]
        for recipient in range(1, config.threshold.n + 1):
            if recipient == idx:
                continue
            # Seal each share to the recipient's X25519 key — but only after verifying that
            # key against the recipient's config member address, so a substituted key (via a
            # lying coordinator) can't redirect the plaintext; at worst it's a DoS. The
            # share is also signed (authenticity), verified over the unsealed scalar.
            peer = _peer(recipient)
            member = _members_addr(config, recipient)
            enc_hex, enc_sig = peer.get("enc_pubkey"), peer.get("enc_pubkey_sig")
            if member is None or not enc_hex or not enc_sig:
                log.warning("op=dkg phase=distribute_shares status=error election=%s recipient=%s "
                            "reason=no_verified_enc_key (re-bootstrap needed)", eid_hex, recipient)
                abort(500, f"no verified encryption key for keyper {recipient}; re-bootstrap")
            try:
                enc_pub = boot.verify_encryption_pubkey(member, enc_hex, enc_sig)
            except Exception as e:  # noqa: BLE001
                log.warning("op=dkg phase=distribute_shares status=error election=%s recipient=%s "
                            "reason=enc_key_verify_failed err=%s", eid_hex, recipient, e)
                abort(500, f"peer {recipient} encryption key failed verification: {e}")
            share_val = st.shares_for_others[recipient]
            sealed = boot.seal_share(share_val, enc_pub)
            sig = write_auth.sign_digest(
                signer.private_key, write_auth.dkg_share_digest(eid, idx, recipient, share_val))
            _post_peer(recipient, "/dkg/receive_share",
                       {"electionId": eid_hex, "dealerIndex": idx, "recipientIndex": recipient,
                        "sealedShare": sealed, "signature": "0x" + sig.hex()})
        return jsonify(ok=True)

    @app.post("/dkg/receive_share")
    def dkg_receive_share():
        """Receive a sealed+signed secret share from a dealer.

        The value travels sealed to this keyper's X25519 key (``sealedShare``) so a
        passive observer sees only ciphertext. Plaintext is not accepted on this path
        (multi-operator HTTP is always bootstrapped). Confidentiality (sealing) and
        authenticity (the dealer's signature over the *recovered* scalar) are independent.
        The dealer's signature is retained as evidence for a later complaint/reveal.
        """
        body = request.get_json(force=True)
        eid_hex = body["electionId"]
        eid = bytes.fromhex(eid_hex)
        config = _config(eid)
        try:
            dealer = int(body["dealerIndex"])
            recipient = int(body["recipientIndex"])
            sig_hex = str(body["signature"])
            if "sealedShare" not in body:
                log.warning("op=dkg phase=receive_share status=rejected election=%s reason=plaintext_share_refused",
                            eid_hex)
                abort(400, "sealedShare required")  # no plaintext downgrade on the HTTP path
            share = boot.unseal_share(body["sealedShare"], x25519)
        except (KeyError, ValueError, TypeError) as e:
            log.warning("op=dkg phase=receive_share status=rejected election=%s reason=bad_or_unsealable err=%s",
                        eid_hex, e)
            abort(400, f"bad share: {e}")
        if recipient != _my_index(config):
            log.warning("op=dkg phase=receive_share status=rejected election=%s dealer=%s recipient=%s "
                        "reason=recipient_mismatch", eid_hex, dealer, recipient)
            abort(400, "share recipient mismatch")
        # Verify the dealer's signature over the recovered scalar against its member address.
        dealer_addr = _members_addr(config, dealer)
        try:
            sig = bytes.fromhex(sig_hex.removeprefix("0x"))
            ok = dealer_addr is not None and \
                write_auth.recover_digest(write_auth.dkg_share_digest(eid, dealer, recipient, share), sig) == dealer_addr
        except (ValueError, TypeError):
            ok = False
        if not ok:
            log.warning("op=dkg phase=receive_share status=rejected election=%s dealer=%s reason=bad_signature",
                        eid_hex, dealer)
            abort(401, "bad dealer share signature")
        with lock:
            box = _inbox(eid_hex)
            shares = box["shares"]
            if dealer in shares and shares[dealer] != share:
                abort(409, "different share already received from this dealer")
            shares[dealer] = share
            # Retain the dealer's signed share as evidence for a complaint/reveal.
            box.setdefault("share_sigs", {})[dealer] = sig_hex
        return jsonify(ok=True)

    @app.post("/dkg/round2")
    def dkg_round2():
        body = request.get_json(force=True)
        eid = _eid(body); eid_hex = eid.hex()
        config = _config(eid)
        st = dkg_states[eid_hex]
        box = _inbox(eid_hex)
        my_idx = _my_index(config)
        try:
            st.round2(box["commitments"], box["shares"])
        except ValueError as err:
            bad = getattr(err, "bad_dealers", [])
            # Security-relevant: this keyper's VSS verification rejected a dealer's shares.
            log.warning("op=dkg phase=round2 status=verify_failed election=%s complaints=%s err=%s",
                        eid_hex, bad, err)
            # Sign one accusation per bad dealer. This recipient-signed DKG-ACCUSE-v1 is the
            # evidence the accused dealer's gated /dkg/reveal_share requires before disclosing
            # a share, and that the coordinator surfaces on halt. We are the complaining
            # recipient (my_idx); the accusation names the accused dealer, bound to this election.
            accusations = [
                {
                    "electionId": eid_hex,
                    "accusedDealerIndex": int(bad_dealer),
                    "recipientIndex": my_idx,
                    "signature": "0x" + write_auth.sign_digest(
                        signer.private_key,
                        write_auth.dkg_accusation_digest(eid, int(bad_dealer), my_idx),
                    ).hex(),
                }
                for bad_dealer in bad
            ]
            return jsonify(verified=False, complaints=bad, accusations=accusations), 200
        with lock:
            completed[eid_hex] = persist.DkgEntry(
                combined_share=st.combined_share,
                expires_at=(int(config.voting_end) + _SECRET_RETENTION_S
                            if _SECRET_RETENTION_S is not None else None),
            )
            persist.save_dkg_secrets(fernet, completed, state_dir)
        return jsonify(verified=True)

    @app.post("/dkg/reveal_share")
    def dkg_reveal_share():
        """Accusation-gated Feldman-VSS rebuttal: reveal the share THIS dealer dealt to a
        recipient, *only* on a valid recipient-signed ``DKG-ACCUSE-v1`` naming this dealer
        for the pinned election. Since only recipient ``j`` can sign as ``j``, ``j`` can
        unlock only its own share ``f_i(j)`` — which it already holds — so the endpoint
        discloses nothing new. The gate lives here in the handler (not ``before_request``).

        Returns the dealer's own ``DKG-REVEAL-v1`` signature; with the accusation it is
        two-sided signed evidence for a resolver (adjudication is out of scope — see
        DKG_SECURITY_HARDENING_PLAN.md). All gate failures return a uniform 401 so a prober
        cannot learn which check failed (e.g. whether a share exists for that recipient).
        """
        body = request.get_json(silent=True) or {}
        acc = body.get("accusation")
        if not isinstance(acc, dict):
            log.info("op=dkg phase=reveal_share status=rejected reason=missing_accusation")
            return jsonify(error="missing accusation"), 400
        try:
            acc_eid_hex = str(acc["electionId"])
            accused_dealer = int(acc["accusedDealerIndex"])
            recipient = int(acc["recipientIndex"])
            acc_sig = bytes.fromhex(str(acc["signature"]).removeprefix("0x"))
        except (KeyError, ValueError, TypeError):
            log.info("op=dkg phase=reveal_share status=rejected reason=bad_accusation")
            return jsonify(error="bad accusation"), 400

        def _deny(reason: str):
            # Uniform 401 to the caller (no oracle); the specific reason is server-side only,
            # so an operator can see *why* a reveal was refused without leaking it to a prober.
            log.warning("op=dkg phase=reveal_share status=denied election=%s accused_dealer=%s recipient=%s reason=%s",
                        acc_eid_hex, accused_dealer, recipient, reason)
            return jsonify(error="unauthorized"), 401

        st = dkg_states.get(acc_eid_hex)
        if st is None:  # not mid-ceremony for this election
            return _deny("not_in_ceremony")
        try:
            eid = bytes.fromhex(acc_eid_hex)
            config = _config(eid)
            my_idx = _my_index(config)  # aborts if we're not in the committee
        except Exception:  # noqa: BLE001 — uniform 401, never leak which check failed
            return _deny("not_committee_member")
        # Must name THIS dealer (so one accusation unlocks exactly one (dealer, recipient)
        # share), and we must actually have dealt a share to that recipient.
        if accused_dealer != my_idx or recipient not in st.shares_for_others:
            return _deny("wrong_dealer_or_recipient")
        # The accusation must be signed by the recipient itself → it can only ever unlock
        # its own share, which it is already entitled to.
        expected = _members_addr(config, recipient)
        try:
            recovered = write_auth.recover_digest(
                write_auth.dkg_accusation_digest(eid, accused_dealer, recipient), acc_sig)
        except Exception:  # noqa: BLE001
            recovered = None
        if expected is None or recovered != expected:
            return _deny("bad_accusation_signer")

        share_val = st.shares_for_others[recipient]
        reveal_sig = write_auth.sign_digest(
            signer.private_key, write_auth.dkg_reveal_digest(eid, my_idx, recipient, share_val))
        # A genuine disclosure — significant security event; record the who/what.
        log.warning("op=dkg phase=reveal_share status=revealed election=%s dealer=%s recipient=%s "
                    "(recipient-accusation-gated)", acc_eid_hex, my_idx, recipient)
        return jsonify(
            electionId=acc_eid_hex, dealerIndex=my_idx, recipientIndex=recipient,
            share=hex(share_val), signature="0x" + reveal_sig.hex(),
        )

    @app.post("/dkg/publish")
    def dkg_publish():
        body = request.get_json(force=True)
        eid = _eid(body); eid_hex = eid.hex()
        commitments = _inbox(eid_hex)["commitments"]
        pk = derive_joint_mpk(commitments)
        committee = [derive_mpk_share(i, commitments) for i in sorted(commitments)]
        pk_b = g2_to_compressed(pk)
        committee_b = [g2_to_compressed(c) for c in committee]
        sig = write_auth.sign_dkg_result(signer.private_key, eid, pk_b, committee_b)
        submitter.submit_dkg_result(eid, pk_b, committee_b, sig)  # direct or via coordinator relay
        return jsonify(ok=True)

    # -- aggregation (keyper-quorum; deterministic re-derivation from ballots) #

    @app.post("/aggregate")
    def aggregate():
        body = request.get_json(force=True)
        eid = _eid(body)
        config = _config(eid)
        # No persisted DKG secret needed — aggregation only reads the ordered
        # ballot list and re-runs admission (self-guarded on votingEnd inside).
        ks = KeyperService(_my_index(config), signer, data_layer, clock=clock)
        try:
            produced = ks.produce_aggregate(eid)
        except Exception as err:  # noqa: BLE001 — refusal / precondition failure
            log.debug("op=tally phase=aggregate status=refused election=%s reason=%s", eid.hex(), err)
            return jsonify(ok=False, reason=str(err)), 409
        if produced is not None:  # None = already submitted (idempotent)
            artifact, sig = produced
            try:
                submitter.submit_aggregate(eid, artifact, sig)  # direct or via coordinator relay
            except Exception as err:  # noqa: BLE001
                if not _is_benign_write_conflict(err):
                    raise
                # The t+1 quorum finalized the (identical) aggregate before this
                # submission landed — canonical already; this keyper wasn't needed.
                return jsonify(ok=True, note="aggregate already finalized by quorum"), 200
        return jsonify(ok=True)

    # -- partial decryption -- #

    @app.post("/publish_decr_share")
    def publish_decr_share():
        body = request.get_json(force=True)
        eid = _eid(body); eid_hex = eid.hex()
        entry = completed.get(eid_hex)
        if entry is None:
            log.warning("op=tally phase=decrypt status=refused election=%s reason=no_persisted_dkg_share", eid_hex)
            abort(409, "no persisted DKG share for this election")
        config = _config(eid)
        ks = KeyperService(_my_index(config), signer, data_layer, clock=clock)  # data_layer = reads
        ks.dkg.combined_share = entry.combined_share
        ks.dkg.public_key_share = entry.public_key_share
        try:
            produced = ks.produce_decryption_share(eid)
        except Exception as err:  # noqa: BLE001 — refusal / precondition failure
            log.debug("op=tally phase=decrypt status=refused election=%s reason=%s", eid_hex, err)
            return jsonify(ok=False, reason=str(err)), 409
        if produced is not None:  # None = already submitted (idempotent)
            share, sig = produced
            try:
                submitter.submit_decryption_share(eid, share, sig)  # direct or via coordinator relay
            except Exception as err:  # noqa: BLE001
                if not _is_benign_write_conflict(err):
                    raise
                # Enough shares already recorded before this one landed — benign.
                return jsonify(ok=True, note="decryption share already recorded"), 200
        return jsonify(ok=True)

    return app


def resolve_read_url(env) -> str:
    """Resolve the keyper's read endpoint from the environment.

    A keyper only **reads** the election data (its writes go to the coordinator relay),
    and it reads them from the public API's port surface — not from the data-layer
    service, which is internal-only because its ballot write path is unauthenticated.

    ``GEG_API_URL`` is therefore the API's **base** URL (e.g. ``https://vote.example.org``
    or ``http://host.docker.internal:8500``); the keyper appends the port-surface path
    itself, so an operator never has to know or spell it.
    """
    api_url = (env.get("GEG_API_URL") or "").strip()
    if api_url:
        return api_url.rstrip("/") + PORT_READ_PREFIX

    raise SystemExit(
        "set GEG_API_URL to the public API's base URL (e.g. http://host.docker.internal:8500); "
        f"the keyper reads through its port surface at {PORT_READ_PREFIX}"
    )


def main() -> None:
    """Run one keyper process, reading through the public API's port surface.

    Env: ``KEYPER_SIGNING_KEY`` (hex secp256k1 scalar — this keyper's Ethereum
    identity, whose 20-byte address is its committee identity), ``COORDINATOR_IDENTITY``
    (hex 20-byte address the keyper pins for bootstrap auth — the coordinator is the
    **sole** bootstrapper), ``GEG_API_URL`` (the public API's **base** URL — the keyper
    appends the port read surface itself; see :func:`resolve_read_url`),
    ``COORDINATOR_URL`` (where the keyper POSTs its signed DKG result / decryption
    shares — the coordinator relays them; if unset, writes go directly to the read
    handle, which will fail against a read-only surface). The relay bearer token is
    **not** an env var: the coordinator pushes it over ``/auth/bootstrap`` and it
    persists in state. ``KEYPER_STATE_DIR``, ``KEYPER_HOST``/``KEYPER_PORT``.
    """
    import os
    import time

    from geg.adapters.db.client import HttpDataLayerClient
    from geg.core.authz import Signer
    from geg.services.coordinator import CoordinatorClient

    logging.basicConfig(level=logging.INFO)
    signer = Signer.from_sk(int(os.environ["KEYPER_SIGNING_KEY"], 16))
    # The coordinator is the sole keyper bootstrapper; pin only its identity.
    trusted_identities = {bytes.fromhex(os.environ["COORDINATOR_IDENTITY"].removeprefix("0x"))}
    data_layer = HttpDataLayerClient(resolve_read_url(os.environ))
    state_dir = os.environ.get("KEYPER_STATE_DIR", "/keyper-state")

    # Writes go to the coordinator relay when configured; otherwise directly to the
    # data layer (reads always use the data-layer handle). The relay bearer token is
    # NOT pre-shared — the coordinator pushes it over /auth/bootstrap, and the keyper
    # applies it to this client (persisted, so it survives restart). Start empty.
    coordinator_url = os.environ.get("COORDINATOR_URL")
    submitter = CoordinatorClient(coordinator_url, "") if coordinator_url else None

    port = int(os.environ.get("KEYPER_PORT", "8100"))
    logging.getLogger("geg.keyper").info(
        "op=start service=keyper port=%d keyper_identity=%s", port, signer.identity.hex())
    app = build_keyper_app(signer, data_layer, trusted_identities,
                           clock=lambda: int(time.time()), state_dir=state_dir, submitter=submitter)
    app.run(host=os.environ.get("KEYPER_HOST", "0.0.0.0"), port=port)


if __name__ == "__main__":
    main()
