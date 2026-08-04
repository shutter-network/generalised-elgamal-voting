"""Wallet-authenticated eligibility-attestation HTTP service.

Exposes the issuing side over HTTP so a browser voter client can obtain an
``ATTESTATION_V1`` credential for its ballot:

    ``POST /attest``  {electionId, vk, signature}  ->  {attestation, pseudonym}

The identity gate — *one wallet, one vote* — lives here, not in the ballot/gateway/tally,
and needs **no chain**: proving control of an address is just a signature.

  1. The voter **personal-signs** (EIP-191) a human-readable challenge binding
     ``(electionId, vk)``. We ``ecrecover`` the address (a bad/missing signature is a 401).
     This is chain-agnostic — no EIP-712 domain, no chainId, no network to configure or
     switch. Binding ``vk`` makes the signature non-transferable to another ballot key.
  2. The pseudonym is derived from the address:
     ``pseudonym = HMAC-SHA256(secret, electionId ‖ address)[:32]`` — **stable** per
     (wallet, election) so two ballots from one wallet share a pseudonym and the tally's
     ``last-wins`` dedup keeps the latest (a voter can change their vote until close), and
     **private** (only this service, holding ``secret``, can link pseudonym ↔ wallet).

This is a **dummy** issuer: it grants a fixed weight (``ELIGIBILITY_DUMMY_WEIGHT``) to any
recovered address; a real deployment authenticates differently and reads voting power from
a registry. The returned ``attestation`` is the exact :func:`geg.envelopes.codecs.enc_attestation`
envelope the gateway / tally verify against ``config.eligibility_key`` — swapping issuers
needs no client change. CORS-enabled (the browser calls it directly).
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak
from flask import Flask, jsonify, request

from geg.adapters.eligibility_stub import StubEligibilityService
from geg.envelopes import codecs
from geg.ports.eligibility import AttestationRequest

_LOG = logging.getLogger("geg.eligibility")


def challenge_message(election_id: bytes, vk: bytes) -> str:
    """The human-readable EIP-191 message the voter's wallet signs. Wallets show this text
    verbatim, and both the browser and this service reconstruct the identical UTF-8 bytes
    (ASCII: fixed labels + lowercase 0x-hex), so ``ecrecover`` matches."""
    return (
        "GEG eligibility attestation\n"
        f"electionId: {codecs.enc_bytes(election_id)}\n"
        f"vk: {codecs.enc_bytes(vk)}"
    )


def derive_pseudonym(secret: bytes, election_id: bytes, address: bytes) -> bytes:
    """Deterministic, private per-(wallet, election) pseudonym (see module docstring)."""
    return hmac.new(secret, bytes(election_id) + bytes(address), hashlib.sha256).digest()[:32]


def build_eligibility_app(service: StubEligibilityService, *, pseudonym_secret: bytes,
                          weight: int = 1) -> Flask:
    """Build the wallet-authenticated eligibility HTTP app. ``pseudonym_secret`` keys the
    pseudonym; ``weight`` is the (dummy) voting weight granted to any recovered address."""
    app = Flask(__name__)

    @app.errorhandler(ValueError)
    def _bad_request(e):
        return jsonify(error="ValueError", message=str(e)), 400

    @app.after_request
    def _cors(resp):
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return resp

    @app.get("/health")
    def health():
        return jsonify(ok=True, eligibilityKey=codecs.enc_bytes(service.eligibility_key))

    @app.post("/attest")
    def attest():
        body = request.get_json(force=True)
        if not body.get("signature"):
            return jsonify(error="Unauthorized", message="missing wallet signature"), 401
        election_id = codecs.dec_bytes(body["electionId"], name="electionId")
        vk = codecs.dec_bytes(body["vk"], name="vk")

        # Authenticate the wallet over the exact (electionId, vk) it is attesting.
        message = encode_defunct(text=challenge_message(election_id, vk))
        try:
            recovered = Account.recover_message(
                message, signature=codecs.dec_bytes(body["signature"], name="signature"))
        except Exception:
            return jsonify(error="Unauthorized", message="bad wallet signature"), 401
        address = bytes.fromhex(recovered[2:])

        pseudonym = derive_pseudonym(pseudonym_secret, election_id, address)
        att = service.issue_attestation(AttestationRequest(
            election_id=election_id, pseudonym=pseudonym, vk=vk, weight=weight))
        _LOG.info("op=attest status=ok election=%s weight=%d", election_id.hex(), att.weight)
        return jsonify(attestation=codecs.enc_attestation(att),
                       pseudonym=codecs.enc_bytes(pseudonym))

    return app


def _pseudonym_secret(elig_sk_hex: str) -> bytes:
    """HMAC secret keying the private pseudonym: ``ELIGIBILITY_PSEUDONYM_SECRET`` if set,
    else a stable value derived from the issuing key (so dev needs no extra config)."""
    env = os.environ.get("ELIGIBILITY_PSEUDONYM_SECRET")
    if env:
        return bytes.fromhex(env.removeprefix("0x"))
    _LOG.warning("ELIGIBILITY_PSEUDONYM_SECRET unset — deriving from the issuing key (dev default)")
    return keccak(b"geg-pseudonym-v1" + int(elig_sk_hex, 16).to_bytes(32, "big"))


def main() -> None:
    """Run the wallet-authenticated (dummy) eligibility service.

    Env: ``ELIGIBILITY_PRIVATE_KEY`` (issuing key; its public key is ``eligibility_key``),
    ``ELIGIBILITY_PSEUDONYM_SECRET`` (hex; optional — derived from the issuing key if unset),
    ``ELIGIBILITY_DUMMY_WEIGHT`` (weight granted to any wallet; default 1),
    ``ELIGIBILITY_HOST`` / ``ELIGIBILITY_PORT`` (default 8600).
    """
    logging.basicConfig(level=logging.INFO)
    elig_sk_hex = os.environ["ELIGIBILITY_PRIVATE_KEY"]
    service = StubEligibilityService(int(elig_sk_hex, 16))
    port = int(os.environ.get("ELIGIBILITY_PORT", "8600"))
    _LOG.info("op=start service=eligibility port=%d eligibility_key=%s auth=wallet-personal-sign",
              port, codecs.enc_bytes(service.eligibility_key))
    app = build_eligibility_app(
        service,
        pseudonym_secret=_pseudonym_secret(elig_sk_hex),
        weight=int(os.environ.get("ELIGIBILITY_DUMMY_WEIGHT", "1")),
    )
    app.run(host=os.environ.get("ELIGIBILITY_HOST", "0.0.0.0"), port=port)


if __name__ == "__main__":
    main()
