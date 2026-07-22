#!/usr/bin/env python3
"""Reference voter client — build ballots and submit them to the gateway.

For the deployment demos (RUNNING.md): reads the finalized election key from the
data-layer service, builds valid weighted ballots in-browser style (plaintext +
proof randomness never leave here), issues each an attestation with the eligibility
secret, and POSTs the §7.2 ballot envelope to the gateway. Backend-agnostic — it
only speaks HTTP to the data-layer + gateway services.

    GEG_DATA_LAYER_URL=http://127.0.0.1:8000 GATEWAY_URL=http://127.0.0.1:8200 \
      ELIGIBILITY_PRIVATE_KEY=0x... python scripts/vote_sample.py

Submits two ballots: [3,0,0] weight 2 and [0,3,0] weight 5 → expected tally
[6, 15, 0].
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import requests

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from geg.adapters.eligibility_stub import StubEligibilityService  # noqa: E402
from geg.crypto import ballot as ballot_crypto  # noqa: E402
from geg.crypto import schnorr  # noqa: E402
from geg.crypto.points import g1_to_compressed, g2_from_compressed  # noqa: E402
from geg.envelopes import codecs  # noqa: E402
from geg.envelopes.types import BallotEnvelope, Ciphertext  # noqa: E402
from geg.ports.eligibility import AttestationRequest  # noqa: E402

def _discover_election(dl_url: str) -> bytes:
    """Election id (registry-assigned). Use GEG_ELECTION_ID if set, else the most
    recent election reported by the data-layer service."""
    override = os.environ.get("GEG_ELECTION_ID")
    if override:
        return bytes.fromhex(override.removeprefix("0x"))
    ids = requests.get(f"{dl_url}/elections").json()["electionIds"]
    if not ids:
        raise SystemExit("no elections registered yet")
    return bytes.fromhex(ids[-1].removeprefix("0x"))


def main() -> None:
    dl_url = os.environ.get("GEG_DATA_LAYER_URL", "http://127.0.0.1:8000").rstrip("/")
    gw_url = os.environ.get("GATEWAY_URL", "http://127.0.0.1:8200").rstrip("/")
    elig = StubEligibilityService(int(os.environ["ELIGIBILITY_PRIVATE_KEY"], 16))

    EID = _discover_election(dl_url)
    print(f"election id: 0x{EID.hex()}")
    fk = requests.get(f"{dl_url}/elections/{EID.hex()}/dkg/finalized").json()["finalizedKey"]
    if fk is None:
        raise SystemExit("election has no finalized key yet — run DKG first")
    mpk = g2_from_compressed(bytes.fromhex(fk["pkElection"].removeprefix("0x")))

    def vote(votes, pseudonym, weight):
        sk, vk = schnorr.keygen()
        vkb = g1_to_compressed(vk)
        built = ballot_crypto.build_ballot(mpk=mpk, election_id=EID, pseudonym=pseudonym,
                                           sk=sk, vk=vk, votes=votes, num_candidates=3, budget=3)
        att = elig.issue_attestation(AttestationRequest(EID, pseudonym, vkb, weight))
        env = BallotEnvelope(election_id=EID, pseudonym=pseudonym, vk=vkb,
                             ciphertexts=tuple(Ciphertext(c1=a, c2=b) for (a, b) in built.ciphertexts),
                             zk_proof=built.zk_proof, voter_signature=built.voter_signature, attestation=att)
        r = requests.post(f"{gw_url}/elections/{EID.hex()}/ballots", json={"ballot": codecs.enc_ballot(env)})
        print(f"vote {votes} weight={weight}: {r.status_code} {r.text.strip()}")
        r.raise_for_status()

    vote([3, 0, 0], b"\x01" * 32, 2)
    vote([0, 3, 0], b"\x02" * 32, 5)


if __name__ == "__main__":
    main()
