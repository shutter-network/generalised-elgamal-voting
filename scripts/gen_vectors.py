"""Generate geg-native conformance vectors.

Produces vectors for the protocol extensions the reference SDK suite does not
cover — the weighted ``ATTESTATION_V1`` and legacy attestation (positive +
negative cases) — plus a full-election **flow fixture** (config, ballots incl.
invalid + duplicate, aggregate with exclusions, decryption shares, result) that
any implementation can replay to reproduce the tally.

Run: ``python scripts/gen_vectors.py`` (writes under tests/vectors/).
Deterministic vectors pin their randomness so regeneration is stable in git; the
flow fixture is a self-consistent snapshot (its stored artifacts replay to the
same result regardless of how it was generated).
"""

from __future__ import annotations

import json
from pathlib import Path

from geg.core.admission import StoredBallot, admit
from geg.core.aggregation import build_aggregate_artifact, recover_result
from geg.core.config import DuplicatePolicy, ElectionConfig, KeyperIdentity, Mode, Threshold, Variant
from geg.crypto import attestation as att, ballot as ballot_crypto, binding, proofs, schnorr
from geg.crypto.dkg import KeyperDKGState, derive_joint_mpk, derive_mpk_share
from geg.crypto.points import g1_to_compressed, g2_from_compressed, g2_to_compressed
from geg.envelopes import codecs
from geg.envelopes.types import (
    Attestation,
    AttestationScheme,
    BallotEnvelope,
    Ciphertext,
    DecryptionShareEntry,
    DecryptionShareEnvelope,
)
from geg.ports.eligibility import AttestationRequest

VECTORS = Path(__file__).resolve().parents[1] / "tests" / "vectors"
ELECTION_ID = bytes.fromhex("11" * 32)


def _write(category: str, name: str, obj: dict) -> None:
    d = VECTORS / category
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{name}.json").write_text(json.dumps(obj, indent=2) + "\n")
    print(f"wrote {category}/{name}.json")


# --------------------------------------------------------------------------- #
#  Attestation vectors (ATTESTATION_V1 + legacy; positive + negative)
# --------------------------------------------------------------------------- #

def gen_attestation():
    elig_sk, elig_vk = schnorr.keygen(0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF)
    elig_key = g1_to_compressed(elig_vk)
    _, voter_vk = schnorr.keygen(0x0FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA098765432)
    vk = g1_to_compressed(voter_vk)
    pseudonym = bytes.fromhex("22" * 32)
    k = 0x1111222233334444555566667777888899990000AAAABBBBCCCCDDDDEEEEFFFF

    def att_obj(name, desc, *, weight, scheme, election_id, sig, verify, max_weight=10, nonce=1):
        return {
            "name": name, "description": desc, "version": 1,
            "inputs": {
                "eligibilityKey": elig_key.hex(), "electionId": election_id.hex(),
                "pseudonym": pseudonym.hex(), "vk": vk.hex(), "weight": weight, "nonce": nonce,
                "scheme": scheme, "signature": sig.hex(), "maxWeight": max_weight,
            },
            "expected": {"verify": verify},
        }

    # Valid V1 (weighted). nonce=1 = the voter's first vote.
    sig_v1 = att.sign_attestation(elig_sk, elig_vk, ELECTION_ID, pseudonym, vk, 5, 1, k=k)
    _write("attestation", "attestation_v1_valid",
           att_obj("attestation_v1_valid", "Weighted ATTESTATION_V1 over (eid,pseudonym,vk,weight=5,nonce=1).",
                   weight=5, scheme="ATTESTATION_V1", election_id=ELECTION_ID, sig=sig_v1, verify=True))

    # Negative: tampered weight (signature over 5, envelope claims 9).
    _write("attestation", "attestation_v1_tampered_weight",
           att_obj("attestation_v1_tampered_weight", "Signature over weight=5 but envelope claims weight=9.",
                   weight=9, scheme="ATTESTATION_V1", election_id=ELECTION_ID, sig=sig_v1, verify=False))

    # Negative: tampered nonce (signature over nonce=1, envelope claims nonce=2). This is the
    # replay-protection binding — a lower-nonce credential can't masquerade as a re-vote.
    _write("attestation", "attestation_v1_tampered_nonce",
           att_obj("attestation_v1_tampered_nonce", "Signature over nonce=1 but envelope claims nonce=2.",
                   weight=5, scheme="ATTESTATION_V1", election_id=ELECTION_ID, sig=sig_v1, verify=False, nonce=2))

    # Negative: wrong-election binding (signature over a different election id).
    other = bytes.fromhex("99" * 32)
    sig_other = att.sign_attestation(elig_sk, elig_vk, other, pseudonym, vk, 5, 1, k=k)
    _write("attestation", "attestation_v1_wrong_election",
           att_obj("attestation_v1_wrong_election", "Signature bound to a different electionId.",
                   weight=5, scheme="ATTESTATION_V1", election_id=ELECTION_ID, sig=sig_other, verify=False))

    # Negative: weight exceeds maxWeight.
    sig_big = att.sign_attestation(elig_sk, elig_vk, ELECTION_ID, pseudonym, vk, 50, 1, k=k)
    _write("attestation", "attestation_v1_over_max_weight",
           att_obj("attestation_v1_over_max_weight", "weight=50 exceeds maxWeight=10.",
                   weight=50, scheme="ATTESTATION_V1", election_id=ELECTION_ID, sig=sig_big, verify=False, max_weight=10))

    # Valid legacy (weightless, weight 1, nonceless).
    sig_legacy = att.sign_attestation_legacy(elig_sk, elig_vk, ELECTION_ID, pseudonym, vk, k=k)
    _write("attestation", "attestation_legacy_valid",
           att_obj("attestation_legacy_valid", "Legacy weightless attestation, valid at weight 1.",
                   weight=1, scheme="ATTESTATION_LEGACY", election_id=ELECTION_ID, sig=sig_legacy, verify=True, max_weight=1))


# --------------------------------------------------------------------------- #
#  Full-election flow fixture (conformance level 1: variant A / exact / weighted)
# --------------------------------------------------------------------------- #

def _run_dkg(n, quorum):
    states = {i: KeyperDKGState() for i in range(1, n + 1)}
    comms, shares = {}, {}
    for i, st in states.items():
        comms[i], shares[i] = st.round1(i, n, quorum)
    for i, st in states.items():
        st.round2(comms, {d: shares[d][i] for d in states})
    # Both helpers require the quorum explicitly — inferring the expected commitment
    # count from the vectors would accept a committee that all agreed on a wrong degree.
    # (This call site was stale: it predates the commitment-length guard that made the
    # argument mandatory, so the script raised TypeError before it could emit the flow
    # vector. Note the generator is NOT seeded — running it rewrites the flow vector's
    # crypto material, so regenerate deliberately, not casually.)
    mpk = derive_joint_mpk(comms, quorum)
    committee = {i: derive_mpk_share(i, comms, quorum) for i in states}
    return mpk, committee, states


def gen_flow():
    n, t, budget, num_candidates = 3, 2, 3, 3  # t IS the quorum: 2-of-3
    mpk, committee, states = _run_dkg(n, t)
    mpk_bytes = g2_to_compressed(mpk)
    committee_pks = tuple(g2_to_compressed(committee[i]) for i in range(1, n + 1))

    elig_sk, elig_vk = schnorr.keygen()
    elig_key = g1_to_compressed(elig_vk)

    config = ElectionConfig(
        election_id=ELECTION_ID, num_candidates=num_candidates, budget=budget, mode=Mode.EXACT,
        variant=Variant.A, weighted=True, max_weight=10, duplicate_policy=DuplicatePolicy.LAST_WINS,
        voting_start=1000, voting_end=2000, threshold=Threshold(t=t, n=n),
        keypers=tuple(KeyperIdentity(signing_key=bytes([i]) * 20, url="") for i in range(n)),
        eligibility_key=elig_key, result_publisher_key=b"\xa1" * 20, gateway_keys=(b"\x91" * 20,),
        admin_key=b"\xad" * 20, protocol_version="SHUTTER-VOTE-v1",
    )

    def make_ballot(votes, pseudonym, weight, *, nonce=1, tamper_sig=False):
        sk, vk = schnorr.keygen()
        vk_b = g1_to_compressed(vk)
        built = ballot_crypto.build_ballot(mpk=mpk, election_id=ELECTION_ID, pseudonym=pseudonym,
                                           sk=sk, vk=vk, votes=votes, num_candidates=num_candidates, budget=budget)
        sig = built.voter_signature
        if tamper_sig:
            b = bytearray(sig); b[-1] ^= 0x01; sig = bytes(b)
        a = att.sign_attestation(elig_sk, elig_vk, ELECTION_ID, pseudonym, vk_b, weight, nonce)
        att_obj = Attestation(election_id=ELECTION_ID, pseudonym=pseudonym, vk=vk_b, weight=weight,
                              signature=a, scheme=AttestationScheme.V1, nonce=nonce)
        return BallotEnvelope(election_id=ELECTION_ID, pseudonym=pseudonym, vk=vk_b,
                              ciphertexts=tuple(Ciphertext(c1=c[0], c2=c[1]) for c in built.ciphertexts),
                              zk_proof=built.zk_proof, voter_signature=sig, attestation=att_obj,
                              # Signed over the *untampered* ballot digest even when
                              # `tamper_sig` is set: that case exists to exercise
                              # INVALID_SIGNATURE, and a binding that failed alongside it
                              # would stop the fixture distinguishing the two rejections.
                              voter_attestation_signature=binding.sign_ballot_binding(
                                  voter_sk=sk, voter_vk=vk, election_id=ELECTION_ID,
                                  pseudonym=pseudonym, vk_bytes=vk_b,
                                  ciphertexts=built.ciphertexts, zk_proof=built.zk_proof,
                                  attestation=att_obj))

    P1, P2, P3, P4 = (bytes([x]) * 32 for x in (0xA1, 0xA2, 0xA3, 0xA4))
    stored = [
        StoredBallot(0, make_ballot([3, 0, 0], P1, 2, nonce=1)),                 # P1 first vote (nonce 1)
        StoredBallot(1, make_ballot([0, 3, 0], P2, 3, nonce=1)),                 # valid, weight 3
        StoredBallot(2, make_ballot([1, 1, 1], P3, 1, nonce=1, tamper_sig=True)),  # invalid signature
        StoredBallot(3, make_ballot([0, 0, 3], P1, 2, nonce=2)),                 # P1 re-vote (nonce 2 wins)
        StoredBallot(4, make_ballot([1, 1, 1], P4, 1, nonce=1)),                 # valid, weight 1
    ]

    admission = admit(stored, config, mpk_bytes)
    aggregate = build_aggregate_artifact(config, admission)

    # Keypers t+1 partially decrypt the aggregate.
    shares = []
    for i in (1, 2):
        entries = []
        for j, ct in enumerate(aggregate.aggregates):
            c1 = g2_from_compressed(ct.c1); c2 = g2_from_compressed(ct.c2)
            sigma = states[i].partial_decrypt(c1)
            tr = proofs.make_decrypt_transcript(ELECTION_ID, j)
            e, z = proofs.prove_decryption_share(tr, c1, c2, committee[i], sigma, states[i].combined_share, i)
            entries.append(DecryptionShareEntry(sigma=g2_to_compressed(sigma), proof=proofs.encode_dleq(e, z)))
        shares.append(DecryptionShareEnvelope(election_id=ELECTION_ID, keyper_index=i, entries=tuple(entries)))

    result = recover_result(config, aggregate, shares, committee_pks, t)

    fixture = {
        "name": "full_election_level1",
        "description": "Complete variant-A/exact/weighted election: 5 ballots (1 invalid, 1 duplicate), "
                       "t+1 shares, replayable to the published aggregate + result.",
        "version": 1,
        "config": codecs.enc_config(config),
        "finalizedKey": {"pkElection": mpk_bytes.hex(), "committeePKs": [p.hex() for p in committee_pks]},
        "ballots": [codecs.enc_ballot(sb.envelope) for sb in stored],
        "aggregate": codecs.enc_aggregate(aggregate),
        "shares": [codecs.enc_decryption_share(s) for s in shares],
        "result": codecs.enc_result(result),
    }
    _write("flow", "full_election_level1", fixture)


# --------------------------------------------------------------------------- #
#  Binding vectors (voter's ballot<->credential binding; cross-language)
# --------------------------------------------------------------------------- #

def gen_binding():
    """Vectors for `crypto/binding.py`, so the browser can prove it agrees.

    Seeded throughout — unlike the flow fixture, these must not move when
    regenerated, because a silent change here is a change to what every voter
    signs. Deterministic keys and a fixed nonce `k` make the whole file a pure
    function of the code that emits it.
    """
    elig_sk, elig_vk = schnorr.keygen(0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF)
    voter_sk, voter_vk = schnorr.keygen(0x0FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA098765432)
    vk = g1_to_compressed(voter_vk)
    pseudonym = bytes.fromhex("22" * 32)
    ballot_digest = bytes.fromhex("33" * 32)
    k = 0x1111222233334444555566667777888899990000AAAABBBBCCCCDDDDEEEEFFFF

    cases = []
    for name, scheme, weight, nonce in [
        ("v1_weight1_nonce1", AttestationScheme.V1, 1, 1),
        ("v1_weighted", AttestationScheme.V1, 7, 3),
        ("v1_timestamp_nonce", AttestationScheme.V1, 2, 1_700_000_000),  # sx uses a unix timestamp
        # Past 2^32, so a truncating scalar encoding cannot pass: a timestamp alone
        # still fits in 32 bits and would leave that bug invisible until much later.
        ("v1_nonce_beyond_32_bits", AttestationScheme.V1, 5, 2**40 + 12345),
        ("legacy", AttestationScheme.LEGACY, 1, 1),
    ]:
        if scheme is AttestationScheme.V1:
            sig = att.sign_attestation(elig_sk, elig_vk, ELECTION_ID, pseudonym, vk, weight, nonce, k=k)
        else:
            sig = att.sign_attestation_legacy(elig_sk, elig_vk, ELECTION_ID, pseudonym, vk, k=k)
        att_obj = Attestation(election_id=ELECTION_ID, pseudonym=pseudonym, vk=vk, weight=weight,
                              signature=sig, scheme=scheme, nonce=nonce)
        msg = binding.binding_message(
            election_id=ELECTION_ID, pseudonym=pseudonym, vk_bytes=vk,
            ballot_digest=ballot_digest, attestation_scheme=scheme,
            attestation_digest=binding.attestation_digest_for(att_obj),
            eligibility_signature=sig,
        )
        cases.append({
            "name": name,
            "attestation": codecs.enc_attestation(att_obj),
            "ballotDigest": "0x" + ballot_digest.hex(),
            "attestationDigest": "0x" + binding.attestation_digest_for(att_obj).hex(),
            "bindingMessage": "0x" + msg.hex(),
            "voterAttestationSignature": "0x" + binding.sign_binding(voter_sk, voter_vk, msg, k=k).hex(),
        })

    _write("binding", "binding_message", {
        "name": "binding_message",
        "description": (
            "Voter ballot<->credential binding message and signature. The browser "
            "rebuilds the transcript itself (the SDK keeps Transcript.preimage private), "
            "so these vectors are what hold the two languages together: a disagreement "
            "of one byte excludes every ballot as INVALID_ATTESTATION."
        ),
        "version": 1,
        "inputs": {
            "electionId": "0x" + ELECTION_ID.hex(),
            "pseudonym": "0x" + pseudonym.hex(),
            "vk": "0x" + vk.hex(),
            "eligibilityKey": "0x" + g1_to_compressed(elig_vk).hex(),
        },
        "cases": cases,
    })


if __name__ == "__main__":
    import sys

    # Named targets, because the generator is unseeded: regenerating a category
    # rewrites its crypto material, so a schema change to one fixture must not
    # churn the others as a side effect.
    targets = sys.argv[1:] or ["attestation", "binding", "flow"]
    for name in targets:
        {"attestation": gen_attestation, "binding": gen_binding, "flow": gen_flow}[name]()
