"""Cross-language conformance vectors.

Verifies that geg's crypto reproduces every cross-implementation vector — the
same JSON files an independent re-verifier (the TS SDK, a future port) consumes.
Vectors follow the shared schema: compressed-hex points, decimal-string scalars,
hex byte blobs. Adopted from the reference SDK suite and extended here; this is
the protocol conformance gate (single command: ``pytest tests/test_conformance_vectors.py``).

Categories: encrypt, dleq, or, budget (exact+atMost), schnorr, decrypt-share,
ballot, tally. Variant-B / atMost *ballots* are conformance level 2 (specified,
not implemented in the reference) and are skipped with a reason.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from geg.crypto import schnorr
from geg.crypto.ballot import verify_ballot_crypto
from geg.crypto.elgamal import encrypt
from geg.crypto.points import Z2, add, g1_from_compressed, g2_from_compressed, g2_to_compressed, mul, neg
from geg.crypto.proofs import (
    ORBranch,
    decode_dleq,
    verify_budget_at_most,
    verify_budget_exact,
    verify_decryption_share,
    verify_dleq,
    verify_or,
)
from geg.crypto.recovery import baby_step_giant_step, combine_shares
from geg.crypto.transcript import Transcript

VECTORS = Path(__file__).parent / "vectors"


def _load(category: str):
    files = sorted((VECTORS / category).glob("*.json"))
    return [(f.stem, json.loads(f.read_text())) for f in files]


def _g2(h):
    return g2_from_compressed(bytes.fromhex(h))


def _g1(h):
    return g1_from_compressed(bytes.fromhex(h))


def _hx(h):
    return bytes.fromhex(h)


def _decode_or(hexstr: str):
    b = bytes.fromhex(hexstr)
    n = (b[0] << 8) | b[1]
    off, branches = 2, []
    for _ in range(n):
        a1 = g2_from_compressed(b[off:off + 96]); off += 96
        a2 = g2_from_compressed(b[off:off + 96]); off += 96
        e = int.from_bytes(b[off:off + 32], "big"); off += 32
        z = int.from_bytes(b[off:off + 32], "big"); off += 32
        branches.append(ORBranch(a1, a2, e, z))
    return branches


def _ids(cases):
    return [c[0] for c in cases]


# --------------------------------------------------------------------------- #
#  encrypt — byte-parity (deterministic ciphertext under pinned r)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name,v", _load("encrypt"), ids=_ids(_load("encrypt")))
def test_encrypt_vector(name, v):
    i = v["inputs"]
    c1, c2, _ = encrypt(_g2(i["mpk"]), int(i["m"]), int(i["r"]))
    assert g2_to_compressed(c1).hex() == v["expected"]["c1"]
    assert g2_to_compressed(c2).hex() == v["expected"]["c2"]


# --------------------------------------------------------------------------- #
#  dleq / or / budget / schnorr / decrypt-share — verify path
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name,v", _load("dleq"), ids=_ids(_load("dleq")))
def test_dleq_vector(name, v):
    i = v["inputs"]
    e, z = decode_dleq(_hx(i["proof"]))
    ok = verify_dleq(_g2(i["base1"]), _g2(i["point1"]), _g2(i["base2"]), _g2(i["point2"]),
                     e, z, Transcript(i["transcript_label"]))
    assert ok is v["expected"]["verify"]


@pytest.mark.parametrize("name,v", _load("or"), ids=_ids(_load("or")))
def test_or_vector(name, v):
    i = v["inputs"]
    branches = _decode_or(i["or_proof_encoded"])
    ok = verify_or(_g2(i["ct"]["c1"]), _g2(i["ct"]["c2"]), _g2(i["mpk"]),
                   [int(x) for x in i["candidates"]], branches, Transcript(i["transcript_label"]))
    assert ok is v["expected"]["verify"]


@pytest.mark.parametrize("name,v", _load("budget"), ids=_ids(_load("budget")))
def test_budget_vector(name, v):
    i = v["inputs"]
    c1, c2, mpk, B = _g2(i["ct_sum"]["c1"]), _g2(i["ct_sum"]["c2"]), _g2(i["mpk"]), i["budget"]
    t = Transcript(i["transcript_label"])
    if i["mode"] == "exact":
        e, z = decode_dleq(_hx(i["proof_encoded"]))
        ok = verify_budget_exact(c1, c2, mpk, B, e, z, t)
    else:
        ok = verify_budget_at_most(c1, c2, mpk, B, _decode_or(i["proof_encoded"]), t)
    assert ok is v["expected"]["verify"]


@pytest.mark.parametrize("name,v", _load("schnorr"), ids=_ids(_load("schnorr")))
def test_schnorr_vector(name, v):
    i = v["inputs"]
    if "sig" not in i:
        pytest.skip("build-style fixture — covered by test_parity_vectors")
    R, s = schnorr.decode(_hx(i["sig"]))
    assert schnorr.verify(_g1(i["vk"]), _hx(i["message"]), R, s) is v["expected"]["verify"]


@pytest.mark.parametrize("name,v", _load("decrypt-share"), ids=_ids(_load("decrypt-share")))
def test_decrypt_share_vector(name, v):
    i = v["inputs"]
    sh = i["share"]
    e, z = decode_dleq(_hx(sh["dleq_proof"]))
    ok = verify_decryption_share(
        Transcript(i["transcript_label"]),
        _g2(i["ct_sum"]["c1"]), _g2(i["ct_sum"]["c2"]),
        _g2(i["committee_pk"]), _g2(sh["sigma"]), e, z, i["keyper_index"],
    )
    assert ok is v["expected"]["verify"]


# --------------------------------------------------------------------------- #
#  ballot — full validity-proof + signature (variant A / exact = level 1)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name,v", _load("ballot"), ids=_ids(_load("ballot")))
def test_ballot_vector(name, v):
    i = v["inputs"]
    if "zkProof" not in i:
        pytest.skip("build-style fixture — covered by test_parity_vectors")
    params = i["params"]
    if params["mode"] != "exact" or params["variant"] != "A":
        pytest.skip("variant B / atMost ballot is conformance level 2 (not implemented)")
    ok, _reason = verify_ballot_crypto(
        mpk=_g2(i["mpk"]),
        election_id=_hx(i["election_id"]),
        pseudonym=_hx(i["pseudonym"]),
        vk_bytes=_hx(i["vk"]),
        ciphertext_bytes=[(_hx(c["c1"]), _hx(c["c2"])) for c in i["ciphertexts"]],
        zk_proof=_hx(i["zkProof"]),
        voter_signature=_hx(i["signature"]),
        num_candidates=params["numCandidates"],
        budget=params["budget"],
    )
    assert ok is v["expected"]["verify"]


# --------------------------------------------------------------------------- #
#  tally — Lagrange combine (via published alphas) + BSGS recovery
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name,v", _load("tally"), ids=_ids(_load("tally")))
def test_tally_vector(name, v):
    i = v["inputs"]
    c2 = _g2(i["ct_sum"]["c2"])
    # `alphas` are the evaluation points (keyper indices) of the t+1 subset,
    # in shares order; Lagrange-combine at zero, then subtract and BSGS-recover.
    pairs = [(int(alpha), _g2(sh["sigma"])) for sh, alpha in zip(i["shares"], i["alphas"])]
    tau = add(c2, neg(combine_shares(pairs)))
    recovered = baby_step_giant_step(tau, int(i["upper_bound"]))
    assert recovered == int(v["expected"]["V"])


# --------------------------------------------------------------------------- #
#  attestation (geg-native: ATTESTATION_V1 + legacy, positive + negative)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name,v", _load("attestation"), ids=_ids(_load("attestation")))
def test_attestation_vector(name, v):
    from geg.envelopes.types import Attestation, AttestationScheme
    from geg.ports.eligibility import verify_attestation

    i = v["inputs"]
    att = Attestation(
        election_id=_hx(i["electionId"]), pseudonym=_hx(i["pseudonym"]), vk=_hx(i["vk"]),
        weight=i["weight"], signature=_hx(i["signature"]), scheme=AttestationScheme(i["scheme"]),
    )
    ok = verify_attestation(_hx(i["eligibilityKey"]), att, election_id=_hx(i["electionId"]), max_weight=i["maxWeight"])
    assert ok is v["expected"]["verify"]


# --------------------------------------------------------------------------- #
#  flow — replay a full election from its stored public artifacts
# --------------------------------------------------------------------------- #

def test_full_election_flow_replay():
    from geg.core.admission import StoredBallot, admit
    from geg.core.aggregation import build_aggregate_artifact, recover_result
    from geg.envelopes import codecs

    fx = json.loads((VECTORS / "flow" / "full_election_level1.json").read_text())
    config = codecs.dec_config(fx["config"])
    mpk_bytes = bytes.fromhex(fx["finalizedKey"]["pkElection"])
    committee = tuple(bytes.fromhex(p) for p in fx["finalizedKey"]["committeePKs"])
    stored = [StoredBallot(seq, codecs.dec_ballot(b)) for seq, b in enumerate(fx["ballots"])]
    published_agg = codecs.dec_aggregate(fx["aggregate"])
    shares = [codecs.dec_decryption_share(s) for s in fx["shares"]]
    published_result = codecs.dec_result(fx["result"])

    # 1. Re-derive admission + aggregate; must byte-match the published aggregate.
    admission = admit(stored, config, mpk_bytes)
    recomputed_agg = build_aggregate_artifact(config, admission)
    assert recomputed_agg == published_agg
    # sanity on the fixture's shape: last-wins keeps the P1 duplicate at seq 3,
    # excludes seq 0 (duplicate) and seq 2 (invalid signature).
    assert set(published_agg.admitted) == {1, 3, 4}
    assert {x.reason.value for x in published_agg.exclusions} == {"INVALID_SIGNATURE", "DUPLICATE_PSEUDONYM"}

    # 2. Recover from the published aggregate + shares; must match the published result.
    recovered = recover_result(config, published_agg, shares, committee, config.threshold.t)
    assert recovered is not None
    assert tuple(recovered.totals) == tuple(published_result.totals)
    assert recovered.bsgs_bound == published_result.bsgs_bound
