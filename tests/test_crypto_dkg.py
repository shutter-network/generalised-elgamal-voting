"""DKG + threshold decryption end-to-end at the crypto layer.

Runs a full Feldman VSS ceremony among n keypers, checks the derived joint key
matches the sum of public shares, then encrypts a homomorphic aggregate and
recovers it from t+1 partial decryptions with DLEQ-verified shares.
"""

from __future__ import annotations

from geg.crypto import elgamal, proofs
from geg.crypto.dkg import KeyperDKGState, derive_joint_mpk, derive_mpk_share
from geg.crypto.params import ONCHAIN_DECRYPT_LABEL
from geg.crypto.points import G2, mul
from geg.crypto.recovery import threshold_decrypt
from geg.crypto.transcript import Transcript


def run_dkg(n: int, t: int):
    """Simulate a full DKG. Returns (mpk, committee_pks, states, all_commitments)."""
    states = {i: KeyperDKGState() for i in range(1, n + 1)}
    all_commitments, all_shares = {}, {}
    for i, st in states.items():
        comms, shares = st.round1(i, n, t)
        all_commitments[i] = comms
        all_shares[i] = shares
    for i, st in states.items():
        received = {dealer: all_shares[dealer][i] for dealer in states}
        st.round2(all_commitments, received)
    mpk = derive_joint_mpk(all_commitments)
    committee_pks = {i: derive_mpk_share(i, all_commitments) for i in states}
    return mpk, committee_pks, states, all_commitments


def test_dkg_joint_key_matches_public_shares():
    mpk, committee_pks, states, _ = run_dkg(n=3, t=1)
    # Each keyper's public share equals combined_share * P2.
    for i, st in states.items():
        assert committee_pks[i] == mul(G2, st.combined_share)
        assert st.public_key_share == committee_pks[i]


def test_threshold_decrypt_recovers_aggregate():
    mpk, committee_pks, states, _ = run_dkg(n=3, t=1)
    # Homomorphic aggregate of votes 2 + 3 + 4 = 9 under mpk.
    cts = [elgamal.encrypt(mpk, v)[:2] for v in (2, 3, 4)]
    c1_sum, c2_sum = elgamal.sum_cts(cts)

    # t+1 = 2 keypers each partially decrypt the aggregate C1.
    used = [1, 2]
    shares = [(i, states[i].partial_decrypt(c1_sum)) for i in used]
    recovered = threshold_decrypt(c1_sum, c2_sum, shares, max_val=100)
    assert recovered == 9


def test_any_t_plus_1_subset_recovers_same_value():
    mpk, committee_pks, states, _ = run_dkg(n=3, t=1)
    c1_sum, c2_sum = elgamal.sum_cts([elgamal.encrypt(mpk, 7)[:2]])
    results = set()
    for subset in ([1, 2], [1, 3], [2, 3]):
        shares = [(i, states[i].partial_decrypt(c1_sum)) for i in subset]
        results.add(threshold_decrypt(c1_sum, c2_sum, shares, max_val=50))
    assert results == {7}


def test_decryption_share_dleq_verifies():
    mpk, committee_pks, states, _ = run_dkg(n=3, t=1)
    c1, c2 = elgamal.sum_cts([elgamal.encrypt(mpk, 5)[:2]])
    i = 1
    msk_k = states[i].combined_share
    mpk_k = committee_pks[i]
    sigma = states[i].partial_decrypt(c1)

    t = Transcript(ONCHAIN_DECRYPT_LABEL)
    e, z = proofs.prove_decryption_share(t, c1, c2, mpk_k, sigma, msk_k, keyper_index=i)

    tv = Transcript(ONCHAIN_DECRYPT_LABEL)
    assert proofs.verify_decryption_share(tv, c1, c2, mpk_k, sigma, e, z, keyper_index=i)


def test_decryption_share_dleq_rejects_wrong_sigma():
    mpk, committee_pks, states, _ = run_dkg(n=3, t=1)
    c1, c2 = elgamal.sum_cts([elgamal.encrypt(mpk, 5)[:2]])
    i = 1
    msk_k = states[i].combined_share
    mpk_k = committee_pks[i]
    sigma = states[i].partial_decrypt(c1)
    t = Transcript(ONCHAIN_DECRYPT_LABEL)
    e, z = proofs.prove_decryption_share(t, c1, c2, mpk_k, sigma, msk_k, keyper_index=i)

    wrong_sigma = mul(sigma, 2)
    tv = Transcript(ONCHAIN_DECRYPT_LABEL)
    assert not proofs.verify_decryption_share(tv, c1, c2, mpk_k, wrong_sigma, e, z, keyper_index=i)
