"""The voter's binding of a ballot to the credential it was cast with.

The credential was already bound to the *voter*: ``validate_ballot`` requires
``att.pseudonym == env.pseudonym`` and ``att.vk == env.vk``, and the ballot
signature is verified against that same ``vk``. What no voter-signed message
covered was **which** of that voter's credentials this ballot was cast with —
``canonical_ballot_message`` spans ``(election_id, pseudonym, ciphertexts,
zk_proof)`` and neither ``weight`` nor ``nonce``.

Worth being exact about how reachable that was, because it decides what these
tests are for. Every client generates a fresh Schnorr key per ballot, so two of a
voter's ballots never share a ``vk`` and the existing check already refuses a
swapped credential. The gap is real but *latent*: nothing in the protocol
requires a fresh key, so a client that reused one — an obvious-looking saving,
given the cost of keygen in WASM — would silently reopen it. The binding turns an
accident of client behaviour into an enforced property.

Where it is not latent is a backend that issues the credentials itself. There is
no swap to detect: it authors ``weight`` and ``nonce`` for whatever ``vk``
arrives, and the voter, never having seen the credential, cannot be shown to have
endorsed it. That is the sx-monorepo shape, and it is why the voter must sign.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from geg.core.admission import StoredBallot, admit
from geg.crypto import binding, schnorr
from geg.crypto.points import g1_to_compressed
from geg.envelopes.types import AttestationScheme, ExclusionReason

P1 = b"\xa1" * 32
P2 = b"\xa2" * 32


def _stored(env, seq, votes, pseudonym, **kw):
    return StoredBallot(sequence_number=seq, envelope=env.ballot(votes, pseudonym, **kw))


# --------------------------------------------------------------------------- #
#  The attack
# --------------------------------------------------------------------------- #

def _ballot_with_key(env, sk, vk, votes, pseudonym, *, nonce, weight=1):
    """A ballot under a *caller-supplied* key, so two ballots can share one `vk`.

    `env.ballot` generates a fresh keypair each call, which is what every real
    client does today — and which is precisely why the naive swap already fails.
    Reproducing the gap needs the case the protocol permits but no client
    currently produces.
    """
    from geg.crypto import attestation as att_crypto
    from geg.crypto import ballot as ballot_crypto
    from geg.envelopes.types import Attestation, BallotEnvelope, Ciphertext

    vk_bytes = g1_to_compressed(vk)
    built = ballot_crypto.build_ballot(
        mpk=env.mpk_point, election_id=env.config().election_id, pseudonym=pseudonym,
        sk=sk, vk=vk, votes=votes, num_candidates=len(votes), budget=3,
    )
    _, elig_vk_pt = schnorr.keygen(env.elig_sk)
    eid = env.config().election_id
    att = Attestation(
        election_id=eid, pseudonym=pseudonym, vk=vk_bytes, weight=weight,
        signature=att_crypto.sign_attestation(
            env.elig_sk, elig_vk_pt, eid, pseudonym, vk_bytes, weight, nonce
        ),
        scheme=AttestationScheme.V1, nonce=nonce,
    )
    return BallotEnvelope(
        election_id=eid, pseudonym=pseudonym, vk=vk_bytes,
        ciphertexts=tuple(Ciphertext(c1=a, c2=b) for (a, b) in built.ciphertexts),
        zk_proof=built.zk_proof, voter_signature=built.voter_signature, attestation=att,
        voter_attestation_signature=binding.sign_ballot_binding(
            voter_sk=sk, voter_vk=vk, election_id=eid, pseudonym=pseudonym,
            vk_bytes=vk_bytes, ciphertexts=built.ciphertexts,
            zk_proof=built.zk_proof, attestation=att,
        ),
    )


def test_credential_swap_between_ballots_sharing_a_key(env):
    """The gap the binding closes, and the only shape in which it is reachable.

    A voter casts A (nonce 1) then re-votes B (nonce 2) under the *same* key. An
    assembler lifts B's credential onto ballot A: the credential still names this
    pseudonym and this vk, so every pre-binding check passes, and A now carries
    the winning nonce. Under `LAST_WINS` resolved on ``(nonce, sequence)`` the
    voter's superseded first ballot would beat their real re-vote.

    Both artifacts are individually genuine. Only the pairing is forged — which
    is what nothing verified before.
    """
    cfg = env.config()
    sk, vk = schnorr.keygen()
    a = _ballot_with_key(env, sk, vk, [3, 0, 0], P1, nonce=1)
    b = _ballot_with_key(env, sk, vk, [0, 0, 3], P1, nonce=2)

    forged = replace(a, attestation=b.attestation)

    # Every check that existed before the binding is satisfied.
    assert forged.attestation.pseudonym == forged.pseudonym
    assert forged.attestation.vk == forged.vk
    assert forged.attestation.nonce == 2  # the winning nonce, on the older ballot

    res = admit([StoredBallot(0, forged), StoredBallot(1, b)], cfg, env.mpk_bytes)
    assert [e.reason for e in res.exclusions] == [ExclusionReason.INVALID_ATTESTATION]
    assert [x.sequence_number for x in res.admitted] == [1]  # the real re-vote wins


def test_fresh_key_per_ballot_already_blocks_the_naive_swap(env):
    """Why the attack above needed a shared key — and why that is not a defence.

    Every client today calls `schnorrKeygen()` per ballot, so two ballots never
    share a `vk` and `att.vk != env.vk` catches the swap on its own. That is real,
    but it is *accidental*: nothing in the protocol requires a fresh key, nothing
    else tests it, and reusing one is an obvious-looking saving given how costly
    keygen is in WASM. The binding makes the property structural instead of
    depending on every client independently choosing to preserve it.
    """
    a = env.ballot([3, 0, 0], P1, nonce=1)
    b = env.ballot([0, 0, 3], P1, nonce=2)
    assert a.vk != b.vk  # the accident this test names

    res = admit([StoredBallot(0, replace(a, attestation=b.attestation))], env.config(), env.mpk_bytes)
    assert [e.reason for e in res.exclusions] == [ExclusionReason.INVALID_ATTESTATION]


def test_credential_cannot_be_moved_between_voters(env):
    """Already prevented by the pseudonym/vk checks; pinned so it stays that way."""
    cfg = env.config()
    a = env.ballot([3, 0, 0], P1)
    b = env.ballot([0, 0, 3], P2)
    forged = replace(a, attestation=b.attestation)
    res = admit([StoredBallot(0, forged)], cfg, env.mpk_bytes)
    assert [e.reason for e in res.exclusions] == [ExclusionReason.INVALID_ATTESTATION]


# --------------------------------------------------------------------------- #
#  Admission wiring
# --------------------------------------------------------------------------- #

def test_valid_binding_is_admitted(env):
    cfg = env.config()
    res = admit([_stored(env, 0, [1, 0, 2], P1)], cfg, env.mpk_bytes)
    assert res.exclusions == ()
    assert len(res.admitted) == 1


@pytest.mark.parametrize("sig", [b"", b"\x00" * 80, b"\xff" * 80, b"\x01" * 79])
def test_missing_or_malformed_binding_is_rejected(env, sig):
    cfg = env.config()
    env_ = replace(env.ballot([1, 0, 2], P1), voter_attestation_signature=sig)
    res = admit([StoredBallot(0, env_)], cfg, env.mpk_bytes)
    assert [e.reason for e in res.exclusions] == [ExclusionReason.INVALID_ATTESTATION]


def test_another_voters_binding_does_not_transfer(env):
    """A well-formed signature under the wrong key is still a rejection."""
    cfg = env.config()
    a = env.ballot([1, 0, 2], P1)
    b = env.ballot([0, 1, 2], P2)
    res = admit(
        [StoredBallot(0, replace(a, voter_attestation_signature=b.voter_attestation_signature))],
        cfg,
        env.mpk_bytes,
    )
    assert [e.reason for e in res.exclusions] == [ExclusionReason.INVALID_ATTESTATION]


def test_a_tampered_ballot_still_reports_its_own_reason(env):
    """Ordering: the binding covers the ballot digest, so it breaks on any tamper.

    Checked last for exactly that reason — otherwise every mangled ballot would
    report INVALID_ATTESTATION and bury the real cause. This pins the order.
    """
    cfg = env.config()
    b = env.ballot([1, 0, 2], P1)
    broken = bytearray(b.voter_signature)
    broken[-1] ^= 0x01
    res = admit(
        [StoredBallot(0, replace(b, voter_signature=bytes(broken)))], cfg, env.mpk_bytes
    )
    assert [e.reason for e in res.exclusions] == [ExclusionReason.INVALID_SIGNATURE]


# --------------------------------------------------------------------------- #
#  The message itself
# --------------------------------------------------------------------------- #

def _msg(**over):
    sk, vk = schnorr.keygen()
    base = dict(
        election_id=b"\x11" * 32,
        pseudonym=b"\x22" * 32,
        vk_bytes=g1_to_compressed(vk),
        ballot_digest=b"\x33" * 32,
        attestation_scheme=AttestationScheme.V1,
        attestation_digest=b"\x44" * 32,
        eligibility_signature=b"\x55" * 80,
    )
    base.update(over)
    return binding.binding_message(**base)


@pytest.mark.parametrize(
    "field,value",
    [
        ("election_id", b"\x99" * 32),
        ("pseudonym", b"\x99" * 32),
        ("ballot_digest", b"\x99" * 32),
        ("attestation_digest", b"\x99" * 32),
        ("eligibility_signature", b"\x99" * 80),
        ("attestation_scheme", AttestationScheme.LEGACY),
    ],
)
def test_every_field_moves_the_message(field, value):
    """A field that does not move the digest is a field the voter has not signed."""
    base = _msg()
    assert _msg(**{field: value}) != base


def test_scheme_is_bound_so_credentials_cannot_be_confused():
    """A LEGACY and a V1 credential over identical fields must not share a binding."""
    assert _msg(attestation_scheme=AttestationScheme.V1) != _msg(
        attestation_scheme=AttestationScheme.LEGACY
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("election_id", b"\x11" * 31),
        ("pseudonym", b"\x22" * 33),
        ("vk_bytes", b"\x33" * 47),
        ("ballot_digest", b"\x33" * 31),
        ("attestation_digest", b"\x44" * 33),
        ("eligibility_signature", b""),
    ],
)
def test_malformed_input_raises_rather_than_digesting_nonsense(field, value):
    with pytest.raises(ValueError):
        _msg(**{field: value})


def test_unknown_scheme_is_refused():
    with pytest.raises(ValueError):
        _msg(attestation_scheme="ATTESTATION_V99")


def test_sign_and_verify_round_trip():
    sk, vk = schnorr.keygen()
    vkb = g1_to_compressed(vk)
    msg = _msg(vk_bytes=vkb)
    sig = binding.sign_binding(sk, vk, msg)
    assert binding.verify_binding_sig(vkb, msg, sig)
    assert not binding.verify_binding_sig(vkb, _msg(vk_bytes=vkb, ballot_digest=b"\x99" * 32), sig)


def test_verify_returns_false_rather_than_raising_on_garbage():
    """Callers treat False as one uniform rejection, so nothing may escape as an
    exception and turn a bad ballot into a crashed tally."""
    sk, vk = schnorr.keygen()
    vkb = g1_to_compressed(vk)
    msg = _msg(vk_bytes=vkb)
    for bad_vk, bad_sig in [(b"", b"\x00" * 80), (vkb, b"nope"), (b"\x01" * 48, b"\x00" * 80)]:
        assert binding.verify_binding_sig(bad_vk, msg, bad_sig) is False
