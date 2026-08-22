"""The voter's binding of a ballot to the credential it was cast with.

The attestation is already bound to the *voter*: ``validate_ballot`` requires
``att.pseudonym == env.pseudonym`` and ``att.vk == env.vk``, and the ballot's
Schnorr signature is verified against that same ``vk``. A credential cannot be
lifted onto someone else's ballot.

What the voter never committed to was **which** of their own credentials this
ballot was cast with. ``canonical_ballot_message`` covers
``(election_id, pseudonym, ciphertexts, zk_proof)`` — not ``weight`` and not
``nonce``. So whoever assembled the ballot/attestation pair chose those two
fields, and the nonce is what orders re-votes:

    key = (envelope.attestation.nonce, sequence_number)     # core/admission

Given a voter's ballots A (nonce 100), B (200) and C (300), an assembler that
attaches C's attestation to ballot A and drops C makes A = (300, seq 0) outrank
B = (200, seq 1). The voter's last choice is discarded in favour of their first,
using only credentials the voter legitimately obtained. On a backend that issues
the credentials itself, no theft is needed at all — it simply picks the nonce.

This module closes that: a second Schnorr signature, under the same voter key,
over **the ballot and the credential together**.

Binding the pair is the point. A signature over the credential alone travels
*with* the credential, so the assembler moves both onto a different ballot and
the attack is unchanged. Only a message covering the ballot digest fixes the
pairing.

Nothing here is a new primitive. It is the house ``Transcript`` — length-prefixed,
domain-separated, byte-identical in the SDK — so the browser building the ballot
and the keyper validating it derive the same preimage from the same rules. The
signature is verified against the ballot's existing ``vk``, so a keyper needs no
new curve, no secp256k1 recovery and no chain context to check it.
"""

from __future__ import annotations

from eth_utils import keccak

from geg.crypto import schnorr
from geg.crypto.params import BINDING_LABEL
from geg.crypto.points import g1_from_compressed
from geg.crypto.transcript import Transcript

# The scheme is bound as a scalar rather than by name so the two credential
# schemes can never be read as one another: a LEGACY credential and a V1 one
# over the same fields must not produce the same binding.
_SCHEME_CODES = {"ATTESTATION_V1": 1, "ATTESTATION_LEGACY": 2}


def _scheme_code(scheme) -> int:
    name = getattr(scheme, "value", scheme)
    code = _SCHEME_CODES.get(name)
    if code is None:
        raise ValueError(f"unknown attestation scheme: {name!r}")
    return code


def binding_message(
    *,
    election_id: bytes,
    pseudonym: bytes,
    vk_bytes: bytes,
    ballot_digest: bytes,
    attestation_scheme,
    attestation_digest: bytes,
    eligibility_signature: bytes,
) -> bytes:
    """The keccak256 digest the voter signs to bind one ballot to one credential.

    ``ballot_digest`` is ``keccak(canonical_ballot_message(...))`` and
    ``attestation_digest`` is the credential's own signed digest — ``V1`` and
    ``LEGACY`` each already define one, and reusing them keeps a single
    definition of each message rather than a second copy that can drift.

    ``eligibility_signature`` is included so the voter commits to the exact
    credential *instance*, not merely to its contents. It costs nothing and is
    strictly tighter.
    """
    if len(election_id) != 32:
        raise ValueError(f"electionId must be 32 bytes (got {len(election_id)})")
    if len(pseudonym) != 32:
        raise ValueError(f"pseudonym must be 32 bytes (got {len(pseudonym)})")
    if len(vk_bytes) != 48:
        raise ValueError(f"vk must be 48 bytes (got {len(vk_bytes)})")
    if len(ballot_digest) != 32:
        raise ValueError(f"ballotDigest must be 32 bytes (got {len(ballot_digest)})")
    if len(attestation_digest) != 32:
        raise ValueError(f"attestationDigest must be 32 bytes (got {len(attestation_digest)})")
    if not eligibility_signature:
        raise ValueError("eligibilitySignature must not be empty")

    t = Transcript(BINDING_LABEL)
    t.append("bind:electionId", election_id)
    t.append("bind:pseudonym", pseudonym)
    t.append("bind:vk", vk_bytes)
    t.append("bind:ballot", ballot_digest)
    t.append_scalar("bind:scheme", _scheme_code(attestation_scheme))
    t.append("bind:attestation", attestation_digest)
    t.append("bind:eligSig", eligibility_signature)
    return keccak(t.preimage())


def attestation_digest_for(att) -> bytes:
    """The credential's own signed digest, whichever scheme it uses."""
    from geg.crypto.attestation import attestation_message, legacy_attestation_message
    from geg.envelopes.types import AttestationScheme

    if att.scheme is AttestationScheme.V1:
        return attestation_message(att.election_id, att.pseudonym, att.vk, att.weight, att.nonce)
    if att.scheme is AttestationScheme.LEGACY:
        return legacy_attestation_message(att.election_id, att.pseudonym, att.vk)
    raise ValueError(f"unknown attestation scheme: {att.scheme!r}")


def ballot_message_digest(env) -> bytes:
    """``keccak(canonical_ballot_message(...))`` for an envelope.

    The same preimage the voter's *ballot* signature is taken over, so the binding
    inherits its coverage — election, pseudonym, every ciphertext and the proof —
    without restating it and risking a second, divergent definition.
    """
    from geg.crypto.ballot import canonical_ballot_message

    return keccak(
        canonical_ballot_message(
            env.election_id,
            env.pseudonym,
            [(ct.c1, ct.c2) for ct in env.ciphertexts],
            env.zk_proof,
        )
    )


def envelope_binding_message(env, ballot_digest: bytes) -> bytes:
    """``binding_message`` for a whole ballot envelope — the form callers want."""
    return binding_message(
        election_id=env.election_id,
        pseudonym=env.pseudonym,
        vk_bytes=env.vk,
        ballot_digest=ballot_digest,
        attestation_scheme=env.attestation.scheme,
        attestation_digest=attestation_digest_for(env.attestation),
        eligibility_signature=env.attestation.signature,
    )


def sign_ballot_binding(
    *,
    voter_sk: int,
    voter_vk,
    election_id: bytes,
    pseudonym: bytes,
    vk_bytes: bytes,
    ciphertexts,
    zk_proof: bytes,
    attestation,
    k: int | None = None,
) -> bytes:
    """Produce the binding signature from the parts a voter holds at build time.

    This is the whole signer-side API: a caller that has just built a ballot and
    obtained a credential should never assemble the message itself, because a
    second assembly is a second chance to disagree with the verifier about it.
    """
    from geg.crypto.ballot import canonical_ballot_message

    ballot_digest = keccak(
        canonical_ballot_message(election_id, pseudonym, list(ciphertexts), zk_proof)
    )
    message = binding_message(
        election_id=election_id,
        pseudonym=pseudonym,
        vk_bytes=vk_bytes,
        ballot_digest=ballot_digest,
        attestation_scheme=attestation.scheme,
        attestation_digest=attestation_digest_for(attestation),
        eligibility_signature=attestation.signature,
    )
    return sign_binding(voter_sk, voter_vk, message, k=k)


def sign_binding(voter_sk: int, voter_vk, message: bytes, *, k: int | None = None) -> bytes:
    """Sign a binding message with the voter's ballot key (80-byte ``R ‖ s``)."""
    R, s = schnorr.sign(voter_sk, voter_vk, message, k=k)
    return schnorr.encode(R, s)


def verify_binding_sig(vk_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a binding signature. Returns ``False`` (never raises) on any
    malformed input, so callers treat a ``False`` uniformly as a rejection."""
    try:
        vk = g1_from_compressed(vk_bytes)
        R, s = schnorr.decode(signature)
        return schnorr.verify(vk, message, R, s)
    except Exception:  # noqa: BLE001
        return False
