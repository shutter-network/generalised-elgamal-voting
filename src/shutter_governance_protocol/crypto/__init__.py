"""The protocol-v1 crypto suite, built fresh in this repo.

BLS12-381; ElGamal + DKG in G2, Schnorr + attestations in G1; keccak256
transcripts. Byte-faithful to the reference SDK so cross-language conformance
vectors pass — achieved by reimplementation, never by importing the reference
repos.

Submodules:
    params      constants, generators, sizes, DSTs, encoding helpers
    points      BLS12-381 arithmetic + compressed codecs (subgroup-checked)
    transcript  Merlin-style Fiat-Shamir transcript + hash_to_scalar
    elgamal     exponential ElGamal in G2 + homomorphic ops
    schnorr     Schnorr signatures on G1
    proofs      DLEQ, (B+1)-branch OR, budget (exact/atMost), decryption-share DLEQ
    dkg         Feldman VSS distributed key generation
    recovery    Lagrange combination + baby-step giant-step
    ballot      ballot construction, validity-proof codec, crypto verification
    attestation ATTESTATION_V1 (weighted eligibility credential)
"""
