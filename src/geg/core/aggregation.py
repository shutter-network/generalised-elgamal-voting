"""Weighted homomorphic aggregation and threshold recovery (DESIGN.md §6.3, §8).

Aggregation is uniform: the per-candidate aggregate is always
``Σ_i weight_i · ct_i`` over admitted ballots, with ``weight_i`` from each
ballot's attestation (weight 1 is the one-person-one-vote case — one code path).

Recovery verifies every decryption share's DLEQ against the finalized committee
keys, Lagrange-combines ``t+1`` of them per candidate, and recovers each total by
baby-step giant-step within the **derived** bound ``budget · Σ(admitted weights)``
(DESIGN.md §6.3) — computable from public data since weights are attested.
"""

from __future__ import annotations

from geg.core.admission import AdmissionResult
from geg.core.config import ElectionConfig
from geg.crypto.elgamal import add_ct, scalar_mul_ct
from geg.crypto.points import Z2, add, g2_from_compressed, g2_to_compressed, neg
from geg.crypto.proofs import decode_dleq, make_decrypt_transcript, verify_decryption_share
from geg.crypto.recovery import baby_step_giant_step, combine_shares
from geg.envelopes.types import (
    AggregateArtifact,
    Ciphertext,
    DecryptionShareEnvelope,
    ResultArtifact,
)


def bsgs_bound(config: ElectionConfig, total_admitted_weight: int) -> int:
    """Derived plaintext bound for BSGS: ``budget · Σ(admitted weights)`` (§6.3)."""
    return config.budget * total_admitted_weight


def aggregate_points(admitted, num_candidates: int) -> list[tuple]:
    """Per-candidate ``Σ_i weight_i · ct_i`` as G2 point pairs."""
    acc = [(Z2, Z2) for _ in range(num_candidates)]
    for ab in admitted:
        cts = ab.envelope.ciphertexts
        for j in range(num_candidates):
            ct_pts = (g2_from_compressed(cts[j].c1), g2_from_compressed(cts[j].c2))
            acc[j] = add_ct(acc[j], scalar_mul_ct(ab.weight, ct_pts))
    return acc


def build_aggregate_artifact(config: ElectionConfig, admission: AdmissionResult) -> AggregateArtifact:
    """Compose the admitted set + weighted aggregate into the published artifact (§7.2)."""
    agg_pts = aggregate_points(admission.admitted, config.num_candidates)
    aggregates = tuple(
        Ciphertext(c1=g2_to_compressed(c1), c2=g2_to_compressed(c2)) for (c1, c2) in agg_pts
    )
    return AggregateArtifact(
        election_id=config.election_id,
        aggregates=aggregates,
        admitted=tuple(a.sequence_number for a in admission.admitted),
        exclusions=admission.exclusions,
        total_admitted_weight=admission.total_admitted_weight,
    )


def recover_result(
    config: ElectionConfig,
    aggregate: AggregateArtifact,
    shares: list[DecryptionShareEnvelope],
    committee_pks: tuple[bytes, ...],
    threshold_t: int,
) -> ResultArtifact | None:
    """Recover per-candidate totals from ``t+1`` DLEQ-verified shares (§8.3).

    ``committee_pks`` is the finalized ``committee_pks`` tuple (index
    ``keyper_index - 1``). Returns ``None`` if any candidate lacks ``t+1`` valid
    shares or BSGS fails — the caller treats that as a ``Void`` election.
    """
    bound = bsgs_bound(config, aggregate.total_admitted_weight)
    totals: list[int] = []
    indices_used: tuple[int, ...] | None = None

    for j, ct in enumerate(aggregate.aggregates):
        c1 = g2_from_compressed(ct.c1)
        c2 = g2_from_compressed(ct.c2)
        valid: list[tuple[int, object]] = []
        for share in shares:
            if j >= len(share.entries):
                continue
            entry = share.entries[j]
            idx = share.keyper_index
            if not (1 <= idx <= len(committee_pks)):
                continue
            try:
                sigma = g2_from_compressed(entry.sigma)
                e, z = decode_dleq(entry.proof)
                mpk_k = g2_from_compressed(committee_pks[idx - 1])
            except ValueError:
                continue
            t = make_decrypt_transcript(config.election_id, j)
            if verify_decryption_share(t, c1, c2, mpk_k, sigma, e, z, idx):
                valid.append((idx, sigma))

        if len(valid) < threshold_t + 1:
            return None
        chosen = valid[: threshold_t + 1]
        combined = combine_shares(chosen)
        tau = add(c2, neg(combined))
        m = baby_step_giant_step(tau, bound)
        if m is None:
            return None
        totals.append(m)
        if indices_used is None:
            indices_used = tuple(idx for idx, _ in chosen)

    return ResultArtifact(
        election_id=config.election_id,
        totals=tuple(totals),
        keyper_indices=indices_used or (),
        bsgs_bound=bound,
    )
