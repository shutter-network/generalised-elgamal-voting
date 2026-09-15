"""Weighted homomorphic aggregation and threshold recovery.

Aggregation is uniform: the per-candidate aggregate is always
``Σ_i weight_i · ct_i`` over admitted ballots, with ``weight_i`` from each
ballot's attestation (weight 1 is the one-person-one-vote case — one code path).

Recovery verifies every decryption share's DLEQ against the finalized committee
keys, Lagrange-combines ``t+1`` of them per candidate, and recovers each total by
baby-step giant-step within the **derived** bound ``budget · Σ(admitted weights)``
 — computable from public data since weights are attested.

There are **two** ways to establish a result, and they are not equally expensive.
:func:`recover_result` *solves* the discrete log (BSGS, ``O(√bound)`` in time and
memory) and is what the tally aggregator runs. :func:`check_result` *checks* a
total someone already published — one scalar multiplication, no bound, no table —
and is what every auditor should run. The two are equally conclusive: G2 has prime
order, so ``x ↦ x·P2`` is a bijection and there is exactly one ``x`` with
``x·P2 == τ``. Searching for a number you already hold is work, not assurance.

Both go through :func:`_derive_taus`, so they cannot drift on share verification,
quorum selection, or Lagrange combination.
"""

from __future__ import annotations

from geg.core.admission import AdmissionResult
from geg.core.config import ElectionConfig, Mode
from geg.crypto.elgamal import add_ct, scalar_mul_ct
from geg.crypto.points import G2, Z2, add, g2_from_compressed, g2_to_compressed, mul, neg
from geg.crypto.proofs import decode_dleq, make_decrypt_transcript, verify_decryption_share
from geg.crypto.recovery import (
    baby_step_giant_step_with_table,
    build_baby_step_table,
    combine_shares,
)
from geg.envelopes.types import (
    AggregateArtifact,
    Ciphertext,
    DecryptionShareEnvelope,
    ResultArtifact,
)


class TallyInfeasible(Exception):
    """The derived BSGS bound exceeds what this deployment is configured to solve.

    Raised *before* any table is allocated, so an over-sized election reports
    instead of dying in the allocator or running for hours. That distinction is the
    whole point: "infeasible" and "crashed" need different responses from an
    operator, and only one of them is fixed by giving the coordinator more memory.
    """


def scaled_weight(weight: int, scale: int) -> int:
    """One attested weight, in the units this election counts in.

    Integer half-up: ``(w + s//2) // s``. **Never** Python's :func:`round`, which is
    half-to-even, while JavaScript's ``Math.round`` is half-up — the two disagree at
    exactly ``.5``, and the SDK and this library must produce byte-identical
    aggregates from the same ballots. That divergence would surface as an honest
    committee appearing to publish a false aggregate, with nothing in the error to
    suggest rounding.

    ``scale == 1`` returns ``weight`` unchanged, which is the expected path.
    """
    return (weight + scale // 2) // scale


def bsgs_bound(config: ElectionConfig, total_scaled_weight: int) -> int:
    """Derived plaintext bound for BSGS: ``budget · Σ(scaled admitted weights)``.

    Takes the **scaled** total, because that is what the aggregate was built from.
    Passing the raw total would search a range larger than the plaintext can occupy
    whenever ``scale > 1`` — wasteful, and it would disagree with the published
    ``bsgs_bound``.
    """
    return config.budget * total_scaled_weight


def aggregate_points(admitted, num_candidates: int, scale: int = 1) -> list[tuple]:
    """Per-candidate ``Σ_i scaled(weight_i) · ct_i`` as G2 point pairs.

    A ballot whose weight scales to zero contributes nothing but is still admitted —
    it appears in the admitted set and in no exclusion list. That only happens when
    ``scale > 1``, and the voter is told before signing; see the weight scaling plan.
    """
    acc = [(Z2, Z2) for _ in range(num_candidates)]
    for ab in admitted:
        w = scaled_weight(ab.weight, scale)
        if w == 0:
            continue
        cts = ab.envelope.ciphertexts
        for j in range(num_candidates):
            ct_pts = (g2_from_compressed(cts[j].c1), g2_from_compressed(cts[j].c2))
            acc[j] = add_ct(acc[j], scalar_mul_ct(w, ct_pts))
    return acc


def build_aggregate_artifact(config: ElectionConfig, admission: AdmissionResult) -> AggregateArtifact:
    """Compose the admitted set + weighted aggregate into the published artifact."""
    agg_pts = aggregate_points(admission.admitted, config.num_candidates, config.scale)
    aggregates = tuple(
        Ciphertext(c1=g2_to_compressed(c1), c2=g2_to_compressed(c2)) for (c1, c2) in agg_pts
    )
    # Both totals are published: the raw one is turnout in token units, which is what
    # a reader expects it to mean, and the scaled one is what the aggregate was
    # actually built from and what bounds the recovery. They are equal at scale 1, so
    # a divergence is itself the signal that scaling is in effect.
    total_scaled = sum(scaled_weight(a.weight, config.scale) for a in admission.admitted)
    return AggregateArtifact(
        election_id=config.election_id,
        aggregates=aggregates,
        admitted=tuple(a.sequence_number for a in admission.admitted),
        exclusions=admission.exclusions,
        total_admitted_weight=admission.total_admitted_weight,
        total_scaled_weight=total_scaled,
    )


def _derive_taus(
    config: ElectionConfig,
    aggregate: AggregateArtifact,
    shares: list[DecryptionShareEnvelope],
    committee_pks: tuple[bytes, ...],
    quorum: int,
) -> tuple[list[object], tuple[int, ...]] | None:
    """Per-candidate ``τ = C2 − σ`` from ``quorum`` DLEQ-verified shares.

    Returns ``(taus, keyper_indices_used)``, or ``None`` if any candidate has fewer
    than ``quorum`` shares whose DLEQ verifies — the caller leaves the election in
    ``Tallying``.

    This is the whole trust-bearing part of establishing a result: every share is
    checked against the finalized committee key and the per-candidate decrypt
    transcript before it is allowed into the Lagrange combination. Both
    :func:`recover_result` and :func:`check_result` route through here so a change
    to share verification cannot apply to one and not the other.

    ``keyper_indices_used`` is taken from the first candidate, matching the
    published :class:`ResultArtifact` field.
    """
    taus: list[object] = []
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

        if len(valid) < quorum:
            return None
        chosen = valid[:quorum]
        taus.append(add(c2, neg(combine_shares(chosen))))
        if indices_used is None:
            indices_used = tuple(idx for idx, _ in chosen)

    return taus, (indices_used or ())


def recover_result(
    config: ElectionConfig,
    aggregate: AggregateArtifact,
    shares: list[DecryptionShareEnvelope],
    committee_pks: tuple[bytes, ...],
    quorum: int,
    solver_ceiling: int | None = None,
) -> ResultArtifact | None:
    """Recover per-candidate totals from ``quorum`` DLEQ-verified shares.

    **Solves** the discrete log per candidate. This is the expensive path — BSGS is
    ``O(√bound)`` in time *and* memory — and only the tally aggregator needs to run
    it. Anyone verifying a result that is already published should call
    :func:`check_result` instead, which is one scalar multiplication and just as
    conclusive.

    ``quorum`` is ``config.threshold.t`` — the number of keypers required, since ``t``
    *is* the quorum; it is passed explicitly rather than read off ``config``
    so callers can recover under a deliberately different count in tests.
    ``committee_pks`` is the finalized ``committee_pks`` tuple (index
    ``keyper_index - 1``). Returns ``None`` if any candidate lacks ``quorum`` valid
    shares or BSGS fails — the caller leaves the election in ``Tallying``.
    """
    bound = bsgs_bound(config, aggregate.total_scaled_weight)
    # Checked before the shares are even verified, and long before a table is
    # allocated: the bound follows from public data, so an election that cannot be
    # tallied on this machine should say so immediately rather than after minutes
    # of work or an OOM kill. `solver_ceiling` is the deployment's number — see
    # docs/COORDINATOR_SIZING.md for how to size it against real hardware — and
    # `None` means "do not check", which is what the conformance vectors and the
    # in-memory tests want.
    if solver_ceiling is not None and bound > solver_ceiling:
        raise TallyInfeasible(
            f"BSGS bound {bound} (budget {config.budget} x total admitted weight "
            f"{aggregate.total_admitted_weight}) exceeds this deployment's solver "
            f"ceiling of {solver_ceiling}. Raise the ceiling and give the "
            f"coordinator memory to match (docs/COORDINATOR_SIZING.md), or the "
            f"tally cannot complete."
        )

    derived = _derive_taus(config, aggregate, shares, committee_pks, quorum)
    if derived is None:
        return None
    taus, indices_used = derived

    # One table for the whole election, not one per candidate. It depends only on
    # the bound, so rebuilding it per candidate would be ℓ times the work — the
    # build is the expensive half (~11 µs and 218 B per entry), while the walks
    # across all candidates share a single budget of ≈√bound steps in exact mode.
    table = build_baby_step_table(bound)
    totals: list[int] = []
    for tau in taus:
        m = baby_step_giant_step_with_table(tau, table)
        if m is None:
            return None
        totals.append(m)

    return ResultArtifact(
        election_id=config.election_id,
        totals=tuple(totals),
        keyper_indices=indices_used,
        bsgs_bound=bound,
    )


def check_result(
    config: ElectionConfig,
    aggregate: AggregateArtifact,
    shares: list[DecryptionShareEnvelope],
    committee_pks: tuple[bytes, ...],
    quorum: int,
    claimed_totals: tuple[int, ...],
) -> tuple[bool, str | None]:
    """Verify already-published totals against the aggregate and the shares.

    The auditor's path, and the cheap one: ``O(candidates)`` scalar multiplications
    with no BSGS table and no bound to search. Returns ``(ok, reason)`` where
    ``reason`` is ``None`` on success, mirroring ``verify_ballot_crypto``. Reasons
    are prefixed ``shares:`` or ``result:`` so a caller can tell "the committee did
    not produce enough valid shares" from "the published totals are wrong".

    **This is not trusting the publisher.** Everything except the candidate answer is
    recomputed here: every share's DLEQ is checked against the finalized committee
    key, the quorum subset is Lagrange-combined locally, and ``τ`` is derived from
    the caller's own aggregate. The only input taken from the publisher is the
    integer, and a wrong integer fails the equality with certainty — the same shape
    as verifying a signature rather than forging one.

    Three checks, all required:

    1. ``T_j · P2 == τ_j``. Conclusive because ``x ↦ x·P2`` is a bijection on a
       prime-order group: if the equality holds, ``T_j`` *is* the plaintext.
    2. ``0 <= T_j <= bound``. Closes the one gap in (1): ``T_j + q`` maps to the same
       group element and would pass the equality while being a nonsense 256-bit
       integer. Without this the check is sound over ``Z_q`` but not over the tallies
       anyone can read.
    3. ``Σ_j T_j == bound`` in ``exact`` mode (``<= bound`` in ``atMost``). Every
       admitted ballot spends exactly ``budget``, so the totals sum to
       ``budget · Σ(weights)`` identically. Pins the whole vector rather than each
       element alone, and catches a publisher that used a different admitted set.
    """
    if len(claimed_totals) != len(aggregate.aggregates):
        return False, (
            f"result: {len(claimed_totals)} totals published for "
            f"{len(aggregate.aggregates)} candidates"
        )

    derived = _derive_taus(config, aggregate, shares, committee_pks, quorum)
    if derived is None:
        return False, f"shares: fewer than {quorum} valid shares for some candidate"
    taus, _ = derived

    bound = bsgs_bound(config, aggregate.total_scaled_weight)

    for j, (tau, total) in enumerate(zip(taus, claimed_totals)):
        if not (0 <= total <= bound):
            return False, f"result: total[{j}] = {total} outside [0, {bound}]"
        if mul(G2, total) != tau:
            return False, f"result: total[{j}] = {total} does not decrypt the aggregate"

    summed = sum(claimed_totals)
    if config.mode is Mode.EXACT:
        if summed != bound:
            return False, (
                f"result: totals sum to {summed}, not the {bound} that "
                f"budget x total admitted weight requires in exact mode"
            )
    elif summed > bound:
        return False, f"result: totals sum to {summed}, over the bound {bound}"

    return True, None
