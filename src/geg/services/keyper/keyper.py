"""Keyper service (DESIGN.md §2, §5.3, §8.2).

A committee member: participates in the fresh per-election DKG and produces
precondition-guarded partial decryptions of the canonical aggregate. Keypers are
triggered automatically by the aggregator but **never trust the trigger** — before
producing shares a keyper re-derives the necessary facts from the data layer
itself (§8.2). An optional **hardening profile** (a MAY in v1) removes the admin
from the individual-ballot privacy trust base.

The DKG round exchange here is in-process (driven by the coordinator); a
multi-operator deployment wraps the same round methods behind authenticated P2P
HTTP (§5.3), which is a transport concern, not a protocol one.
"""

from __future__ import annotations

from geg.core import write_auth
from geg.core.admission import StoredBallot, validate_ballot
from geg.core.aggregation import aggregate_points
from geg.core.authz import Signer
from geg.crypto import proofs
from geg.crypto.dkg import KeyperDKGState, derive_joint_mpk, derive_mpk_share
from geg.crypto.points import g2_from_compressed, g2_to_compressed
from geg.envelopes.types import DecryptionShareEntry, DecryptionShareEnvelope
from geg.ports.data_layer import ElectionDataLayer
from geg.core.state import ElectionState, StateFacts, derive_state


class KeyperRefusal(RuntimeError):
    """Raised when a keyper refuses to decrypt because a §8.2 precondition fails."""


class KeyperService:
    def __init__(self, index: int, signer: Signer, data_layer: ElectionDataLayer, *, clock):
        self.index = index  # 1-based DKG id / keyper index
        self.signer = signer
        self.dl = data_layer
        self._clock = clock
        self.dkg = KeyperDKGState()

    # -- DKG (round methods; sequenced by the coordinator) ------------------ #

    def dkg_round1(self, n: int, t: int):
        """Generate this keyper's commitments and shares. Returns (commitments, shares)."""
        return self.dkg.round1(self.index, n, t)

    def dkg_round2(self, all_commitments: dict, received_shares: dict):
        """Verify received shares and form the combined secret share."""
        return self.dkg.round2(all_commitments, received_shares)

    def submit_dkg_result(self, election_id: bytes, all_commitments: dict) -> None:
        """Derive the joint key from all commitments and submit it (signed).

        Honest keypers submit byte-identical ``(pk_election, committee_pks)``, so
        the data layer's quorum rule finalizes the key.
        """
        pk = derive_joint_mpk(all_commitments)
        committee = [derive_mpk_share(i, all_commitments) for i in sorted(all_commitments)]
        pk_b = g2_to_compressed(pk)
        committee_b = [g2_to_compressed(c) for c in committee]
        sig = write_auth.sign_dkg_result(self.signer.private_key, election_id, pk_b, committee_b)
        self.dl.submit_dkg_result(election_id, pk_b, committee_b, sig) # TODO

    # -- partial decryption with §8.2 preconditions ------------------------ #

    def produce_decryption_share(self, election_id: bytes, *, hardened: bool = False):
        """Check §8.2 and produce this keyper's signed decryption share.

        Returns ``(share, signature)`` to submit, or ``None`` if this keyper already
        submitted for this election (idempotent no-op). Raises :class:`KeyperRefusal`
        if any precondition fails. All reads are against ``self.dl`` (the data layer);
        the caller decides where to *write* the result (directly, or via the
        coordinator relay), so this method never writes.
        """
        rec = self.dl.get_election(election_id)  # raises if unknown → precondition 1
        cfg = rec.config

        # Precondition 1: voting has ended (derived state Tallying or later).
        facts = StateFacts(
            cancelled=rec.cancelled,
            key_finalized=rec.finalized_key is not None,
            result_published=self.dl.get_result(election_id) is not None,
        )
        state = derive_state(cfg, facts, self._clock())
        if state not in (ElectionState.TALLYING, ElectionState.COMPLETE, ElectionState.VOID):
            raise KeyperRefusal(f"refuse: state is {state.value}, not tallying")
        if rec.finalized_key is None:
            raise KeyperRefusal("refuse: no finalized key")

        # Precondition 2: a canonical aggregate exists (published under aggregatorKey,
        # which the data layer enforced at write time).
        agg = self.dl.get_aggregate(election_id)
        if agg is None:
            raise KeyperRefusal("refuse: no aggregate published")

        # Precondition 3: not already decrypted (idempotent resend allowed).
        mine = [s for s in self.dl.list_decryption_shares(election_id) if s.keyper_index == self.index]
        if mine:
            return None

        if hardened:
            self._verify_aggregate_honesty(cfg, rec.finalized_key.pk_election, agg)

        entries = []
        for j, ct in enumerate(agg.aggregates):
            c1 = g2_from_compressed(ct.c1)
            c2 = g2_from_compressed(ct.c2)
            sigma = self.dkg.partial_decrypt(c1)
            t = proofs.make_decrypt_transcript(election_id, j)
            e, z = proofs.prove_decryption_share(
                t, c1, c2, self.dkg.public_key_share, sigma, self.dkg.combined_share, self.index
            )
            entries.append(DecryptionShareEntry(sigma=g2_to_compressed(sigma), proof=proofs.encode_dleq(e, z)))

        share = DecryptionShareEnvelope(election_id=election_id, keyper_index=self.index, entries=tuple(entries))
        sigmas = [e.sigma for e in entries]
        dleq_proofs = [(int.from_bytes(e.proof[:32], "big"), int.from_bytes(e.proof[32:], "big")) for e in entries]
        sig = write_auth.sign_decryption_share(self.signer.private_key, election_id, sigmas, dleq_proofs)
        return share, sig

    def decrypt_and_submit(self, election_id: bytes, *, hardened: bool = False) -> bool:
        """Produce the share (§8.2) and write it directly via ``self.dl``.

        The in-process path (tests, ``run_dkg_once``). Multi-operator keypers instead
        ``produce_decryption_share`` and POST the result to the coordinator relay.
        Idempotent: a keyper that already submitted is a no-op.
        """
        produced = self.produce_decryption_share(election_id, hardened=hardened)
        if produced is None:
            return True  # already submitted
        share, sig = produced
        self.dl.submit_decryption_share(election_id, share, sig)
        return True

    def _verify_aggregate_honesty(self, cfg, pk_election_bytes: bytes, agg) -> None:
        """Hardening profile (§8.2): defeat the 'exclude everyone but Alice' attack.

        (a) Recompute the homomorphic sum over the published admitted set (pure EC
            addition, no proof verification) and refuse on mismatch.
        (b) Re-verify only the excluded ballots, refusing if a valid ballot was
            excluded. In an honest election exclusions are near zero, so this is
            cheap; the gateway filter bounds the flood risk.
        """
        mpk = g2_from_compressed(pk_election_bytes)
        n = self.dl.count_ballots(cfg.election_id)
        ballots = self.dl.list_ballots(cfg.election_id, 0, n)
        by_seq = dict(enumerate(ballots))

        # (a) sum over admitted set must match the published aggregate.
        admitted = [
            _WeightedBallot(by_seq[s], by_seq[s].attestation.weight)
            for s in agg.admitted
            if s in by_seq
        ]
        if len(admitted) != len(agg.admitted):
            raise KeyperRefusal("refuse: admitted set references unknown ballots")
        recomputed = aggregate_points(admitted, cfg.num_candidates)
        published = [(g2_from_compressed(ct.c1), g2_from_compressed(ct.c2)) for ct in agg.aggregates]
        for (rc1, rc2), (pc1, pc2) in zip(recomputed, published):
            if not (rc1 == pc1 and rc2 == pc2):
                raise KeyperRefusal("refuse: recomputed aggregate does not match published aggregate")

        # (b) every excluded ballot must genuinely be invalid.
        for exclusion in agg.exclusions:
            env = by_seq.get(exclusion.sequence_number)
            if env is None:
                continue
            reason = validate_ballot(StoredBallot(exclusion.sequence_number, env), cfg, mpk)
            if reason is None:
                raise KeyperRefusal(
                    f"refuse: ballot {exclusion.sequence_number} was excluded but is valid"
                )


class _WeightedBallot:
    """Minimal admitted-ballot shape for ``aggregate_points`` (envelope + weight)."""

    __slots__ = ("envelope", "weight")

    def __init__(self, envelope, weight: int):
        self.envelope = envelope
        self.weight = weight
