"""Auditor procedure (DESIGN.md §8.4).

Anyone can audit an election from public reads alone: recompute DKG finalization
from the stored submissions, independently re-derive the admitted set and the
weighted aggregate, re-verify every decryption share's DLEQ, and recombine +
re-run BSGS to check the published result. Any mismatch is publishable evidence.
Detection is guaranteed even against a malicious data layer / gateway /
aggregator (v1 has no in-protocol challenge; §3).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from geg.core import write_auth
from geg.core.admission import StoredBallot, admit
from geg.core.aggregation import build_aggregate_artifact, recover_result
from geg.ports.data_layer import ElectionDataLayer


@dataclass
class AuditReport:
    dkg_ok: bool = False
    aggregate_ok: bool = False
    shares_ok: bool = False
    result_ok: bool = False
    discrepancies: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.dkg_ok and self.aggregate_ok and self.shares_ok and self.result_ok and not self.discrepancies


def _submitter_index(cfg, election_id: bytes, submission) -> int | None:
    """Recover the DKG submitter from its content signature (see geg.write_auth)."""
    try:
        recovered = write_auth.recover_digest(
            write_auth.dkg_result_digest(election_id, submission.pk_election, list(submission.committee_pks)),
            submission.keyper_signature,
        )
    except Exception:  # noqa: BLE001
        return None
    for i, k in enumerate(cfg.keypers, start=1):
        if k.signing_key == recovered:
            return i
    return None


def audit(dl: ElectionDataLayer, election_id: bytes) -> AuditReport:
    report = AuditReport()
    rec = dl.get_election(election_id)
    cfg = rec.config

    # 1. Recompute DKG finalization from the stored submissions (quorum rule).
    submissions = dl.get_dkg_submissions(election_id)
    groups: dict[tuple, set[int]] = {}
    for sub in submissions:
        idx = _submitter_index(cfg, election_id, sub)
        if idx is None:
            report.discrepancies.append("dkg: a submission is signed by no registered keyper")
            continue
        groups.setdefault((sub.pk_election, sub.committee_pks), set()).add(idx)
    finalized = next((k for k, v in groups.items() if len(v) >= cfg.threshold.t + 1), None)
    published_key = dl.get_finalized_key(election_id)
    if finalized is None:
        report.discrepancies.append("dkg: no quorum among submissions")
    elif published_key is None or (published_key.pk_election, published_key.committee_pks) != finalized:
        report.discrepancies.append("dkg: published finalized key disagrees with recomputation")
    else:
        report.dkg_ok = True

    if published_key is None:
        return report  # cannot proceed without a key

    # 2. Independently re-derive the admitted set + weighted aggregate; compare.
    n = dl.count_ballots(election_id)
    stored = [StoredBallot(i, env) for i, env in enumerate(dl.list_ballots(election_id, 0, n))]
    admission = admit(stored, cfg, published_key.pk_election)
    recomputed_agg = build_aggregate_artifact(cfg, admission)
    published_agg = dl.get_aggregate(election_id)
    if published_agg is None:
        report.discrepancies.append("aggregate: none published")
        return report
    if recomputed_agg == published_agg:
        report.aggregate_ok = True
    else:
        if recomputed_agg.admitted != published_agg.admitted:
            report.discrepancies.append("aggregate: admitted set differs from recomputation")
        if recomputed_agg.aggregates != published_agg.aggregates:
            report.discrepancies.append("aggregate: ciphertexts differ from recomputation")
        if recomputed_agg.exclusions != published_agg.exclusions:
            report.discrepancies.append("aggregate: exclusions differ from recomputation")
        if recomputed_agg.total_admitted_weight != published_agg.total_admitted_weight:
            report.discrepancies.append("aggregate: total admitted weight differs")

    # 3 + 4. Re-verify shares' DLEQs and recover; compare to the published result.
    shares = dl.list_decryption_shares(election_id)
    recovered = recover_result(cfg, published_agg, shares, published_key.committee_pks, cfg.threshold.t)
    published_result = dl.get_result(election_id)
    if recovered is None:
        report.discrepancies.append("shares: fewer than t+1 valid shares (cannot recover)")
        return report
    report.shares_ok = True  # recover_result verified every used share's DLEQ

    if published_result is None:
        report.discrepancies.append("result: none published")
    elif tuple(recovered.totals) != tuple(published_result.totals):
        report.discrepancies.append("result: published totals disagree with recomputation")
    elif recovered.bsgs_bound != published_result.bsgs_bound:
        report.discrepancies.append("result: derived BSGS bound differs")
    else:
        report.result_ok = True

    return report
