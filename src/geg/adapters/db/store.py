"""``PostgresStore`` — the database adapter's enforcement engine (DESIGN.md §5.1).

Implements the ``ElectionDataLayer`` contract against Postgres, server-side:
stable total ballot ordering (a per-election 0-based sequence assigned under a row
lock), config immutability after ``voting_start``, append-only artifacts and
idempotent shares (via primary keys + read-compare), the DKG finalization quorum
rule, the write-authorization matrix (:mod:`geg.authz` request signatures), and
public reads. It enforces the *same* contract as the in-memory reference and
passes the *same* conformance suite.

Time is injected via ``clock`` (the service's NTP-disciplined wall clock in
production; a controllable clock in tests) so immutability/cancellation windows
are deterministic — matching "the authoritative timestamp source is the adapter's"
(DESIGN.md §4.2).
"""

from __future__ import annotations

from dataclasses import replace
from typing import Callable

import psycopg
from psycopg.types.json import Jsonb

from geg.core import authz, write_auth
from geg.adapters.db.schema import DDL
from geg.core.config import ElectionConfig
from geg.envelopes import codecs
from geg.envelopes.types import (
    AggregateArtifact,
    BallotEnvelope,
    DecryptionShareEnvelope,
    DKGResultSubmission,
    ResultArtifact,
)
from geg.ports.data_layer import (
    ElectionDataLayer,
    ElectionFilter,
    ElectionRecord,
    FinalizedKey,
    ImmutabilityError,
    WriteAuthorizationError,
)


class PostgresStore(ElectionDataLayer):
    def __init__(self, dsn: str, clock: Callable[[], int] | None = None):
        self._dsn = dsn
        self._clock = clock or (lambda: 0)

    # -- connection + schema ------------------------------------------------ #

    def _conn(self):
        return psycopg.connect(self._dsn)

    def init_schema(self) -> None:
        with self._conn() as conn:
            conn.execute(DDL)

    def truncate_all(self) -> None:
        """Wipe all rows (test helper)."""
        from geg.adapters.db.schema import TABLES

        with self._conn() as conn:
            conn.execute("TRUNCATE " + ", ".join(TABLES) + " CASCADE")
            conn.execute("ALTER SEQUENCE election_id_seq RESTART WITH 1")

    def _config(self, conn, election_id: bytes) -> ElectionConfig:
        row = conn.execute(
            "SELECT config FROM elections WHERE election_id = %s", (election_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"unknown election {election_id.hex()}")
        return codecs.dec_config(row[0])

    # -- election lifecycle ------------------------------------------------- #

    def register_election(self, config: ElectionConfig, admin_sig: bytes) -> bytes:
        if not authz.verify_register(config.admin_key, admin_sig, config):
            raise WriteAuthorizationError("register: bad admin signature")
        with self._conn() as conn:
            (next_id,) = conn.execute("SELECT nextval('election_id_seq')").fetchone()
            election_id = int(next_id).to_bytes(32, "big")  # registry-style sequential id
            stored = replace(config, election_id=election_id)
            conn.execute(
                "INSERT INTO elections (election_id, config, admin_key, voting_start) "
                "VALUES (%s, %s, %s, %s)",
                (election_id, Jsonb(codecs.enc_config(stored)), stored.admin_key, stored.voting_start),
            )
        return election_id

    def cancel_election(self, election_id: bytes, admin_sig: bytes) -> None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT admin_key, voting_start FROM elections WHERE election_id = %s FOR UPDATE",
                (election_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"unknown election {election_id.hex()}")
            admin_key, voting_start = bytes(row[0]), int(row[1])
            if self._clock() >= voting_start:
                raise ImmutabilityError("cannot cancel at or after voting_start")
            if not authz.verify_request(admin_key, admin_sig, "cancel", election_id):
                raise WriteAuthorizationError("cancel: bad admin signature")
            conn.execute("UPDATE elections SET cancelled = TRUE WHERE election_id = %s", (election_id,))

    def get_election(self, election_id: bytes) -> ElectionRecord:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT config, cancelled FROM elections WHERE election_id = %s", (election_id,)
            ).fetchone()
            if row is None:
                raise KeyError(f"unknown election {election_id.hex()}")
            config = codecs.dec_config(row[0])
            return ElectionRecord(
                config=config, cancelled=bool(row[1]),
                finalized_key=self._finalized_key(conn, config),
            )

    def list_elections(self, filter: ElectionFilter | None = None) -> list[bytes]:
        with self._conn() as conn:
            if filter and filter.admin_key is not None:
                rows = conn.execute(
                    "SELECT election_id FROM elections WHERE admin_key = %s ORDER BY election_id",
                    (filter.admin_key,),
                ).fetchall()
            else:
                rows = conn.execute("SELECT election_id FROM elections ORDER BY election_id").fetchall()
            return [bytes(r[0]) for r in rows]

    # -- DKG ---------------------------------------------------------------- #

    def submit_dkg_result(self, election_id, pk_election, committee_pks, keyper_sig) -> None:
        with self._conn() as conn:
            config = self._config(conn, election_id)
            committee = [bytes(p) for p in committee_pks]
            digest = write_auth.dkg_result_digest(election_id, bytes(pk_election), committee)
            idx = self._keyper_index_by_recovery(config, digest, keyper_sig)
            submission = DKGResultSubmission(
                election_id=election_id,
                pk_election=bytes(pk_election),
                committee_pks=tuple(bytes(p) for p in committee_pks),
                keyper_signature=keyper_sig,
            )
            existing = conn.execute(
                "SELECT submission FROM dkg_submissions WHERE election_id = %s AND keyper_index = %s",
                (election_id, idx),
            ).fetchone()
            if existing is not None:
                prev = codecs.dec_dkg_result(existing[0])
                if (prev.pk_election, prev.committee_pks) != (submission.pk_election, submission.committee_pks):
                    raise ImmutabilityError(f"keyper {idx} already submitted a different DKG result")
                return
            conn.execute(
                "INSERT INTO dkg_submissions (election_id, keyper_index, submission) VALUES (%s, %s, %s)",
                (election_id, idx, Jsonb(codecs.enc_dkg_result(submission))),
            )

    def get_dkg_submissions(self, election_id) -> list[DKGResultSubmission]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT submission FROM dkg_submissions WHERE election_id = %s ORDER BY keyper_index",
                (election_id,),
            ).fetchall()
            return [codecs.dec_dkg_result(r[0]) for r in rows]

    def get_finalized_key(self, election_id) -> FinalizedKey | None:
        with self._conn() as conn:
            config = self._config(conn, election_id)
            return self._finalized_key(conn, config)

    def _finalized_key(self, conn, config: ElectionConfig) -> FinalizedKey | None:
        rows = conn.execute(
            "SELECT keyper_index, submission FROM dkg_submissions WHERE election_id = %s",
            (config.election_id,),
        ).fetchall()
        groups: dict[tuple, set[int]] = {}
        for idx, sub_json in rows:
            sub = codecs.dec_dkg_result(sub_json)
            groups.setdefault((sub.pk_election, sub.committee_pks), set()).add(int(idx))
        needed = config.threshold.t + 1
        for (pk, committee), keypers in groups.items():
            if len(keypers) >= needed:
                return FinalizedKey(pk_election=pk, committee_pks=committee)
        return None

    # -- ballots ------------------------------------------------------------ #

    def submit_ballot(self, election_id, ballot: BallotEnvelope) -> int:
        with self._conn() as conn:
            # Lock the election row to serialize sequence assignment (stable total order).
            locked = conn.execute(
                "SELECT 1 FROM elections WHERE election_id = %s FOR UPDATE", (election_id,)
            ).fetchone()
            if locked is None:
                raise KeyError(f"unknown election {election_id.hex()}")
            row = conn.execute(
                "SELECT COALESCE(MAX(seq) + 1, 0) FROM ballots WHERE election_id = %s", (election_id,)
            ).fetchone()
            seq = int(row[0])
            conn.execute(
                "INSERT INTO ballots (election_id, seq, ballot) VALUES (%s, %s, %s)",
                (election_id, seq, Jsonb(codecs.enc_ballot(ballot))),
            )
            return seq

    def list_ballots(self, election_id, start: int, count: int) -> list[BallotEnvelope]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT ballot FROM ballots WHERE election_id = %s AND seq >= %s ORDER BY seq LIMIT %s",
                (election_id, start, count),
            ).fetchall()
            return [codecs.dec_ballot(r[0]) for r in rows]

    def count_ballots(self, election_id) -> int:
        with self._conn() as conn:
            return int(
                conn.execute(
                    "SELECT COUNT(*) FROM ballots WHERE election_id = %s", (election_id,)
                ).fetchone()[0]
            )

    # -- tally artifacts ---------------------------------------------------- #

    def submit_aggregate(self, election_id, aggregate: AggregateArtifact, keyper_sig) -> None:
        with self._conn() as conn:
            config = self._config(conn, election_id)
            digest = write_auth.aggregate_digest_of(election_id, aggregate)
            idx = self._keyper_index_by_recovery(config, digest, keyper_sig)
            # Lock the election row to serialize concurrent submissions (the finalize
            # check + override must be atomic — otherwise two overrides could race the
            # quorum). Mirrors submit_ballot's serialization.
            if conn.execute(
                "SELECT 1 FROM elections WHERE election_id = %s FOR UPDATE", (election_id,)
            ).fetchone() is None:
                raise KeyError(f"unknown election {election_id.hex()}")
            existing = conn.execute(
                "SELECT aggregate FROM aggregates WHERE election_id = %s AND keyper_index = %s",
                (election_id, idx),
            ).fetchone()
            if existing is not None and codecs.dec_aggregate(existing[0]) == aggregate:
                return  # idempotent resend of this keyper's current submission
            # Mutable per keyper *until the quorum finalizes*: a keyper that submitted a
            # wrong/stale aggregate can override it so honest keypers re-converge (a
            # deterministic re-derivation, unlike the append-only one-shot DKG result).
            if self._aggregate_finalized(conn, config):
                raise ImmutabilityError("aggregate already finalized (quorum reached)")
            conn.execute(
                """INSERT INTO aggregates (election_id, keyper_index, aggregate) VALUES (%s, %s, %s)
                   ON CONFLICT (election_id, keyper_index) DO UPDATE SET aggregate = EXCLUDED.aggregate""",
                (election_id, idx, Jsonb(codecs.enc_aggregate(aggregate))),
            )

    def _aggregate_group_counts(self, conn, election_id) -> dict[bytes, tuple[AggregateArtifact, set[int]]]:
        rows = conn.execute(
            "SELECT keyper_index, aggregate FROM aggregates WHERE election_id = %s",
            (election_id,),
        ).fetchall()
        groups: dict[bytes, tuple[AggregateArtifact, set[int]]] = {}
        for idx, agg_json in rows:
            agg = codecs.dec_aggregate(agg_json)
            key = write_auth.aggregate_digest_of(election_id, agg)
            _, keypers = groups.setdefault(key, (agg, set()))
            keypers.add(int(idx))
        return groups

    def _aggregate_finalized(self, conn, config: ElectionConfig) -> bool:
        needed = config.threshold.t + 1
        return any(len(kps) >= needed for _, kps in self._aggregate_group_counts(conn, config.election_id).values())

    def get_aggregate(self, election_id) -> AggregateArtifact | None:
        with self._conn() as conn:
            config = self._config(conn, election_id)
            needed = config.threshold.t + 1
            for agg, keypers in self._aggregate_group_counts(conn, election_id).values():
                if len(keypers) >= needed:
                    return agg
            return None

    def submit_decryption_share(self, election_id, share: DecryptionShareEnvelope, keyper_sig) -> None:
        with self._conn() as conn:
            config = self._config(conn, election_id)
            shares = [e.sigma for e in share.entries]
            proofs = [(int.from_bytes(e.proof[:32], "big"), int.from_bytes(e.proof[32:], "big")) for e in share.entries]
            digest = write_auth.decryption_share_digest(election_id, shares, proofs)
            idx = self._keyper_index_by_recovery(config, digest, keyper_sig)
            if idx != share.keyper_index:
                raise WriteAuthorizationError(
                    f"share keyper_index {share.keyper_index} does not match signer {idx}"
                )
            existing = conn.execute(
                "SELECT share FROM decryption_shares WHERE election_id = %s AND keyper_index = %s",
                (election_id, idx),
            ).fetchone()
            if existing is not None:
                if codecs.dec_decryption_share(existing[0]) != share:
                    raise ImmutabilityError(f"keyper {idx} already submitted different shares")
                return
            conn.execute(
                "INSERT INTO decryption_shares (election_id, keyper_index, share) VALUES (%s, %s, %s)",
                (election_id, idx, Jsonb(codecs.enc_decryption_share(share))),
            )

    def list_decryption_shares(self, election_id) -> list[DecryptionShareEnvelope]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT share FROM decryption_shares WHERE election_id = %s ORDER BY keyper_index",
                (election_id,),
            ).fetchall()
            return [codecs.dec_decryption_share(r[0]) for r in rows]

    def publish_result(self, election_id, result: ResultArtifact, result_publisher_sig) -> None:
        with self._conn() as conn:
            config = self._config(conn, election_id)
            if not authz.verify_request(config.result_publisher_key, result_publisher_sig, "result", election_id):
                raise WriteAuthorizationError("publish_result: bad result-publisher signature")
            existing = conn.execute(
                "SELECT result FROM results WHERE election_id = %s", (election_id,)
            ).fetchone()
            if existing is not None:
                if codecs.dec_result(existing[0]) != result:
                    raise ImmutabilityError("result already published (append-only)")
                return
            conn.execute(
                "INSERT INTO results (election_id, result) VALUES (%s, %s)",
                (election_id, Jsonb(codecs.enc_result(result))),
            )

    def get_result(self, election_id) -> ResultArtifact | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT result FROM results WHERE election_id = %s", (election_id,)
            ).fetchone()
            return codecs.dec_result(row[0]) if row else None

    def verifiability_tier(self) -> int:
        return 0

    # -- helpers ------------------------------------------------------------ #

    def _keyper_index_by_recovery(self, config: ElectionConfig, digest: bytes, sig: bytes) -> int:
        try:
            recovered = write_auth.recover_digest(digest, sig)
        except Exception as exc:  # noqa: BLE001
            raise WriteAuthorizationError("bad keyper signature") from exc
        for i, k in enumerate(config.keypers, start=1):
            if k.signing_key == recovered:
                return i
        raise WriteAuthorizationError("signature matches no registered keyper")
