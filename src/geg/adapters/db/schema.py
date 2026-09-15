"""Relational schema for the database data-layer adapter.

Artifacts are stored as their JSON envelopes in ``jsonb`` columns — the
adapter never interprets crypto (availability only). The schema provides the two
things SQL must guarantee for the port contract:

* **stable total ballot ordering** via a ``BIGSERIAL`` sequence number
  (``ballots.seq``), reproducible by every auditor;
* **append-only / idempotency** via primary keys: one DKG submission per
  (election, keyper), one decryption-share row per (election, keyper), one
  aggregate submission per (election, keyper), and one result per election.

Config immutability after ``voting_start`` and the two quorum rules (finalized key
and canonical aggregate — each ≥ t+1 byte-identical submissions) are enforced in
:mod:`geg.adapters.db.store` (they are logic, not constraints).
"""

from __future__ import annotations

DDL = """
-- Registry-style sequential election ids (1, 2, …); election_id = id as bytes32.
CREATE SEQUENCE IF NOT EXISTS election_id_seq START 1;

CREATE TABLE IF NOT EXISTS elections (
    election_id   BYTEA PRIMARY KEY,
    config        JSONB NOT NULL,
    admin_key     BYTEA NOT NULL,
    voting_start  BIGINT NOT NULL,
    cancelled     BOOLEAN NOT NULL DEFAULT FALSE,
    tally_stalled BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS dkg_submissions (
    election_id   BYTEA NOT NULL REFERENCES elections(election_id),
    keyper_index  INT NOT NULL,
    submission    JSONB NOT NULL,   -- DKGResultSubmission envelope
    PRIMARY KEY (election_id, keyper_index)
);

CREATE TABLE IF NOT EXISTS ballots (
    election_id   BYTEA NOT NULL REFERENCES elections(election_id),
    seq           BIGINT NOT NULL,  -- stable total order, 0-based per election
    ballot        JSONB NOT NULL,   -- BallotEnvelope
    submitted_at  BIGINT NOT NULL,  -- adapter receive time, for the tally-time window check
    PRIMARY KEY (election_id, seq)
);

CREATE TABLE IF NOT EXISTS decryption_shares (
    election_id   BYTEA NOT NULL REFERENCES elections(election_id),
    keyper_index  INT NOT NULL,
    share         JSONB NOT NULL,   -- DecryptionShareEnvelope
    PRIMARY KEY (election_id, keyper_index)
);

CREATE TABLE IF NOT EXISTS aggregates (
    election_id   BYTEA NOT NULL REFERENCES elections(election_id),
    keyper_index  INT NOT NULL,
    aggregate     JSONB NOT NULL,   -- AggregateArtifact (one keyper's submission)
    PRIMARY KEY (election_id, keyper_index)
);

CREATE TABLE IF NOT EXISTS results (
    election_id   BYTEA PRIMARY KEY REFERENCES elections(election_id),
    result        JSONB NOT NULL    -- ResultArtifact
);

-- Spent stall/resume request nonces.
--
-- These two ops are the only writes whose digest binds no content -- they toggle a
-- flag -- so without a freshness term one valid signature authorises the toggle
-- forever, and a captured stall replayed after each admin retry keeps a tally from
-- ever completing. Deduplicating the signature bytes is not an alternative: signing
-- is RFC 6979 deterministic, so a genuine second stall is byte-identical to a replay.
-- The signer binds a timestamp instead, and the primary key here spends it once.
CREATE TABLE IF NOT EXISTS request_nonces (
    election_id   BYTEA NOT NULL REFERENCES elections(election_id),
    op            TEXT NOT NULL,
    issued_at     BIGINT NOT NULL,
    PRIMARY KEY (election_id, op, issued_at)
);
"""

# Tables in dependency order (children before parent) for test truncation.
TABLES = ["dkg_submissions", "ballots", "decryption_shares", "aggregates", "results", "request_nonces", "elections"]
