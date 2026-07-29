"""Relational schema for the database data-layer adapter (DESIGN.md §5.1).

Artifacts are stored as their JSON envelopes (§7.2) in ``jsonb`` columns — the
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
    cancelled     BOOLEAN NOT NULL DEFAULT FALSE
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
"""

# Tables in dependency order (children before parent) for test truncation.
TABLES = ["dkg_submissions", "ballots", "decryption_shares", "aggregates", "results", "elections"]
