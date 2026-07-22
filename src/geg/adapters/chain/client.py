"""``BlockchainDataLayer`` — the per-actor chain adapter (DESIGN.md §5.1).

Maps the ``ElectionDataLayer`` port onto the extended bulletin-board contracts.
Authorization is by transaction sender (this adapter is bound to one actor's
Ethereum key); the port's ``*_sig`` byte arguments are ignored on chain. A thin
emulation layer reads chain state before writes so the adapter presents the exact
uniform port semantics (idempotent resend, divergent-write rejection) the
conformance suite asserts, even where the raw contract would revert differently.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from eth_utils import keccak
from web3 import Web3

from geg.core import write_auth
from geg.adapters.chain import codec
from geg.core.config import DuplicatePolicy, ElectionConfig, KeyperIdentity, Mode, Threshold, Variant
from geg.envelopes.types import AggregateArtifact, BallotEnvelope, DecryptionShareEnvelope, DKGResultSubmission
from geg.ports.data_layer import (
    ElectionDataLayer,
    ElectionFilter,
    ElectionRecord,
    FinalizedKey,
    ImmutabilityError,
    WriteAuthorizationError,
)

_ABI_DIR = Path(__file__).parent / "abis"
_ZERO = "0x0000000000000000000000000000000000000000"


def _selector(signature: str) -> str:
    return "0x" + keccak(text=signature)[:4].hex()


# Custom-error selectors mapped to port exceptions (the Election ABI does not carry
# AccessControl's error defs, so reverts arrive as raw selector data we decode here).
_AUTHZ_SELECTORS = {
    _selector("AccessControlUnauthorizedAccount(address,bytes32)"),
    _selector("UnauthorizedKeyper(address)"),
    _selector("InvalidMember(address)"),
}
_IMMUTABILITY_SELECTORS = {
    _selector("AlreadyCancelled()"),
    _selector("VotingAlreadyStarted(uint256)"),
    _selector("AlreadyVoted(address)"),
    _selector("AlreadyFinalized()"),
    _selector("ElectionIdTaken(uint256)"),
}


def _abi(name: str):
    return json.loads((_ABI_DIR / f"{name}.json").read_text())


ELECTION_ABI = _abi("Election")
REGISTRY_ABI = _abi("ElectionRegistry")
KEYPERSET_ABI = _abi("KeyperSet")


def _addr_bytes(checksummed: str) -> bytes:
    return bytes.fromhex(checksummed[2:])


class BlockchainDataLayer(ElectionDataLayer):
    def __init__(self, w3: Web3, registry_address: str, account):
        self.w3 = w3
        self.account = account  # eth_account LocalAccount (None => read-only)
        self.registry = w3.eth.contract(address=Web3.to_checksum_address(registry_address), abi=REGISTRY_ABI)

    # -- tx plumbing -------------------------------------------------------- #

    def _send(self, fn):
        acct = self.account
        try:
            gas = fn.estimate_gas({"from": acct.address})
        except Exception as exc:  # noqa: BLE001 — revert surfaces here (pre-flight)
            raise self._map_revert(exc) from exc
        tx = fn.build_transaction({
            "from": acct.address,
            "nonce": self.w3.eth.get_transaction_count(acct.address),
            "gas": int(gas * 12 // 10),
            "gasPrice": self.w3.eth.gas_price,
        })
        signed = acct.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt.status != 1:
            raise RuntimeError("transaction reverted on chain")
        return receipt

    @staticmethod
    def _map_revert(exc: Exception) -> Exception:
        msg = str(exc)
        # Decoded error names (when the ABI carried the error def).
        if any(s in msg for s in ("AlreadyCancelled", "VotingAlreadyStarted", "AlreadyVoted", "AlreadyFinalized", "ElectionIdTaken")):
            return ImmutabilityError(msg)
        if any(s in msg for s in ("AccessControl", "UnauthorizedKeyper", "InvalidMember", "missing role")):
            return WriteAuthorizationError(msg)
        # Raw custom-error selectors in the revert data.
        selectors = {m[:10] for m in re.findall(r"0x[0-9a-fA-F]{8,}", msg)}
        if selectors & _IMMUTABILITY_SELECTORS:
            return ImmutabilityError(msg)
        if selectors & _AUTHZ_SELECTORS:
            return WriteAuthorizationError(msg)
        return ValueError(msg)

    def _election(self, election_id: bytes):
        addr = self.registry.functions.elections(codec.eid_to_uint(election_id)).call()
        if int(addr, 16) == 0:
            raise KeyError(f"unknown election {election_id.hex()}")
        return self.w3.eth.contract(address=addr, abi=ELECTION_ABI)

    def _keyper_set_of(self, election):
        ks_addr = election.functions.keyperSet().call()
        return self.w3.eth.contract(address=ks_addr, abi=KEYPERSET_ABI)

    # -- election lifecycle ------------------------------------------------- #

    def register_election(self, config: ElectionConfig, admin_sig: bytes) -> bytes:
        # Deploy a fresh KeyperSet from the config's keyper addresses + endpoints
        # (fresh DKG per election). Storing endpoints on-chain lets any service read
        # keyper URLs through the data-layer port — no off-chain endpoint registry.
        members = [Web3.to_checksum_address(k.signing_key) for k in config.keypers]
        endpoints = [k.endpoint for k in config.keypers]
        quorum = config.threshold.t + 1  # on-chain threshold is the quorum count
        ks = self._deploy(KEYPERSET_ABI, "KeyperSet", members, endpoints, quorum)
        params = self._config_to_params(config)
        # The registry assigns the next sequential id; read it back from the event.
        # The receipt also carries the KeyperSet/Election deploy + role-grant logs, so
        # DISCARD non-matching ones instead of warning on each.
        from web3.logs import DISCARD

        receipt = self._send(self.registry.functions.publishElection(ks, params))
        ev = self.registry.events.ElectionCreated().process_receipt(receipt, errors=DISCARD)[0]
        return codec.uint_to_eid(int(ev["args"]["electionId"]))

    def cancel_election(self, election_id: bytes, admin_sig: bytes) -> None:
        self._send(self._election(election_id).functions.cancelElection())

    def get_election(self, election_id: bytes) -> ElectionRecord:
        election = self._election(election_id)
        config_raw, dkg_raw = election.functions.getElection().call()
        config = self._config_from_view(config_raw)  # keyper endpoints included (from getElection)
        finalized = None
        if election.functions.isDKGFinalized().call():
            finalized = FinalizedKey(
                pk_election=bytes(dkg_raw[0]),
                committee_pks=tuple(bytes(p) for p in dkg_raw[1]),
            )
        return ElectionRecord(config=config, cancelled=bool(config_raw[17]), finalized_key=finalized)

    def list_elections(self, filter: ElectionFilter | None = None) -> list[bytes]:
        # Ids are dense (1..electionCount), so enumerate by index — one paged read,
        # no event-log scan (cheap + provider-friendly on a real chain).
        count = int(self.registry.functions.electionCount().call())
        if count == 0:
            return []
        addrs = self.registry.functions.getElections(1, count).call()
        out = []
        for i, addr in enumerate(addrs, start=1):
            if int(addr, 16) == 0:
                continue
            election = self.w3.eth.contract(address=addr, abi=ELECTION_ABI)
            if filter and filter.admin_key is not None:
                if _addr_bytes(election.functions.adminAddr().call()) != filter.admin_key:
                    continue
            out.append(codec.uint_to_eid(i))
        return out

    # -- DKG ---------------------------------------------------------------- #

    def submit_dkg_result(self, election_id, pk_election, committee_pks, keyper_sig) -> None:
        election = self._election(election_id)
        pk = bytes(pk_election)
        committee = [bytes(p) for p in committee_pks]
        # Meta-tx: the keyper signed the content; recover it (the on-chain author),
        # not the relaying tx sender (this adapter's account, which just pays gas).
        keyper_addr = Web3.to_checksum_address(
            write_auth.recover_digest(write_auth.dkg_result_digest(election_id, pk, committee), keyper_sig)
        )
        if election.functions.isDKGFinalized().call():
            _, dkg_raw = election.functions.getElection().call()
            if bytes(dkg_raw[0]) == pk:
                return
            raise ImmutabilityError("DKG already finalized with a different key")
        # Emulate append-only-per-dealer: inspect this keyper's prior vote via events.
        mine = [
            ev for ev in election.events.DKGVoteRegistered().get_logs(from_block=0)
            if ev["args"]["keyper"] == keyper_addr
        ]
        if mine:
            if bytes(mine[-1]["args"]["pkElection"]) == pk:
                return  # identical resend → no-op
            raise ImmutabilityError("keyper already submitted a different DKG result")
        self._send(election.functions.voteDKGResultSigned(pk, committee, keyper_sig))

    def get_dkg_submissions(self, election_id) -> list[DKGResultSubmission]:
        election = self._election(election_id)
        finalized = election.functions.isDKGFinalized().call()
        committee = []
        if finalized:
            _, dkg_raw = election.functions.getElection().call()
            committee = [bytes(p) for p in dkg_raw[1]]
        out = []
        for ev in election.events.DKGVoteRegistered().get_logs(from_block=0):
            out.append(DKGResultSubmission(
                election_id=election_id,
                pk_election=bytes(ev["args"]["pkElection"]),
                committee_pks=tuple(committee),  # populated once finalized; empty otherwise
                keyper_signature=b"",  # authz is tx-sender on chain
            ))
        return out

    def get_finalized_key(self, election_id) -> FinalizedKey | None:
        election = self._election(election_id)
        if not election.functions.isDKGFinalized().call():
            return None
        _, dkg_raw = election.functions.getElection().call()
        return FinalizedKey(pk_election=bytes(dkg_raw[0]), committee_pks=tuple(bytes(p) for p in dkg_raw[1]))

    # -- ballots ------------------------------------------------------------ #

    def submit_ballot(self, election_id, ballot: BallotEnvelope) -> int:
        election = self._election(election_id)
        receipt = self._send(election.functions.submitVote(codec.ballot_to_tuple(ballot)))
        logs = election.events.VoteSubmitted().process_receipt(receipt)
        return int(logs[0]["args"]["ballotIndex"])

    def list_ballots(self, election_id, start: int, count: int) -> list[BallotEnvelope]:
        election = self._election(election_id)
        total = election.functions.getNumBallots().call()
        count = min(count, max(0, total - start))
        if count <= 0:
            return []
        raw = election.functions.getBallots(start, count).call()
        return [codec.ballot_from_contract(b, election_id) for b in raw]

    def count_ballots(self, election_id) -> int:
        return int(self._election(election_id).functions.getNumBallots().call())

    # -- tally artifacts ---------------------------------------------------- #

    def publish_aggregate(self, election_id, aggregate: AggregateArtifact, aggregator_sig) -> None:
        election = self._election(election_id)
        existing = self._read_aggregate(election, election_id)
        if existing is not None:
            if existing != aggregate:
                raise ImmutabilityError("aggregate already published (append-only)")
            return
        self._send(election.functions.publishAggregate(codec.aggregate_to_tuple(aggregate)))

    def get_aggregate(self, election_id) -> AggregateArtifact | None:
        return self._read_aggregate(self._election(election_id), election_id)

    @staticmethod
    def _read_aggregate(election, election_id):
        try:
            raw = election.functions.getAggregate().call()
        except Exception:  # noqa: BLE001 — AggregateNotPublished
            return None
        return codec.aggregate_from_contract(raw, election_id)

    def submit_decryption_share(self, election_id, share: DecryptionShareEnvelope, keyper_sig) -> None:
        election = self._election(election_id)
        ks = self._keyper_set_of(election)
        shares, proofs = codec.share_to_contract(share)
        # Meta-tx: recover the keyper that signed the content (the on-chain author).
        keyper_addr = Web3.to_checksum_address(
            write_auth.recover_digest(write_auth.decryption_share_digest(election_id, shares, proofs), keyper_sig)
        )
        try:
            idx0 = int(ks.functions.getMemberIndex(keyper_addr).call())
        except Exception as exc:  # noqa: BLE001 — non-member reverts InvalidMember
            raise WriteAuthorizationError("submit_decryption_share: signer is not a registered keyper") from exc
        if share.keyper_index != idx0 + 1:
            raise WriteAuthorizationError(
                f"share keyper_index {share.keyper_index} does not match signer index {idx0 + 1}"
            )
        existing = {s.keyper_index: s for s in self.list_decryption_shares(election_id)}
        if share.keyper_index in existing:
            if existing[share.keyper_index] != share:
                raise ImmutabilityError(f"keyper {share.keyper_index} already submitted different shares")
            return
        self._send(election.functions.submitDecryptionShareSigned(shares, proofs, keyper_sig))

    def list_decryption_shares(self, election_id) -> list[DecryptionShareEnvelope]:
        election = self._election(election_id)
        raw = election.functions.getDecryptionShares().call()
        return [codec.share_from_contract(s, election_id) for s in raw]

    def publish_result(self, election_id, result, aggregator_sig) -> None:
        election = self._election(election_id)
        if election.functions.isResultFinalized().call():
            existing = self.get_result(election_id)
            if existing is not None and tuple(existing.totals) != tuple(result.totals):
                raise ImmutabilityError("result already published (append-only)")
            return
        totals = [int(t) for t in result.totals]
        keyper_indices = [int(i) for i in result.keyper_indices]
        self._send(election.functions.publishResult(totals, keyper_indices))

    def get_result(self, election_id):
        election = self._election(election_id)
        if not election.functions.isResultFinalized().call():
            return None
        raw = election.functions.getResult().call()
        totals = tuple(int(t) for t in raw[0])
        keyper_indices = tuple(int(i) for i in raw[1])
        # bsgs_bound is derived (not stored on chain): budget * total admitted weight.
        agg = self.get_aggregate(election_id)
        budget = int(election.functions.budget().call())
        bound = budget * (agg.total_admitted_weight if agg else 0)
        from geg.envelopes.types import ResultArtifact
        return ResultArtifact(election_id=election_id, totals=totals, keyper_indices=keyper_indices, bsgs_bound=bound)

    def verifiability_tier(self) -> int:
        return 0

    # -- config <-> params -------------------------------------------------- #

    def _config_to_params(self, config: ElectionConfig):
        return (
            config.voting_start,
            config.voting_end,
            config.tally_deadline,
            0,  # selfSubmitFee
            config.num_candidates,
            config.budget,
            codec.MODE_TO_U8[config.mode],
            codec.VARIANT_TO_U8[config.variant],
            config.weighted,
            config.max_weight,
            codec.DUP_TO_U8[config.duplicate_policy],
            config.protocol_version,
            config.eligibility_key,  # pkWR
            Web3.to_checksum_address(config.aggregator_key),
            Web3.to_checksum_address(config.gateway_keys[0]),
        )

    def _config_from_view(self, v) -> ElectionConfig:
        keyper_addrs = [_addr_bytes(a) for a in v[15]]
        keyper_endpoints = [str(e) for e in v[21]]  # index-aligned with keyperAddresses
        threshold_n = int(v[13])
        threshold_t = int(v[14]) - 1  # on-chain threshold is the quorum count (t+1)
        return ElectionConfig(
            election_id=codec.uint_to_eid(int(v[0])),
            num_candidates=int(v[5]),
            budget=int(v[6]),
            mode=codec.U8_TO_MODE[int(v[7])],
            variant=codec.U8_TO_VARIANT[int(v[8])],
            weighted=bool(v[9]),
            max_weight=int(v[10]),
            duplicate_policy=codec.U8_TO_DUP[int(v[11])],
            voting_start=int(v[1]),
            voting_end=int(v[2]),
            tally_deadline=int(v[3]),
            threshold=Threshold(t=threshold_t, n=threshold_n),
            keypers=tuple(
                KeyperIdentity(signing_key=a, endpoint=e) for a, e in zip(keyper_addrs, keyper_endpoints)
            ),
            eligibility_key=bytes(v[16]),
            aggregator_key=_addr_bytes(v[19]),
            gateway_keys=(_addr_bytes(v[20]),),
            admin_key=_addr_bytes(v[18]),
            protocol_version=str(v[12]),
        )

    # -- deploy helper ------------------------------------------------------ #

    def _deploy(self, abi, name: str, *args) -> str:
        """Deploy a contract from the forge artifact bytecode and return its address."""
        from geg.adapters.chain.deploy import bytecode_of

        contract = self.w3.eth.contract(abi=abi, bytecode=bytecode_of(name))
        receipt = self._send(contract.constructor(*args))
        return receipt.contractAddress
