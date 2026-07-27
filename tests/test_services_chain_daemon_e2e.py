"""Full election over the DEPLOYED daemon topology against the blockchain backend.

Where ``test_services_chain_e2e`` drives the services in-process, this runs the
actual multi-operator deployment shape (RUNNING.md / docker-compose.chain.yml)
over Anvil:

* the uniform **data-layer service** (``build_app``) fronts a ``BlockchainDataLayer``
  bound to a **relayer** account — its role is public reads + relaying keyper
  meta-tx writes (pays gas; the contract ``ecrecover``s the keyper);
* three **keyper HTTP servers** hold no chain key — they content-sign their DKG
  result / decryption shares and write them through ``HttpDataLayerClient`` to the
  relayer service (Option A);
* the **coordinator** bootstraps the committee and sequences the DKG over HTTP;
* admin / aggregator / gateway submit their **own** chain txs (``msg.sender``
  authz) via chain-direct adapters.

This is the automated end-to-end the chain docker-compose stack was missing.
Skips if ``anvil`` is unavailable.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import threading
import time

import pytest
from werkzeug.serving import make_server

from geg.core.config import DuplicatePolicy, ElectionConfig, KeyperIdentity, Mode, Threshold, Variant
from geg.crypto import ballot as ballot_crypto
from geg.crypto import schnorr
from geg.crypto.points import g1_to_compressed, g2_from_compressed
from geg.envelopes.types import BallotEnvelope, Ciphertext
from geg.ports.eligibility import AttestationRequest
from geg.services.coordinator import dkg_coordinator as coord
from geg.services import tally_aggregator as agg
from geg.services.gateway import submit_ballot

from test_adapter_chain import ANVIL_KEYS  # reuse dev keys (7 funded accounts)

ELECTION_ID = (1).to_bytes(32, "big")
N, T = 3, 1
TOKEN = "coordinator-relay-token"


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture(scope="module")
def anvil_w3():
    if shutil.which("anvil") is None:
        pytest.skip("anvil not installed")
    from web3 import Web3

    port = _free_port()
    proc = subprocess.Popen(
        ["anvil", "--port", str(port), "--timestamp", "0", "--silent"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    w3 = Web3(Web3.HTTPProvider(f"http://127.0.0.1:{port}"))
    try:
        for _ in range(50):
            if w3.is_connected():
                break
            time.sleep(0.1)
        else:
            pytest.skip("anvil did not start")
        yield w3
    finally:
        proc.terminate()
        proc.wait()


class ChainDaemonWorld:
    def __init__(self, w3, tmp_path):
        from eth_account import Account

        from geg.adapters.chain.client import BlockchainDataLayer
        from geg.adapters.chain.deploy import chain_now, deploy_registry
        from geg.adapters.db.client import HttpDataLayerClient
        from geg.adapters.eligibility_stub import StubEligibilityService
        from geg.core.authz import Signer
        from geg.services.coordinator import CoordinatorClient, build_coordinator_app
        from geg.services.data_layer import build_app
        from geg.services.keyper import build_keyper_app

        self.w3 = w3
        # Accounts: admin/aggregator/gateway submit their own txs; relayer pays gas
        # for keyper writes; keyper identities sit in the KeyperSet (they never send).
        self.admin = Signer.from_sk(int(ANVIL_KEYS[0], 16))
        self.aggregator = Signer.from_sk(int(ANVIL_KEYS[1], 16))
        self.gateway = Signer.from_sk(int(ANVIL_KEYS[2], 16))
        relayer = Account.from_key(ANVIL_KEYS[3])
        self.keyper_signers = [Signer.from_sk(int(ANVIL_KEYS[4 + i], 16)) for i in range(N)]
        self.coordinator = Signer.generate()  # off-chain: bootstraps + sequences DKG over HTTP

        self.registry = deploy_registry(w3, self.admin.account)
        self.base = chain_now(w3)
        self.clock = lambda: chain_now(w3)

        self.admin_dl = BlockchainDataLayer(w3, self.registry, self.admin.account)
        self.aggregator_dl = BlockchainDataLayer(w3, self.registry, self.aggregator.account)
        self.gateway_dl = BlockchainDataLayer(w3, self.registry, self.gateway.account)

        elig_sk, _ = schnorr.keygen()
        self.elig = StubEligibilityService(elig_sk)

        self.config = ElectionConfig(
            election_id=ELECTION_ID, num_candidates=3, budget=3, mode=Mode.EXACT, variant=Variant.A,
            weighted=True, max_weight=10, duplicate_policy=DuplicatePolicy.LAST_WINS,
            voting_start=self.base + 1000, voting_end=self.base + 2000, tally_deadline=self.base + 3000,
            threshold=Threshold(t=T, n=N),
            keypers=tuple(KeyperIdentity(signing_key=self.keyper_signers[i].identity, endpoint="") for i in range(N)),
            eligibility_key=self.elig.eligibility_key, aggregator_key=self.aggregator.identity,
            gateway_keys=(self.gateway.identity,), admin_key=self.admin.identity, protocol_version="v1",
        )
        # Admin registers directly on chain (deploys the KeyperSet from these keypers).
        self.admin_dl.register_election(self.config, self.admin.sign_register(self.config))

        self._servers = []

        def _serve(app):
            srv = make_server("127.0.0.1", 0, app, threaded=True)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            self._servers.append(srv)
            return f"http://127.0.0.1:{srv.server_port}"

        # Data-layer service: READS ONLY on chain (account=None). The public read
        # surface keypers/services query.
        self.data_layer_url = _serve(build_app(BlockchainDataLayer(w3, self.registry, None)))

        # Coordinator relay: holds the RELAYER account and does the keyper meta-tx
        # writes (the coordinator is the keyper-write relayer, Option A).
        relayer_dl = BlockchainDataLayer(w3, self.registry, relayer)
        self.coordinator_url = _serve(build_coordinator_app(relayer_dl, api_token=TOKEN))

        # Keypers hold no chain key: they READ via the data-layer service and POST
        # their signed writes to the coordinator relay.
        keyper_reads = HttpDataLayerClient(self.data_layer_url)
        submitter = CoordinatorClient(self.coordinator_url, "")  # relay token pushed via bootstrap
        self.keyper_urls = {}
        for i in range(1, N + 1):
            app = build_keyper_app(self.keyper_signers[i - 1], keyper_reads, self.coordinator.identity,
                                   clock=self.clock, state_dir=tmp_path / f"keyper{i}", submitter=submitter)
            self.keyper_urls[i] = _serve(app)

    def shutdown(self):
        for srv in self._servers:
            srv.shutdown()

    def warp(self, offset):
        from geg.adapters.chain.deploy import anvil_set_time

        anvil_set_time(self.w3, self.base + offset)

    def voter_ballot(self, votes, pseudonym, weight=1):
        mpk = g2_from_compressed(self.admin_dl.get_finalized_key(ELECTION_ID).pk_election)
        sk, vk = schnorr.keygen()
        vkb = g1_to_compressed(vk)
        built = ballot_crypto.build_ballot(mpk=mpk, election_id=ELECTION_ID, pseudonym=pseudonym,
                                           sk=sk, vk=vk, votes=votes, num_candidates=3, budget=3)
        att = self.elig.issue_attestation(AttestationRequest(ELECTION_ID, pseudonym, vkb, weight))
        return BallotEnvelope(election_id=ELECTION_ID, pseudonym=pseudonym, vk=vkb,
                              ciphertexts=tuple(Ciphertext(c1=a, c2=b) for (a, b) in built.ciphertexts),
                              zk_proof=built.zk_proof, voter_signature=built.voter_signature, attestation=att)


@pytest.fixture
def world(anvil_w3, tmp_path):
    w = ChainDaemonWorld(anvil_w3, tmp_path)
    try:
        yield w
    finally:
        w.shutdown()


def test_full_election_over_chain_daemons(world):
    from geg.adapters.db.client import HttpDataLayerClient

    w = world

    # DKG over HTTP: coordinator bootstraps the committee, sequences the ceremony;
    # keypers POST their signed result to the coordinator relay, which meta-tx's it to chain.
    api_tokens, _peer = coord.bootstrap_keypers(w.coordinator, w.keyper_urls, relay_token=TOKEN)
    assert coord.run_dkg_http(ELECTION_ID, w.keyper_urls, api_tokens, HttpDataLayerClient(w.data_layer_url))
    assert w.admin_dl.get_finalized_key(ELECTION_ID) is not None

    # Voting window: two weighted ballots via the gateway's own chain adapter.
    w.warp(1500)
    submit_ballot(w.gateway_dl, ELECTION_ID, w.voter_ballot([3, 0, 0], b"\x01" * 32, weight=2), clock=w.clock)
    submit_ballot(w.gateway_dl, ELECTION_ID, w.voter_ballot([0, 3, 0], b"\x02" * 32, weight=5), clock=w.clock)
    assert w.admin_dl.count_ballots(ELECTION_ID) == 2

    # Tally: aggregator publishes the aggregate (its own tx), coordinator triggers
    # keypers over HTTP (their shares relayed to chain), aggregator finalizes.
    w.warp(2500)
    agg.publish_aggregate(w.aggregator_dl, ELECTION_ID, w.aggregator, clock=w.clock)
    coord.trigger_decrypt_http(ELECTION_ID, w.keyper_urls, api_tokens, hardened=True)
    result = agg.finalize(w.aggregator_dl, ELECTION_ID, w.aggregator, clock=w.clock)

    assert result is not None
    assert list(result.totals) == [6, 15, 0]  # [2*3, 5*3, 0]

    # Durable on chain: a fresh reader sees the result.
    from geg.adapters.chain.client import BlockchainDataLayer

    fresh = BlockchainDataLayer(w.w3, w.registry, w.admin.account)
    assert list(fresh.get_result(ELECTION_ID).totals) == [6, 15, 0]
