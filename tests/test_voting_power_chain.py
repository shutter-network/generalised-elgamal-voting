"""Chain-backed voting power + wallet eligibility integration (Anvil).

Deploys a mock voting-power contract, reads power on-chain via
``chain_voting_power``, and drives the wallet eligibility adapter with it so an
attestation's weight equals the voter's on-chain voting power (clamped to
maxWeight). Skips if ``anvil`` is unavailable.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

from geg.adapters.eligibility_wallet import WalletEligibilityService
from geg.crypto import schnorr
from geg.crypto.points import g1_to_compressed
from geg.ports.eligibility import verify_attestation

from test_adapter_chain import ANVIL_KEYS

ELECTION = b"\x11" * 32
CHAIN_ID = 31337
_OUT = Path(__file__).resolve().parents[1] / "contracts" / "out"


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
        ["anvil", "--port", str(port), "--silent"],
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


def _deploy_mock_token(w3, account):
    from geg.adapters.chain.deploy import send_tx

    art = json.loads((_OUT / "MockVotingToken.sol" / "MockVotingToken.json").read_text())
    contract = w3.eth.contract(abi=art["abi"], bytecode=art["bytecode"]["object"])
    receipt = send_tx(w3, account, contract.constructor())
    return w3.eth.contract(address=receipt.contractAddress, abi=art["abi"])


def test_chain_voting_power_reads_balance(anvil_w3):
    from eth_account import Account

    from geg.adapters.chain.deploy import send_tx
    from geg.adapters.voting_power import chain_voting_power

    deployer = Account.from_key(ANVIL_KEYS[0])
    voter = Account.from_key(ANVIL_KEYS[1])
    voter_bytes = bytes.fromhex(voter.address[2:])

    token = _deploy_mock_token(anvil_w3, deployer)
    send_tx(anvil_w3, deployer, token.functions.setPower(voter.address, 42))

    vp = chain_voting_power(anvil_w3, token.address)
    assert vp(voter_bytes) == 42
    # getVotes shape reads the same power.
    vp_votes = chain_voting_power(anvil_w3, token.address, method="getVotes")
    assert vp_votes(voter_bytes) == 42
    # An address with no power reads 0.
    no_power = bytes.fromhex(Account.from_key(ANVIL_KEYS[2]).address[2:])
    assert vp(no_power) == 0


def test_wallet_adapter_weight_from_chain_voting_power(anvil_w3):
    from eth_account import Account

    from geg.adapters.chain.deploy import send_tx
    from geg.adapters.voting_power import chain_voting_power

    deployer = Account.from_key(ANVIL_KEYS[0])
    voter = Account.from_key(ANVIL_KEYS[3])
    voter_bytes = bytes.fromhex(voter.address[2:])

    token = _deploy_mock_token(anvil_w3, deployer)
    send_tx(anvil_w3, deployer, token.functions.setPower(voter.address, 6))

    elig_sk, _ = schnorr.keygen()
    svc = WalletEligibilityService(
        elig_sk, chain_voting_power(anvil_w3, token.address), max_weight=10, chain_id=CHAIN_ID
    )
    _, vk = schnorr.keygen()
    vk_bytes = g1_to_compressed(vk)
    sig = voter.sign_message(svc.challenge(ELECTION, vk_bytes)).signature
    att = svc.issue_for_wallet(ELECTION, vk_bytes, sig)

    assert att.weight == 6  # equals on-chain voting power
    assert verify_attestation(svc.eligibility_key, att, election_id=ELECTION, max_weight=10)


def test_wallet_weight_clamped_to_max_from_chain(anvil_w3):
    from eth_account import Account

    from geg.adapters.chain.deploy import send_tx
    from geg.adapters.voting_power import chain_voting_power

    deployer = Account.from_key(ANVIL_KEYS[0])
    voter = Account.from_key(ANVIL_KEYS[4])
    voter_bytes = bytes.fromhex(voter.address[2:])

    token = _deploy_mock_token(anvil_w3, deployer)
    send_tx(anvil_w3, deployer, token.functions.setPower(voter.address, 1_000))

    elig_sk, _ = schnorr.keygen()
    svc = WalletEligibilityService(
        elig_sk, chain_voting_power(anvil_w3, token.address), max_weight=10, chain_id=CHAIN_ID
    )
    _, vk = schnorr.keygen()
    vk_bytes = g1_to_compressed(vk)
    sig = voter.sign_message(svc.challenge(ELECTION, vk_bytes)).signature
    att = svc.issue_for_wallet(ELECTION, vk_bytes, sig)
    assert att.weight == 10  # clamped to maxWeight
