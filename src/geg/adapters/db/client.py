"""``HttpDataLayerClient`` — the remote data-layer adapter.

Implements the ``ElectionDataLayer`` port by calling the database microservice
over HTTP with the JSON envelopes. This is the object the services actually
hold when a deployment selects the database backend; it is behaviourally
interchangeable with the in-memory and blockchain adapters and passes the same
conformance suite. HTTP error statuses are mapped back to the port's exception
types so callers handle failures identically across backends.
"""

from __future__ import annotations

import requests

from geg.envelopes import codecs
from geg.ports.data_layer import (
    ElectionDataLayer,
    ElectionFilter,
    ElectionRecord,
    FinalizedKey,
    ImmutabilityError,
    VotingWindowError,
    WriteAuthorizationError,
)

_STATUS_EXC = {
    403: WriteAuthorizationError,
    409: ImmutabilityError,
    422: VotingWindowError,
}


def _raise_for_status(resp: requests.Response) -> None:
    if resp.ok:
        return
    try:
        body = resp.json()
        message = body.get("message", resp.text)
    except Exception:  # noqa: BLE001
        message = resp.text
    if resp.status_code == 404:
        raise KeyError(message)
    exc = _STATUS_EXC.get(resp.status_code)
    if exc is not None:
        raise exc(message)
    raise ValueError(f"HTTP {resp.status_code}: {message}")


def _finalized_key(d) -> FinalizedKey | None:
    if d is None:
        return None
    return FinalizedKey(
        pk_election=codecs.dec_bytes(d["pkElection"], name="pkElection"),
        committee_pks=tuple(codecs.dec_bytes(p, name="committeePKs[]") for p in d["committeePKs"]),
    )


class HttpDataLayerClient(ElectionDataLayer):
    def __init__(self, base_url: str, session: requests.Session | None = None, *, timeout: float = 10.0):
        self._base = base_url.rstrip("/")
        self._s = session or requests.Session()
        self._timeout = timeout

    def _url(self, path: str) -> str:
        return f"{self._base}{path}"

    def _get(self, path: str, **params):
        r = self._s.get(self._url(path), params=params or None, timeout=self._timeout)
        _raise_for_status(r)
        return r.json()

    def _post(self, path: str, body: dict):
        r = self._s.post(self._url(path), json=body, timeout=self._timeout)
        _raise_for_status(r)
        return r.json() if r.content and r.headers.get("content-type", "").startswith("application/json") else None

    @staticmethod
    def _eid(election_id: bytes) -> str:
        return election_id.hex()

    # -- election lifecycle ------------------------------------------------- #

    def register_election(self, config, admin_sig: bytes) -> bytes:
        out = self._post("/elections", {"config": codecs.enc_config(config), "adminSig": codecs.enc_bytes(admin_sig)})
        return codecs.dec_bytes(out["electionId"], name="electionId")

    def cancel_election(self, election_id: bytes, admin_sig: bytes) -> None:
        self._post(f"/elections/{self._eid(election_id)}/cancel", {"adminSig": codecs.enc_bytes(admin_sig)})

    def get_election(self, election_id: bytes) -> ElectionRecord:
        d = self._get(f"/elections/{self._eid(election_id)}")
        return ElectionRecord(
            config=codecs.dec_config(d["config"]),
            cancelled=bool(d["cancelled"]),
            finalized_key=_finalized_key(d["finalizedKey"]),
        )

    def list_elections(self, filter: ElectionFilter | None = None) -> list[bytes]:
        params = {}
        if filter and filter.admin_key is not None:
            params["adminKey"] = codecs.enc_bytes(filter.admin_key)
        d = self._get("/elections", **params)
        return [codecs.dec_bytes(e, name="electionId") for e in d["electionIds"]]

    # -- DKG ---------------------------------------------------------------- #

    def submit_dkg_result(self, election_id, pk_election, committee_pks, keyper_sig) -> None:
        self._post(f"/elections/{self._eid(election_id)}/dkg", {
            "pkElection": codecs.enc_bytes(bytes(pk_election)),
            "committeePKs": [codecs.enc_bytes(bytes(p)) for p in committee_pks],
            "keyperSig": codecs.enc_bytes(keyper_sig),
        })

    def get_dkg_submissions(self, election_id):
        d = self._get(f"/elections/{self._eid(election_id)}/dkg")
        return [codecs.dec_dkg_result(s) for s in d["submissions"]]

    def get_finalized_key(self, election_id) -> FinalizedKey | None:
        d = self._get(f"/elections/{self._eid(election_id)}/dkg/finalized")
        return _finalized_key(d["finalizedKey"])

    # -- ballots ------------------------------------------------------------ #

    def submit_ballot(self, election_id, ballot) -> int:
        out = self._post(f"/elections/{self._eid(election_id)}/ballots", {"ballot": codecs.enc_ballot(ballot)})
        return int(out["sequenceNumber"])

    def list_ballots(self, election_id, start: int, count: int):
        d = self._get(f"/elections/{self._eid(election_id)}/ballots", start=start, count=count)
        return [codecs.dec_ballot(b) for b in d["ballots"]]

    def count_ballots(self, election_id) -> int:
        return int(self._get(f"/elections/{self._eid(election_id)}/ballots/count")["count"])

    # -- tally artifacts ---------------------------------------------------- #

    def submit_aggregate(self, election_id, aggregate, keyper_sig) -> None:
        self._post(f"/elections/{self._eid(election_id)}/aggregate", {
            "aggregate": codecs.enc_aggregate(aggregate),
            "keyperSig": codecs.enc_bytes(keyper_sig),
        })

    def get_aggregate(self, election_id):
        d = self._get(f"/elections/{self._eid(election_id)}/aggregate")
        return codecs.dec_aggregate(d["aggregate"]) if d["aggregate"] else None

    def submit_decryption_share(self, election_id, share, keyper_sig) -> None:
        self._post(f"/elections/{self._eid(election_id)}/shares", {
            "share": codecs.enc_decryption_share(share),
            "keyperSig": codecs.enc_bytes(keyper_sig),
        })

    def list_decryption_shares(self, election_id):
        d = self._get(f"/elections/{self._eid(election_id)}/shares")
        return [codecs.dec_decryption_share(s) for s in d["shares"]]

    def publish_result(self, election_id, result, result_publisher_sig) -> None:
        self._post(f"/elections/{self._eid(election_id)}/result", {
            "result": codecs.enc_result(result),
            "resultPublisherSig": codecs.enc_bytes(result_publisher_sig),
        })

    def get_result(self, election_id):
        d = self._get(f"/elections/{self._eid(election_id)}/result")
        return codecs.dec_result(d["result"]) if d["result"] else None

    # -- capability --------------------------------------------------------- #

    def verifiability_tier(self) -> int:
        return int(self._get("/capability")["verifiabilityTier"])
