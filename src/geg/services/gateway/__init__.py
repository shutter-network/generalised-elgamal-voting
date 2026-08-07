"""Ballot admission (gateway): on-by-default filter, non-authoritative.

A library only — the ballot ingest HTTP endpoint lives on the ``api`` service.
"""
from geg.services.gateway.gateway import GatewayRejection, submit_ballot

__all__ = ["submit_ballot", "GatewayRejection"]
