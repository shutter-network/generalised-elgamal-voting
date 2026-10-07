"""Dummy eligibility-attestation service.

A development HTTP wrapper over :class:`shutter_governance_protocol.adapters.eligibility_stub.StubEligibilityService`
so browser voter clients can obtain an ``ATTESTATION_V1`` credential for a ballot. It
authenticates nobody — issuance authentication is exactly what a real adapter (wallet /
OIDC / Wahlregister) adds — so operators of this monorepo swap it out without touching the
frontends (the verifying side, ``verify_attestation``, is identical regardless of issuer).
"""

from __future__ import annotations

from shutter_governance_protocol.services.eligibility.eligibility import build_eligibility_app, main

__all__ = ["build_eligibility_app", "main"]
