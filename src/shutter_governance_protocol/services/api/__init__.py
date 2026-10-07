"""Public election API (reads + ballot ingest; frontend / external integrators)."""
from shutter_governance_protocol.services.api.api import build_api_app

__all__ = ["build_api_app"]
