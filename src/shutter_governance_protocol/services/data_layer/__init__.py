"""Uniform data-layer HTTP service (fronts any ElectionDataLayer backend)."""
from shutter_governance_protocol.services.data_layer.data_layer import build_app, main

__all__ = ["build_app", "main"]
