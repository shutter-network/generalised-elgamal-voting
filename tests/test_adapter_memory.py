"""Run the shared conformance suite against the in-memory adapter.

The in-memory adapter is the executable reference; the database and blockchain
adapters subclass ``DataLayerConformance`` the same way and must pass it
unmodified (each via its own backend seam).
"""

from __future__ import annotations

import pytest

from conformance import DataLayerConformance, ManualClock, SignatureBackend

from geg.adapters.memory import InMemoryDataLayer


class TestInMemoryConformance(DataLayerConformance):
    @pytest.fixture
    def backend(self):
        clock = ManualClock(0)
        return SignatureBackend(InMemoryDataLayer(clock=clock), clock)
