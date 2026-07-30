"""The three abstraction seams of the system.

- :mod:`geg.ports.data_layer` — ``ElectionDataLayer``, the single storage
  abstraction (chain / database / in-memory adapters).
- :mod:`geg.ports.eligibility` — ``EligibilityService``, the authority on who may
  vote and with what weight (wallet / OIDC / Wahlregister adapters).
- :mod:`geg.ports.keyper_p2p` — the keyper-to-keyper DKG message schema.

These modules define contracts only. Adapters and services live in later slices.
"""
