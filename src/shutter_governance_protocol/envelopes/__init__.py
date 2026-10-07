"""Transport envelopes and their JSON codecs.

The **byte codecs** (fixed sizes: G1=48, G2=96, Schnorr=80, DLEQ=64, and the
versioned ballot-validity-proof encoding) are the normative interop layer,
adopted from the SDK v1 formats by reference. The **transport envelopes** in this
package are JSON objects with ``0x``-hex byte fields — one shape per artifact
type — used verbatim by the database adapter and the gateway API; the chain
adapter maps the same fields onto contract structs. Auditors parse one shape
regardless of backend.
"""
