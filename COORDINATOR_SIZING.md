# Coordinator sizing — what a tally costs

How much machine the tally needs, and what that machine buys you in voting power. Read this before
choosing a coordinator host, and before setting an election's `scale`.

The timings below are previously recorded measurements for `py_arkworks_bls12381`,
this repository's curve backend. They have not been rerun for this documentation
update. Use `benchmarks/scale_tally_cost.py` to measure on your target machine.

---

## Where the cost is

Three stages have very different cost profiles, and only one of them cares about voting power.

| Stage | Who runs it | Cost | Sensitive to weight magnitude? |
| --- | --- | --- | --- |
| Ballot admission — range/budget proofs + signature | **every keyper**, every ballot | `choices x (budget + 1)` branches at **~2.7 ms** each | No |
| Aggregation — `Σ_i weight_i · ct_i` | **every keyper** | ~418 µs per (ballot, candidate): 2 decompressions at 161 µs, 2 mults at 45.8 µs, 2 adds | **No** — a mult by 1e18 costs the same as by 3 |
| **Recovery — Lagrange + baby-step giant-step** | **coordinator only** (`services/tally_aggregator`) | `O(√bound)` time **and** memory | **Yes. This is the only stage that scales with voting power.** |

Keypers never run BSGS; nothing under `services/keyper/` calls it. The Python
auditor uses `check_result` to verify published totals against verified shares
without BSGS. The dashboard's result verifier still runs BSGS in the browser.

---

## Recovery cost model

`recover_result` recovers each candidate total by BSGS over
`bound = budget × Σ(scaled admitted weights)` (`bsgs_bound` in `core/aggregation.py`). Each weight
is divided by the election's `scale` before it is summed; with the default `scale = 1` this is
the plain sum of admitted weights. With `m = √bound`:

```
tally time    ≈ 2m × 11 µs      (m ops to build the baby-step table, plus ~m giant steps in total)
table memory  ≈ 218 B × m
```

**11 µs per inner-loop operation** (G2 add + compress + hash-map op), stable from `m = 3e5` to
`m = 5e6` — no cache cliff. The model approximates the recorded runs (within about 6% in this table):

| Bound | `m` | Predicted | Measured |
| --- | --- | --- | --- |
| 1e12 | 1,000,002 | 22 s | 22.9 s |
| 9e12 | 3,000,002 | 66 s | 69.4 s |
| 2.5e13 | 5,000,002 | 110 s | 107.9 s |

Measured again end-to-end through `recover_result` after the hoist, at 5 candidates — the split
confirms the model's two halves and that the walk really is shared across candidates:

| Bound | `m` | Table build | Giant-step walk, **all 5 candidates** | Total |
| --- | --- | --- | --- | --- |
| 1e10 | 100,002 | 1.0 s | 1.1 s | **2.1 s** |
| 1e12 | 1,000,002 | 10.6 s | 10.8 s | **21.4 s** |
| 1e13 | 3,162,279 | 34.5 s | 34.9 s | **69.4 s** |

The walk costs `≈ m` in total rather than `m` per candidate, exactly as the `Σ_j T_j = m²` identity
predicts. Pre-hoist, the 1e12 row would have been ~64 s.

**218 bytes per table entry**, exactly linear at 500k and 2M entries — 144 B for the 96-byte
compressed G2 point (a `bytes` object, pymalloc-rounded), 32 B for the integer value (`j > 256`, so
outside CPython's small-int cache), 42 B of `dict` slot.

**The leading BSGS search cost is shared across candidates.** The giant-step total is `≈ m` across *all*
candidates, not per candidate: in `mode: exact` the per-candidate totals sum to
`budget × Σw = m²`, so all the walks share one budget. Share verification, aggregation and ballot
admission still grow with candidate count.

---

## Machine table

Sized at ~300 B per entry of machine RAM — the 218 B table plus the `dict` resize transient,
interpreter, ballots and aggregate.

| Coordinator RAM (GiB) | `m` | Search bound `budget × Σw` | Max Σ weight, budget 1 | Max Σ weight, budget 100 | Tally wall-clock |
| --- | --- | --- | --- | --- | --- |
| 1 GiB | 3.6e6 | 1.3e13 | 1.3e13 | 1.3e11 | 1.3 min |
| **2 GiB** | 7.2e6 | **5.1e13** | **5.1e13** | **5.1e11** | **2.6 min** |
| 4 GiB | 1.4e7 | 2.0e14 | 2.0e14 | 2.0e12 | 5.3 min |
| 8 GiB | 2.9e7 | 8.2e14 | 8.2e14 | 8.2e12 | 11 min |
| 16 GiB | 5.7e7 | 3.3e15 | 3.3e15 | 3.3e13 | 21 min |
| 32 GiB | 1.1e8 | 1.3e16 | 1.3e16 | 1.3e14 | 42 min |
| 64 GiB | 2.3e8 | 5.2e16 | 5.2e16 | 5.2e14 | 84 min |

`Σ weight` is the sum of attested weights over ballots actually admitted, not over the eligible
electorate. When `scale > 1`, read it as the sum of *scaled* weights. Cost scales as `√`, so
**4× the RAM buys 16× the voting power**.

### Three caveats before reading a row off this table

1. **Measure on Linux.** macOS compresses memory, so `ps` RSS reads roughly half the true footprint
   (87 B/entry observed at `m = 3e6` against 218 B/entry accounted). Size against the accounted
   figure.
2. **The table is built once per election** — `recover_result` hoists
   `build_baby_step_table` out of its candidate loop, so the figures above are the whole election,
   not per candidate. It used to rebuild per candidate, which cost about `(ℓ+1)/2` times as much
   (roughly 3× at 5 candidates) for an identical answer. `tests/test_aggregation.py` asserts the
   build count directly rather than inferring it from timing, so a regression names itself.
3. **Leave memory headroom.** A larger bound increases both runtime and memory;
   exceeding available memory can terminate recovery. `recover_result` accepts an
   optional `solver_ceiling` and raises `TallyInfeasible` before allocating a table
   when that ceiling is exceeded. The deployed `finalize` path does not currently
   pass a ceiling, so this guard is not enabled by the standard coordinator.

---

## Choosing `scale`

`scale` on `ElectionConfig` is the setting that controls how much a tally costs.

**What `scale` does.** At aggregation, every attested weight is divided by `scale` and rounded half
up: `(weight + scale // 2) // scale` (`scaled_weight` in `core/aggregation.py`). The tally then
counts in units of `scale` instead of single tokens. Integer rounding can change
relative voting power and potentially the outcome. Scaling is therefore a voting
rule that must be disclosed, as well as a way to reduce recovery cost.

**When to change it.** Leave `scale = 1` unless the election cannot be tallied otherwise. Work it
out like this:

1. Estimate the total weight that will be admitted. Over-estimating is safe.
2. Multiply by `budget` to get the bound.
3. If the bound exceeds what the coordinator can hold, estimate a suitable `scale`
   using `bound / scale`, then check `budget × Σ((weight + scale // 2) // scale)`
   using the expected weight distribution. Rounding each weight can make this
   larger than simply dividing the original bound. Include headroom for uncertainty.

Example: a budget-100 election where up to 1e15 tokens may vote has a bound of 1e17, which no row
in the table covers. With `scale = 1e4` the bound becomes 1e13, which is near the table's 1 GiB estimate. Verify the rounded bound and leave memory headroom.

**What it costs voters.** A weight below `scale / 2` rounds to 0. That ballot is still admitted but
adds nothing to the tally. In the example above, any voter holding fewer than 5,000 tokens would
count for nothing. Each scaled weight can round up or down by up to half a unit.

**When it is set.** `scale` is part of the signed election config. The deployment chooses it, it is
fixed before voting opens, and voters must be told about it, because it changes what each ballot is
worth.

---

## What actually limits an election

Ballot admission can dominate runtime, especially with many candidates or a large
vote budget. Recovery can instead dominate for large scaled weights. Admission
cost is independent of weight magnitude:

| Proposal shape | Branches/ballot | Proof size | Verify/ballot |
| --- | --- | --- | --- |
| 2 candidates, budget 1 | 4 | 1.1 KiB | 0.01 s |
| 5 candidates, budget 1 | 10 | 2.6 KiB | 0.027 s |
| **5 candidates, budget 100** | 505 | 126 KiB | **1.30 s** |
| **24 candidates, budget 100** (the max `MAX_PROOF_BRANCHES` allows) | 2,424 | 606 KiB | **6.55 s** |

Per keyper, and again for any auditor:

| | 1,000 ballots | 10,000 ballots |
| --- | --- | --- |
| 5 candidates, budget 1 | 27 s | 4.5 min |
| **5 candidates, budget 100** | **22 min** | **3.6 hours** |
| 24 candidates, budget 100 | 1.8 hours | 18 hours |

For a 5-candidate weighted proposal with 1,000 ballots: **22 minutes of admission, 2 seconds of
aggregation, about 23 seconds of recovery at a search bound of 1e12.**
`MAX_PROOF_BRANCHES = 2500` in `src/shutter_governance_protocol/core/config.py` limits work per ballot.
Total admission work also grows with ballot count. The coordinator checks a
six-hour limit from voting end while waiting for keyper work or shares, but this
does not cancel work already running in a keyper or interrupt synchronous BSGS
recovery. It is not a hard runtime or memory limit.
