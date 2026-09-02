# Coordinator sizing — what a tally costs

How much machine the tally needs, and what that machine buys you in voting power. Read this before
choosing a coordinator host, and before setting an election's `max_weight`.

All figures measured against `py_arkworks_bls12381`, this repository's curve backend.

---

## Where the cost is

Three stages have very different cost profiles, and only one of them cares about voting power.

| Stage | Who runs it | Cost | Sensitive to weight magnitude? |
| --- | --- | --- | --- |
| Ballot admission — range/budget proofs + signature | **every keyper**, every ballot | `choices x (budget + 1)` branches at **~2.7 ms** each | No |
| Aggregation — `Σ_i weight_i · ct_i` | **every keyper** | ~418 µs per (ballot, candidate): 2 decompressions at 161 µs, 2 mults at 45.8 µs, 2 adds | **No** — a mult by 1e18 costs the same as by 3 |
| **Recovery — Lagrange + baby-step giant-step** | **coordinator only** (`services/tally_aggregator`) | `O(√bound)` time **and** memory | **Yes. This is the only stage that scales with voting power.** |

Keypers never run BSGS; nothing under `services/keyper/` calls it. `services/auditor` does, because it
re-derives the result independently.

---

## Recovery cost model

`recover_result` recovers each candidate total by BSGS over `bound = budget × Σ(admitted weights)`
(`core/aggregation.py:29`). With `m = √bound`:

```
tally time    ≈ 2m × 11 µs      (m ops to build the baby-step table, plus ~m giant steps in total)
table memory  ≈ 218 B × m
```

**11 µs per inner-loop operation** (G2 add + compress + hash-map op), stable from `m = 3e5` to
`m = 5e6` — no cache cliff. The model predicts measured runs within 5%:

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

**Candidate count does not change tally cost.** The giant-step total is `≈ m` across *all*
candidates, not per candidate: in `mode: exact` the per-candidate totals sum to
`budget × Σw = m²`, so all the walks share one budget.

---

## Machine table

Sized at ~300 B per entry of machine RAM — the 218 B table plus the `dict` resize transient,
interpreter, ballots and aggregate.

| Coordinator RAM | `m` | Search bound `budget × Σw` | Max Σ weight, budget 1 | Max Σ weight, budget 100 | Tally wall-clock |
| --- | --- | --- | --- | --- | --- |
| 1 GB | 3.6e6 | 1.3e13 | 1.3e13 | 1.3e11 | 1.3 min |
| **2 GB** | 7.2e6 | **5.1e13** | **5.1e13** | **5.1e11** | **2.6 min** |
| 4 GB | 1.4e7 | 2.0e14 | 2.0e14 | 2.0e12 | 5.3 min |
| 8 GB | 2.9e7 | 8.2e14 | 8.2e14 | 8.2e12 | 11 min |
| 16 GB | 5.7e7 | 3.3e15 | 3.3e15 | 3.3e13 | 21 min |
| 32 GB | 1.1e8 | 1.3e16 | 1.3e16 | 1.3e14 | 42 min |
| 64 GB | 2.3e8 | 5.2e16 | 5.2e16 | 5.2e14 | 84 min |

`Σ weight` is the sum of attested weights over ballots actually admitted, not over the eligible
electorate. Cost scales as `√`, so **4× the RAM buys 16× the voting power**.

### Three caveats before reading a row off this table

1. **Measure on Linux.** macOS compresses memory, so `ps` RSS reads roughly half the true footprint
   (87 B/entry observed at `m = 3e6` against 218 B/entry accounted). Size against the accounted
   figure.
2. **The table is built once per election** — `recover_result` hoists
   `build_baby_step_table` out of its candidate loop, so the figures above are the whole election,
   not per candidate. It used to rebuild per candidate, which cost about `(ℓ+1)/2` times as much
   (roughly 3× at 5 candidates) for an identical answer. `tests/test_aggregation.py` asserts the
   build count directly rather than inferring it from timing, so a regression names itself.
3. **Exceeding a row is not fatal.** The bound is derived at tally time from public data, so
   overshooting the machine you planned for means a slower tally, not an impossible one — until it
   exceeds what the machine can ever hold, at which point BSGS dies in the allocator. Leave headroom,
   and assert the derived bound before entering BSGS so an infeasible election reports rather than
   hangs.

---

## Choosing `max_weight`

`ElectionConfig` enforces `budget × max_weight ≤ MAX_BUDGET_TIMES_WEIGHT` (`core/config.py:231`),
defaulting to 1e6. Note what that expression is and is not:

- It is a **per-voter** bound. The quantity that actually drives BSGS is `budget × Σ weights`, a
  **per-election total**.
- The two coincide only when exactly one ballot is admitted. With `N` ballots the real bound reaches
  `N × budget × max_weight`.

So the default is simultaneously **too strict** for a small election (a 3-voter election with one
large holder is trivially tallyable and gets capped anyway) and **too loose** for a large one (1,000
voters at `max_weight = 1e4` and budget 100 gives bound 1e9, which registers cleanly and which no
check anywhere rejects).

If you are integrating this protocol, size `max_weight` from the two constraints separately:

- **Feasibility** is `budget × Σ(expected weights) ≤` the bound your coordinator's RAM allows, per
  the table above. Use a conservative estimate of total voting power; over-estimating is safe.
- **`max_weight` itself** is best understood as an **issuer-abuse bound** — `verify_attestation`
  rejects `weight > max_weight` (`ports/eligibility.py:96`) and every keyper enforces it
  independently at admission, so it caps the damage a compromised or buggy eligibility service can
  do. Set it from that reasoning, not from a compute budget.

---

## What actually limits an election

Not voting power. Admission does, and it is entirely independent of weight:

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
aggregation, 23 seconds of tally.** `MAX_PROOF_BRANCHES = 2500` (`core/config.py:203`) is the ceiling
that matters, and it is correctly placed — but total admission cost is `ballots × branches`, which
registration cannot know, so it stays bounded at run time by the coordinator's tally-phase deadline.
