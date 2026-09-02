"""Does weight scaling actually pay for itself?

The whole justification for the `scale` factor is that tally cost grows as
`sqrt(bound)` where `bound = budget * sum(scaled weights)`, so dividing every weight
by `s` should divide the bound by `s` and the tally cost by `sqrt(s)`. At `s = 128`
that predicts roughly an 11x faster tally.

That is the load-bearing claim of the design and it has only ever been asserted.
This measures it directly, against the same `build_baby_step_table` /
`baby_step_giant_step_with_table` pair `recover_result` calls.

It also re-derives the two constants `docs/COORDINATOR_SIZING.md` is built on --
~11 us and ~218 bytes per table entry -- so the sizing table stays honest against
the current curve backend rather than a backend it was measured on months ago.

    .venv/bin/python benchmarks/scale_tally_cost.py

Bounds are kept small enough to run in a couple of minutes; the model is what
extrapolates, and the point of the run is to check the model's shape, not to
reproduce a 1e12 tally.
"""

from __future__ import annotations

import math
import sys
import time
import tracemalloc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from geg.crypto.recovery import (  # noqa: E402
    build_baby_step_table,
    baby_step_giant_step_with_table,
)
from geg.crypto.points import G2, mul  # noqa: E402

GREEN, YELLOW, BOLD, RESET = "\x1b[32m", "\x1b[33m", "\x1b[1m", "\x1b[0m"


def info(msg: str) -> None:
    print(f"{YELLOW}->{RESET} {msg}")


def measure(bound: int, probes: int = 3) -> dict:
    """Build the table for `bound`, then resolve `probes` targets from it."""
    tracemalloc.start()
    t0 = time.perf_counter()
    table = build_baby_step_table(bound)
    build_s = time.perf_counter() - t0
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # Targets spread across the range, as a real election's per-candidate totals
    # are. In exact mode they sum to the bound, so the walks share one budget --
    # which is why candidate count does not change tally cost.
    walk_s = 0.0
    for k in range(1, probes + 1):
        target_m = (bound * k) // (probes + 1)
        target = mul(G2, target_m)
        t1 = time.perf_counter()
        got = baby_step_giant_step_with_table(target, table)
        walk_s += time.perf_counter() - t1
        assert got == target_m, f"BSGS returned {got}, expected {target_m}"

    entries = table.n
    return {
        "bound": bound,
        "entries": entries,
        "build_s": build_s,
        "walk_s": walk_s,
        "total_s": build_s + walk_s,
        "us_per_entry": build_s * 1e6 / entries,
        "bytes_per_entry": peak / entries,
    }


def main() -> None:
    print()
    print(f"{BOLD}Part 1 -- cost model: is tally cost really O(sqrt(bound))?{RESET}")
    print()
    print(
        f"{BOLD}{'bound':>12} {'entries':>9} {'build s':>9} {'walk s':>8} "
        f"{'total s':>9} {'us/entry':>9} {'B/entry':>9}{RESET}"
    )

    rows = []
    # Large enough that a run is seconds, not milliseconds: at 1e6 the whole
    # measurement is ~30 ms and process noise swamps the 2x signal being tested.
    for bound in (10**9, 4 * 10**9, 16 * 10**9, 64 * 10**9):
        r = measure(bound)
        rows.append(r)
        print(
            f"{r['bound']:>12,} {r['entries']:>9,} {r['build_s']:>9.2f} "
            f"{r['walk_s']:>8.2f} {r['total_s']:>9.2f} "
            f"{r['us_per_entry']:>9.2f} {r['bytes_per_entry']:>9.0f}"
        )

    print()
    info(
        "Each row is 4x the previous bound. sqrt scaling predicts 2x the cost; "
        "a 4x rise would mean the model is linear, not sqrt."
    )
    for prev, cur in zip(rows, rows[1:]):
        ratio = cur["total_s"] / prev["total_s"]
        print(
            f"   {prev['bound']:>12,} -> {cur['bound']:>12,}   "
            f"cost x{ratio:.2f}   (sqrt predicts x2.00)"
        )
    # Adjacent pairs are noisy at these durations; the end-to-end ratio is the
    # signal worth reading, and it spans a 64x change in bound.
    span_bound = rows[-1]["bound"] / rows[0]["bound"]
    span_cost = rows[-1]["total_s"] / rows[0]["total_s"]
    print()
    print(
        f"   end to end: bound x{span_bound:.0f}  ->  cost x{span_cost:.2f}   "
        f"(sqrt predicts x{math.sqrt(span_bound):.2f})"
    )

    # ---------------------------------------------------------------- part 2
    print()
    print(f"{BOLD}Part 2 -- what `scale` buys, at the live erc20.eth numbers{RESET}")
    print()

    # From the live run: V = 1,011,123 supply, budget 100, holders summing to
    # 995,653. `scale` divides every weight, so the bound falls by ~s.
    budget = 100
    total_weight = 995_653
    print(
        f"budget={budget}, sum(weights)={total_weight:,} "
        f"(the four erc20.eth holders)"
    )
    print()
    print(
        f"{BOLD}{'scale':>6} {'bound':>14} {'entries':>9} {'measured s':>11} "
        f"{'speedup':>8} {'predicted':>10}{RESET}"
    )

    base = None
    for s in (1, 8, 128):
        scaled = sum((w + s // 2) // s for w in (995_500, 69, 53, 31))
        bound = budget * scaled
        r = measure(bound, probes=3)
        if base is None:
            base = r["total_s"]
        print(
            f"{s:>6} {bound:>14,} {r['entries']:>9,} {r['total_s']:>11.2f} "
            f"{base / r['total_s']:>7.1f}x {math.sqrt(s):>9.1f}x"
        )

    print()
    info(
        "'predicted' is sqrt(s). Scaling is only worth its precision cost if the "
        "measured speedup tracks it."
    )

    # ---------------------------------------------------------------- part 3
    print()
    print(f"{BOLD}Part 3 -- the constants COORDINATOR_SIZING.md is built on{RESET}")
    print()
    us = sum(r["us_per_entry"] for r in rows) / len(rows)
    by = sum(r["bytes_per_entry"] for r in rows) / len(rows)
    print(f"   measured   ~{us:.1f} us/entry, ~{by:.0f} B/entry")
    print("   documented ~11.0 us/entry, ~218 B/entry")
    print()
    info(
        "Bytes are Python-heap accounted via tracemalloc, so they are comparable to "
        "the documented 218 B figure and not to an RSS reading -- macOS compresses "
        "memory and reads roughly half the true footprint."
    )
    print()
    for r in rows:
        pred = 2 * math.sqrt(r["bound"]) * 11e-6
        print(
            f"   bound {r['bound']:>12,}: model {pred:>7.2f}s vs measured "
            f"{r['total_s']:>7.2f}s  ({r['total_s'] / pred:.2f}x)"
        )


if __name__ == "__main__":
    main()
