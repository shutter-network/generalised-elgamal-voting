import type { TFunction } from "i18next";

export type ElectionOutcome = {
  maxVotes: bigint;
  leaders: number[];
  totalVotes: bigint;
  isTie: boolean;
};

export function computeElectionOutcome(tally: readonly bigint[]): ElectionOutcome {
  const totalVotes = tally.reduce((s, c) => s + c, 0n);
  if (tally.length === 0) {
    return { maxVotes: 0n, leaders: [], totalVotes: 0n, isTie: false };
  }

  let maxVotes = 0n;
  for (const c of tally) {
    if (c > maxVotes) maxVotes = c;
  }

  const leaders =
    maxVotes > 0n
      ? tally.map((c, i) => (c === maxVotes ? i : -1)).filter((i) => i >= 0)
      : [];

  return {
    maxVotes,
    leaders,
    totalVotes,
    isTie: leaders.length > 1,
  };
}

function formatCandidateList(
  t: TFunction,
  indices: number[],
  label: (i: number) => string,
): string {
  const parts = indices.map(label);
  if (parts.length <= 1) return parts[0] ?? "";
  if (parts.length === 2) return `${parts[0]}${t(" and ")}${parts[1]}`;
  return `${parts.slice(0, -1).join(", ")}${t(", and ")}${parts[parts.length - 1]}`;
}

/** Points -> votes. A **vote** is one unit of voting power fully allocated, so
 *  `points / budget`: with budget 100, a candidate holding 4000 points has 40 votes, and
 *  the per-candidate votes sum to the total voting power (5100/100 = 51 = the sum of the
 *  admitted weights). That makes the headline number comparable across elections with
 *  different budgets, which raw points are not.
 *
 *  Can be fractional — a weight-1 voter splitting a budget of 100 as 60/40 gives 0.6 and
 *  0.4 votes — so show up to 2dp and trim. Winner/tie selection stays on the exact integer
 *  points (see `computeElectionOutcome`); only the display divides, or rounding could
 *  invent a tie that the real totals do not have.
 */
export function formatVotes(points: bigint | number, budget: number): string {
  if (!budget || budget <= 0) return Number(points).toLocaleString();
  const v = Number(points) / budget;
  return Number.isInteger(v) ? v.toLocaleString() : v.toLocaleString(undefined, { maximumFractionDigits: 2 });
}


/** Overview header — lowercase “candidate”. */
export function formatOutcomeOverviewTitle(outcome: ElectionOutcome, t: TFunction, budget = 0): string {
  const votes = formatVotes(outcome.maxVotes, budget);
  if (outcome.leaders.length === 0 || outcome.maxVotes === 0n) {
    return t("No votes recorded");
  }
  if (!outcome.isTie) {
    return t("Winner: candidate {{i}} · {{votes}} votes", { i: outcome.leaders[0], votes });
  }
  const names = formatCandidateList(t, outcome.leaders, (i) => t("candidate {{i}}", { i }));
  return t("Tied between {{names}} · {{votes}} votes each", { names, votes });
}

/** Stage list RESULT row — capitalized “Candidate”. */
export function formatOutcomeStageTitle(outcome: ElectionOutcome, t: TFunction, budget = 0): string {
  const votes = formatVotes(outcome.maxVotes, budget);
  if (outcome.leaders.length === 0 || outcome.maxVotes === 0n) {
    return t("No votes recorded");
  }
  if (!outcome.isTie) {
    return t("Winner: Candidate {{i}} · {{votes}} votes", { i: outcome.leaders[0], votes });
  }
  const names = formatCandidateList(t, outcome.leaders, (i) => t("Candidate {{i}}", { i }));
  return t("Tied: {{names}} · {{votes}} votes each", { names, votes });
}
