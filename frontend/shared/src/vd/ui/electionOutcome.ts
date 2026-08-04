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

/** Overview header — lowercase “candidate”. */
export function formatOutcomeOverviewTitle(outcome: ElectionOutcome, t: TFunction): string {
  const votes = outcome.maxVotes.toString();
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
export function formatOutcomeStageTitle(outcome: ElectionOutcome, t: TFunction): string {
  const votes = outcome.maxVotes.toString();
  if (outcome.leaders.length === 0 || outcome.maxVotes === 0n) {
    return t("No votes recorded");
  }
  if (!outcome.isTie) {
    return t("Winner: Candidate {{i}} · {{votes}} votes", { i: outcome.leaders[0], votes });
  }
  const names = formatCandidateList(t, outcome.leaders, (i) => t("Candidate {{i}}", { i }));
  return t("Tied: {{names}} · {{votes}} votes each", { names, votes });
}
