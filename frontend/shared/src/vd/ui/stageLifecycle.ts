import type { EncryptedTally, DecryptionShare } from "../eth/types";

export type StageLifecycle = "done" | "in_progress" | "stalled" | "pending";

export type StageStatusContext = {
  isDKGFinalized: boolean;
  phase: number;
  isResultFinalized: boolean;
  thresholdT: number;
  aggregate: EncryptedTally | null;
  shares: DecryptionShare[] | null;
  /** A cancelled election is terminal before anything ran: no stage is done, active, or verifiable. */
  cancelled?: boolean;
  /** The coordinator gave up on the tally (under-quorum aggregate/decryption). The
   *  currently-active stage is shown as stalled until an admin retries. */
  tallyStalled?: boolean;
};

export function getStageDone(stageNum: number, ctx: StageStatusContext): boolean {
  if (ctx.cancelled) return false;
  const dkgDone = ctx.isDKGFinalized;
  const votingDone = dkgDone && ctx.phase >= 4;
  const aggregateDone = votingDone && ctx.aggregate !== null;
  const sharesDone =
    aggregateDone && ctx.shares !== null && ctx.shares.length >= ctx.thresholdT;
  const resultDone = ctx.isResultFinalized;

  switch (stageNum) {
    case 1:
      return dkgDone;
    case 2:
      return votingDone;
    case 3:
      return aggregateDone;
    case 4:
      return sharesDone;
    case 5:
      return resultDone;
    default:
      return false;
  }
}

/** First stage currently in progress; null if none. DKG (stage 1) never counts — it goes pending → done. */
export function getActiveStageNum(ctx: StageStatusContext): number | null {
  if (ctx.cancelled) return null;
  if (!ctx.isDKGFinalized) return null;
  if (ctx.phase === 3) return 2;
  if (ctx.phase < 3) return null;
  if (!ctx.aggregate) return 3;
  if (!ctx.shares || ctx.shares.length < ctx.thresholdT) return 4;
  if (!ctx.isResultFinalized) return 5;
  return null;
}

export function getStageLifecycle(stageNum: number, ctx: StageStatusContext): StageLifecycle {
  if (getStageDone(stageNum, ctx)) return "done";
  // DKG finalizes atomically on-chain — no meaningful "in progress" window for stage 1.
  if (stageNum === 1) return "pending";
  // The stage the tally is stuck on (aggregate or decryption) reads as stalled, not "in progress".
  if (getActiveStageNum(ctx) === stageNum) return ctx.tallyStalled ? "stalled" : "in_progress";
  return "pending";
}

/** Stages before `viewingStageNum` that are not done yet. */
export function getWaitingOnStageNums(viewingStageNum: number, ctx: StageStatusContext): number[] {
  const nums: number[] = [];
  for (let i = 1; i < viewingStageNum; i++) {
    if (!getStageDone(i, ctx)) nums.push(i);
  }
  return nums;
}

export function isStageVerificationAvailable(
  stageNum: number,
  ctx: StageStatusContext,
  opts: { hasAggregate: boolean; hasShares: boolean; hasResult: boolean },
): boolean {
  if (getStageLifecycle(stageNum, ctx) === "pending") return false;
  switch (stageNum) {
    case 3:
      return opts.hasAggregate;
    case 4:
      return opts.hasAggregate && opts.hasShares;
    case 5:
      return opts.hasResult && opts.hasAggregate && opts.hasShares;
    default:
      return false;
  }
}
