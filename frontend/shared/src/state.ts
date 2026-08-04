/** Derived election lifecycle — a faithful TS mirror of `geg.core.state.derive_state`.
 *
 * The public API exposes no derived state, so the dashboard computes it from the
 * config timings + the facts it can read (cancelled, finalized key, result). The
 * voting window is half-open `[votingStart, votingEnd)`. */

export type ElectionState =
  | "Cancelled"
  | "Complete"
  | "DKGFailed"
  | "Registered"
  | "KeyReady"
  | "Voting"
  | "Tallying";

export interface StateTimings {
  votingStart: number;
  votingEnd: number;
}

export interface StateFacts {
  cancelled: boolean;
  keyFinalized: boolean;
  resultPublished: boolean;
}

/** Same normative ordering as `derive_state`: terminal outcomes before live states. */
export function deriveState(c: StateTimings, f: StateFacts, now: number): ElectionState {
  if (f.cancelled) return "Cancelled";
  if (f.resultPublished) return "Complete";
  if (now >= c.votingStart && !f.keyFinalized) return "DKGFailed";
  if (!f.keyFinalized) return "Registered"; // now < votingStart guaranteed here
  if (now < c.votingStart) return "KeyReady";
  if (now < c.votingEnd) return "Voting";
  return "Tallying";
}

export function isVotingOpen(c: StateTimings, now: number): boolean {
  return c.votingStart <= now && now < c.votingEnd;
}

/** Non-terminal states never change again on their own. */
export const TERMINAL_STATES: ReadonlySet<ElectionState> = new Set<ElectionState>([
  "Cancelled",
  "Complete",
  "DKGFailed",
]);

/** Theme badge-color modifier class for a lifecycle state (see theme.css). */
export function stateBadgeClass(s: ElectionState): string {
  const map: Record<ElectionState, string> = {
    Complete: "badge--green",
    Voting: "badge--blue",
    KeyReady: "badge--blue",
    Tallying: "badge--amber",
    Registered: "badge--gray",
    Cancelled: "badge--gray",
    DKGFailed: "badge--red",
  };
  return `badge ${map[s]}`;
}
