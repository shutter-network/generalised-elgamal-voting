import { useCallback, useEffect, useState } from "react";
import { api, cancelElection, deriveState, eidToBareHex, eidToHex, formatApiError, type ElectionRecord } from "@geg/shared";
import { type WalletSigner } from "@geg/shared/wallet";
import { cancelDigest } from "./adminSign";

type Status = { kind: "ok" | "err" | "info"; msg: string } | null;

/** "Cancel this election" panel shown under the election detail (admin dashboard).
 * Enabled only when the admin wallet is connected and voting has not started yet — the
 * data layer likewise rejects a cancel once voting_start has passed. */
export function CancelElectionButton({ electionId, wallet }: { electionId: number; wallet: WalletSigner | null }) {
  const [rec, setRec] = useState<ElectionRecord | null>(null);
  const [stalled, setStalled] = useState(false);
  const [status, setStatus] = useState<Status>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const r = await api.getElection(electionId);
      setRec(r);
      // Hand the slot to the Retry button while the tally is stalled (they never co-render).
      const res = await api.getResult(electionId);
      const now = Math.floor(Date.now() / 1000);
      const state = deriveState(r.config, {
        cancelled: r.cancelled, keyFinalized: r.finalizedKey != null,
        resultPublished: res.result != null, tallyStalled: r.tallyStalled,
      }, now);
      setStalled(state === "TallyStalled");
    } catch { /* transient */ }
  }, [electionId]);

  useEffect(() => {
    load();
    const h = setInterval(load, 5000); // refresh so the button disables once voting opens
    return () => clearInterval(h);
  }, [load]);

  if (!rec || stalled) return null; // stalled → the Retry button takes this slot instead
  const now = Math.floor(Date.now() / 1000);
  const votingStarted = now >= rec.config.votingStart;
  const cancelled = rec.cancelled;
  const connected = !!wallet?.account;
  const canCancel = connected && !votingStarted && !cancelled && !busy;

  const cancel = async () => {
    if (!wallet) return;
    setBusy(true);
    setStatus({ kind: "info", msg: "Awaiting wallet signature…" });
    try {
      const eidHex = eidToHex(electionId);
      const signature = await wallet.signDigest(cancelDigest(eidHex));
      await cancelElection(eidToBareHex(electionId), signature);
      setStatus({ kind: "ok", msg: `Cancelled election #${electionId}` });
      load();
    } catch (e: unknown) {
      setStatus({ kind: "err", msg: formatApiError(e) });
    } finally {
      setBusy(false);
    }
  };

  const hint = cancelled
    ? "This election is already cancelled."
    : votingStarted
      ? "Voting has started — cancellation is no longer possible."
      : !connected
        ? "Connect the admin wallet to cancel."
        : null;

  // Compact form — rendered in the dashboard header's right column, under the election dropdown.
  return (
    <div style={{ display: "inline-flex", flexDirection: "column", alignItems: "flex-end" }}>
      <button className="btn btn--danger btn--sm" disabled={!canCancel} onClick={cancel}>
        {busy ? "Cancelling…" : "Cancel this election"}
      </button>
      {hint && <div className="dim" style={{ fontSize: 11, marginTop: 5, textAlign: "right", whiteSpace: "nowrap" }}>{hint}</div>}
      {status && (
        <div className={`notice notice--${status.kind === "ok" ? "ok" : status.kind === "err" ? "err" : "info"}`} style={{ marginTop: 6, textAlign: "right" }}>
          {status.msg}
        </div>
      )}
    </div>
  );
}
