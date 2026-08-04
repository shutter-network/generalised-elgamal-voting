import { useCallback, useEffect, useState } from "react";
import { api, isVotingOpen, type ElectionRecord } from "@geg/shared";
import { useWalletSigner } from "@geg/shared/wallet";
import { castVote } from "./ballot";

type Status = { kind: "ok" | "err" | "info"; msg: string } | null;

/** Header button that opens the ballot form (unchanged "Cast a ballot" card) in a modal.
 * Disabled for a cancelled election — voting can never happen, so there's nothing to open. */
export function VoteButton({ electionId }: { electionId: number }) {
  const [open, setOpen] = useState(false);
  const [cancelled, setCancelled] = useState(false);

  useEffect(() => {
    let alive = true;
    const load = () =>
      api.getElection(electionId).then((r) => { if (alive) setCancelled(r.cancelled); }).catch(() => {});
    load();
    const h = setInterval(load, 5000);
    return () => { alive = false; clearInterval(h); };
  }, [electionId]);

  return (
    <>
      {/* Same size/shape as the admin Cancel button (.btn btn--sm), blue instead of red. */}
      <button className="btn btn--primary btn--sm" disabled={cancelled}
        title={cancelled ? "This election was cancelled" : undefined}
        onClick={() => !cancelled && setOpen(true)}>
        {cancelled ? "Election cancelled" : "Vote for this election"}
      </button>
      {open && !cancelled && (
        <div className="modal-overlay" onClick={() => setOpen(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <button className="modal-close" onClick={() => setOpen(false)} aria-label="Close">×</button>
            <VoteForm electionId={electionId} />
          </div>
        </div>
      )}
    </>
  );
}

/** Vote panel for the selected election. Requires a connected wallet — the ballot's
 * eligibility attestation is bound to a wallet-signed EIP-712 challenge, and the service
 * derives a stable per-wallet pseudonym, so it is one wallet, one vote (last-wins: a wallet
 * may re-cast to change its vote until the window closes). Ballot crypto is client-side. */
export function VoteForm({ electionId }: { electionId: number }) {
  const [rec, setRec] = useState<ElectionRecord | null>(null);
  const [votes, setVotes] = useState<number[]>([]);
  const [status, setStatus] = useState<Status>(null);
  const [busy, setBusy] = useState(false);
  const { account, signMessage } = useWalletSigner();

  const load = useCallback(async () => {
    const r = await api.getElection(electionId);
    setRec(r);
    setVotes((v) => (v.length === r.config.numCandidates ? v : Array(r.config.numCandidates).fill(0)));
  }, [electionId]);

  useEffect(() => {
    load();
    const h = setInterval(load, 4000);
    return () => clearInterval(h);
  }, [load]);

  if (!rec) return null;
  const cfg = rec.config;
  const now = Math.floor(Date.now() / 1000);
  const open = isVotingOpen(cfg, now) && !rec.cancelled;
  const hasKey = rec.finalizedKey != null;
  const sum = votes.reduce((a, b) => a + b, 0);
  const budgetOk = cfg.mode === "exact" ? sum === cfg.budget : sum <= cfg.budget;
  const enabled = open && hasKey && !!account;
  const canCast = enabled && budgetOk && !busy;

  const cast = async () => {
    if (!rec.finalizedKey || !account) return;
    setBusy(true);
    setStatus({ kind: "info", msg: "Sign the eligibility challenge in your wallet…" });
    try {
      const { sequenceNumber } = await castVote({
        config: cfg,
        pkElectionHex: rec.finalizedKey.pkElection,
        votes,
        signMessage,
        onStage: (msg) => setStatus({ kind: "info", msg }),
      });
      setStatus({ kind: "ok", msg: `Ballot accepted — sequence #${sequenceNumber}` });
    } catch (e: any) {
      setStatus({ kind: "err", msg: e?.shortMessage ?? e?.message ?? String(e) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="card">
      <div className="card-head"><h3 className="card-title">Cast a ballot</h3></div>
      {!account && <div className="banner" style={{ marginBottom: 12 }}>Connect your wallet (top-right) to vote — one wallet, one vote.</div>}
      {account && !hasKey && <div className="banner" style={{ marginBottom: 12 }}>Waiting for the DKG to finalize the election key…</div>}
      {account && hasKey && !open && <div className="banner" style={{ marginBottom: 12 }}>Voting window is not open for this election.</div>}

      <div style={{ opacity: enabled ? 1 : 0.55, pointerEvents: enabled ? "auto" : "none" }}>
        <p style={{ margin: "0 0 12px", fontSize: 14, color: "var(--text)" }}>
          Enter a vote per candidate ({cfg.mode === "exact" ? `must sum to ${cfg.budget}` : `sum ≤ ${cfg.budget}`}).
          {cfg.weighted && " Your voting weight is set by the eligibility service."}
        </p>
        <div className="stack" style={{ gap: 8 }}>
          {votes.map((v, i) => (
            <label className="field" key={i} style={{ gridTemplateColumns: "120px 1fr" }}>
              <span className="label-inline" style={{ color: "var(--text)", fontWeight: 500 }}>Candidate {i}</span>
              <input type="number" min={0} value={v}
                onChange={(e) => setVotes((arr) => arr.map((x, j) => (j === i ? Number(e.target.value) : x)))} />
            </label>
          ))}
          <div className={budgetOk ? "notice notice--ok" : "notice notice--err"}>
            sum = {sum} {budgetOk ? "✓" : `(needs ${cfg.mode === "exact" ? `= ${cfg.budget}` : `≤ ${cfg.budget}`})`}
          </div>
          <button className="btn btn--primary" onClick={cast} disabled={!canCast} style={{ justifySelf: "start" }}>
            {busy ? "Submitting…" : "Cast ballot"}
          </button>
        </div>
      </div>

      {status && <div className={`notice notice--${status.kind === "ok" ? "ok" : status.kind === "err" ? "err" : "info"}`} style={{ marginTop: 10 }}>{status.msg}</div>}
    </section>
  );
}
