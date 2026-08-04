import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import { deriveState, stateBadgeClass, type ElectionState } from "../state";
import type {
  AggregateJson,
  DecryptionShareJson,
  DkgSubmission,
  ElectionRecord,
  ResultJson,
} from "../types";

const CANDIDATE_COLORS = ["#0044a4", "#15803d", "#a16207", "#7c3aed", "#b91c1c", "#0891b2", "#c2410c", "#4f46e5"];
const fmtTime = (t: number) => new Date(t * 1000).toLocaleString();
const short = (h: string, n = 10) => (h.length > 2 * n + 2 ? `${h.slice(0, n + 2)}…${h.slice(-n)}` : h);
const isAddress = (h: string) => /^0x[0-9a-fA-F]{40}$/.test(h);

export function StateBadge({ state }: { state: ElectionState }) {
  return <span className={stateBadgeClass(state)}>{state}</span>;
}

/** A hex value with a copy button. 20-byte Ethereum addresses render in full; longer hex
 * (BLS keys, election key, …) is trimmed. The copy button always copies the full value. */
export function HexValue({ value, trim = 10 }: { value: string; trim?: number }) {
  const [copied, setCopied] = useState(false);
  const display = isAddress(value) ? value : short(value, trim);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch { /* clipboard blocked */ }
  };
  return (
    <span className="hexval">
      <code className="mono" title={value}>{display}</code>
      <button type="button" className="copy-btn" onClick={copy} aria-label="Copy" title="Copy">
        {copied ? (
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12" /></svg>
        ) : (
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></svg>
        )}
      </button>
    </span>
  );
}

interface Bundle {
  rec: ElectionRecord;
  dkg: DkgSubmission[];
  ballotCount: number;
  aggregate: AggregateJson | null;
  shares: DecryptionShareJson[];
  result: ResultJson | null;
}

/** Full read-only detail for one election, polled live. `onData` lets a host app
 * observe the loaded record (e.g. the voter app decides whether voting is open). */
export function ElectionDetail({
  electionId,
  refreshMs = 4000,
  onData,
  action,
}: {
  electionId: number;
  refreshMs?: number;
  onData?: (b: Bundle) => void;
  /** App-specific header action (e.g. the voter app's "Vote for this election" button);
   * rendered right-aligned in the header. Falls back to a config summary when absent. */
  action?: React.ReactNode;
}) {
  const [b, setB] = useState<Bundle | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const rec = await api.getElection(electionId);
      const [dkg, ballots, aggregate, shares, result] = await Promise.all([
        api.getDkg(electionId),
        api.countBallots(electionId),
        api.getAggregate(electionId),
        api.getShares(electionId),
        api.getResult(electionId),
      ]);
      const bundle: Bundle = {
        rec, dkg: dkg.submissions, ballotCount: ballots.count,
        aggregate: aggregate.aggregate, shares: shares.shares, result: result.result,
      };
      setErr(null);
      setB(bundle);
      onData?.(bundle);
    } catch (e: any) {
      setErr(e?.message ?? String(e));
    }
  }, [electionId, onData]);

  useEffect(() => {
    load();
    const h = setInterval(load, refreshMs);
    return () => clearInterval(h);
  }, [load, refreshMs]);

  if (err) return <div className="card"><div className="error">Error: {err}</div></div>;
  if (!b) return <div className="card"><div className="dim">Loading election #{electionId}…</div></div>;

  const { rec, dkg, ballotCount, aggregate, shares, result } = b;
  const cfg = rec.config;
  const now = Math.floor(Date.now() / 1000);
  const state = deriveState(cfg, {
    cancelled: rec.cancelled, keyFinalized: rec.finalizedKey != null, resultPublished: result != null,
  }, now);
  const maxTotal = result ? Math.max(1, ...result.totals) : 1;
  const totalVotes = result ? result.totals.reduce((a, b) => a + b, 0) : 0;

  return (
    <div className="stack">
      <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
        <h2 style={{ margin: 0, fontSize: 22, letterSpacing: "-0.02em" }}>Election #{electionId}</h2>
        <StateBadge state={state} />
        <div style={{ marginLeft: "auto" }}>
          {action ?? (
            <span className="dim">
              {cfg.numCandidates} candidates · budget {cfg.budget} · {cfg.threshold.t + 1}-of-{cfg.threshold.n}
            </span>
          )}
        </div>
      </div>

      <Card title="Configuration">
        <div className="kv">
          <KV k="Candidates" v={cfg.numCandidates} />
          <KV k="Budget" v={cfg.budget} />
          <KV k="Mode" v={`${cfg.mode} · variant ${cfg.variant}`} />
          <KV k="Weighting" v={cfg.weighted ? `weighted, max ${cfg.maxWeight}` : "one per voter"} />
          <KV k="Duplicates" v={cfg.duplicatePolicy} />
          <KV k="Voting opens" v={fmtTime(cfg.votingStart)} />
          <KV k="Voting closes" v={fmtTime(cfg.votingEnd)} />
        </div>
      </Card>

      <Card title="Committee & DKG" right={<span className="label">{cfg.threshold.t + 1}-of-{cfg.threshold.n} threshold</span>}>
        <div>
          {cfg.keypers.map((k, i) => (
            <div className="keyper" key={i}>
              <span className="keyper-idx">{i + 1}</span>
              <span className="keyper-addr"><HexValue value={k.signingKey} /></span>
            </div>
          ))}
        </div>
        <hr className="divider" style={{ margin: "14px 0" }} />
        {rec.finalizedKey ? (
          <div className="kv">
            <KV k="Status" v={<span className="badge badge--green">key finalized</span>} />
            <KV k="Election key" v={<HexValue value={rec.finalizedKey.pkElection} trim={14} />} />
            <KV k="Committee PKs" v={`${rec.finalizedKey.committeePKs.length}`} />
            <KV k="Quorum submissions" v={`${dkg.length}`} />
          </div>
        ) : (
          <div className="dim">DKG not finalized yet.</div>
        )}
      </Card>

      <Card title="Ballots">
        <div className="stat"><span className="stat-num">{ballotCount}</span><span className="stat-label">ballots submitted</span></div>
        {aggregate && (
          <>
            <hr className="divider" style={{ margin: "14px 0" }} />
            <div className="kv">
              <KV k="Admitted" v={`${aggregate.admitted.length}`} />
              <KV k="Total weight" v={`${aggregate.totalAdmittedWeight}`} />
              <KV k="Excluded" v={`${aggregate.exclusions.length}`} />
            </div>
          </>
        )}
      </Card>

      <Card title="Result" right={<span className="label">{shares.length} decryption share{shares.length === 1 ? "" : "s"}</span>}>
        {result ? (
          <div className="result">
            {result.totals.map((v, i) => {
              const color = CANDIDATE_COLORS[i % CANDIDATE_COLORS.length];
              const pct = totalVotes ? (v / totalVotes) * 100 : 0;
              const leading = maxTotal > 0 && v === maxTotal;
              return (
                <div className={`result-row${leading ? " result-row--win" : ""}`} key={i}>
                  <div className="result-row__head">
                    <span className="result-name">
                      <span className="result-dot" style={{ background: color }} />
                      Candidate {i}
                      {leading && <span className="result-win">Leading</span>}
                    </span>
                    <span className="result-num"><b>{v}</b><span className="dim"> · {pct.toFixed(0)}%</span></span>
                  </div>
                  <span className="bar-track">
                    <span className="bar-fill" style={{ width: `${(v / maxTotal) * 100}%`, background: color }} />
                  </span>
                </div>
              );
            })}
            <div className="result-meta">
              {totalVotes} total · recovered by keypers [{result.keyperIndices.join(", ")}]
            </div>
          </div>
        ) : aggregate ? (
          <div className="dim">Aggregate sealed; awaiting decryption shares & result…</div>
        ) : (
          <div className="dim">No result yet — needs the t+1 keyper quorum to aggregate, then decrypt.</div>
        )}
      </Card>
    </div>
  );
}

function Card({ title, right, children }: { title: string; right?: React.ReactNode; children: React.ReactNode }) {
  return (
    <section className="card">
      <div className="card-head">
        <h3 className="card-title">{title}</h3>
        {right}
      </div>
      {children}
    </section>
  );
}
function KV({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <>
      <span className="kv-key">{k}</span>
      <span className="kv-val">{v}</span>
    </>
  );
}
