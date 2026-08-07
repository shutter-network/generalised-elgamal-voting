import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import { VotingDashboard } from "../vd/VotingDashboard";

/** Shared multi-election dashboard: the ported voting-dashboard (technical mode) with its
 * own in-header election dropdown. The election list is fetched here; `detailAction`
 * (voter Vote) / `extra` (admin Cancel) are injected into the dashboard header, under the
 * dropdown. */
export function Dashboard({
  adminFilter,
  extra,
  detailAction,
  focusId,
  onFocusConsumed,
}: {
  adminFilter?: string;
  extra?: (selectedId: number | null) => React.ReactNode;
  detailAction?: (selectedId: number) => React.ReactNode;
  /** When set (e.g. a just-registered election), select it once and report back so the
   * caller can clear it — later manual selections then win. */
  focusId?: number | null;
  onFocusConsumed?: () => void;
}) {
  const [elections, setElections] = useState<number[]>([]);
  const [selected, setSelected] = useState<number | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (focusId != null) {
      setSelected(focusId);
      onFocusConsumed?.();
    }
  }, [focusId, onFocusConsumed]);

  const load = useCallback(async () => {
    try {
      const { electionIds } = await api.listElections({ admin: adminFilter, limit: 200 });
      const sorted = [...electionIds].sort((a, b) => b - a); // latest first
      setErr(null);
      setElections(sorted);
      setSelected((cur) => (cur != null && sorted.includes(cur) ? cur : sorted[0] ?? null));
    } catch (e: any) {
      setErr(e?.message ?? String(e));
    }
  }, [adminFilter]);

  useEffect(() => {
    load();
    const h = setInterval(load, 8000); // pick up newly-registered elections
    return () => clearInterval(h);
  }, [load]);

  if (selected == null) {
    return (
      <div className="stack" style={{ maxWidth: 960, margin: "0 auto", width: "100%" }}>
        <div className="card"><div className="empty">{err
          ? <>Couldn't load elections<span style={{ opacity: 0.7 }}>({err})</span></>
          : "No elections registered yet."}</div></div>
      </div>
    );
  }

  const headerAction = detailAction?.(selected) ?? extra?.(selected) ?? null;

  return (
    <VotingDashboard
      electionId={selected}
      elections={elections}
      onSelectElection={setSelected}
      headerAction={headerAction}
    />
  );
}
