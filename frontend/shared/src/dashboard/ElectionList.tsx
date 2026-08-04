import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../api";
import { deriveState, type ElectionState } from "../state";
import { StateBadge } from "./ElectionDetail";

interface Row {
  id: number;
  state: ElectionState;
}

/** Full-width election picker: a dropdown of every election with a live lifecycle badge.
 * Auto-selects the latest election on first load so the detail shows immediately. */
export function ElectionPicker({
  selectedId,
  onSelect,
  adminFilter,
  refreshMs = 5000,
}: {
  selectedId: number | null;
  onSelect: (id: number) => void;
  adminFilter?: string;
  refreshMs?: number;
}) {
  const [rows, setRows] = useState<Row[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  const load = useCallback(async () => {
    try {
      const { electionIds } = await api.listElections({ admin: adminFilter, limit: 200 });
      const now = Math.floor(Date.now() / 1000);
      const out = await Promise.all(
        electionIds.map(async (id): Promise<Row> => {
          const [rec, result] = await Promise.all([api.getElection(id), api.getResult(id)]);
          return {
            id,
            state: deriveState(rec.config, {
              cancelled: rec.cancelled,
              keyFinalized: rec.finalizedKey != null,
              resultPublished: result.result != null,
            }, now),
          };
        }),
      );
      out.sort((a, b) => b.id - a.id);
      setErr(null);
      setRows(out);
    } catch (e: any) {
      setErr(e?.message ?? String(e));
    }
  }, [adminFilter]);

  useEffect(() => {
    load();
    const h = setInterval(load, refreshMs);
    return () => clearInterval(h);
  }, [load, refreshMs]);

  // Auto-select the latest election once the list is available.
  useEffect(() => {
    if (selectedId == null && rows.length > 0) onSelect(rows[0].id);
  }, [rows, selectedId, onSelect]);

  // Close the dropdown on outside click.
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [open]);

  const selected = rows.find((r) => r.id === selectedId) ?? null;

  return (
    <div className={`picker${open ? " picker--open" : ""}`} ref={ref}>
      <button type="button" className="picker-trigger" onClick={() => setOpen((o) => !o)} disabled={rows.length === 0 && !err}>
        <span className="picker-trigger__label">Election</span>
        {selected ? (
          <>
            <span className="picker-trigger__value">#{selected.id}</span>
            <StateBadge state={selected.state} />
          </>
        ) : (
          <span className="picker-trigger__value picker-trigger__value--dim">
            {err ? "unavailable" : rows.length === 0 ? "none registered yet" : "Select…"}
          </span>
        )}
        <span className="picker-trigger__chev" aria-hidden="true">▾</span>
      </button>

      {open && rows.length > 0 && (
        <div className="picker-menu" role="listbox">
          {rows.map((r) => (
            <button
              key={r.id}
              type="button"
              role="option"
              aria-selected={r.id === selectedId}
              className={`picker-item${r.id === selectedId ? " picker-item--on" : ""}`}
              onClick={() => { onSelect(r.id); setOpen(false); }}
            >
              <span className="picker-item__id">#{r.id}</span>
              <StateBadge state={r.state} />
            </button>
          ))}
        </div>
      )}
      {err && <div className="error" style={{ marginTop: 8 }}>{err}</div>}
    </div>
  );
}
