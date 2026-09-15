import { useRef, useState } from "react";
import { createPortal } from "react-dom";

/** A form-label hover hint: the label gets a subtle info affordance and, on hover, a
 * dark "dialog box" tooltip (title + explanation) — like the voting-dashboard's technical
 * Term popovers, but self-contained for the (non-`.vd`) admin form. The tooltip renders
 * in a body portal and positions above the label, flipping below near the viewport top. */
const WIDTH = 288;
const GAP = 8;
const EDGE = 10;
const FLIP = 180;

type Pos = { top: number; left: number; below: boolean };

export function FieldHint({ title, body, children }: { title: string; body: string; children: React.ReactNode }) {
  const [pos, setPos] = useState<Pos | null>(null);
  const ref = useRef<HTMLSpanElement>(null);

  function enter() {
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    let left = r.left + r.width / 2 - WIDTH / 2;
    left = Math.max(EDGE, Math.min(left, window.innerWidth - WIDTH - EDGE));
    const below = r.top < FLIP;
    setPos({ top: below ? r.bottom + GAP : r.top - GAP, left, below });
  }

  return (
    <span ref={ref} className="fieldHint" onMouseEnter={enter} onMouseLeave={() => setPos(null)}>
      <span className="fieldHint__label">{children}</span>
      <svg className="fieldHint__icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" aria-hidden>
        <circle cx="12" cy="12" r="10" /><line x1="12" y1="11" x2="12" y2="16" /><line x1="12" y1="7.5" x2="12.01" y2="7.5" />
      </svg>
      {pos && createPortal(
        <span className="fieldHintPop" role="tooltip" data-below={pos.below ? "true" : undefined}
          style={{ top: pos.top, left: pos.left, width: WIDTH, transform: pos.below ? "none" : "translateY(-100%)" }}>
          <span className="fieldHintPop__title">{title}</span>
          <span className="fieldHintPop__body">{body}</span>
        </span>,
        document.body,
      )}
    </span>
  );
}
