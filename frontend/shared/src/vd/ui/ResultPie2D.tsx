import { useEffect, useMemo, useRef } from "react";
import * as echarts from "echarts";
import { computeElectionOutcome } from "./electionOutcome";

export const SLICE_COLORS = [
  "#0044a4",
  "#15803d",
  "#a16207",
  "#7c3aed",
  "#b91c1c",
  "#0891b2",
  "#c2410c",
  "#4f46e5",
];

type Props = { tally: readonly bigint[] };

export type TallyBreakdownRow = {
  candidateIndex: number;
  votes: number;
  percentLabel: string;
  color: string;
  inChart: boolean;
};

export function formatPercent(value: number, total: number): string {
  if (total <= 0) return "0";
  const pct = (100 * value) / total;
  if (pct >= 10 || Math.abs(pct - Math.round(pct)) < 0.05) return pct.toFixed(1);
  return pct.toFixed(2);
}

/** Whole-number % for the pie: halves round down (5.5→5), above half rounds up (5.6→6). */
export function roundPiePercent(pct: number): number {
  return Math.floor(pct + 0.5 - 1e-9);
}

export function buildTallyBreakdown(tally: readonly bigint[]): TallyBreakdownRow[] {
  const values = tally.map((c) => Number(c));
  const total = values.reduce((a, b) => a + b, 0);
  return values.map((votes, candidateIndex) => ({
    candidateIndex,
    votes,
    percentLabel: formatPercent(votes, total),
    color: SLICE_COLORS[candidateIndex % SLICE_COLORS.length],
    inChart: votes > 0 && total > 0,
  }));
}

export function ResultPie2D({ tally }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const breakdown = useMemo(() => buildTallyBreakdown(tally), [tally]);

  const totalVotes = tally.reduce((sum, c) => sum + c, 0n);
  const outcome = useMemo(() => computeElectionOutcome(tally), [tally]);
  const leaderSet = useMemo(() => new Set(outcome.leaders), [outcome.leaders]);

  useEffect(() => {
    const el = containerRef.current;
    if (!el || totalVotes === 0n) return;

    const chartSlices = buildTallyBreakdown(tally).filter((r) => r.inChart);
    if (chartSlices.length === 0) return;

    const chart = echarts.init(el);

    const totalVotesStr = totalVotes.toString();
    const sliceTotal = chartSlices.reduce((sum, row) => sum + row.votes, 0);

    chart.setOption({
      legend: { show: false },
      tooltip: { show: false },
      graphic: [
        {
          type: "group",
          left: "center",
          top: "center",
          children: [
            {
              type: "text",
              x: 0,
              y: -16,
              style: {
                text: "TOTAL",
                fontSize: 12,
                fontWeight: "600",
                fill: "#9ca3af",
                textAlign: "center",
                fontFamily: "ui-sans-serif, system-ui, sans-serif",
                letterSpacing: 0.6,
              },
            },
            {
              type: "text",
              x: 0,
              y: 6,
              style: {
                text: totalVotesStr,
                fontSize: 22,
                fontWeight: "700",
                fill: "#111827",
                textAlign: "center",
                fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
              },
            },
          ],
        },
      ],
      series: [
        {
          type: "pie",
          radius: ["42%", "68%"],
          center: ["50%", "50%"],
          silent: true,
          avoidLabelOverlap: true,
          minShowLabelAngle: 22,
          itemStyle: {
            borderColor: "#fff",
            borderWidth: 2,
          },
          label: {
            show: true,
            position: "inside",
            color: "#ffffff",
            fontSize: 10,
            fontWeight: 700,
            fontFamily: "ui-sans-serif, system-ui, sans-serif",
            formatter: (params: { data?: { chartPercent: number } }) => {
              const p = params.data?.chartPercent;
              if (p === undefined) return "";
              return `${p}%`;
            },
          },
          labelLine: { show: false },
          emphasis: {
            scale: false,
            focus: "none",
          },
          data: chartSlices.map((row) => {
            const pct = sliceTotal > 0 ? (100 * row.votes) / sliceTotal : 0;
            return {
              name: `Candidate ${row.candidateIndex}`,
              value: row.votes,
              candidateIndex: row.candidateIndex,
              chartPercent: roundPiePercent(pct),
              itemStyle: { color: row.color },
            };
          }),
        },
      ],
    });

    const ro = new ResizeObserver(() => chart.resize());
    ro.observe(el);
    return () => {
      ro.disconnect();
      chart.dispose();
    };
  }, [tally, totalVotes]);

  if (totalVotes === 0n) {
    return <div className="dim">No votes to chart.</div>;
  }

  return (
    <div className="resultPie2DWrap">
      <div
        ref={containerRef}
        className="resultPie2D"
        role="img"
        aria-label="Tally pie chart by candidate"
      />
      <div className="resultPieBreakdown" aria-label="Vote share by candidate">
        <div className="resultPieBreakdownHead">
          <span>Candidates</span>
          <span className="resultPieBreakdownNum">Votes</span>
          <span className="resultPieBreakdownNum">Share</span>
        </div>
        <div className="resultPieBreakdownBody">
          {breakdown.map((row) => {
            const isLeader = leaderSet.has(row.candidateIndex);
            return (
            <div
              key={row.candidateIndex}
              className={[
                "resultPieBreakdownRow",
                !row.inChart && "resultPieBreakdownRowMuted",
                isLeader && "resultPieBreakdownRow--leader",
              ]
                .filter(Boolean)
                .join(" ")}
            >
              <span className="resultPieBreakdownCandidate">
                <span
                  className="resultPieSwatch"
                  style={{ background: row.color }}
                  aria-hidden
                />
                <span className="resultPieBreakdownCandidateName">Candidate {row.candidateIndex}</span> 
                {leaderSet.has(row.candidateIndex) &&
                  (outcome.isTie ? (
                    <span className="tiedBadge">TIED</span>
                  ) : (
                    <span className="winnerBadge">WINNER</span>
                  ))}
              </span>
              <span className="resultPieBreakdownNum mono">{row.votes}</span>
              <span className="resultPieBreakdownNum mono">{row.percentLabel}%</span>
            </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
