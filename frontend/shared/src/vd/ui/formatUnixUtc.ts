/** Format on-chain Unix seconds as a fixed UTC wall-clock string (no local TZ, no raw epoch). */
export function formatUnixUtc(seconds: bigint | number): string {
  const n = typeof seconds === "bigint" ? Number(seconds) : seconds;
  if (!Number.isFinite(n)) return "—";
  const d = new Date(n * 1000);
  if (Number.isNaN(d.getTime())) return "—";
  const pad = (x: number) => String(x).padStart(2, "0");
  return (
    `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ` +
    `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`
  );
}
