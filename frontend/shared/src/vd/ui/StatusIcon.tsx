/** Verification status icon (green tick / red cross / amber spinner / grey ring), shared by
 * the ballot detail and the per-keyper decryption-share result so they look identical. */
export function StatusIcon({ type }: { type: "ok" | "bad" | "checking" | "idle" }) {
  if (type === "ok") {
    return (
      <svg width="22" height="22" viewBox="0 0 22 22" fill="none" aria-hidden>
        <circle cx="11" cy="11" r="11" fill="#15803d" />
        <path d="M6 11.5l3.5 3.5 6.5-7" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    );
  }
  if (type === "bad") {
    return (
      <svg width="22" height="22" viewBox="0 0 22 22" fill="none" aria-hidden>
        <circle cx="11" cy="11" r="11" fill="#b91c1c" />
        <path d="M7 7l8 8M15 7l-8 8" stroke="#fff" strokeWidth="2" strokeLinecap="round" />
      </svg>
    );
  }
  if (type === "checking") {
    return (
      <svg width="22" height="22" viewBox="0 0 22 22" fill="none" aria-hidden className="bdSpinner">
        <circle cx="11" cy="11" r="9" stroke="#a16207" strokeWidth="2.5" strokeDasharray="40 20" strokeLinecap="round" />
      </svg>
    );
  }
  return (
    <svg width="22" height="22" viewBox="0 0 22 22" fill="none" aria-hidden>
      <circle cx="11" cy="11" r="9" stroke="#9ca3af" strokeWidth="2" />
    </svg>
  );
}
