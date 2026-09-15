import { useCallback, useState } from "react";
import { copyTextToClipboard } from "./clipboard";

function ClipboardIcon() {
  return (
    <svg className="hexCopyIcon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden>
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"
      />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg className="hexCopyIcon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden>
      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
    </svg>
  );
}

/** Same control as hex copy; copies arbitrary text (e.g. DLEQ scalars e and z). */
export function CopyTextButton({
  text,
  ariaLabel = "Copy to clipboard",
}: {
  text: string;
  ariaLabel?: string;
}) {
  const [copied, setCopied] = useState(false);

  const onCopy = useCallback(async () => {
    if (!text) return;
    const ok = await copyTextToClipboard(text);
    if (ok) {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    }
  }, [text]);

  return (
    <button
      type="button"
      className={`hexCopyBtn${copied ? " hexCopied" : ""}`}
      onClick={() => void onCopy()}
      title={copied ? "Copied" : ariaLabel}
      aria-label={copied ? "Copied to clipboard" : ariaLabel}
    >
      {copied ? <CheckIcon /> : <ClipboardIcon />}
    </button>
  );
}

/** Middle-ellipsis preview for hex (`0x` prefix preserved when present). */
export function trimHexMiddle(value: string, trim = 10): string {
  if (value.length <= 2 + trim * 2) return value;
  return `${value.slice(0, 2 + trim)}...${value.slice(-trim)}`;
}

/** Middle-ellipsis preview for arbitrary strings (e.g. DLEQ scalars). */
export function trimMiddle(value: string, trim = 6): string {
  if (value.length <= trim * 2 + 3) return value;
  return `${value.slice(0, trim)}...${value.slice(-trim)}`;
}

/**
 * Renders hex with optional middle ellipsis. Always offers **Copy** for the
 * full `value` (not the trimmed preview) so long proofs / ciphertexts are
 * one-click copyable · `title` alone is not selectable in most browsers.
 */
export function Hex({
  value,
  trim = 10,
  copyable = true,
  full = false,
  nowrap = false,
}: {
  value: string;
  trim?: number;
  /** When false, only the preview is shown (no copy control). */
  copyable?: boolean;
  /** When true, show the whole string (no middle ellipsis). Use for short addresses. */
  full?: boolean;
  /** When true, keep the copy button on the same row as a long preview (flex-wrap: nowrap). */
  nowrap?: boolean;
}) {
  const [copied, setCopied] = useState(false);

  const onCopy = useCallback(async () => {
    if (!value) return;
    const ok = await copyTextToClipboard(value);
    if (ok) {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    }
  }, [value]);

  if (!value) return <span className="mono dim">(empty)</span>;

  const display = full ? value : trimHexMiddle(value, trim);

  return (
    <span className={`hexWrap${full ? " hexWrapFull" : ""}${nowrap ? " hexWrapNowrap" : ""}`}>
      <span className="mono hexPreview" title={display === value ? undefined : value}>
        {display}
      </span>
      {copyable ? (
        <button
          type="button"
          className={`hexCopyBtn${copied ? " hexCopied" : ""}`}
          onClick={() => void onCopy()}
          title={copied ? "Copied" : "Copy full hex"}
          aria-label={copied ? "Copied to clipboard" : "Copy full hex to clipboard"}
        >
          {copied ? <CheckIcon /> : <ClipboardIcon />}
        </button>
      ) : null}
    </span>
  );
}
