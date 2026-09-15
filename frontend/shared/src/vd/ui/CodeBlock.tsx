import { useState, useCallback } from "react";
import { copyTextToClipboard } from "./clipboard";

function ClipboardIcon() {
  return (
    <svg className="vpCodeCopyIcon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg className="vpCodeCopyIcon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden>
      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
    </svg>
  );
}

export function CodeBlock({ children }: { children: string }) {
  const [copied, setCopied] = useState(false);
  const isMultiLine = children.includes("\n");

  const onCopy = useCallback(async () => {
    const ok = await copyTextToClipboard(children);
    if (ok) {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    }
  }, [children]);

  const btn = (
    <button
      type="button"
      className={`vpCodeCopyBtn${copied ? " vpCodeCopyBtn--copied" : ""}`}
      onClick={() => void onCopy()}
      title={copied ? "Copied" : "Copy"}
      aria-label={copied ? "Copied to clipboard" : "Copy code to clipboard"}
    >
      {copied ? <CheckIcon /> : <ClipboardIcon />}
    </button>
  );

  if (!isMultiLine) {
    return (
      <div className="vpCodeWrap vpCodeWrap--inline">
        <pre className="vpCodeBlock"><code>{children}</code></pre>
        {btn}
      </div>
    );
  }

  return (
    <div className="vpCodeWrap">
      <pre className="vpCodeBlock vpCodeBlock--multi"><code>{children}</code></pre>
      {btn}
    </div>
  );
}
