import { useState, useRef } from "react";
import { createPortal } from "react-dom";
import { useTranslation } from "react-i18next";

type GlossaryEntry = { title: string; body: string };

const GLOSSARY: Record<string, GlossaryEntry> = {
  DKG: {
    title: "DKG",
    body: "A way for a committee to jointly produce a shared encryption key. The matching decryption key is split into pieces; no single member ever holds the whole thing.",
  },
  "BLS12-381": {
    title: "BLS12-381",
    body: "An elliptic curve optimised for pairing-based cryptography. Used here for threshold key generation, ballot proofs, and keyper share verification.",
  },
  "budget": {
    title: "Budget",
    body: "The number of points each voter has to distribute. With a budget of 3, you might give 3 to one candidate, or 1+1+1 across three, or 2+1, etc. Each per-candidate value must stay within range · the ZK range proof guarantees this.",
  },
  "zero-knowledge proof": {
    title: "Zero-knowledge Proof",
    body: "Math that lets one party prove a statement is true without revealing the underlying secret. Here, it proves things like 'this vote is in range' or 'this decryption share is correct' · without revealing the vote or the secret share.",
  },
  "homomorphic tallying": {
    title: "Homomorphic tallying",
    body: "Homomorphic aggregation · adding encrypted values together so the result is the encryption of the sum. The contract never sees individual votes, only the encrypted total.",
  },
  DLEQ: {
    title: "DLEQ proof",
    body: "Discrete-log equality proof · a tiny piece of math each keyper publishes alongside their decryption share. It proves the share matches their committee public key, so a bad share can't slip through.",
  },
  keypers: {
    title: "Keypers",
    body: "The independent committee members who jointly hold the election's decryption key. A threshold of them must cooperate to decrypt; no single keyper can act alone.",
  },
  "t-of-n threshold": {
    title: "t-of-n Threshold",
    body: "Any t members of a committee of n can act together to produce an output (e.g., decrypt), but fewer than t cannot. This prevents a single point of failure or compromise.",
  },
  ElGamal: {
    title: "ElGamal Encryption",
    body: "Threshold ElGamal in G₂ · ciphertexts (c1, c2) can be added homomorphically. The encryption of a sum equals the sum of encryptions. That's what lets us add ballots together while they stay encrypted.",
  },
  "Schnorr signature": {
    title: "Schnorr Signature",
    body: "A compact digital signature on G₁ used here by voters (and the whitelist registrar) to authenticate ballot bytes · proving they created it without revealing any private key material.",
  },
  "Lagrange interpolation": {
    title: "Lagrange interpolation",
    body: "Lagrange combination · the standard way to reconstruct a value from t-of-n shares. We use it on the decryption side so no one ever assembles the full private key in memory.",
  },
  "ciphertext": {
    title: "Ciphertext",
    body: "An encrypted value. With ElGamal on this curve, every ciphertext is a pair of points labelled (c1, c2).",
  },
  "Decrypted Result": {
    title: "Decrypted Result",
    body: "The encrypted total per candidate is decrypted into a plain integer count. The winner is determined and the result is published on-chain.",
  },
  "baby-step / giant-step": {
    title: "Baby-step / Giant-step",
    body: "An algorithm that efficiently recovers a small plaintext integer from a discrete-log in G₂ · used to decode the vote count after threshold decryption.",
  },
  "keyper": {
    title: "Keyper",
    body: "A member of the decryption committee. Each one holds one share of the decryption key and publishes one piece of the final decryption.",
  },
  "Distributed Key Generation (DKG)": {
    title: "Distributed Key Generation (DKG)",
    body: "A way for a committee to jointly produce a shared encryption key. The matching decryption key is split into pieces; no single member ever holds the whole thing.",
  },
  "Distributed Key Generation": {
    title: "Distributed Key Generation (DKG)",
    body: "A way for a committee to jointly produce a shared encryption key. The matching decryption key is split into pieces; no single member ever holds the whole thing.",
  },
  "Threshold": {
    title: "Threshold",
    body: "How many of the N committee members must combine their pieces before anything can be decrypted. With 3 of 5, any three of the five working together is enough · but two or fewer learn nothing.",
  },
  "Election Public Key": {
    title: "Election Public Key",
    body: "The public key that voters use to encrypt their ballots. Anyone can encrypt with it; only the keyper committee · acting together · can ever decrypt anything with it.",
  },
  "Election public key": {
    title: "Election Public Key",
    body: "The public key that voters use to encrypt their ballots. Anyone can encrypt with it; only the keyper committee · acting together · can ever decrypt anything with it.",
  },
  "Whitelist Registrar": {
    title: "Whitelist Registrar",
    body: "An off-chain service that signs an attestation saying \"this voter appears on the official eligibility list\". The dashboard checks that signature on every ballot.",
  },
  "Whitelist registrar key": {
    title: "Whitelist Registrar",
    body: "An off-chain service that signs an attestation saying \"this voter appears on the official eligibility list\". The dashboard checks that signature on every ballot.",
  },
  "Keyper committee": {
    title: "Keyper Committee",
    body: "The independent group of guardians who jointly hold the election's decryption key. Each member holds one share; only when enough members combine their shares can anything be decrypted.",
  },
  "Keyper Decryption Shares (DLEQ-proven)": {
    title: "Keyper Decryption Shares (DLEQ-proven)",
    body: "Each keyper publishes one piece of the decryption together with a tiny proof that the piece is correct. Only when enough pieces are combined does the result emerge.",
  },
  "Homomorphic Aggregation": {
    title: "Homomorphic Aggregation",
    body: "Homomorphic aggregation · adding encrypted values together so the result is the encryption of the sum. The contract never sees individual votes, only the encrypted total.",
  },
  "Encrypted Ballot Submission": {
    title: "Encrypted Ballot Submission",
    body: "Each voter encrypts their ballot in their own browser and sends only the ciphertext on-chain, together with proofs of eligibility and validity.",
  },
};

const TOOLTIP_WIDTH = 250;
const GAP = 8;
const EDGE_MARGIN = 10;
const FLIP_THRESHOLD = 160;

type TooltipPos = { top: number; left: number; below: boolean };

export function Term({ id, children }: { id: string; children?: React.ReactNode }) {
  const { t } = useTranslation();
  const [pos, setPos] = useState<TooltipPos | null>(null);
  const wrapRef = useRef<HTMLSpanElement>(null);
  const entry = GLOSSARY[id];
  if (!entry) return <>{children ?? id}</>;

  function handleMouseEnter() {
    const el = wrapRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();

    // Horizontal: center tooltip over the trigger word, clamp within viewport
    let left = rect.left + rect.width / 2 - TOOLTIP_WIDTH / 2;
    if (left + TOOLTIP_WIDTH > window.innerWidth - EDGE_MARGIN) {
      left = window.innerWidth - TOOLTIP_WIDTH - EDGE_MARGIN;
    }
    if (left < EDGE_MARGIN) left = EDGE_MARGIN;

    // Vertical: show above by default (CSS translateY(-100%) handles exact height).
    // Flip below if near the top of the viewport.
    const below = rect.top < FLIP_THRESHOLD;
    const top = below ? rect.bottom + GAP : rect.top - GAP;

    setPos({ top, left, below });
  }

  return (
    <span
      ref={wrapRef}
      className="termWrap"
      onMouseEnter={handleMouseEnter}
      onMouseLeave={() => setPos(null)}
    >
      <span className="termTrigger">{children ?? id}</span>
      {pos && createPortal(
        <span
          className="termTooltip"
          role="tooltip"
          data-below={pos.below ? "true" : undefined}
          style={{
            top: pos.top,
            left: pos.left,
            transform: pos.below ? "none" : "translateY(-100%)",
          }}
        >
          <span className="termTooltipTitle">{t(entry.title)}</span>
          <span className="termTooltipBody">{t(entry.body)}</span>
        </span>,
        document.body
      )}
    </span>
  );
}
