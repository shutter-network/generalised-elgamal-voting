import { useTranslation } from "react-i18next";
import { Hex } from "./Hex";
import type { Ballot } from "../eth/types";

type VerifyState =
  | { status: "idle" }
  | { status: "verifying"; token: number }
  | { status: "ok"; token: number }
  | { status: "bad"; reason: string; token: number };

function hexBytesLen(hex: string): number {
  if (!hex || hex === "0x") return 0;
  if (!hex.startsWith("0x")) return 0;
  return Math.max(0, (hex.length - 2) / 2);
}

function StatusIcon({ type }: { type: "ok" | "bad" | "checking" | "idle" }) {
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

type Props = {
  ballot: Ballot;
  globalIndex: number;
  verifyState: VerifyState;
  onBack: () => void;
  onVerifyLocally: () => void;
  txHash?: string | null;
  explorerUrl?: string;
};

export function BallotDetail({ ballot, globalIndex, verifyState, onBack, onVerifyLocally, txHash, explorerUrl }: Props) {
  const { t } = useTranslation();
  const vs = verifyState.status;
  const iconType = vs === "ok" ? "ok" : vs === "bad" ? "bad" : vs === "verifying" ? "checking" : "idle";
  const explorerTxUrl = explorerUrl && txHash ? `${explorerUrl}/tx/${txHash}` : null;

  return (
    <div className="bdContainer">
      <button type="button" className="bdBack" onClick={onBack}>
        {t("← Back to ballots")}
      </button>

      <div className="bdBallotLabel">{t("BALLOT")}</div>
      <h2 className="bdBallotIndex">{t("Index {{n}}", { n: globalIndex })}</h2>

      <div className="bdPseudonymRow">
        <span className="dim">pseudonym</span>
        <Hex value={ballot.pseudonym} trim={20} />
      </div>

      <div className="bdTxRow">
        <span className="dim">transaction</span>
        {explorerTxUrl ? (
          <a
            href={explorerTxUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="bdTxLink mono"
          >
            <Hex value={txHash!} trim={20} />
          </a>
        ) : txHash === undefined ? (
          <span className="dim">{t("Loading…")}</span>
        ) : (
          <span className="dim">—</span>
        )}
      </div>

      {/* Status card */}
      <div className={`bdStatusCard bdStatusCard--${iconType}`}>
        <div className="bdStatusIcon">
          <StatusIcon type={iconType} />
        </div>
        <div className="bdStatusBody">
          {vs === "ok" && (
            <>
              <div className="bdStatusTitle">{t("VALID")}</div>
              <div className="bdStatusDesc">
                {t("All cryptographic checks passed · WR attestation, ZK proofs, voter signature, field decoding.")}
              </div>
            </>
          )}
          {vs === "bad" && (
            <>
              <div className="bdStatusTitle">{t("INVALID")}</div>
              <div className="bdStatusDesc">
                {(verifyState as Extract<VerifyState, { status: "bad" }>).reason}
              </div>
            </>
          )}
          {vs === "verifying" && (
            <>
              <div className="bdStatusTitle">{t("Verifying…")}</div>
              <div className="bdStatusDesc">{t("Running cryptographic checks in the background.")}</div>
            </>
          )}
          {vs === "idle" && (
            <>
              <div className="bdStatusTitle">{t("Pending")}</div>
              <div className="bdStatusDesc">{t("Verification will run automatically.")}</div>
            </>
          )}
        </div>
      </div>

      {/* Details section */}
      <div className="bdSection">
        <div className="bdSectionLabel">{t("DETAILS")}</div>
        <div className="bdGrid mono">
          <div className="dim">vk</div>
          <div>
            <Hex value={ballot.vk} trim={26} />{" "}
            <span className="dim">{t("({{n}} bytes)", { n: hexBytesLen(ballot.vk) })}</span>
          </div>

          <div className="dim">ciphertexts</div>
          <div>
            {ballot.ciphertexts.map((ct, j) => (
              <div key={j} className="bdCiphertext">
                <div className="dim bdCandidateLabel">{t("candidate {{n}}", { n: j })}</div>
                <div className="bdCipherRow">
                  <span className="dim">c1</span>
                  <Hex value={ct.c1} trim={20} />
                </div>
                <div className="bdCipherRow">
                  <span className="dim">c2</span>
                  <Hex value={ct.c2} trim={20} />
                </div>
              </div>
            ))}
          </div>

          <div className="dim">zkProof</div>
          <div>
            <Hex value={ballot.zkProof} trim={26} />
          </div>

          <div className="dim">voterSignature</div>
          <div>
            <Hex value={ballot.voterSignature} trim={26} />
          </div>

          <div className="dim">wrAttestation</div>
          <div>
            <Hex value={ballot.wrAttestation} trim={26} />
          </div>
        </div>
      </div>

      {/* Verify yourself section */}
      <div className="verifyYourselfSection">
        <div className="verifyYourselfLabel">{t("VERIFY YOURSELF")}</div>
          <p className="verifyYourselfDesc">
            {t("Don't trust this panel · re-run the same cryptographic check yourself, against this stage's on-chain data, on your own machine.")}
          </p>
          <button type="button" className="verifyYourselfBtn" onClick={onVerifyLocally}>
            {t("Open manual verification guide →")}
          </button>
      </div>
    </div>
  );
}
