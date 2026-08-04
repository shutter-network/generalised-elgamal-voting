import { useTranslation } from "react-i18next";
import { formatUnixUtc } from "./formatUnixUtc";
import { StageLifecycleBadge, type StageLifecycle } from "./StageLifecycleBadge";

export type WaitingOnStage = {
  num: number;
  title: string;
  subLabel: string;
  lifecycle: StageLifecycle;
};

const LOCKED_HINT: Record<number, string> = {
  1: "The guardian committee must finish distributed key generation before voting can begin.",
  2: "Once voting opens, accepted ballots will appear here with automatic validity checks. Until then, this registry stays empty.",
  3: "Once voting closes, the homomorphic sum of every accepted ballot will appear here as one (c1, c2) ciphertext pair per candidate · still encrypted, ready for threshold decryption.",
  4: "Once the aggregate is published, a table of decryption shares and DLEQ proofs will appear here · one row per keyper, one share per candidate.",
  5: "Once a threshold of keyper shares is combined, the decrypted vote count per candidate will appear here · together with the winner and the final per-candidate pie chart.",
};

const LOCKED_HINT_EASY: Record<number, string> = {
  1: "The guardians need to finish setting up the election lock first.",
  2: "Once voting starts, the sealed votes will appear here.",
  3: "Once voting ends, the vote totals will appear here, still sealed.",
  4: "Once the totals are published, the guardians will begin unlocking the final count.",
  5: "Once enough guardians contribute their piece, the final vote counts will appear here.",
};

type Props = {
  stageNum: number;
  waitingOn: WaitingOnStage[];
  votingStart: bigint;
  votingEnd: bigint;
  isEasy?: boolean;
};

export function StageLockedPanel({ stageNum, waitingOn, votingStart, votingEnd, isEasy }: Props) {
  const { t } = useTranslation();
  const hintMap = isEasy ? LOCKED_HINT_EASY : LOCKED_HINT;
  const hint = t(hintMap[stageNum] ?? "This stage will unlock once earlier steps complete.");

  return (
    <div className="stageLockedCard">
      <div className="stageLockedTop">
        <div className="stageLockedIconBox" aria-hidden>
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
            <rect x="5" y="11" width="14" height="10" rx="2" stroke="currentColor" strokeWidth="1.8" />
            <path d="M8 11V8a4 4 0 0 1 8 0v3" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
          </svg>
        </div>
        <div className="stageLockedHdrCol">
          <div className="stageLockedHdrPending">{t("PENDING")}</div>
          <h3 className="stageLockedHdrTitle">{t("This stage hasn't started yet.")}</h3>
        </div>
      </div>
      <p className="stageLockedHint">{hint}</p>
      {waitingOn.length > 0 && (
        <div className="stageWaitingOn">
          <div className="stageWaitingOnLabel">{t("WAITING ON")}</div>
          <div className="stageWaitingOnList">
            {waitingOn.map((s, i) => (
              <div
                key={s.num}
                className={`stageWaitingOnRow${i < waitingOn.length - 1 ? " stageWaitingOnRow--bordered" : ""}`}
              >
                <span className="stageWaitingOnNum">{String(s.num).padStart(2, "0")}</span>
                <div className="stageWaitingOnRowBody">
                  <div className="stageWaitingOnRowTitle">{t(s.title)}</div>
                  <div className="stageWaitingOnRowSub">{t(s.subLabel)}</div>
                </div>
                <StageLifecycleBadge lifecycle={s.lifecycle} small />
              </div>
            ))}
          </div>
        </div>
      )}
      <div className="stageLockedDates">
        <div className="stageLockedDateRow">
          <span className="stageLockedDateLabel">{t("Voting opens")}</span>
          <span className="stageLockedDateValue">{formatUnixUtc(votingStart)} UTC</span>
        </div>
        <div className="stageLockedDateRow">
          <span className="stageLockedDateLabel">{t("Voting closes")}</span>
          <span className="stageLockedDateValue">{formatUnixUtc(votingEnd)} UTC</span>
        </div>
      </div>
    </div>
  );
}
