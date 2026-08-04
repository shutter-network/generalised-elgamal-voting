import { useTranslation } from "react-i18next";

export type StageLifecycle = "done" | "in_progress" | "pending";

function HourglassIcon({ small }: { small?: boolean }) {
  const size = small ? 10 : 11;
  return (
    <svg
      className="stageBadgeIcon"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <path d="M6 2h12v5l-6 5 6 5v5H6v-5l6-5-6-5V2z" />
    </svg>
  );
}

export function StageLifecycleBadge({
  lifecycle,
  small,
}: {
  lifecycle: StageLifecycle;
  small?: boolean;
}) {
  const { t } = useTranslation();
  const base = small ? "stageBadge stageBadge--sm" : "stageBadge";
  if (lifecycle === "done") {
    return <span className={`${base} stageBadge--done`}>{t("✓ DONE")}</span>;
  }
  if (lifecycle === "in_progress") {
    return (
      <span className={`${base} stageBadge--progress`}>
        <HourglassIcon small={small} />
        {t("IN PROGRESS")}
      </span>
    );
  }
  return <span className={`${base} stageBadge--pending`}>{t("PENDING")}</span>;
}
