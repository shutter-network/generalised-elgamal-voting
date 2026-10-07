import { Dashboard } from "@shutter-governance-protocol/shared";
import { ConnectButton } from "@shutter-governance-protocol/shared/wallet";
import { VoteButton } from "./VoteForm";

export function App() {
  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="topbar-brand">
          <img src="/shutter.png" alt="Shutter" className="topbar-logo-img" />
          <div>
            <div className="topbar-title">Shutter Governance Protocol</div>
            <div className="topbar-sub">Voter Panel</div>
          </div>
        </div>
        <div className="topbar-spacer" />
        <div className="topbar-actions">
          <div className="topbar-connect">
            <ConnectButton />
          </div>
        </div>
      </header>

      <main className="page">
        <Dashboard audience="voter" detailAction={(id) => <VoteButton electionId={id} />} />
      </main>
    </div>
  );
}
