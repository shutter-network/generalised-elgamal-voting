import { useCallback, useState } from "react";
import { Dashboard } from "@geg/shared";
import { ConnectButton, useWalletSigner } from "@geg/shared/wallet";
import { CancelElectionButton } from "./CancelElectionButton";
import { RegisterForm } from "./RegisterForm";

type Tab = "dashboard" | "register";

export function App() {
  const [tab, setTab] = useState<Tab>("dashboard");
  const [focusId, setFocusId] = useState<number | null>(null);
  const signer = useWalletSigner();
  const wallet = signer.account ? signer : null; // null until a wallet is connected

  // From the register success dialog: jump to the dashboard focused on the new election.
  const viewElection = useCallback((id: number) => {
    setFocusId(id);
    setTab("dashboard");
  }, []);
  const clearFocus = useCallback(() => setFocusId(null), []);

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="topbar-brand">
          <img src="/shutter.png" alt="Shutter" className="topbar-logo-img" />
          <div>
            <div className="topbar-title">Shutter OpenGov</div>
            <div className="topbar-sub">Admin Panel</div>
          </div>
        </div>
        <nav className="navtabs" style={{ marginLeft: 20 }}>
          <button className={`navtab${tab === "dashboard" ? " navtab--on" : ""}`} onClick={() => setTab("dashboard")}>Dashboard</button>
          <button className={`navtab${tab === "register" ? " navtab--on" : ""}`} onClick={() => setTab("register")}>Register / Cancel</button>
        </nav>
        <div className="topbar-spacer" />
        <div className="topbar-actions">
          <div className="topbar-connect">
            <ConnectButton showBalance={false} chainStatus="none" accountStatus="address" />
          </div>
        </div>
      </header>

      <main className="page">
        {tab === "dashboard" ? (
          <Dashboard
            focusId={focusId}
            onFocusConsumed={clearFocus}
            extra={(id) => (id == null ? null : <CancelElectionButton electionId={id} wallet={wallet} />)}
          />
        ) : (
          <RegisterForm wallet={wallet} onViewElection={viewElection} />
        )}
      </main>
    </div>
  );
}
