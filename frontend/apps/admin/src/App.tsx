import { useCallback, useEffect, useState } from "react";
import { Dashboard } from "@geg/shared";
import { ConnectButton, useWalletSigner } from "@geg/shared/wallet";
import { CancelElectionButton } from "./CancelElectionButton";
import { RetryTallyButton } from "./RetryTallyButton";
import { RegisterForm } from "./RegisterForm";

type Tab = "dashboard" | "register";

export function App() {
  // Persist the active tab in the URL hash so a refresh stays on it (default: dashboard).
  const [tab, setTab] = useState<Tab>(() => (window.location.hash === "#register" ? "register" : "dashboard"));
  const [focusId, setFocusId] = useState<number | null>(null);

  useEffect(() => {
    const h = tab === "register" ? "#register" : "#dashboard";
    if (window.location.hash !== h) window.history.replaceState(null, "", h);
  }, [tab]);
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
            <ConnectButton />
          </div>
        </div>
      </header>

      <main className="page">
        {tab === "dashboard" ? (
          <Dashboard
            audience="admin"
            focusId={focusId}
            onFocusConsumed={clearFocus}
            extra={(id) => (id == null ? null : (
              <div style={{ display: "inline-flex", flexDirection: "column", alignItems: "flex-end", gap: 10 }}>
                <CancelElectionButton electionId={id} wallet={wallet} />
                <RetryTallyButton electionId={id} wallet={wallet} />
              </div>
            ))}
          />
        ) : (
          <RegisterForm wallet={wallet} onViewElection={viewElection} />
        )}
      </main>
    </div>
  );
}
