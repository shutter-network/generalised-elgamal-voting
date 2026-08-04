import React from "react";
import ReactDOM from "react-dom/client";
import { Web3Providers } from "@geg/shared/wallet";
import { App } from "./App";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <Web3Providers>
      <App />
    </Web3Providers>
  </React.StrictMode>,
);
