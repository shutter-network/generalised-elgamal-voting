import { Buffer } from "buffer";
// The crypto SDK expects a Node-style Buffer global in the browser.
(globalThis as any).Buffer = (globalThis as any).Buffer ?? Buffer;

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
