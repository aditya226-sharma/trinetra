import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import "./index.css";

// Vite's BASE_URL reflects the build `base` (e.g. "/trinetra/" on GitHub
// Pages, "/" for local/Docker), so deep links resolve on sub-path deploys.
const basename = import.meta.env.BASE_URL.replace(/\/+$/, "") || "/";

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <BrowserRouter basename={basename}>
      <App />
    </BrowserRouter>
  </React.StrictMode>,
);