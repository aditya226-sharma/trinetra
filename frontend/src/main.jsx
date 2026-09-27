import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, HashRouter } from "react-router-dom";
import App from "./App";
import "./index.css";

// Root builds (Docker, local dev, VITE_OFFLINE_DEMO off) use clean BrowserRouter
// paths against the same-origin API. Sub-path deploys (GitHub Pages at
// /trinetra/) switch to hash routing — Pages answers unknown document paths
// with HTTP 404 even when serving 404.html, so path deep-links log a
// "Failed to load resource: 404" every visit. Hash URLs never hit the server.
const base = import.meta.env.BASE_URL || "/";
const Router = base === "/" ? BrowserRouter : HashRouter;

// Opt into the v6 behaviours that change in v7 now, so the upgrade is a
// version bump rather than a migration. Without these the router logs a
// future-flag warning on every route in dev.
const future = { v7_startTransition: true, v7_relativeSplatPath: true };

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <Router future={future}>
      <App />
    </Router>
  </React.StrictMode>,
);