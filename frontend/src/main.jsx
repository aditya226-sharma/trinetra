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

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <Router>
      <App />
    </Router>
  </React.StrictMode>,
);