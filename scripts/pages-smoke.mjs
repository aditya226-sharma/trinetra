// Smoke-test the GitHub Pages build: serve frontend/dist under /trinetra/
// (no API present) and verify the shell bootstraps into the STATIC PREVIEW
// state with no fatal JS errors.
// Usage: node scripts/pages-smoke.mjs <dist-dir>
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer } from "node:http";
import { readFileSync, existsSync, statSync } from "node:fs";

const dist = process.argv[2] || "frontend/dist";
const BASE = "/trinetra/";
const PORT = 8899;

// Minimal static server that maps /trinetra/* -> dist/*
const MIME = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon" };
const server = createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  let p = url.pathname;
  if (!p.startsWith(BASE)) { res.writeHead(404); res.end("nope"); return; }
  let rel = p.slice(BASE.length) || "index.html";
  let file = join(dist, rel);
  if (!existsSync(file) || statSync(file).isDirectory()) file = join(dist, "index.html");
  if (!existsSync(file)) { res.writeHead(404); res.end(); return; }
  const ext = file.slice(file.lastIndexOf("."));
  res.writeHead(200, { "content-type": MIME[ext] || "application/octet-stream" });
  res.end(readFileSync(file));
});

server.listen(PORT, async () => {
  const require = createRequire(import.meta.url);
  const FRONTEND = join(dirname(fileURLToPath(import.meta.url)), "..", "frontend");
  const puppeteer = require(join(FRONTEND, "node_modules", "puppeteer-core"));
  const CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: true, pipe: true,
    args: ["--headless=new", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
      "--user-data-dir=" + join(process.env.TMPDIR || "/tmp", "trinetra-pages-", String(Date.now()))],
    defaultViewport: { width: 1440, height: 900 },
  });
  const page = await browser.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push("pageerror: " + e.message));
  page.on("requestfailed", (r) => { if (!r.url().includes("/api/")) errors.push("requestfailed: " + r.url()); });

  await page.goto(`http://127.0.0.1:${PORT}${BASE}`, { waitUntil: "networkidle2", timeout: 30000 });

  // give the health probe time to fail -> apiOffline
  await new Promise((r) => setTimeout(r, 2500));

  const title = await page.title();
  const banner = await page.evaluate(() => document.body.innerText.includes("STATIC PREVIEW"));
  const rail = await page.evaluate(() => document.querySelector(".rail-link") !== null);

  // deep link check under the base path
  await page.goto(`http://127.0.0.1:${PORT}${BASE}alerts`, { waitUntil: "networkidle2", timeout: 30000 });
  const deepOk = await page.evaluate(() => document.title !== "" );

  console.log("title:", title);
  console.log("static-preview banner:", banner);
  console.log("nav rail rendered:", rail);
  console.log("deep-link /trinetra/alerts loads:", deepOk);
  console.log("js errors:", errors.length ? errors : "none");

  await browser.close();
  server.close();
  process.exit(errors.length ? 1 : 0);
});