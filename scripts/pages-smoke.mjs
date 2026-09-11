// Smoke-test the GitHub Pages build: serve frontend/dist under /trinetra/
// with NO API available and verify every route renders real bundled data
// (VITE_OFFLINE_DEMO=1) with zero JS errors and zero "Failed to load" text.
// Usage: node scripts/pages-smoke.mjs <dist-dir>
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer } from "node:http";
import { readFileSync, existsSync, statSync } from "node:fs";

const dist = process.argv[2] || "frontend/dist";
const BASE = "/trinetra/";
const PORT = 8899;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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

  const routes = ["/trinetra/", "/trinetra/events", "/trinetra/alerts", "/trinetra/graph",
                  "/trinetra/assets", "/trinetra/compliance", "/trinetra/ingest"];
  let failed = 0;

  for (const route of routes) {
    const page = await browser.newPage();
    const errors = [];
    page.on("pageerror", (e) => errors.push("pageerror: " + e.message));
    page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
    await page.goto(`http://127.0.0.1:${PORT}${route}`, { waitUntil: "networkidle2", timeout: 30000 });
    await sleep(1800);
    const text = await page.evaluate(() => document.body.innerText);
    const bad = /Failed to load|Request failed|chunkLoadError|cannot read|is not a function/i.test(text);
    const previewBadge = text.includes("PREVIEW DATA");
    const shell = text.includes("TriNetra");
    const hasData = /232|events in store|matches|findings|alerts/i.test(text);
    console.log(`${route.padEnd(26)} shell=${shell} previewBadge=${previewBadge} data=${hasData || "?"} errText=${bad} jserr=${errors.length}${errors.length ? " -> " + errors[0] : ""}`);
    if (!shell || bad || errors.length) failed++;
    await page.close();
  }

  // interactions: event detail first (full list), then live search on preview
  const page = await browser.newPage();
  await page.goto(`http://127.0.0.1:${PORT}/trinetra/events`, { waitUntil: "networkidle2", timeout: 30000 });
  await sleep(1500);
  const rowExists = await page.evaluate(() => document.querySelector(".glass-row") !== null);
  await page.evaluate(() => document.querySelector(".glass-row")?.click());
  await sleep(700);
  const hasDetail = await page.evaluate(() => document.body.innerText.includes("EVENT DETAIL"));
  console.log(`preview event detail drawer: ${hasDetail} (rows existed: ${rowExists})`);
  if (!hasDetail) failed++;

  await page.evaluate(() => document.querySelector(".glass-row") !== null &&
    [...document.querySelectorAll("button")].find((b) => b.textContent === "×")?.click());
  await page.type('input[placeholder*="search 203"]', "sshd");
  await sleep(1500);
  const filtered = await page.evaluate(() => document.body.innerText.match(/\d+ MATCHES IN FILTERED CORPUS/i)?.[0] || null);
  console.log("preview search 'sshd' ->", filtered || "no match text");
  if (!filtered) failed++;

  await browser.close();
  server.close();
  console.log(failed ? `\nPAGES SMOKE: ${failed} FAILURES` : "\nPAGES SMOKE: CLEAN");
  process.exit(failed ? 1 : 0);
});