// Bug-hunt harness: sweep every route for console/page errors + React
// warnings, then exercise key interactions (search, detail, ingest, graph,
// assets, compliance). Exits non-zero if any real error is observed.
// Usage: node scripts/bugcheck.mjs [base-url]
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const FRONTEND = join(dirname(fileURLToPath(import.meta.url)), "..", "frontend");
const puppeteer = require(join(FRONTEND, "node_modules", "puppeteer-core"));
const BASE = process.argv[2] || "http://127.0.0.1:8000";
const CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const ROUTES = ["/", "/events", "/alerts", "/graph", "/assets", "/compliance", "/ingest"];

const browser = await puppeteer.launch({
  executablePath: CHROME, headless: true, pipe: true,
  args: ["--headless=new", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
    "--user-data-dir=" + join(process.env.TMPDIR || "/tmp", "trinetra-bug-", String(Date.now()))],
  defaultViewport: { width: 1440, height: 900 },
});

const results = [];
const log = (m) => { console.log(m); results.push(m); };

// ------------------------------------------------------------- page sweep
for (const route of ROUTES) {
  const page = await browser.newPage();
  const errors = [];
  const warns = [];
  page.on("pageerror", (e) => errors.push("pageerror: " + e.message));
  page.on("console", (m) => {
    if (m.type() === "error") errors.push("console.error: " + m.text());
    if (m.type() === "warning") warns.push(m.text());
  });
  page.on("response", (r) => { if (r.status() >= 500) errors.push(`HTTP ${r.status()} ${r.url()}`); });
  try {
    await page.goto(BASE + route, { waitUntil: "networkidle2", timeout: 30000 });
    await sleep(1200);
    const body = await page.evaluate(() => document.body.innerText.slice(0, 400).replace(/\s+/g, " "));
    log(`${route.padEnd(10)} errors=${errors.length} warns=${warns.length} | body: ${body.slice(0, 110)}`);
    errors.forEach((e) => log("    ✗ " + e));
    warns.slice(0, 4).forEach((w) => log("    ⚠ " + w.slice(0, 140)));
  } catch (e) {
    log(`${route.padEnd(10)} NAV FAIL: ${e.message}`);
  }
  await page.close();
}

// --------------------------------------------------------- interactions
const page = await browser.newPage();
const errors = [];
page.on("pageerror", (e) => errors.push("pageerror: " + e.message));
page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
page.on("response", (r) => { if (r.status() >= 500) errors.push(`HTTP ${r.status()} ${r.url()}`); });
await page.goto(BASE + "/events", { waitUntil: "networkidle2", timeout: 30000 });
await sleep(1000);

const setNative = (el, val) => {
  const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  const desc = Object.getOwnPropertyDescriptor(proto, "value");
  desc.set.call(el, val);
  el.dispatchEvent(new Event("input", { bubbles: true }));
};

// 1. events search filter (live, debounced)
try {
  await page.type('input[placeholder*="search 203"]', "sshd");
  await sleep(1400);
  const filtered = await page.evaluate(() =>
    document.body.innerText.match(/\d+ matches in filtered corpus/gi)?.[0] || null);
  log("search 'sshd' live-filter -> " + (filtered || "NO RESULT TEXT"));
} catch (e) { log("search interact FAIL: " + e.message); }

// 2. event row -> detail drawer
try {
  const rows = await page.evaluate(() => document.querySelectorAll(".glass-row").length);
  await page.evaluate(() => document.querySelector(".glass-row")?.click());
  await sleep(700);
  const hasDetail = await page.evaluate(() => document.body.innerText.includes("EVENT DETAIL") && document.body.innerText.includes("PARSED FIELDS"));
  log(`event rows=${rows}, detail drawer opened: ${hasDetail}`);
} catch (e) { log("detail FAIL: " + e.message); }

// 3. ingest a couple lines
try {
  await page.goto(BASE + "/ingest", { waitUntil: "networkidle2", timeout: 30000 });
  await sleep(1000);
  await page.evaluate(() => {
    const ta = document.querySelector("textarea");
    const proto = HTMLTextAreaElement.prototype;
    const desc = Object.getOwnPropertyDescriptor(proto, "value");
    desc.set.call(ta, "<134>Sep 10 09:00:01 web01 sshd: Failed password for invalid user root from 203.0.113.9 port 51122 ssh2\njunk line that means nothing");
    ta.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await page.evaluate(() => [...document.querySelectorAll("button")].find((b) => b.textContent.includes("INGEST"))?.click());
  await sleep(2200);
  const ingested = await page.evaluate(() => document.body.innerText.match(/\d+ lines? (accepted|ingested)/i)?.[0] ||
    document.body.innerText.match(/accepted/i) && "accepted-tile-present");
  log("ingest clicked -> " + (ingested || "no result text found"));
} catch (e) { log("ingest FAIL: " + e.message); }

// 4. assets relations modal
try {
  await page.goto(BASE + "/assets", { waitUntil: "networkidle2", timeout: 30000 });
  await sleep(1200);
  const assetCount = await page.evaluate(() => document.querySelectorAll(".glass-row").length);
  await page.evaluate(() => document.querySelector(".glass-row")?.click());
  await sleep(900);
  const panel = await page.evaluate(() => {
    const t = document.body.innerText;
    return /Relations —/.test(t) || /Asset drill-down/.test(t);
  });
  const findingsOrEdges = await page.evaluate(() => /findings|edges|\d+ relation/i.test(document.body.innerText));
  log(`assets cards=${assetCount}, drill-down panel: ${panel}, with data: ${findingsOrEdges || "CHECK PANEL>"}`);
  await page.evaluate(() => [...document.querySelectorAll("button")].find((b) => /close/.test(b.textContent))?.click());
  await sleep(300);
  const closed = await page.evaluate(() => !/Relations —/.test(document.body.innerText));
  log("assets drill-down closes: " + closed);
} catch (e) { log("assets FAIL: " + e.message); }

// 5. compliance page renders mappings
try {
  await page.goto(BASE + "/compliance", { waitUntil: "networkidle2", timeout: 30000 });
  await sleep(1000);
  const txt = await page.evaluate(() => document.body.innerText);
  const ok = /mapping|control|iso|nist/i.test(txt);
  log("compliance renders mapping/controls: " + ok);
} catch (e) { log("compliance FAIL: " + e.message); }

// 6. graph node click -> detail panel
try {
  await page.goto(BASE + "/graph", { waitUntil: "networkidle2", timeout: 30000 });
  await sleep(2500);
  const hasNode = await page.evaluate(() => document.querySelector("svg g") !== null);
  await page.evaluate(() => document.querySelector("svg g g, svg g")?.dispatchEvent(new MouseEvent("click", { bubbles: true })));
  await sleep(700);
  const nodePanel = await page.evaluate(() => {
    const t = document.body.innerText;
    return /kind|domain|threat class/i.test(t) || /selected/i.test(t);
  });
  log("graph rendered svg: " + hasNode + ", node click panel: " + nodePanel);
} catch (e) { log("graph FAIL: " + e.message); }

log("--- interaction JS errors: " + (errors.length ? errors.join(" | ") : "none"));
await browser.close();
const failed = results.some((r) => r.includes("✗") || r.includes("FAIL") || r.includes("HTTP 5"));
console.log(failed ? "\nBUG SENSORS TRIGGERED" : "\nSWEEP CLEAN");
process.exit(failed ? 1 : 0);