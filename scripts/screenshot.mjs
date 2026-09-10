// Capture dashboard screenshots using the installed system Chrome.
// Usage: node scripts/screenshot.mjs <base-url> <out-dir>
import { mkdirSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// puppeteer-core is a dev-dependency of the frontend (not published to npm).
const require = createRequire(import.meta.url);
const FRONTEND = join(dirname(fileURLToPath(import.meta.url)), "..", "frontend");
const puppeteer = require(join(FRONTEND, "node_modules", "puppeteer-core"));

const [baseUrl, outDir] = [process.argv[2] || "http://127.0.0.1:8000", process.argv[3] || "screenshots"];
mkdirSync(outDir, { recursive: true });

const CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

const pages = [
  ["dashboard", { to: "/", wait: 1800 }],
  ["events", { to: "/events", wait: 1800 }],
  ["alerts", { to: "/alerts", wait: 1800 }],
  ["graph", { to: "/graph", wait: 2500 }],
  ["assets", { to: "/assets", wait: 1800 }],
  ["compliance", { to: "/compliance", wait: 1800 }],
  ["ingest", { to: "/ingest", wait: 1800 }],
];

const browser = await puppeteer.launch({
  executablePath: CHROME,
  headless: true,
  pipe: true,
  args: [
    "--headless=new",
    "--no-sandbox",
    "--disable-gpu",
    "--disable-dev-shm-usage",
    "--user-data-dir=" + join(process.env.TMPDIR || "/tmp", "trinetra-chrome-" + Date.now()),
  ],
  defaultViewport: { width: 1440, height: 900 },
});

const page = await browser.newPage();
await page.goto(baseUrl, { waitUntil: "networkidle2", timeout: 30000 });

// Nav item clicks drive react-router without a full page reload.
const nav = async (to) =>
  page.evaluate((target) => {
    const link = [...document.querySelectorAll("a")]
      .find((a) => new URL(a.href).pathname === target);
    if (link) link.click();
  }, to);

for (const [name, cfg] of pages) {
  if (cfg.to !== "/") await nav(cfg.to);
  await new Promise((r) => setTimeout(r, cfg.wait));
  await page.screenshot({ path: `${outDir}/${name}.png` });
  console.log("captured", `${outDir}/${name}.png`);
}

await browser.close();
console.log("done");