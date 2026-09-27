import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

// Light mode used to be broken in ways no unit test could see, because the
// damage is in the cascade rather than in any component's output. These
// checks read the stylesheet and assert the structure that keeps it working.

const css = readFileSync(resolve(process.cwd(), "src/index.css"), "utf8");

describe("light theme remaps", () => {
  it("puts the theme-blind colour overrides in @layer utilities", () => {
    // The cascade reverses layer order for !important declarations, so a
    // layered !important from Tailwind beats an unlayered one regardless of
    // specificity. Sharing the layer is what lets these overrides win.
    const start = css.indexOf("@layer utilities {");
    expect(start).toBeGreaterThan(-1);
    const block = css.slice(start);
    expect(block).toContain("[data-theme=\"light\"] .text-emerald-300");
    expect(block).toContain("[data-theme=\"light\"] .text-cyan-300");
    expect(block).toContain("[data-theme=\"light\"] .text-red-400");
  });

  it("remaps every Tailwind !important colour class the source uses", () => {
    // Tailwind's ! modifier is part of the class name, so !text-cyan-300 is
    // a different selector from .text-cyan-300 and needs its own rule.
    for (const cls of [
      "!text-cyan-300",
      "!text-emerald-300",
      "!text-amber-300",
      "!text-slate-300",
      "!text-slate-400",
    ]) {
      expect(css).toContain(`[data-theme="light"] .\\${cls}`);
    }
  });

  it("keeps the dark terminal surface out of the light palette", () => {
    // The log console is dark in both themes. Re-declaring the dark tokens on
    // the surface opts its whole subtree out, because every light remap
    // resolves through these variables.
    expect(css).toContain(".term-surface {");
    const rule = css.slice(css.indexOf(".term-surface {"));
    for (const v of ["--text:", "--accent:", "--sev-critical-ink:", "--sev-info-ink:"]) {
      expect(rule.slice(0, rule.indexOf("}"))).toContain(v);
    }
  });

  it("re-colours .chip for light, including the active state", () => {
    expect(css).toContain('[data-theme="light"] .chip {');
    expect(css).toContain('[data-theme="light"] .chip-on {');
  });
});
