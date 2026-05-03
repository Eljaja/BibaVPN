/**
 * Regenerates PNG + ICO from the dark BIBA:// mark (united-design-new/app/icon.jsx).
 * Run: npm run icons --prefix ui
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Resvg } from "@resvg/resvg-js";
import pngToIco from "png-to-ico";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(__dirname, "..", "..");
const iconsDir = path.join(root, "src-tauri", "icons");
const uiPublic = path.join(__dirname, "..", "public");

const svg = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="512" height="512" viewBox="0 0 512 512">
  <rect width="512" height="512" rx="112" fill="#0c0f12"/>
  <g fill="none" stroke="rgba(244,244,240,0.55)" stroke-width="4">
    <path d="M41 41 L41 72 M41 41 L72 41"/>
    <path d="M471 41 L471 72 M471 41 L440 41"/>
    <path d="M41 471 L41 440 M41 471 L72 471"/>
    <path d="M471 471 L471 440 M471 471 L440 471"/>
  </g>
  <text x="256" y="270" text-anchor="middle" font-family="IBM Plex Mono, monospace" font-size="78" fill="#f4f4f0">
    <tspan fill="rgba(244,244,240,0.55)" font-weight="500">&gt; </tspan>
    <tspan font-weight="700">BIBA</tspan>
    <tspan font-weight="400" opacity="0.85">://</tspan>
  </text>
  <line x1="92" y1="340" x2="420" y2="340" stroke="rgba(244,244,240,0.22)" stroke-width="2"/>
</svg>`;

async function renderPng(size) {
  const resvg = new Resvg(svg, {
    fitTo: { mode: "width", value: size },
  });
  const pngData = resvg.render();
  return pngData.asPng();
}

async function main() {
  fs.mkdirSync(iconsDir, { recursive: true });
  fs.mkdirSync(uiPublic, { recursive: true });

  const sizes = [32, 128, 256];
  const pngs = {};
  for (const s of sizes) {
    const buf = await renderPng(s);
    pngs[s] = buf;
    const name = s === 32 ? "32x32.png" : `${s}x${s}.png`;
    fs.writeFileSync(path.join(iconsDir, name), buf);
  }
  fs.writeFileSync(path.join(uiPublic, "favicon.png"), pngs[32]);

  const icoBuf = await pngToIco([pngs[32], pngs[128]]);
  fs.writeFileSync(path.join(iconsDir, "icon.ico"), icoBuf);

  console.log("Wrote icons to", iconsDir, "and favicon to", uiPublic);
  console.log("Note: regenerate icon.icns on macOS with iconutil if needed.");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
