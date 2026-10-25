/**
 * Chart Generator for MedRec & MedRec+ Evaluation
 * Reads benchmark CSV results dynamically and generates crisp, clean SVG visualization charts.
 *
 * Run with: node bench/generate-charts.js
 * Outputs to bench/results/*.svg
 */

const fs = require("fs");
const path = require("path");

const RESULTS_DIR = path.join(__dirname, "results");

function parseCsv(filename) {
  const filePath = path.join(RESULTS_DIR, filename);
  if (!fs.existsSync(filePath)) return [];
  const content = fs.readFileSync(filePath, "utf-8").trim();
  const lines = content.split("\n");
  const headers = lines[0].split(",").map((h) => h.replace(/^"|"$/g, "").trim());
  return lines.slice(1).map((line) => {
    // Basic CSV row splitter handling quotes
    const values = [];
    let current = "";
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const char = line[i];
      if (char === '"') inQuotes = !inQuotes;
      else if (char === "," && !inQuotes) {
        values.push(current.trim());
        current = "";
      } else current += char;
    }
    values.push(current.trim());

    const row = {};
    headers.forEach((h, idx) => {
      row[h] = (values[idx] || "").replace(/^"|"$/g, "").trim();
    });
    return row;
  });
}

// ── 1. Gas Comparison Bar Chart ──────────────────────────────────────────

function generateGasChart() {
  const secExp = parseCsv("security-experiments.csv");
  const getGas = (expName) => {
    const row = secExp.find((r) => r.experiment === expName);
    return row ? { base: Number(row.baseline), plus: Number(row.medrec_plus) } : { base: 0, plus: 0 };
  };

  const reg = getGas("H4_gas_register");
  const ppr = getGas("H4_gas_create_ppr");
  const ptr = getGas("H4_gas_add_pointer");
  const shEvt = getGas("H4_gas_share_event");
  const shStr = getGas("H4_gas_share_storage");
  const rvk = getGas("H4_gas_revoke");

  const operations = [
    { name: "Register", baseline: reg.base, plusEvent: reg.plus, plusStorage: reg.plus },
    { name: "Create PPR", baseline: ppr.base, plusEvent: ppr.plus, plusStorage: ppr.plus },
    { name: "Add Pointer", baseline: ptr.base, plusEvent: ptr.plus, plusStorage: ptr.plus },
    { name: "Share Access", baseline: shEvt.base, plusEvent: shEvt.plus, plusStorage: shStr.plus },
    { name: "Revoke", baseline: rvk.base, plusEvent: rvk.plus, plusStorage: rvk.plus },
  ];

  const width = 850;
  const height = 480;
  const margin = { top: 60, right: 30, bottom: 80, left: 90 };
  const chartWidth = width - margin.left - margin.right;
  const chartHeight = height - margin.top - margin.bottom;

  const maxGas = 1400000;
  const barGroupWidth = chartWidth / operations.length;
  const barWidth = 24;

  let barsSvg = "";
  operations.forEach((op, i) => {
    const groupX = margin.left + i * barGroupWidth;

    const hBase = (op.baseline / maxGas) * chartHeight;
    const yBase = margin.top + chartHeight - hBase;

    const hEvent = (op.plusEvent / maxGas) * chartHeight;
    const yEvent = margin.top + chartHeight - hEvent;

    const hStorage = (op.plusStorage / maxGas) * chartHeight;
    const yStorage = margin.top + chartHeight - hStorage;

    barsSvg += `
      <!-- ${op.name} -->
      <rect x="${groupX + 15}" y="${yBase}" width="${barWidth}" height="${hBase}" fill="#4F46E5" rx="3" />
      <text x="${groupX + 15 + barWidth / 2}" y="${yBase - 6}" font-size="10" font-family="sans-serif" text-anchor="middle" fill="#312E81">${Math.round(op.baseline / 1000)}k</text>

      <rect x="${groupX + 15 + barWidth + 6}" y="${yEvent}" width="${barWidth}" height="${hEvent}" fill="#059669" rx="3" />
      <text x="${groupX + 15 + barWidth + 6 + barWidth / 2}" y="${yEvent - 6}" font-size="10" font-family="sans-serif" text-anchor="middle" fill="#065F46">${Math.round(op.plusEvent / 1000)}k</text>

      <rect x="${groupX + 15 + (barWidth + 6) * 2}" y="${yStorage}" width="${barWidth}" height="${hStorage}" fill="#D97706" rx="3" />
      <text x="${groupX + 15 + (barWidth + 6) * 2 + barWidth / 2}" y="${yStorage - 6}" font-size="10" font-family="sans-serif" text-anchor="middle" fill="#92400E">${Math.round(op.plusStorage / 1000)}k</text>

      <text x="${groupX + barGroupWidth / 2 - 10}" y="${height - margin.bottom + 25}" font-size="12" font-family="sans-serif" text-anchor="middle" fill="#1F2937" font-weight="600">${op.name}</text>
    `;
  });

  let gridSvg = "";
  for (let g = 0; g <= maxGas; g += 200000) {
    const y = margin.top + chartHeight - (g / maxGas) * chartHeight;
    gridSvg += `
      <line x1="${margin.left}" y1="${y}" x2="${width - margin.right}" y2="${y}" stroke="#E5E7EB" stroke-width="1" stroke-dasharray="3,3" />
      <text x="${margin.left - 10}" y="${y + 4}" font-size="11" font-family="sans-serif" text-anchor="end" fill="#6B7280">${g.toLocaleString()} gas</text>
    `;
  }

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}">
    <rect width="${width}" height="${height}" fill="#FFFFFF" />
    <text x="${width / 2}" y="32" font-size="18" font-family="sans-serif" font-weight="bold" text-anchor="middle" fill="#111827">Gas Consumption: Baseline vs MedRec+ (Event vs Storage Publishing)</text>
    <text x="${width / 2}" y="50" font-size="12" font-family="sans-serif" text-anchor="middle" fill="#6B7280">Measured in Hardhat EVM — Source: bench/results/security-experiments.csv (H4)</text>

    ${gridSvg}
    ${barsSvg}

    <!-- Legend -->
    <g transform="translate(${width / 2 - 180}, ${height - 25})">
      <rect x="0" y="0" width="14" height="14" fill="#4F46E5" rx="2" />
      <text x="20" y="11" font-size="12" font-family="sans-serif" fill="#374151">MedRec Baseline</text>

      <rect x="140" y="0" width="14" height="14" fill="#059669" rx="2" />
      <text x="160" y="11" font-size="12" font-family="sans-serif" fill="#374151">MedRec+ (Event-based)</text>

      <rect x="310" y="0" width="14" height="14" fill="#D97706" rx="2" />
      <text x="330" y="11" font-size="12" font-family="sans-serif" fill="#374151">MedRec+ (Storage-based)</text>
    </g>
  </svg>`;

  fs.writeFileSync(path.join(RESULTS_DIR, "chart-gas-comparison.svg"), svg);
  console.log("✓ Generated chart-gas-comparison.svg from security-experiments.csv");
}

// ── 2. Latency vs Payload Size Line Chart ────────────────────────────────

function generateLatencyChart() {
  const latRows = parseCsv("latency-bench.csv");
  const secExp = parseCsv("security-experiments.csv");

  const getHash = (label) => {
    const row = latRows.find((r) => r.operation === `hash_${label}`);
    return row ? Number(row.mean_ms) : 0;
  };

  const getCrypto = (label) => {
    const row = secExp.find((r) => r.experiment === `H3_crypto_overhead_${label}`);
    if (!row) return 0;
    const match = row.medrec_plus.match(/^([0-9.]+)ms/);
    return match ? Number(match[1]) : 0;
  };

  const sizes = ["1KB", "100KB", "1MB", "10MB", "50MB"];
  const data = sizes.map((s) => ({
    label: s,
    baselineHash: getHash(s),
    cryptoTotal: getCrypto(s),
  }));

  const width = 800;
  const height = 450;
  const margin = { top: 60, right: 40, bottom: 60, left: 80 };
  const chartWidth = width - margin.left - margin.right;
  const chartHeight = height - margin.top - margin.bottom;

  const maxLatency = 80;

  const getX = (i) => margin.left + (i / (data.length - 1)) * chartWidth;
  const getY = (val) => margin.top + chartHeight - (val / maxLatency) * chartHeight;

  let gridSvg = "";
  for (let val = 0; val <= maxLatency; val += 10) {
    const y = getY(val);
    gridSvg += `
      <line x1="${margin.left}" y1="${y}" x2="${width - margin.right}" y2="${y}" stroke="#E5E7EB" stroke-width="1" stroke-dasharray="3,3" />
      <text x="${margin.left - 10}" y="${y + 4}" font-size="11" font-family="sans-serif" text-anchor="end" fill="#6B7280">${val} ms</text>
    `;
  }

  const pointsBase = data.map((d, i) => `${getX(i)},${getY(d.baselineHash)}`).join(" ");
  const pointsPlus = data.map((d, i) => `${getX(i)},${getY(d.cryptoTotal)}`).join(" ");

  let nodesSvg = "";
  data.forEach((d, i) => {
    const x = getX(i);
    const yBase = getY(d.baselineHash);
    const yPlus = getY(d.cryptoTotal);

    nodesSvg += `
      <circle cx="${x}" cy="${yBase}" r="5" fill="#4F46E5" />
      <text x="${x}" y="${yBase - 8}" font-size="11" font-family="sans-serif" text-anchor="middle" fill="#312E81">${d.baselineHash}ms</text>

      <circle cx="${x}" cy="${yPlus}" r="5" fill="#DC2626" />
      <text x="${x}" y="${yPlus - 8}" font-size="11" font-family="sans-serif" text-anchor="middle" fill="#991B1B">${d.cryptoTotal}ms</text>

      <text x="${x}" y="${height - margin.bottom + 25}" font-size="12" font-family="sans-serif" text-anchor="middle" fill="#1F2937" font-weight="600">${d.label}</text>
    `;
  });

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}">
    <rect width="${width}" height="${height}" fill="#FFFFFF" />
    <text x="${width / 2}" y="32" font-size="18" font-family="sans-serif" font-weight="bold" text-anchor="middle" fill="#111827">Processing Latency vs Payload Size (1 KB to 50 MB)</text>
    <text x="${width / 2}" y="50" font-size="12" font-family="sans-serif" text-anchor="middle" fill="#6B7280">Baseline SHA-256 vs MedRec+ Envelope Crypto — Source: latency-bench.csv &amp; security-experiments.csv (H3)</text>

    ${gridSvg}

    <polyline fill="none" stroke="#4F46E5" stroke-width="3" points="${pointsBase}" />
    <polyline fill="none" stroke="#DC2626" stroke-width="3" points="${pointsPlus}" />

    ${nodesSvg}

    <!-- Legend -->
    <g transform="translate(${width / 2 - 140}, ${height - 20})">
      <circle cx="0" cy="5" r="5" fill="#4F46E5" />
      <text x="12" y="9" font-size="12" font-family="sans-serif" fill="#374151">Baseline Hash Verification</text>

      <circle cx="180" cy="5" r="5" fill="#DC2626" />
      <text x="192" y="9" font-size="12" font-family="sans-serif" fill="#374151">MedRec+ End-to-End Crypto</text>
    </g>
  </svg>`;

  fs.writeFileSync(path.join(RESULTS_DIR, "chart-latency-payload.svg"), svg);
  console.log("✓ Generated chart-latency-payload.svg from benchmark CSVs");
}

// ── 3. Throughput & p95 Latency Chart ────────────────────────────────────

function generateThroughputChart() {
  const tRows = parseCsv("throughput-bench.csv");
  const baseRows = tRows.filter((r) => r.mode === "Baseline");
  const plusRows = tRows.filter((r) => r.mode === "MedRec+");

  const width = 850;
  const height = 480;
  const margin = { top: 60, right: 80, bottom: 60, left: 80 };
  const chartWidth = width - margin.left - margin.right;
  const chartHeight = height - margin.top - margin.bottom;

  const maxRps = 600;
  const maxLat = 350;

  const getX = (i) => margin.left + (i / 3) * chartWidth;
  const getYRps = (val) => margin.top + chartHeight - (val / maxRps) * chartHeight;
  const getYLat = (val) => margin.top + chartHeight - (val / maxLat) * chartHeight;

  let gridSvg = "";
  for (let val = 0; val <= maxRps; val += 100) {
    const y = getYRps(val);
    gridSvg += `
      <line x1="${margin.left}" y1="${y}" x2="${width - margin.right}" y2="${y}" stroke="#E5E7EB" stroke-width="1" stroke-dasharray="3,3" />
      <text x="${margin.left - 10}" y="${y + 4}" font-size="11" font-family="sans-serif" text-anchor="end" fill="#059669">${val} rps</text>
    `;
  }

  for (let val = 0; val <= maxLat; val += 50) {
    const y = getYLat(val);
    gridSvg += `
      <text x="${width - margin.right + 10}" y="${y + 4}" font-size="11" font-family="sans-serif" text-anchor="start" fill="#D97706">${val} ms</text>
    `;
  }

  const basePointsRps = baseRows.map((d, i) => `${getX(i)},${getYRps(Number(d.throughput_rps))}`).join(" ");
  const plusPointsRps = plusRows.map((d, i) => `${getX(i)},${getYRps(Number(d.throughput_rps))}`).join(" ");

  const basePointsLat = baseRows.map((d, i) => `${getX(i)},${getYLat(Number(d.p95_ms))}`).join(" ");
  const plusPointsLat = plusRows.map((d, i) => `${getX(i)},${getYLat(Number(d.p95_ms))}`).join(" ");

  let nodesSvg = "";
  baseRows.forEach((d, i) => {
    const x = getX(i);
    const pRow = plusRows[i] || d;

    nodesSvg += `
      <!-- Baseline -->
      <circle cx="${x}" cy="${getYRps(Number(d.throughput_rps))}" r="4" fill="#059669" />
      <text x="${x - 15}" y="${getYRps(Number(d.throughput_rps)) - 8}" font-size="10" font-family="sans-serif" text-anchor="end" fill="#065F46">Base: ${d.throughput_rps}</text>

      <circle cx="${x}" cy="${getYLat(Number(d.p95_ms))}" r="4" fill="#D97706" />
      <text x="${x - 15}" y="${getYLat(Number(d.p95_ms)) + 12}" font-size="10" font-family="sans-serif" text-anchor="end" fill="#92400E">Base: ${d.p95_ms}ms</text>

      <!-- MedRec+ -->
      <circle cx="${x}" cy="${getYRps(Number(pRow.throughput_rps))}" r="4" fill="#0284C7" />
      <text x="${x + 15}" y="${getYRps(Number(pRow.throughput_rps)) - 8}" font-size="10" font-family="sans-serif" text-anchor="start" fill="#0369A1">Plus: ${pRow.throughput_rps}</text>

      <circle cx="${x}" cy="${getYLat(Number(pRow.p95_ms))}" r="4" fill="#DC2626" />
      <text x="${x + 15}" y="${getYLat(Number(pRow.p95_ms)) + 12}" font-size="10" font-family="sans-serif" text-anchor="start" fill="#991B1B">Plus: ${pRow.p95_ms}ms</text>

      <text x="${x}" y="${height - margin.bottom + 25}" font-size="12" font-family="sans-serif" text-anchor="middle" fill="#1F2937" font-weight="600">${d.concurrency} Client${Number(d.concurrency) > 1 ? "s" : ""}</text>
    `;
  });

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}">
    <rect width="${width}" height="${height}" fill="#FFFFFF" />
    <text x="${width / 2}" y="32" font-size="18" font-family="sans-serif" font-weight="bold" text-anchor="middle" fill="#111827">Gatekeeper Throughput (req/s) &amp; p95 Latency (ms): Baseline vs MedRec+</text>
    <text x="${width / 2}" y="50" font-size="12" font-family="sans-serif" text-anchor="middle" fill="#6B7280">Concurrent Client Load Scaling (1, 10, 50, 100 Clients) — Source: bench/results/throughput-bench.csv (B4)</text>

    ${gridSvg}

    <!-- Throughput lines -->
    <polyline fill="none" stroke="#059669" stroke-width="2.5" points="${basePointsRps}" />
    <polyline fill="none" stroke="#0284C7" stroke-width="2.5" points="${plusPointsRps}" />

    <!-- Latency lines -->
    <polyline fill="none" stroke="#D97706" stroke-width="2" stroke-dasharray="4,4" points="${basePointsLat}" />
    <polyline fill="none" stroke="#DC2626" stroke-width="2" stroke-dasharray="4,4" points="${plusPointsLat}" />

    ${nodesSvg}

    <!-- Legend -->
    <g transform="translate(${width / 2 - 240}, ${height - 20})">
      <circle cx="0" cy="5" r="4" fill="#059669" />
      <text x="10" y="9" font-size="11" font-family="sans-serif" fill="#374151">Base Throughput</text>

      <circle cx="120" cy="5" r="4" fill="#0284C7" />
      <text x="130" y="9" font-size="11" font-family="sans-serif" fill="#374151">MedRec+ Throughput</text>

      <circle cx="260" cy="5" r="4" fill="#D97706" />
      <text x="270" y="9" font-size="11" font-family="sans-serif" fill="#374151">Base p95 Latency</text>

      <circle cx="380" cy="5" r="4" fill="#DC2626" />
      <text x="390" y="9" font-size="11" font-family="sans-serif" fill="#374151">MedRec+ p95 Latency</text>
    </g>
  </svg>`;

  fs.writeFileSync(path.join(RESULTS_DIR, "chart-throughput-latency.svg"), svg);
  console.log("✓ Generated chart-throughput-latency.svg from throughput-bench.csv");
}

function main() {
  generateGasChart();
  generateLatencyChart();
  generateThroughputChart();
  console.log("\n══ All evaluation charts successfully generated from source CSVs ══\n");
}

main();
