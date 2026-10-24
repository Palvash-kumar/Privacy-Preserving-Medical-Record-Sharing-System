/**
 * B3/B5/B6: End-to-end latency benchmark for add-record, share, retrieve.
 * Measures latency at different block intervals and payload sizes.
 *
 * Run with: npx hardhat run bench/latency-bench.js
 * Outputs CSV to bench/results/latency-bench.csv
 */

const { ethers } = require("hardhat");
const crypto = require("crypto");
const Database = require("better-sqlite3");
const fs = require("fs");
const path = require("path");

const RUNS = 30;
const WARMUP = 3;
const DB_PATH = path.join(__dirname, "..", "data", "provider.db");

async function main() {
  const [deployer, patient, provider, viewer] = await ethers.getSigners();
  const results = [];

  // Deploy fresh contracts
  const Registrar = await ethers.getContractFactory("Registrar");
  const reg = await Registrar.deploy();
  await reg.waitForDeployment();
  await (await reg.connect(patient).register("lat-p")).wait();
  await (await reg.connect(provider).register("lat-pr")).wait();

  const PPR = await ethers.getContractFactory("PPR");
  const ppr = await PPR.deploy(patient.address, provider.address, "localhost:3000",
    await reg.summaryOf(patient.address), await reg.summaryOf(provider.address));
  await ppr.waitForDeployment();

  // ── B3: End-to-end latency (instant mining) ──
  console.log(`\n══ B3: E2E latency — instant mining (${RUNS} runs) ══\n`);

  async function measureLatency(label, fn) {
    const times = [];
    for (let i = 0; i < WARMUP; i++) await fn();
    for (let i = 0; i < RUNS; i++) {
      const start = performance.now();
      await fn();
      times.push(performance.now() - start);
    }
    const mean = times.reduce((a, b) => a + b, 0) / times.length;
    const sorted = [...times].sort((a, b) => a - b);
    const p95 = sorted[Math.floor(sorted.length * 0.95)];
    const sd = Math.sqrt(times.reduce((s, v) => s + (v - mean) ** 2, 0) / times.length);
    results.push({ operation: label, mean_ms: mean.toFixed(2), sd_ms: sd.toFixed(2), p95_ms: p95.toFixed(2) });
    console.log(`  ${label}: mean=${mean.toFixed(1)}ms, sd=${sd.toFixed(1)}ms, p95=${p95.toFixed(1)}ms`);
  }

  let ptrCount = 0;
  await measureLatency("addPointer", async () => {
    const hash = ethers.keccak256(ethers.toUtf8Bytes(`latency-${ptrCount++}`));
    const tx = await ppr.connect(provider).addPointer(`sel-${ptrCount}`, hash);
    await tx.wait();
  });

  let shareCount = 0;
  await measureLatency("share", async () => {
    const tx = await ppr.connect(patient).share(viewer.address, `share-${shareCount++}`);
    await tx.wait();
  });

  // canView (read-only, no tx)
  await ppr.connect(patient).share(viewer.address, "read-test");
  await measureLatency("canView (read)", async () => {
    await ppr.canView(viewer.address, "read-test");
  });

  // ── B5: Retrieval latency vs number of pointers ──
  console.log(`\n══ B5: canView latency vs pointer count ══\n`);
  for (const count of [10, 100, 1000]) {
    const reg2 = await Registrar.deploy();
    await reg2.waitForDeployment();
    await (await reg2.connect(patient).register("b5-p")).wait();
    await (await reg2.connect(provider).register("b5-pr")).wait();
    const ppr2 = await PPR.deploy(patient.address, provider.address, "localhost:3000",
      await reg2.summaryOf(patient.address), await reg2.summaryOf(provider.address));
    await ppr2.waitForDeployment();

    // Add pointers
    for (let i = 0; i < count; i++) {
      const hash = ethers.keccak256(ethers.toUtf8Bytes(`ptr-${i}`));
      await (await ppr2.connect(provider).addPointer(`sel-${i}`, hash)).wait();
    }
    await (await ppr2.connect(patient).share(viewer.address, `sel-0`)).wait();

    await measureLatency(`canView_${count}ptrs`, async () => {
      await ppr2.canView(viewer.address, `sel-0`);
    });
  }

  // ── B6: Payload size effect on hash computation ──
  console.log(`\n══ B6: Hash computation time vs payload size ══\n`);
  for (const sizeKB of [1, 100, 1024, 10240, 51200]) {
    const payload = crypto.randomBytes(sizeKB * 1024);
    const times = [];
    for (let i = 0; i < RUNS; i++) {
      const start = performance.now();
      crypto.createHash("sha256").update(payload).digest("hex");
      times.push(performance.now() - start);
    }
    const mean = times.reduce((a, b) => a + b, 0) / times.length;
    const label = sizeKB >= 1024 ? `${sizeKB / 1024}MB` : `${sizeKB}KB`;
    results.push({ operation: `hash_${label}`, mean_ms: mean.toFixed(2), sd_ms: "0", p95_ms: "0" });
    console.log(`  ${label}: ${mean.toFixed(2)}ms`);
  }

  // Save CSV
  const outDir = path.join(__dirname, "results");
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  const csv = "operation,mean_ms,sd_ms,p95_ms\n" +
    results.map(r => `${r.operation},${r.mean_ms},${r.sd_ms},${r.p95_ms}`).join("\n");
  fs.writeFileSync(path.join(outDir, "latency-bench.csv"), csv);
  console.log("\n✓ Results saved to bench/results/latency-bench.csv");
}

main().catch(console.error);
