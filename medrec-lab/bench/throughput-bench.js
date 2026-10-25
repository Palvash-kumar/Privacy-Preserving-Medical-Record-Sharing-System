/**
 * B4: Concurrent-client throughput and p95 latency benchmark
 * Measures Gatekeeper throughput and latency across 1, 10, 50, and 100 concurrent clients
 * for BOTH Baseline MedRec and MedRec+ modes.
 *
 * Run with: npm run bench:throughput
 * Outputs CSV to bench/results/throughput-bench.csv
 */

const { ethers } = require("hardhat");
const crypto = require("crypto");
const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");
const { seedDatabase } = require("../client/deploy");
const { seedEncryptedDatabase } = require("../client/deploy-plus");
const { app, setProvider } = require("../gatekeeper/index");
const {
  generateKeyPair,
  exportPublicKey,
  wrapKey,
  serializeWrappedKey,
  computeSelectorCommit,
} = require("../gatekeeper/crypto-envelope");

const CONCURRENCY_LEVELS = [1, 10, 50, 100];
const REQUESTS_PER_CLIENT = 10;

async function signRequestBaseline(wallet, contractAddr, selector) {
  const nonce = crypto.randomUUID();
  const timestamp = Date.now();
  const message = JSON.stringify({ ppr: contractAddr, selector, nonce, timestamp });
  const signature = await wallet.signMessage(message);
  return { ppr: contractAddr, selector, nonce, timestamp, signature };
}

async function signRequestPlus(wallet, contractAddr, selectorCommit) {
  const nonce = crypto.randomUUID();
  const timestamp = Date.now();
  const message = JSON.stringify({ ppr: contractAddr, selectorCommit, nonce, timestamp });
  const signature = await wallet.signMessage(message);
  return { mode: "plus", ppr: contractAddr, selectorCommit, nonce, timestamp, signature };
}

function queryGatekeeperInMemory(body) {
  return new Promise((resolve) => {
    const req = {
      method: "POST",
      url: "/query",
      headers: { "content-type": "application/json" },
      body,
    };
    const res = {
      statusCode: 200,
      status(code) {
        this.statusCode = code;
        return this;
      },
      setHeader() {},
      getHeader() {},
      json(data) {
        resolve({ status: this.statusCode, body: data });
      },
      send(data) {
        resolve({ status: this.statusCode, body: data });
      },
    };
    app.handle(req, res);
  });
}

async function runBenchmarkForMode(modeName, pprAddr, selectorOrCommit, viewerWallet, isPlus) {
  console.log(`\n── Benchmarking ${modeName} Mode ──`);
  const modeResults = [];

  for (const concurrency of CONCURRENCY_LEVELS) {
    const totalRequests = concurrency * REQUESTS_PER_CLIENT;
    process.stdout.write(`  Concurrency = ${concurrency} (${totalRequests} requests)... `);

    const reqList = [];
    for (let i = 0; i < totalRequests; i++) {
      if (isPlus) {
        reqList.push(await signRequestPlus(viewerWallet, pprAddr, selectorOrCommit));
      } else {
        reqList.push(await signRequestBaseline(viewerWallet, pprAddr, selectorOrCommit));
      }
    }

    const latencies = [];
    let errors = 0;
    const startTime = performance.now();

    let reqIndex = 0;
    async function worker() {
      while (true) {
        const idx = reqIndex++;
        if (idx >= reqList.length) break;
        const req = reqList[idx];
        const t0 = performance.now();
        const res = await queryGatekeeperInMemory(req);
        const elapsed = performance.now() - t0;
        latencies.push(elapsed);
        if (res.status !== 200 || !res.body.integrity.match) {
          errors++;
        }
      }
    }

    const workers = [];
    for (let c = 0; c < concurrency; c++) {
      workers.push(worker());
    }
    await Promise.all(workers);

    const totalDurationSec = (performance.now() - startTime) / 1000;
    const throughput = (totalRequests / totalDurationSec).toFixed(1);

    latencies.sort((a, b) => a - b);
    const mean = (latencies.reduce((a, b) => a + b, 0) / latencies.length).toFixed(2);
    const p50 = latencies[Math.floor(latencies.length * 0.5)].toFixed(2);
    const p95 = latencies[Math.floor(latencies.length * 0.95)].toFixed(2);
    const p99 = latencies[Math.floor(latencies.length * 0.99)].toFixed(2);
    const min = latencies[0].toFixed(2);
    const max = latencies[latencies.length - 1].toFixed(2);

    console.log(`Throughput: ${throughput} req/s | Mean: ${mean}ms | p95: ${p95}ms | Errors: ${errors}`);

    modeResults.push({
      mode: modeName,
      concurrency,
      total_requests: totalRequests,
      duration_sec: totalDurationSec.toFixed(3),
      throughput_rps: throughput,
      mean_ms: mean,
      p50_ms: p50,
      p95_ms: p95,
      p99_ms: p99,
      min_ms: min,
      max_ms: max,
      errors,
    });
  }

  return modeResults;
}

async function main() {
  console.log("\n══════════════════════════════════════════════════════════════");
  console.log("  B4: CONCURRENT THROUGHPUT & p95 LATENCY BENCHMARK           ");
  console.log("══════════════════════════════════════════════════════════════");

  const signers = await ethers.getSigners();
  const [deployer, patient, provider, viewer] = signers;

  setProvider(ethers.provider);

  // 1. Setup Baseline
  await seedDatabase();
  const Registrar = await ethers.getContractFactory("Registrar");
  const reg = await Registrar.deploy();
  await reg.waitForDeployment();
  await (await reg.connect(patient).register("b4-patient")).wait();
  await (await reg.connect(provider).register("b4-provider")).wait();

  const PPRFactory = await ethers.getContractFactory("PPR");
  const pprBase = await PPRFactory.deploy(
    patient.address,
    provider.address,
    "localhost:3000",
    await reg.summaryOf(patient.address),
    await reg.summaryOf(provider.address)
  );
  await pprBase.waitForDeployment();
  const pprBaseAddr = await pprBase.getAddress();

  const DB_PATH = path.join(__dirname, "..", "data", "provider.db");
  const db = new Database(DB_PATH, { readonly: true });
  const rows = db.prepare("SELECT * FROM records WHERE patient_id = ?").all("1");
  db.close();

  const dataHash = "0x" + crypto.createHash("sha256").update(JSON.stringify(rows)).digest("hex");
  await (await pprBase.connect(provider).addPointer("records:patient_id=1", dataHash)).wait();
  await (await pprBase.connect(patient).share(viewer.address, "records:patient_id=1")).wait();

  // 2. Setup MedRec+
  const patientKeys = generateKeyPair();
  const viewerKeys = generateKeyPair();
  const encryptedRecords = await seedEncryptedDatabase(patientKeys);

  const RegistrarPlus = await ethers.getContractFactory("RegistrarPlus");
  const regPlus = await RegistrarPlus.deploy();
  await regPlus.waitForDeployment();
  await (await regPlus.connect(patient).register(exportPublicKey(patientKeys.publicKey))).wait();
  await (await regPlus.connect(provider).register(exportPublicKey(generateKeyPair().publicKey))).wait();
  await (await regPlus.connect(viewer).register(exportPublicKey(viewerKeys.publicKey))).wait();

  const PPRPlusFactory = await ethers.getContractFactory("PPRPlus");
  const pprPlus = await PPRPlusFactory.deploy(
    patient.address,
    provider.address,
    "localhost:3000",
    await regPlus.summaryOf(patient.address),
    await regPlus.summaryOf(provider.address)
  );
  await pprPlus.waitForDeployment();
  const pprPlusAddr = await pprPlus.getAddress();

  const commit = computeSelectorCommit("records:patient_id=1", "saltB4");
  const rec0 = encryptedRecords[0];
  await (await pprPlus.connect(provider).addPointer(commit, rec0.digest)).wait();

  const wrappedKey = serializeWrappedKey(wrapKey(rec0.dek, viewerKeys.publicKey));
  const oneHour = Math.floor(Date.now() / 1000) + 3600;
  await (await pprPlus.connect(patient).share(viewer.address, commit, oneHour, wrappedKey)).wait();

  // 3. Run Benchmark for both modes
  const baseResults = await runBenchmarkForMode("Baseline", pprBaseAddr, "records:patient_id=1", viewer, false);
  const plusResults = await runBenchmarkForMode("MedRec+", pprPlusAddr, commit, viewer, true);

  const allResults = [...baseResults, ...plusResults];

  // 4. Save CSV
  const outDir = path.join(__dirname, "results");
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  const csv =
    "mode,concurrency,total_requests,duration_sec,throughput_rps,mean_ms,p50_ms,p95_ms,p99_ms,min_ms,max_ms,errors\n" +
    allResults
      .map(
        (r) =>
          `"${r.mode}",${r.concurrency},${r.total_requests},${r.duration_sec},${r.throughput_rps},${r.mean_ms},${r.p50_ms},${r.p95_ms},${r.p99_ms},${r.min_ms},${r.max_ms},${r.errors}`
      )
      .join("\n");

  const outPath = path.join(outDir, "throughput-bench.csv");
  fs.writeFileSync(outPath, csv);
  console.log(`\n✓ Combined throughput & latency results saved to ${outPath}\n`);
}

main().catch(console.error);
