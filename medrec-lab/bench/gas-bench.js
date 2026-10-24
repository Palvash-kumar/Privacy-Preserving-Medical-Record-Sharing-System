/**
 * B1-B2: Gas benchmark — measures gas per operation for all contract calls.
 * Run with: npx hardhat run bench/gas-bench.js
 *
 * Outputs CSV to bench/results/gas-bench.csv
 */

const { ethers } = require("hardhat");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const RUNS = 30;
const WARMUP = 3;

async function main() {
  const [deployer, patient, provider, viewer] = await ethers.getSigners();

  const results = [];

  async function bench(name, fn) {
    const gasValues = [];
    // Warmup
    for (let i = 0; i < WARMUP; i++) await fn();
    // Measured runs
    for (let i = 0; i < RUNS; i++) {
      const gasUsed = await fn();
      gasValues.push(Number(gasUsed));
    }

    const mean = gasValues.reduce((a, b) => a + b, 0) / gasValues.length;
    const sorted = [...gasValues].sort((a, b) => a - b);
    const p95 = sorted[Math.floor(sorted.length * 0.95)];
    const sd = Math.sqrt(gasValues.reduce((s, v) => s + (v - mean) ** 2, 0) / gasValues.length);

    results.push({ operation: name, mean: Math.round(mean), sd: Math.round(sd), p95, min: sorted[0], max: sorted[sorted.length - 1], runs: RUNS });
    console.log(`  ${name}: mean=${Math.round(mean)} gas, sd=${Math.round(sd)}, p95=${p95}`);
  }

  console.log(`\n══ B1: Gas per operation (${RUNS} runs, ${WARMUP} warmup) ══\n`);

  // Register
  let regCounter = 0;
  const Registrar = await ethers.getContractFactory("Registrar");

  await bench("register", async () => {
    const reg = await Registrar.deploy();
    await reg.waitForDeployment();
    const tx = await reg.connect(patient).register(`patient-${regCounter++}`);
    const receipt = await tx.wait();
    return receipt.gasUsed;
  });

  // Create PPR
  let pprCounter = 0;
  await bench("createPPR", async () => {
    const reg = await Registrar.deploy();
    await reg.waitForDeployment();
    await (await reg.connect(patient).register(`p-${pprCounter}`)).wait();
    await (await reg.connect(provider).register(`pr-${pprCounter}`)).wait();
    pprCounter++;

    const pSummary = await reg.summaryOf(patient.address);
    const prSummary = await reg.summaryOf(provider.address);

    const PPR = await ethers.getContractFactory("PPR");
    const tx = await PPR.deploy(patient.address, provider.address, "localhost:3000", pSummary, prSummary);
    const receipt = await (await tx.deploymentTransaction()).wait();
    return receipt.gasUsed;
  });

  // addPointer
  await bench("addPointer", async () => {
    const reg = await Registrar.deploy();
    await reg.waitForDeployment();
    await (await reg.connect(patient).register(`ap-p-${Date.now()}`)).wait();
    await (await reg.connect(provider).register(`ap-pr-${Date.now()}`)).wait();
    const PPR = await ethers.getContractFactory("PPR");
    const ppr = await PPR.deploy(patient.address, provider.address, "localhost:3000",
      await reg.summaryOf(patient.address), await reg.summaryOf(provider.address));
    await ppr.waitForDeployment();

    const hash = ethers.keccak256(ethers.toUtf8Bytes(`data-${Date.now()}`));
    const tx = await ppr.connect(provider).addPointer("records:patient_id=1", hash);
    const receipt = await tx.wait();
    return receipt.gasUsed;
  });

  // share
  await bench("share", async () => {
    const reg = await Registrar.deploy();
    await reg.waitForDeployment();
    await (await reg.connect(patient).register(`sh-p-${Date.now()}`)).wait();
    await (await reg.connect(provider).register(`sh-pr-${Date.now()}`)).wait();
    const PPR = await ethers.getContractFactory("PPR");
    const ppr = await PPR.deploy(patient.address, provider.address, "localhost:3000",
      await reg.summaryOf(patient.address), await reg.summaryOf(provider.address));
    await ppr.waitForDeployment();

    const tx = await ppr.connect(patient).share(viewer.address, `sel-${Date.now()}`);
    const receipt = await tx.wait();
    return receipt.gasUsed;
  });

  // revoke
  await bench("revoke", async () => {
    const reg = await Registrar.deploy();
    await reg.waitForDeployment();
    await (await reg.connect(patient).register(`rv-p-${Date.now()}`)).wait();
    await (await reg.connect(provider).register(`rv-pr-${Date.now()}`)).wait();
    const PPR = await ethers.getContractFactory("PPR");
    const ppr = await PPR.deploy(patient.address, provider.address, "localhost:3000",
      await reg.summaryOf(patient.address), await reg.summaryOf(provider.address));
    await ppr.waitForDeployment();

    const sel = `sel-${Date.now()}`;
    await (await ppr.connect(patient).share(viewer.address, sel)).wait();
    const tx = await ppr.connect(patient).revoke(viewer.address, sel);
    const receipt = await tx.wait();
    return receipt.gasUsed;
  });

  // ── B2: On-chain bytes per pointer ──
  console.log("\n══ B2: On-chain bytes per pointer ══\n");
  {
    const reg = await Registrar.deploy();
    await reg.waitForDeployment();
    await (await reg.connect(patient).register("b2-p")).wait();
    await (await reg.connect(provider).register("b2-pr")).wait();
    const PPR = await ethers.getContractFactory("PPR");
    const ppr = await PPR.deploy(patient.address, provider.address, "localhost:3000",
      await reg.summaryOf(patient.address), await reg.summaryOf(provider.address));
    await ppr.waitForDeployment();

    const selector = "records:patient_id=1";
    const hash = ethers.keccak256(ethers.toUtf8Bytes("data"));
    const tx = await ppr.connect(provider).addPointer(selector, hash);
    const receipt = await tx.wait();

    // Calldata size is a proxy for on-chain bytes
    const txData = await ethers.provider.getTransaction(receipt.hash);
    const calldataBytes = (txData.data.length - 2) / 2; // hex string minus 0x
    console.log(`  Calldata bytes: ${calldataBytes}`);
    console.log(`  Selector length: ${selector.length} bytes`);
    console.log(`  Hash: 32 bytes (bytes32)`);
    results.push({ operation: "pointer_calldata_bytes", mean: calldataBytes, sd: 0, p95: calldataBytes, min: calldataBytes, max: calldataBytes, runs: 1 });
  }

  // Save CSV
  const outDir = path.join(__dirname, "results");
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  const csv = "operation,mean_gas,sd,p95,min,max,runs\n" +
    results.map(r => `${r.operation},${r.mean},${r.sd},${r.p95},${r.min},${r.max},${r.runs}`).join("\n");
  fs.writeFileSync(path.join(outDir, "gas-bench.csv"), csv);
  console.log("\n✓ Results saved to bench/results/gas-bench.csv");
}

main().catch(console.error);
