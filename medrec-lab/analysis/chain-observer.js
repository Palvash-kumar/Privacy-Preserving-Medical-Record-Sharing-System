/**
 * Chain Observer Script — reads ALL contract state and events from
 * the blockchain to build a complete patient-provider-viewer graph.
 * Used as part of weakness demo D2 and later for H2 comparison.
 *
 * Run with: npx hardhat run analysis/chain-observer.js
 */

const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

const REGISTRAR_ABI = [
  "event Registered(address indexed who, string id, address summary)",
];

const PPR_ABI = [
  "function patient() view returns (address)",
  "function provider() view returns (address)",
  "function pointerCount() view returns (uint256)",
  "function pointers(uint256 idx) view returns (string selector, bytes32 dataHash)",
  "function getViewers() view returns (address[])",
  "function getShares(address viewer) view returns (string[])",
  "event PointerAdded(address indexed ppr, uint256 index, bytes32 dataHash)",
  "event Shared(address indexed ppr, address indexed viewer, string selector)",
  "event Revoked(address indexed ppr, address indexed viewer, string selector)",
];

const SUMMARY_ABI = [
  "function relCount() view returns (uint256)",
  "function rels(uint256 idx) view returns (address ppr, uint8 status)",
];

async function main() {
  const [deployer, patient, provider, viewer] = await ethers.getSigners();

  // ── Deploy and populate for observation ──
  const Registrar = await ethers.getContractFactory("Registrar");
  const reg = await Registrar.deploy();
  await reg.waitForDeployment();
  const regAddr = await reg.getAddress();

  // Register multiple identities
  await (await reg.connect(patient).register("patient-001")).wait();
  await (await reg.connect(provider).register("provider-hospital-A")).wait();
  await (await reg.connect(viewer).register("dr-specialist-X")).wait();

  // Create PPR
  const PPRFactory = await ethers.getContractFactory("PPR");
  const ppr = await PPRFactory.deploy(
    patient.address, provider.address, "localhost:3000",
    await reg.summaryOf(patient.address), await reg.summaryOf(provider.address)
  );
  await ppr.waitForDeployment();
  const pprAddr = await ppr.getAddress();

  // Add data and share
  const hash = ethers.keccak256(ethers.toUtf8Bytes("medical-data"));
  await (await ppr.connect(provider).addPointer("records:patient_id=1", hash)).wait();
  await (await ppr.connect(patient).share(viewer.address, "records:patient_id=1")).wait();

  // ── Observation phase: read everything as a passive observer ──
  console.log("\n══════════════════════════════════════════════════════════");
  console.log("  CHAIN OBSERVER REPORT — Baseline MedRec");
  console.log("══════════════════════════════════════════════════════════\n");

  // 1. Identity mappings
  const regContract = new ethers.Contract(regAddr, REGISTRAR_ABI, ethers.provider);
  const regEvents = await regContract.queryFilter("Registered");

  const identityMap = {};
  console.log("1. IDENTITY MAPPINGS (from Registrar events):\n");
  for (const e of regEvents) {
    const [addr, id, summary] = [e.args[0], e.args[1], e.args[2]];
    identityMap[addr] = id;
    console.log(`   ${id} → ${addr}`);
    console.log(`     Summary contract: ${summary}`);
  }

  // 2. Relationship graph
  console.log("\n2. RELATIONSHIP GRAPH (from PPR contracts):\n");
  const pprContract = new ethers.Contract(pprAddr, PPR_ABI, ethers.provider);
  const patientAddr = await pprContract.patient();
  const providerAddr = await pprContract.provider();

  console.log(`   PPR: ${pprAddr}`);
  console.log(`   Patient:  ${patientAddr} (${identityMap[patientAddr] || "unknown"})`);
  console.log(`   Provider: ${providerAddr} (${identityMap[providerAddr] || "unknown"})`);

  // 3. Data pointers (selectors visible)
  const ptrCount = await pprContract.pointerCount();
  console.log(`\n3. DATA POINTERS (${ptrCount} total):\n`);
  for (let i = 0; i < ptrCount; i++) {
    const [sel, h] = await pprContract.pointers(i);
    console.log(`   [${i}] selector="${sel}" hash=${h}`);
  }

  // 4. Viewer permissions
  const allViewers = await pprContract.getViewers();
  console.log(`\n4. VIEWER PERMISSIONS:\n`);
  for (const v of allViewers) {
    const shares = await pprContract.getShares(v);
    console.log(`   ${v} (${identityMap[v] || "unknown"}) → [${shares.join(", ")}]`);
  }

  // 5. Event timeline
  console.log("\n5. EVENT TIMELINE:\n");
  const ptrEvents = await pprContract.queryFilter("PointerAdded");
  const shareEvents = await pprContract.queryFilter("Shared");
  const revokeEvents = await pprContract.queryFilter("Revoked");

  const timeline = [
    ...ptrEvents.map(e => ({ block: Number(e.blockNumber), type: "PointerAdded", index: Number(e.args[1]), hash: e.args[2] })),
    ...shareEvents.map(e => ({ block: Number(e.blockNumber), type: "Shared", viewer: e.args[1], selector: e.args[2] })),
    ...revokeEvents.map(e => ({ block: Number(e.blockNumber), type: "Revoked", viewer: e.args[1], selector: e.args[2] })),
  ].sort((a, b) => a.block - b.block);

  for (const t of timeline) {
    if (t.type === "PointerAdded") {
      console.log(`   Block ${t.block}: PointerAdded index=${t.index} hash=${t.hash}`);
    } else {
      console.log(`   Block ${t.block}: ${t.type} viewer=${t.viewer} selector="${t.selector}"`);
    }
  }

  // 6. Summary
  console.log("\n6. OBSERVER SUMMARY:\n");
  console.log(`   Identities discovered: ${Object.keys(identityMap).length}`);
  console.log(`   Relationships discovered: 1 PPR`);
  console.log(`   Viewers with active access: ${allViewers.length}`);
  console.log(`   Data selectors exposed: ${ptrCount}`);
  console.log("\n   ⚠ ALL of the above is visible to ANY network participant.\n");

  // Save report
  const report = {
    identities: identityMap,
    ppr: pprAddr,
    patient: { address: patientAddr, id: identityMap[patientAddr] },
    provider: { address: providerAddr, id: identityMap[providerAddr] },
    viewers: allViewers.map(v => ({ address: v, id: identityMap[v] || "unknown" })),
    timeline,
    mode: "baseline",
  };
  const outDir = path.join(__dirname, "..", "bench", "results");
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  const outPath = path.join(outDir, "observer-report.json");
  fs.writeFileSync(outPath, JSON.stringify(report, (key, value) => typeof value === "bigint" ? value.toString() : value, 2));
  console.log(`   Report saved to ${outPath}`);
}

main().catch(console.error);
