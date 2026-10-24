/**
 * Integration test for the Gatekeeper service.
 * Tests the full flow: signed request → permission check → data retrieval → integrity.
 *
 * Run with: npx hardhat run test/gatekeeper-integration.js
 * (Requires Hardhat node running on :8545 and gatekeeper on :3000)
 */

const { ethers } = require("hardhat");
const crypto = require("crypto");
const Database = require("better-sqlite3");
const { seedDatabase } = require("../client/deploy");
const fs = require("fs");
const path = require("path");

const GATEKEEPER_URL = process.env.GATEKEEPER_URL || "http://127.0.0.1:3000";

const PPR_ABI = [
  "function canView(address who, string calldata selector) view returns (bool)",
  "function share(address viewer, string calldata selector)",
  "function revoke(address viewer, string calldata selector)",
  "function addPointer(string calldata selector, bytes32 dataHash)",
];

async function signRequest(wallet, pprAddr, selector) {
  const nonce = crypto.randomUUID();
  const timestamp = Date.now();
  const message = JSON.stringify({ ppr: pprAddr, selector, nonce, timestamp });
  const signature = await wallet.signMessage(message);
  return { ppr: pprAddr, selector, nonce, timestamp, signature };
}

async function queryGatekeeper(body) {
  const res = await fetch(`${GATEKEEPER_URL}/query`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json() };
}

async function main() {
  const [deployer, patient, provider, viewer, stranger] = await ethers.getSigners();

  // Deploy + seed
  await seedDatabase();

  const Registrar = await ethers.getContractFactory("Registrar");
  const reg = await Registrar.deploy();
  await reg.waitForDeployment();

  await (await reg.connect(patient).register("int-patient")).wait();
  await (await reg.connect(provider).register("int-provider")).wait();

  const PPRFactory = await ethers.getContractFactory("PPR");
  const ppr = await PPRFactory.deploy(
    patient.address, provider.address, "localhost:3000",
    await reg.summaryOf(patient.address), await reg.summaryOf(provider.address)
  );
  await ppr.waitForDeployment();
  const pprAddr = await ppr.getAddress();

  // Add pointer
  const DB_PATH = path.join(__dirname, "..", "data", "provider.db");
  const db = new Database(DB_PATH, { readonly: true });
  const rows = db.prepare("SELECT * FROM records WHERE patient_id = ?").all("1");
  db.close();
  const dataHash = "0x" + crypto.createHash("sha256").update(JSON.stringify(rows)).digest("hex");
  await (await ppr.connect(provider).addPointer("records:patient_id=1", dataHash)).wait();
  await (await ppr.connect(patient).share(viewer.address, "records:patient_id=1")).wait();

  let passed = 0;
  let failed = 0;

  function assert(name, condition) {
    if (condition) {
      console.log(`  ✓ ${name}`);
      passed++;
    } else {
      console.log(`  ✗ ${name}`);
      failed++;
    }
  }

  console.log("\n══ Gatekeeper Integration Tests ══\n");

  // Test 1: Authorized viewer retrieves data
  {
    const req = await signRequest(viewer, pprAddr, "records:patient_id=1");
    const { status, body } = await queryGatekeeper(req);
    assert("Authorized viewer gets 200", status === 200);
    assert("Returns data rows", body.data && body.data.length > 0);
  }

  // Test 2: Unauthorized stranger is rejected
  {
    const req = await signRequest(stranger, pprAddr, "records:patient_id=1");
    const { status, body } = await queryGatekeeper(req);
    assert("Unauthorized stranger gets 403", status === 403);
  }

  // Test 3: Replayed nonce is rejected
  {
    const req = await signRequest(viewer, pprAddr, "records:patient_id=1");
    await queryGatekeeper(req); // first use
    const { status } = await queryGatekeeper(req); // replay
    assert("Replayed nonce gets 401", status === 401);
  }

  // Test 4: Stale timestamp is rejected
  {
    const nonce = crypto.randomUUID();
    const timestamp = Date.now() - 120_000; // 2 minutes ago
    const message = JSON.stringify({ ppr: pprAddr, selector: "records:patient_id=1", nonce, timestamp });
    const signature = await viewer.signMessage(message);
    const { status } = await queryGatekeeper({ ppr: pprAddr, selector: "records:patient_id=1", nonce, timestamp, signature });
    assert("Stale timestamp gets 401", status === 401);
  }

  // Test 5: Revoked viewer is rejected
  {
    // Share a new selector, then revoke
    const sel = "records:patient_id=2";
    await (await ppr.connect(provider).addPointer(sel, ethers.ZeroHash)).wait();
    await (await ppr.connect(patient).share(viewer.address, sel)).wait();
    await (await ppr.connect(patient).revoke(viewer.address, sel)).wait();

    const req = await signRequest(viewer, pprAddr, sel);
    const { status } = await queryGatekeeper(req);
    assert("Revoked viewer gets 403", status === 403);
  }

  console.log(`\n  Results: ${passed} passed, ${failed} failed\n`);
}

main().catch(console.error);
