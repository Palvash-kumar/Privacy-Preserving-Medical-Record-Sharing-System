/**
 * Baseline Weakness Demos (D1-D4)
 * Each demo is scripted and repeatable for screenshots.
 *
 * Run with: npx hardhat run analysis/weakness-demos.js
 */

const { ethers } = require("hardhat");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const DB_PATH = path.join(__dirname, "..", "data", "provider.db");

const PPR_ABI = [
  "function canView(address who, string calldata selector) view returns (bool)",
  "function share(address viewer, string calldata selector)",
  "function revoke(address viewer, string calldata selector)",
  "function addPointer(string calldata selector, bytes32 dataHash)",
  "function pointerCount() view returns (uint256)",
  "function pointers(uint256 idx) view returns (string selector, bytes32 dataHash)",
  "function patient() view returns (address)",
  "function provider() view returns (address)",
  "function getViewers() view returns (address[])",
  "function getShares(address viewer) view returns (string[])",
  "event PointerAdded(address indexed ppr, uint256 index, bytes32 dataHash)",
  "event Shared(address indexed ppr, address indexed viewer, string selector)",
  "event Revoked(address indexed ppr, address indexed viewer, string selector)",
];

const REGISTRAR_ABI = [
  "function idToAddress(string calldata id) view returns (address)",
  "function summaryOf(address who) view returns (address)",
  "event Registered(address indexed who, string id, address summary)",
];

const SUMMARY_ABI = [
  "function owner() view returns (address)",
  "function relCount() view returns (uint256)",
  "function rels(uint256 idx) view returns (address ppr, uint8 status)",
  "event RelationshipAdded(address indexed ppr, uint256 index)",
];

async function main() {
  const [deployer, patient, provider, viewer] = await ethers.getSigners();

  // ── Setup: deploy contracts and seed data ──
  console.log("══ Setting up for weakness demos ══\n");

  // Seed DB
  const dir = path.dirname(DB_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (fs.existsSync(DB_PATH)) fs.unlinkSync(DB_PATH);
  const db = new Database(DB_PATH);
  db.exec(`
    CREATE TABLE records (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      patient_id TEXT, name TEXT, dob TEXT, blood_type TEXT,
      diagnosis TEXT, medication TEXT, visit_date TEXT
    )
  `);
  const records = [
    ["1", "Synthetic Patient A", "1985-03-15", "O+", "J45 Asthma", "Salbutamol 100mcg", "2024-01-10"],
    ["1", "Synthetic Patient A", "1985-03-15", "O+", "E11 Diabetes", "Metformin 500mg", "2024-02-20"],
    ["2", "Synthetic Patient B", "1990-07-22", "A-", "K21 GERD", "Omeprazole 20mg", "2024-01-15"],
  ];
  const insert = db.prepare("INSERT INTO records (patient_id, name, dob, blood_type, diagnosis, medication, visit_date) VALUES (?, ?, ?, ?, ?, ?, ?)");
  for (const r of records) insert.run(...r);
  db.close();

  // Deploy contracts
  const Registrar = await ethers.getContractFactory("Registrar");
  const reg = await Registrar.deploy();
  await reg.waitForDeployment();
  const regAddr = await reg.getAddress();

  await (await reg.connect(patient).register("patient-001")).wait();
  await (await reg.connect(provider).register("provider-hospital-A")).wait();

  const pSummary = await reg.summaryOf(patient.address);
  const prSummary = await reg.summaryOf(provider.address);

  const PPR = await ethers.getContractFactory("PPR");
  const ppr = await PPR.deploy(patient.address, provider.address, "localhost:3000", pSummary, prSummary);
  await ppr.waitForDeployment();
  const pprAddr = await ppr.getAddress();

  const dataDb = new Database(DB_PATH, { readonly: true });
  const rows = dataDb.prepare("SELECT * FROM records WHERE patient_id = ?").all("1");
  dataDb.close();
  const dataHash = "0x" + crypto.createHash("sha256").update(JSON.stringify(rows)).digest("hex");
  await (await ppr.connect(provider).addPointer("records:patient_id=1", dataHash)).wait();
  await (await ppr.connect(patient).share(viewer.address, "records:patient_id=1")).wait();

  // ══════════════════════════════════════════════════════════════════════
  // D1: Open SQLite directly — data is plaintext
  // ══════════════════════════════════════════════════════════════════════
  console.log("═══════════════════════════════════════════════════════");
  console.log("  D1: OFF-CHAIN DATA IS PLAINTEXT");
  console.log("═══════════════════════════════════════════════════════");
  console.log("\nAn attacker with storage access reads the SQLite file directly:\n");

  const attackDb = new Database(DB_PATH, { readonly: true });
  const allRecords = attackDb.prepare("SELECT * FROM records").all();
  attackDb.close();

  console.table(allRecords);
  console.log(`\n⚠  ${allRecords.length} records readable in plaintext.`);
  console.log("   The paper describes no encryption of the off-chain data.");
  console.log("   Contract-level encryption was not added to the prototype.\n");

  // ══════════════════════════════════════════════════════════════════════
  // D2: Chain observer — read all contract state and events
  // ══════════════════════════════════════════════════════════════════════
  console.log("═══════════════════════════════════════════════════════");
  console.log("  D2: ON-CHAIN METADATA IS LINKABLE");
  console.log("═══════════════════════════════════════════════════════");
  console.log("\nA passive chain observer reads all contract state:\n");

  // Read Registrar events
  const regContract = new ethers.Contract(regAddr, REGISTRAR_ABI, ethers.provider);
  const regEvents = await regContract.queryFilter("Registered");
  console.log("Registrar — identity-to-address mappings:");
  for (const e of regEvents) {
    console.log(`  Identity "${e.args[1]}" → Address ${e.args[0]} → Summary ${e.args[2]}`);
  }

  // Read PPR state
  console.log(`\nPPR ${pprAddr}:`);
  console.log(`  Patient:  ${await ppr.patient()}`);
  console.log(`  Provider: ${await ppr.provider()}`);

  const ptrCount = await ppr.pointerCount();
  console.log(`  Pointers: ${ptrCount}`);
  for (let i = 0; i < ptrCount; i++) {
    const [sel, hash] = await ppr.pointers(i);
    console.log(`    [${i}] selector="${sel}" hash=${hash}`);
  }

  const viewers = await ppr.getViewers();
  for (const v of viewers) {
    const shares = await ppr.getShares(v);
    console.log(`  Viewer ${v}: [${shares.join(", ")}]`);
  }

  console.log("\n⚠  Who treats whom, who was given access, and when");
  console.log("   are visible to every node on the network.");
  console.log("   The authors note pseudonymous transactions still");
  console.log("   allow forensic analysis of treatment patterns.\n");

  // ══════════════════════════════════════════════════════════════════════
  // D3: Revoke doesn't recall already-fetched data
  // ══════════════════════════════════════════════════════════════════════
  console.log("═══════════════════════════════════════════════════════");
  console.log("  D3: REVOCATION IS FORWARD-LOOKING ONLY");
  console.log("═══════════════════════════════════════════════════════");

  // Viewer fetches data before revocation
  const canViewBefore = await ppr.canView(viewer.address, "records:patient_id=1");
  console.log(`\nBefore revoke: canView = ${canViewBefore}`);

  const fetchedDb = new Database(DB_PATH, { readonly: true });
  const fetchedData = fetchedDb.prepare("SELECT * FROM records WHERE patient_id = ?").all("1");
  fetchedDb.close();
  console.log(`Viewer fetched ${fetchedData.length} records (data is now in their memory).`);

  // Patient revokes
  await (await ppr.connect(patient).revoke(viewer.address, "records:patient_id=1")).wait();
  const canViewAfter = await ppr.canView(viewer.address, "records:patient_id=1");
  console.log(`After revoke: canView = ${canViewAfter}`);

  console.log(`\nBut the viewer still holds the fetched data:`);
  console.table(fetchedData);
  console.log("\n⚠  Revocation cannot recall data already fetched.\n");

  // ══════════════════════════════════════════════════════════════════════
  // D4: Bypass gatekeeper — access data layer directly
  // ══════════════════════════════════════════════════════════════════════
  console.log("═══════════════════════════════════════════════════════");
  console.log("  D4: BYPASS GATEKEEPER — NO CRYPTOGRAPHIC ENFORCEMENT");
  console.log("═══════════════════════════════════════════════════════");
  console.log("\nAn attacker who can reach the database directly (or the");
  console.log("gatekeeper's /direct endpoint) bypasses all permission checks:\n");

  const directDb = new Database(DB_PATH, { readonly: true });
  const directAccess = directDb.prepare("SELECT * FROM records").all();
  directDb.close();

  console.table(directAccess);
  console.log(`\n⚠  ${directAccess.length} records accessed without ANY on-chain permission check.`);
  console.log("   Permission enforcement lives in the gatekeeper code,");
  console.log("   not in cryptography.\n");

  console.log("══ All weakness demos complete ══\n");
}

main().catch(console.error);
