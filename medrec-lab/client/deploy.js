/**
 * Shared deployment and setup script.
 * Deploys Registrar, registers patient + provider, creates a PPR,
 * seeds the SQLite database with synthetic medical records,
 * and adds on-chain pointers. Used by CLI clients and benchmarks.
 */

const { ethers } = require("hardhat");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

const DB_PATH = path.join(__dirname, "..", "data", "provider.db");
const DEPLOY_STATE_PATH = path.join(__dirname, "..", "data", "deploy-state.json");

// Synthetic medical records (Synthea-style, simplified)
const SYNTHETIC_RECORDS = [
  { patient_id: "1", name: "Synthetic Patient A", dob: "1985-03-15", blood_type: "O+", diagnosis: "J45 Asthma", medication: "Salbutamol 100mcg", visit_date: "2024-01-10" },
  { patient_id: "1", name: "Synthetic Patient A", dob: "1985-03-15", blood_type: "O+", diagnosis: "E11 Type 2 Diabetes", medication: "Metformin 500mg", visit_date: "2024-02-20" },
  { patient_id: "1", name: "Synthetic Patient A", dob: "1985-03-15", blood_type: "O+", diagnosis: "I10 Hypertension", medication: "Amlodipine 5mg", visit_date: "2024-03-05" },
  { patient_id: "2", name: "Synthetic Patient B", dob: "1990-07-22", blood_type: "A-", diagnosis: "K21 GERD", medication: "Omeprazole 20mg", visit_date: "2024-01-15" },
  { patient_id: "2", name: "Synthetic Patient B", dob: "1990-07-22", blood_type: "A-", diagnosis: "M54 Back Pain", medication: "Ibuprofen 400mg", visit_date: "2024-04-01" },
  { patient_id: "3", name: "Synthetic Patient C", dob: "1978-11-30", blood_type: "B+", diagnosis: "J06 Upper Respiratory Infection", medication: "Amoxicillin 500mg", visit_date: "2024-02-10" },
];

async function seedDatabase() {
  const dir = path.dirname(DB_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  // Remove old DB if present
  if (fs.existsSync(DB_PATH)) fs.unlinkSync(DB_PATH);

  const db = new Database(DB_PATH);
  db.exec(`
    CREATE TABLE records (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      patient_id TEXT NOT NULL,
      name TEXT NOT NULL,
      dob TEXT NOT NULL,
      blood_type TEXT NOT NULL,
      diagnosis TEXT NOT NULL,
      medication TEXT NOT NULL,
      visit_date TEXT NOT NULL
    )
  `);

  const insert = db.prepare(
    "INSERT INTO records (patient_id, name, dob, blood_type, diagnosis, medication, visit_date) VALUES (?, ?, ?, ?, ?, ?, ?)"
  );
  for (const r of SYNTHETIC_RECORDS) {
    insert.run(r.patient_id, r.name, r.dob, r.blood_type, r.diagnosis, r.medication, r.visit_date);
  }
  db.close();
  console.log(`✓ Seeded ${SYNTHETIC_RECORDS.length} records into ${DB_PATH}`);
}

async function deployContracts() {
  const signers = await ethers.getSigners();
  const [deployer, patient, provider, viewer] = signers;

  console.log("\n── Deploying MedRec Baseline Contracts ──");
  console.log(`Deployer:  ${deployer.address}`);
  console.log(`Patient:   ${patient.address}`);
  console.log(`Provider:  ${provider.address}`);
  console.log(`Viewer:    ${viewer.address}`);

  // 1. Deploy Registrar
  const Registrar = await ethers.getContractFactory("Registrar");
  const registrar = await Registrar.deploy();
  await registrar.waitForDeployment();
  const regAddr = await registrar.getAddress();
  console.log(`\n✓ Registrar deployed: ${regAddr}`);

  // 2. Register patient & provider
  await (await registrar.connect(patient).register("patient-001")).wait();
  await (await registrar.connect(provider).register("provider-hospital-A")).wait();
  console.log("✓ Patient and Provider registered");

  const patientSummaryAddr = await registrar.summaryOf(patient.address);
  const providerSummaryAddr = await registrar.summaryOf(provider.address);

  // 3. Deploy PPR
  const PPR = await ethers.getContractFactory("PPR");
  const ppr = await PPR.deploy(
    patient.address,
    provider.address,
    "localhost:3000",
    patientSummaryAddr,
    providerSummaryAddr
  );
  await ppr.waitForDeployment();
  const pprAddr = await ppr.getAddress();
  console.log(`✓ PPR deployed: ${pprAddr}`);

  // 4. Add data pointers for patient-001's records
  const db = new Database(DB_PATH, { readonly: true });
  const rows = db.prepare("SELECT * FROM records WHERE patient_id = ?").all("1");
  db.close();

  const selector = "records:patient_id=1";
  const dataJson = JSON.stringify(rows);
  const dataHash = "0x" + crypto.createHash("sha256").update(dataJson).digest("hex");

  await (await ppr.connect(provider).addPointer(selector, dataHash)).wait();
  console.log(`✓ Pointer added: ${selector}`);
  console.log(`  Hash: ${dataHash}`);

  // 5. Patient shares with viewer
  await (await ppr.connect(patient).share(viewer.address, selector)).wait();
  console.log(`✓ Patient shared "${selector}" with viewer ${viewer.address}`);

  // Save state for CLI tools
  const state = {
    registrar: regAddr,
    ppr: pprAddr,
    patientSummary: patientSummaryAddr,
    providerSummary: providerSummaryAddr,
    patient: patient.address,
    provider: provider.address,
    viewer: viewer.address,
    selector,
    dataHash,
    network: "hardhat-local",
    deployedAt: new Date().toISOString(),
  };
  fs.writeFileSync(DEPLOY_STATE_PATH, JSON.stringify(state, null, 2));
  console.log(`\n✓ Deploy state saved to ${DEPLOY_STATE_PATH}`);

  return state;
}

async function main() {
  await seedDatabase();
  await deployContracts();
  console.log("\n══ Baseline deployment complete ══\n");
}

if (require.main === module) {
  main().catch(console.error);
}

module.exports = { seedDatabase, deployContracts, SYNTHETIC_RECORDS, DB_PATH };
