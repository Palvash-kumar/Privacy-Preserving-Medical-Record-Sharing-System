/**
 * MedRec+ Deployment and Encrypted Seeding Script
 *
 * Implements:
 * - E1: AES-256-GCM bulk encryption + X25519 key wrapping
 * - E2: Pseudonymous registration & hidden selector commitments
 * - E3: Time-bound grants with expiry
 * - E4: Emergency break-glass setup
 */

const { ethers } = require("hardhat");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const {
  generateKeyPair,
  exportPublicKey,
  exportPrivateKey,
  encryptRecord,
  wrapKey,
  serializeWrappedKey,
  computeSelectorCommit,
} = require("../gatekeeper/crypto-envelope");
const { SYNTHETIC_RECORDS } = require("./deploy");

const DB_PATH = path.join(__dirname, "..", "data", "provider.db");
const STATE_PLUS_PATH = path.join(__dirname, "..", "data", "deploy-state-plus.json");

async function seedEncryptedDatabase(patientKeyPair) {
  const dir = path.dirname(DB_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  const db = new Database(DB_PATH);
  db.exec(`
    CREATE TABLE IF NOT EXISTS records_encrypted (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      record_id TEXT NOT NULL UNIQUE,
      patient_id TEXT NOT NULL,
      ciphertext_blob BLOB NOT NULL,
      digest TEXT NOT NULL,
      created_at TEXT NOT NULL
    )
  `);

  db.exec("DELETE FROM records_encrypted");

  const insert = db.prepare(
    "INSERT INTO records_encrypted (record_id, patient_id, ciphertext_blob, digest, created_at) VALUES (?, ?, ?, ?, ?)"
  );

  const encryptedRecords = [];

  for (let i = 0; i < SYNTHETIC_RECORDS.length; i++) {
    const raw = SYNTHETIC_RECORDS[i];
    const recordId = `rec-synthetic-${i + 1}`;
    const recordBytes = Buffer.from(JSON.stringify(raw));

    // AES-256-GCM with recordId as AAD
    const { dek, blob, digest } = encryptRecord(recordBytes, recordId);

    // Provider wraps DEK for patient
    const wrappedForPatient = wrapKey(dek, patientKeyPair.publicKey);
    const serializedKey = serializeWrappedKey(wrappedForPatient);

    insert.run(recordId, raw.patient_id, blob, digest, new Date().toISOString());

    encryptedRecords.push({
      recordId,
      patientId: raw.patient_id,
      dek,
      blob,
      digest,
      wrappedForPatient: serializedKey.toString("hex"),
    });
  }

  db.close();
  console.log(`✓ Seeded ${SYNTHETIC_RECORDS.length} encrypted records (zero plaintext columns in records_encrypted)`);
  return encryptedRecords;
}

async function deployPlusSystem() {
  const signers = await ethers.getSigners();
  const [deployer, patient, provider, viewer, emergencyRole] = signers;

  console.log("\n══ Deploying MedRec+ System ══\n");

  // 1. Generate X25519 encryption keypairs for participants
  const patientKeys = generateKeyPair();
  const providerKeys = generateKeyPair();
  const viewerKeys = generateKeyPair();
  const emergencyKeys = generateKeyPair();

  // 2. Seed encrypted SQLite database
  const encryptedRecords = await seedEncryptedDatabase(patientKeys);

  // 3. Deploy RegistrarPlus (no identifying strings on-chain)
  const RegistrarPlus = await ethers.getContractFactory("RegistrarPlus");
  const regPlus = await RegistrarPlus.deploy();
  await regPlus.waitForDeployment();
  const regAddr = await regPlus.getAddress();
  console.log(`✓ RegistrarPlus deployed at: ${regAddr}`);

  // Register participants with X25519 public keys
  await (await regPlus.connect(patient).register(exportPublicKey(patientKeys.publicKey))).wait();
  await (await regPlus.connect(provider).register(exportPublicKey(providerKeys.publicKey))).wait();
  await (await regPlus.connect(viewer).register(exportPublicKey(viewerKeys.publicKey))).wait();
  console.log("✓ Patient, Provider, and Viewer registered pseudonymously");

  const pSummaryAddr = await regPlus.summaryOf(patient.address);
  const prSummaryAddr = await regPlus.summaryOf(provider.address);

  // 4. Deploy PPRPlus
  const PPRPlus = await ethers.getContractFactory("PPRPlus");
  const pprPlus = await PPRPlus.deploy(
    patient.address,
    provider.address,
    "localhost:3000",
    pSummaryAddr,
    prSummaryAddr
  );
  await pprPlus.waitForDeployment();
  const pprAddr = await pprPlus.getAddress();
  console.log(`✓ PPRPlus deployed at: ${pprAddr}`);

  // 5. Add pointer for patient 1 with hidden selector commitment
  const salt = crypto.randomBytes(16).toString("hex");
  const selectorText = "records:patient_id=1";
  const selectorCommit = computeSelectorCommit(selectorText, salt);
  const patient1Record = encryptedRecords[0];

  await (await pprPlus.connect(provider).addPointer(selectorCommit, patient1Record.digest)).wait();
  console.log(`✓ Pointer added with hidden selector commitment: ${selectorCommit}`);
  console.log(`  Digest: ${patient1Record.digest}`);

  // 6. Patient shares time-bound access with Viewer (wraps DEK to Viewer's public key)
  const wrappedForViewer = wrapKey(patient1Record.dek, viewerKeys.publicKey);
  const serializedViewerKey = serializeWrappedKey(wrappedForViewer);

  const oneHourExpiry = Math.floor(Date.now() / 1000) + 3600;
  await (await pprPlus.connect(patient).share(
    viewer.address,
    selectorCommit,
    oneHourExpiry,
    serializedViewerKey
  )).wait();
  console.log(`✓ Patient shared access with Viewer until timestamp ${oneHourExpiry}`);

  // 7. Configure Emergency Access (E4)
  await (await pprPlus.connect(patient).setEmergencyRole(emergencyRole.address)).wait();
  await (await pprPlus.connect(patient).setEmergencySelector(selectorCommit, true)).wait();
  console.log(`✓ Emergency role configured: ${emergencyRole.address}`);

  const state = {
    registrarPlus: regAddr,
    pprPlus: pprAddr,
    patient: patient.address,
    provider: provider.address,
    viewer: viewer.address,
    emergencyRole: emergencyRole.address,
    selectorText,
    salt,
    selectorCommit,
    recordId: patient1Record.recordId,
    dataHash: patient1Record.digest,
    keys: {
      patient: {
        publicKey: exportPublicKey(patientKeys.publicKey).toString("hex"),
        privateKey: exportPrivateKey(patientKeys.privateKey).toString("hex"),
      },
      viewer: {
        publicKey: exportPublicKey(viewerKeys.publicKey).toString("hex"),
        privateKey: exportPrivateKey(viewerKeys.privateKey).toString("hex"),
      },
      emergency: {
        publicKey: exportPublicKey(emergencyKeys.publicKey).toString("hex"),
        privateKey: exportPrivateKey(emergencyKeys.privateKey).toString("hex"),
      },
    },
    deployedAt: new Date().toISOString(),
  };

  fs.writeFileSync(STATE_PLUS_PATH, JSON.stringify(state, null, 2));
  console.log(`✓ MedRec+ state saved to ${STATE_PLUS_PATH}\n`);
  return state;
}

if (require.main === module) {
  deployPlusSystem().catch(console.error);
}

module.exports = { seedEncryptedDatabase, deployPlusSystem };
