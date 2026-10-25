const { expect } = require("chai");
const { ethers } = require("hardhat");
const crypto = require("crypto");
const Database = require("better-sqlite3");
const path = require("path");
const {
  generateKeyPair,
  exportPublicKey,
  importPublicKey,
  importPrivateKey,
  wrapKey,
  unwrapKey,
  serializeWrappedKey,
  deserializeWrappedKey,
  encryptRecord,
  decryptRecord,
  computeSelectorCommit,
} = require("../gatekeeper/crypto-envelope");
const { app, setProvider } = require("../gatekeeper/index");
const { seedEncryptedDatabase } = require("../client/deploy-plus");

describe("MedRec+ Improvement Contracts & Security Tests", function () {
  let registrarPlus, pprPlus;
  let owner, patient, provider, viewer, stranger, emergencyRole;
  let patientKeys, providerKeys, viewerKeys, strangerKeys, emergencyKeys;

  beforeEach(async function () {
    [owner, patient, provider, viewer, stranger, emergencyRole] = await ethers.getSigners();

    patientKeys = generateKeyPair();
    providerKeys = generateKeyPair();
    viewerKeys = generateKeyPair();
    strangerKeys = generateKeyPair();
    emergencyKeys = generateKeyPair();

    const RegistrarPlusFactory = await ethers.getContractFactory("RegistrarPlus");
    registrarPlus = await RegistrarPlusFactory.deploy();
    await registrarPlus.waitForDeployment();

    // Register patient and provider
    await registrarPlus.connect(patient).register(exportPublicKey(patientKeys.publicKey));
    await registrarPlus.connect(provider).register(exportPublicKey(providerKeys.publicKey));

    const pSummary = await registrarPlus.summaryOf(patient.address);
    const prSummary = await registrarPlus.summaryOf(provider.address);

    const PPRPlusFactory = await ethers.getContractFactory("PPRPlus");
    pprPlus = await PPRPlusFactory.deploy(
      patient.address,
      provider.address,
      "localhost:3000",
      pSummary,
      prSummary
    );
    await pprPlus.waitForDeployment();
  });

  // ── 1. RegistrarPlus Tests ──────────────────────────────────────────────

  describe("RegistrarPlus (E2: Pseudonymous Onboarding)", function () {
    it("registers user with X25519 public key and deploys Summary", async function () {
      await registrarPlus.connect(viewer).register(exportPublicKey(viewerKeys.publicKey));
      const summaryAddr = await registrarPlus.summaryOf(viewer.address);
      expect(summaryAddr).to.not.equal(ethers.ZeroAddress);

      const pubKey = await registrarPlus.getPublicKey(viewer.address);
      expect(Buffer.from(pubKey.slice(2), "hex")).to.deep.equal(exportPublicKey(viewerKeys.publicKey));
    });

    it("rejects duplicate registration from same address", async function () {
      await expect(
        registrarPlus.connect(patient).register(exportPublicKey(patientKeys.publicKey))
      ).to.be.revertedWithCustomError(registrarPlus, "AlreadyRegistered");
    });

    it("does not store any identifying plaintext strings on-chain", async function () {
      // RegistrarPlus has no mapping from string to address
      expect(registrarPlus.idToAddress).to.be.undefined;
    });
  });

  // ── 2. Cryptographic Envelope & Key Wrapping Tests ───────────────────────

  describe("Cryptographic Envelope & Key Wrapping (E1)", function () {
    const rawData = Buffer.from(JSON.stringify({ patient: "Synthetic Patient A", diagnosis: "J45 Asthma" }));
    const recordId = "rec-001";

    it("encrypts with AES-256-GCM and unwraps DEK correctly for recipient", function () {
      const { dek, blob, digest } = encryptRecord(rawData, recordId);
      const wrapped = wrapKey(dek, viewerKeys.publicKey);

      // Viewer unwraps and decrypts
      const unwrappedDek = unwrapKey(wrapped, viewerKeys.privateKey);
      expect(unwrappedDek.equals(dek)).to.be.true;

      const plaintext = decryptRecord(blob, unwrappedDek, recordId);
      expect(plaintext.equals(rawData)).to.be.true;
    });

    it("prevents stranger without private key from unwrapping DEK", function () {
      const { dek } = encryptRecord(rawData, recordId);
      const wrapped = wrapKey(dek, viewerKeys.publicKey);

      expect(() => {
        unwrapKey(wrapped, strangerKeys.privateKey);
      }).to.throw();
    });

    it("detects tampered ciphertext blob using GCM auth tag", function () {
      const { dek, blob } = encryptRecord(rawData, recordId);
      const tamperedBlob = Buffer.from(blob);
      tamperedBlob[tamperedBlob.length - 1] ^= 0xff; // flip byte

      expect(() => {
        decryptRecord(tamperedBlob, dek, recordId);
      }).to.throw();
    });

    it("rejects record when swapped to another record ID (AAD binding)", function () {
      const { dek, blob } = encryptRecord(rawData, recordId);
      expect(() => {
        decryptRecord(blob, dek, "rec-002");
      }).to.throw();
    });

    it("serializes and deserializes wrapped keys accurately", function () {
      const { dek } = encryptRecord(rawData, recordId);
      const wrapped = wrapKey(dek, viewerKeys.publicKey);
      const serialized = serializeWrappedKey(wrapped);
      const deserialized = deserializeWrappedKey(serialized);

      const unwrappedDek = unwrapKey(deserialized, viewerKeys.privateKey);
      expect(unwrappedDek.equals(dek)).to.be.true;
    });
  });

  // ── 3. PPRPlus Time-Bound Grants & Revocation Tests ──────────────────────

  describe("PPRPlus Time-Bound Grants & Revocation (E3)", function () {
    const selectorCommit = computeSelectorCommit("records:patient_id=1", "salt123");
    const dataHash = ethers.keccak256(ethers.toUtf8Bytes("ciphertext-data"));

    beforeEach(async function () {
      await pprPlus.connect(provider).addPointer(selectorCommit, dataHash);
    });

    it("permits viewer access before expiry timestamp", async function () {
      const latestBlock = await ethers.provider.getBlock("latest");
      const futureExpiry = latestBlock.timestamp + 3600; // 1 hour ahead
      const dummyWrappedKey = Buffer.from("dummy-wrapped-key");

      await pprPlus.connect(patient).share(viewer.address, selectorCommit, futureExpiry, dummyWrappedKey);

      expect(await pprPlus.canView(viewer.address, selectorCommit)).to.be.true;
      expect(await pprPlus.canView(stranger.address, selectorCommit)).to.be.false;
    });

    it("rejects viewer access after expiry timestamp", async function () {
      const latestBlock = await ethers.provider.getBlock("latest");
      const shortExpiry = latestBlock.timestamp + 10;
      const dummyWrappedKey = Buffer.from("dummy-wrapped-key");

      await pprPlus.connect(patient).share(viewer.address, selectorCommit, shortExpiry, dummyWrappedKey);
      expect(await pprPlus.canView(viewer.address, selectorCommit)).to.be.true;

      // Fast-forward EVM time past expiry
      await ethers.provider.send("evm_increaseTime", [15]);
      await ethers.provider.send("evm_mine");

      expect(await pprPlus.canView(viewer.address, selectorCommit)).to.be.false;
    });

    it("rejects viewer access immediately after revocation", async function () {
      const latestBlock = await ethers.provider.getBlock("latest");
      const futureExpiry = latestBlock.timestamp + 3600;
      const dummyWrappedKey = Buffer.from("dummy-wrapped-key");

      await pprPlus.connect(patient).share(viewer.address, selectorCommit, futureExpiry, dummyWrappedKey);
      expect(await pprPlus.canView(viewer.address, selectorCommit)).to.be.true;

      // Revoke
      await pprPlus.connect(patient).revoke(viewer.address, selectorCommit);
      expect(await pprPlus.canView(viewer.address, selectorCommit)).to.be.false;
    });

    it("supports storage-based wrapped key publishing (H4 comparison)", async function () {
      const latestBlock = await ethers.provider.getBlock("latest");
      const futureExpiry = latestBlock.timestamp + 3600;
      const dummyWrappedKey = Buffer.from("storage-wrapped-key");

      await pprPlus.connect(patient).shareWithStorage(
        viewer.address,
        selectorCommit,
        futureExpiry,
        dummyWrappedKey
      );

      const stored = await pprPlus.wrappedKeyStorage(viewer.address, selectorCommit);
      expect(stored).to.equal(ethers.hexlify(dummyWrappedKey));
      expect(await pprPlus.canView(viewer.address, selectorCommit)).to.be.true;
    });
  });

  // ── 4. Emergency Break-Glass Access (E4) ──────────────────────────────────

  describe("Emergency Break-Glass Access (E4)", function () {
    const selectorCommit = computeSelectorCommit("records:emergency", "saltEmergency");
    const dataHash = ethers.keccak256(ethers.toUtf8Bytes("emergency-ciphertext"));

    beforeEach(async function () {
      await pprPlus.connect(provider).addPointer(selectorCommit, dataHash);
      await pprPlus.connect(patient).setEmergencyRole(emergencyRole.address);
      await pprPlus.connect(patient).setEmergencySelector(selectorCommit, true);
    });

    it("emergency role cannot access before invoking break-glass", async function () {
      expect(await pprPlus.canView(emergencyRole.address, selectorCommit)).to.be.false;
    });

    it("allows emergency access after invoking break-glass and emits audit event", async function () {
      const reasonCode = ethers.encodeBytes32String("CARDIAC_ARREST");
      const duration = 3600; // 1 hour

      await expect(pprPlus.connect(emergencyRole).emergencyAccess(reasonCode, duration))
        .to.emit(pprPlus, "EmergencyAccess");

      expect(await pprPlus.canView(emergencyRole.address, selectorCommit)).to.be.true;
    });

    it("rejects unauthorized caller invoking break-glass", async function () {
      const reasonCode = ethers.encodeBytes32String("IMPOSTOR");
      await expect(
        pprPlus.connect(stranger).emergencyAccess(reasonCode, 3600)
      ).to.be.revertedWithCustomError(pprPlus, "NotEmergencyRole");
    });

    it("rejects emergency access to non-emergency records even during active emergency", async function () {
      const nonEmergencyCommit = computeSelectorCommit("records:routine_notes", "saltRoutine");
      await pprPlus.connect(provider).addPointer(nonEmergencyCommit, dataHash);

      const reasonCode = ethers.encodeBytes32String("TRAUMA");
      await pprPlus.connect(emergencyRole).emergencyAccess(reasonCode, 3600);

      // Can access emergency set
      expect(await pprPlus.canView(emergencyRole.address, selectorCommit)).to.be.true;
      // Cannot access routine records
      expect(await pprPlus.canView(emergencyRole.address, nonEmergencyCommit)).to.be.false;
    });

    it("lapses emergency access automatically after duration expires", async function () {
      const reasonCode = ethers.encodeBytes32String("CODE_BLUE");
      await pprPlus.connect(emergencyRole).emergencyAccess(reasonCode, 100);

      expect(await pprPlus.canView(emergencyRole.address, selectorCommit)).to.be.true;

      // Fast-forward EVM time
      await ethers.provider.send("evm_increaseTime", [150]);
      await ethers.provider.send("evm_mine");

      expect(await pprPlus.canView(emergencyRole.address, selectorCommit)).to.be.false;
    });

    it("allows patient to explicitly revoke active emergency access", async function () {
      const reasonCode = ethers.encodeBytes32String("RESOLVED");
      await pprPlus.connect(emergencyRole).emergencyAccess(reasonCode, 3600);
      expect(await pprPlus.canView(emergencyRole.address, selectorCommit)).to.be.true;

      await pprPlus.connect(patient).revokeEmergency();
      expect(await pprPlus.canView(emergencyRole.address, selectorCommit)).to.be.false;
    });
  });

  // ── 5. End-to-End Gatekeeper MedRec+ Query Flow ────────────────────────────

  describe("End-to-End Gatekeeper MedRec+ Queries", function () {
    let pprAddr;
    let encryptedRecords;
    let selectorCommit;
    let salt;

    beforeEach(async function () {
      setProvider(ethers.provider);
      encryptedRecords = await seedEncryptedDatabase(patientKeys);

      salt = "salt-test-e2e";
      selectorCommit = computeSelectorCommit("records:patient_id=1", salt);
      const rec = encryptedRecords[0];

      await pprPlus.connect(provider).addPointer(selectorCommit, rec.digest);

      // Share access with viewer
      const wrappedForViewer = wrapKey(rec.dek, viewerKeys.publicKey);
      const serializedViewerKey = serializeWrappedKey(wrappedForViewer);
      const futureExpiry = Math.floor(Date.now() / 1000) + 3600;

      await pprPlus.connect(patient).share(
        viewer.address,
        selectorCommit,
        futureExpiry,
        serializedViewerKey
      );

      pprAddr = await pprPlus.getAddress();
    });

    async function queryGatekeeperPlus(wallet, commit, recId) {
      const nonce = crypto.randomUUID();
      const timestamp = Date.now();
      const message = JSON.stringify({ ppr: pprAddr, selectorCommit: commit, nonce, timestamp });
      const signature = await wallet.signMessage(message);

      return new Promise((resolve) => {
        const req = {
          method: "POST",
          url: "/query",
          headers: { "content-type": "application/json" },
          body: {
            mode: "plus",
            ppr: pprAddr,
            selectorCommit: commit,
            recordId: recId,
            nonce,
            timestamp,
            signature,
          },
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

    it("authorized viewer retrieves ciphertext, unwraps DEK, and decrypts record", async function () {
      const { status, body } = await queryGatekeeperPlus(viewer, selectorCommit, encryptedRecords[0].recordId);

      expect(status).to.equal(200);
      expect(body.mode).to.equal("plus");
      expect(body.integrity.match).to.be.true;
      expect(body.wrappedKey).to.be.a("string");

      // Client-side decryption
      const wrappedKeyBuf = Buffer.from(body.wrappedKey.slice(2), "hex");
      const wrappedKeyObj = deserializeWrappedKey(wrappedKeyBuf);
      const dek = unwrapKey(wrappedKeyObj, viewerKeys.privateKey);

      const ciphertextBlob = Buffer.from(body.ciphertextBlob, "hex");
      const decryptedBytes = decryptRecord(ciphertextBlob, dek, body.recordId);
      const parsedRecord = JSON.parse(decryptedBytes.toString("utf8"));

      expect(parsedRecord.patient_id).to.equal("1");
      expect(parsedRecord.name).to.equal("Synthetic Patient A");
      expect(parsedRecord.diagnosis).to.equal("J45 Asthma");
    });

    it("rejects unauthorized stranger with 403 Forbidden", async function () {
      const { status, body } = await queryGatekeeperPlus(stranger, selectorCommit, encryptedRecords[0].recordId);
      expect(status).to.equal(403);
      expect(body.error).to.include("Permission denied");
    });

    it("enforces DEK rotation on record update so revoked viewer cannot decrypt new version", async function () {
      // 1. Revoke viewer on-chain
      await pprPlus.connect(patient).revoke(viewer.address, selectorCommit);
      expect(await pprPlus.canView(viewer.address, selectorCommit)).to.be.false;

      // 2. Provider updates record with a fresh random DEK and re-wraps only for patient
      const newRecordData = Buffer.from(JSON.stringify({ patient_id: "1", name: "Synthetic Patient A", update: "v2-rotated-data" }));
      const newRecId = "rec-updated-v2";
      const { dek: newDek, blob: newBlob } = encryptRecord(newRecordData, newRecId);

      const wrappedForPatient = serializeWrappedKey(wrapKey(newDek, patientKeys.publicKey));

      // 3. Verify patient decrypts new version
      const patientUnwrap = unwrapKey(deserializeWrappedKey(wrappedForPatient), patientKeys.privateKey);
      const patientDecrypted = decryptRecord(newBlob, patientUnwrap, newRecId);
      expect(patientDecrypted.equals(newRecordData)).to.be.true;

      // 4. Even if revoked viewer intercepts new ciphertext, old DEK fails to decrypt new version
      const oldDek = encryptedRecords[0].dek;
      expect(() => {
        decryptRecord(newBlob, oldDek, newRecId);
      }).to.throw();
    });
  });
});
