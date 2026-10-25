/**
 * Integration tests for the Gatekeeper service.
 * Tests the full flow: signed request → permission check → data retrieval → integrity.
 *
 * Runs seamlessly in-memory via `npx hardhat test`
 * or over HTTP if GATEKEEPER_URL is specified.
 */

const { expect } = require("chai");
const { ethers } = require("hardhat");
const crypto = require("crypto");
const Database = require("better-sqlite3");
const path = require("path");
const { seedDatabase } = require("../client/deploy");
const { app, setProvider } = require("../gatekeeper/index");

describe("Gatekeeper Integration Tests", function () {
  let gatekeeperUrl;
  let deployer, patient, provider, viewer, stranger;
  let ppr, pprAddr;

  async function signRequest(wallet, contractAddr, selector, customNonce, customTimestamp) {
    const nonce = customNonce || crypto.randomUUID();
    const timestamp = customTimestamp !== undefined ? customTimestamp : Date.now();
    const message = JSON.stringify({ ppr: contractAddr, selector, nonce, timestamp });
    const signature = await wallet.signMessage(message);
    return { ppr: contractAddr, selector, nonce, timestamp, signature };
  }

  async function queryGatekeeper(body) {
    if (gatekeeperUrl) {
      const res = await fetch(`${gatekeeperUrl}/query`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      return { status: res.status, body: await res.json() };
    }

    // In-memory invocation (no network socket required)
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

  before(async function () {
    [deployer, patient, provider, viewer, stranger] = await ethers.getSigners();

    // 1. Seed database with synthetic records
    await seedDatabase();

    // 2. Set provider on gatekeeper
    setProvider(ethers.provider);
    if (process.env.GATEKEEPER_URL) {
      gatekeeperUrl = process.env.GATEKEEPER_URL;
    }

    // 3. Deploy contracts & initialize relationship
    const Registrar = await ethers.getContractFactory("Registrar");
    const reg = await Registrar.deploy();
    await reg.waitForDeployment();

    await (await reg.connect(patient).register("int-patient")).wait();
    await (await reg.connect(provider).register("int-provider")).wait();

    const PPRFactory = await ethers.getContractFactory("PPR");
    ppr = await PPRFactory.deploy(
      patient.address,
      provider.address,
      "localhost:3000",
      await reg.summaryOf(patient.address),
      await reg.summaryOf(provider.address)
    );
    await ppr.waitForDeployment();
    pprAddr = await ppr.getAddress();

    // 4. Add data pointer with valid SHA-256 hash of patient 1's records
    const DB_PATH = path.join(__dirname, "..", "data", "provider.db");
    const db = new Database(DB_PATH, { readonly: true });
    const rows = db.prepare("SELECT * FROM records WHERE patient_id = ?").all("1");
    db.close();

    const dataHash = "0x" + crypto.createHash("sha256").update(JSON.stringify(rows)).digest("hex");
    await (await ppr.connect(provider).addPointer("records:patient_id=1", dataHash)).wait();
    await (await ppr.connect(patient).share(viewer.address, "records:patient_id=1")).wait();
  });

  it("permits authorized viewer and verifies data hash integrity", async function () {
    const req = await signRequest(viewer, pprAddr, "records:patient_id=1");
    const { status, body } = await queryGatekeeper(req);

    expect(status).to.equal(200);
    expect(body.data).to.be.an("array");
    expect(body.data.length).to.be.greaterThan(0);
    expect(body.integrity.match).to.be.true;
    expect(body.warning).to.be.null;
  });

  it("rejects unauthorized stranger with 403 Forbidden", async function () {
    const req = await signRequest(stranger, pprAddr, "records:patient_id=1");
    const { status, body } = await queryGatekeeper(req);

    expect(status).to.equal(403);
    expect(body.error).to.include("Permission denied");
  });

  it("rejects replayed nonce with 401 Unauthorized", async function () {
    const req = await signRequest(viewer, pprAddr, "records:patient_id=1");
    const res1 = await queryGatekeeper(req);
    expect(res1.status).to.equal(200);

    const res2 = await queryGatekeeper(req);
    expect(res2.status).to.equal(401);
    expect(res2.body.error).to.equal("Replayed nonce");
  });

  it("rejects stale timestamp with 401 Unauthorized", async function () {
    const staleTime = Date.now() - 120_000; // 2 minutes ago
    const req = await signRequest(viewer, pprAddr, "records:patient_id=1", null, staleTime);
    const { status, body } = await queryGatekeeper(req);

    expect(status).to.equal(401);
    expect(body.error).to.equal("Stale timestamp");
  });

  it("rejects revoked viewer with 403 Forbidden", async function () {
    const sel = "records:patient_id=2";
    await (await ppr.connect(provider).addPointer(sel, ethers.ZeroHash)).wait();
    await (await ppr.connect(patient).share(viewer.address, sel)).wait();

    // Verify access before revoke
    const reqBefore = await signRequest(viewer, pprAddr, sel);
    const resBefore = await queryGatekeeper(reqBefore);
    expect(resBefore.status).to.equal(200);

    // Patient revokes
    await (await ppr.connect(patient).revoke(viewer.address, sel)).wait();

    // Verify access after revoke
    const reqAfter = await signRequest(viewer, pprAddr, sel);
    const resAfter = await queryGatekeeper(reqAfter);
    expect(resAfter.status).to.equal(403);
  });

  it("detects data tampering when database content does not match on-chain hash", async function () {
    // Add pointer with a dummy mismatched hash
    const fakeHash = "0x" + "11".repeat(32);
    const sel = "records:patient_id=3";
    await (await ppr.connect(provider).addPointer(sel, fakeHash)).wait();
    await (await ppr.connect(patient).share(viewer.address, sel)).wait();

    const req = await signRequest(viewer, pprAddr, sel);
    const { status, body } = await queryGatekeeper(req);

    expect(status).to.equal(200);
    expect(body.integrity.match).to.be.false;
    expect(body.warning).to.include("possible tampering");
  });
});
