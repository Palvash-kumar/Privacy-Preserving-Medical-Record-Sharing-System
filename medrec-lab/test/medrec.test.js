const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("MedRec Baseline Contracts", function () {
  let registrar, owner, patient, provider, viewer;

  beforeEach(async function () {
    [owner, patient, provider, viewer] = await ethers.getSigners();
    const Registrar = await ethers.getContractFactory("Registrar");
    registrar = await Registrar.deploy();
    await registrar.waitForDeployment();
  });

  // ── Registrar ──────────────────────────────────────────────────────────

  describe("Registrar", function () {
    it("registers a user and deploys a Summary", async function () {
      const tx = await registrar.connect(patient).register("patient-001");
      const receipt = await tx.wait();

      const summaryAddr = await registrar.summaryOf(patient.address);
      expect(summaryAddr).to.not.equal(ethers.ZeroAddress);
      expect(await registrar.idToAddress("patient-001")).to.equal(patient.address);
    });

    it("rejects duplicate identity string", async function () {
      await registrar.connect(patient).register("patient-001");
      await expect(
        registrar.connect(provider).register("patient-001")
      ).to.be.revertedWithCustomError(registrar, "AlreadyRegistered");
    });

    it("rejects duplicate address registration", async function () {
      await registrar.connect(patient).register("patient-001");
      await expect(
        registrar.connect(patient).register("patient-002")
      ).to.be.revertedWithCustomError(registrar, "AlreadyRegistered");
    });
  });

  // ── Full flow: PPR lifecycle ───────────────────────────────────────────

  describe("PPR lifecycle", function () {
    let ppr, patientSummary, providerSummary;

    beforeEach(async function () {
      await registrar.connect(patient).register("patient-001");
      await registrar.connect(provider).register("provider-hospital-A");

      const patientSummaryAddr = await registrar.summaryOf(patient.address);
      const providerSummaryAddr = await registrar.summaryOf(provider.address);

      patientSummary = await ethers.getContractAt("Summary", patientSummaryAddr);
      providerSummary = await ethers.getContractAt("Summary", providerSummaryAddr);

      const PPR = await ethers.getContractFactory("PPR");
      ppr = await PPR.deploy(
        patient.address,
        provider.address,
        "localhost:3000",
        patientSummaryAddr,
        providerSummaryAddr
      );
      await ppr.waitForDeployment();
    });

    it("creates PPR and registers in both summaries", async function () {
      expect(await patientSummary.relCount()).to.equal(1);
      expect(await providerSummary.relCount()).to.equal(1);
    });

    it("only provider can add pointers", async function () {
      const hash = ethers.keccak256(ethers.toUtf8Bytes("test-data"));
      await ppr.connect(provider).addPointer("records:patient_id=1", hash);
      expect(await ppr.pointerCount()).to.equal(1);

      await expect(
        ppr.connect(patient).addPointer("records:patient_id=1", hash)
      ).to.be.revertedWithCustomError(ppr, "NotProvider");
    });

    it("only patient can share", async function () {
      await ppr.connect(patient).share(viewer.address, "records:patient_id=1");
      expect(await ppr.canView(viewer.address, "records:patient_id=1")).to.be.true;

      await expect(
        ppr.connect(provider).share(viewer.address, "records:patient_id=1")
      ).to.be.revertedWithCustomError(ppr, "NotPatient");
    });

    it("patient and provider always have access", async function () {
      expect(await ppr.canView(patient.address, "anything")).to.be.true;
      expect(await ppr.canView(provider.address, "anything")).to.be.true;
    });

    it("viewer with no share is rejected", async function () {
      expect(await ppr.canView(viewer.address, "records:patient_id=1")).to.be.false;
    });

    it("revoked viewer is rejected", async function () {
      await ppr.connect(patient).share(viewer.address, "records:patient_id=1");
      expect(await ppr.canView(viewer.address, "records:patient_id=1")).to.be.true;

      await ppr.connect(patient).revoke(viewer.address, "records:patient_id=1");
      expect(await ppr.canView(viewer.address, "records:patient_id=1")).to.be.false;
    });

    it("rejects duplicate share", async function () {
      await ppr.connect(patient).share(viewer.address, "records:patient_id=1");
      await expect(
        ppr.connect(patient).share(viewer.address, "records:patient_id=1")
      ).to.be.revertedWithCustomError(ppr, "AlreadyShared");
    });

    it("rejects revoke for non-shared selector", async function () {
      await expect(
        ppr.connect(patient).revoke(viewer.address, "records:patient_id=1")
      ).to.be.revertedWithCustomError(ppr, "NotShared");
    });

    it("only patient can revoke", async function () {
      await ppr.connect(patient).share(viewer.address, "records:patient_id=1");
      await expect(
        ppr.connect(provider).revoke(viewer.address, "records:patient_id=1")
      ).to.be.revertedWithCustomError(ppr, "NotPatient");
    });

    it("hash integrity: stores and retrieves correct hash", async function () {
      const data = "patient-data-payload";
      const hash = ethers.keccak256(ethers.toUtf8Bytes(data));
      await ppr.connect(provider).addPointer("records:patient_id=1", hash);

      const [selector, storedHash] = await ppr.pointers(0);
      expect(storedHash).to.equal(hash);
    });

    it("emits events for all state changes", async function () {
      const hash = ethers.keccak256(ethers.toUtf8Bytes("data"));

      await expect(ppr.connect(provider).addPointer("sel", hash))
        .to.emit(ppr, "PointerAdded");

      await expect(ppr.connect(patient).share(viewer.address, "sel"))
        .to.emit(ppr, "Shared");

      await expect(ppr.connect(patient).revoke(viewer.address, "sel"))
        .to.emit(ppr, "Revoked");
    });
  });

  // ── Summary status flow ────────────────────────────────────────────────

  describe("Summary status flow", function () {
    it("owner can change status", async function () {
      await registrar.connect(patient).register("patient-001");
      const summaryAddr = await registrar.summaryOf(patient.address);
      const summary = await ethers.getContractAt("Summary", summaryAddr);

      // Need a PPR to have a relationship
      await registrar.connect(provider).register("provider-001");
      const provSummaryAddr = await registrar.summaryOf(provider.address);

      const PPR = await ethers.getContractFactory("PPR");
      const ppr = await PPR.deploy(
        patient.address, provider.address, "localhost:3000",
        summaryAddr, provSummaryAddr
      );
      await ppr.waitForDeployment();

      // Owner sets status
      await summary.connect(patient).setStatus(0, 2); // Acknowledged
      const [, status] = await summary.rels(0);
      expect(status).to.equal(2);
    });
  });
});
