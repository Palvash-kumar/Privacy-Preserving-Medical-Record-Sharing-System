# Privacy-Preserving Medical Record Sharing System — Project Pack

## The decision

- **Paper to implement:** MedRec (Azaria et al., 2016). Smart contracts hold pointers, hashes and permissions; the data stays in the provider's database behind a gatekeeper.
- **Paper that feeds the improvement:** Li et al. (IEEE TPDS 2013), attribute-based encryption for personal health records. Its file-key pattern and break-glass idea are reused, but it is not reimplemented because it needs pairing cryptography and is too heavy for a course timeline.
- **Improvement ("MedRec+"):** encrypt records and wrap keys per viewer, reduce what a chain observer can link, and add expiring grants (optionally emergency break-glass access). The MedRec paper describes no encryption of the off-chain data (contract-level encryption was left out of the prototype) and its authors acknowledge that pseudonymous transactions still reveal treatment patterns, so the improvement targets a documented gap.

## What is in this directory

| File / Folder | Purpose |
|---|---|
| `medrec-lab/` | Implementation of MedRec baseline: Solidity contracts, Gatekeeper service, benchmarks, weakness demos, and CLI |
| `01_paper_selection.md` | The two papers, scoring, why MedRec wins, other papers for related work |
| `02_implementation_plan_baseline.md` | How to build MedRec: architecture, contract sketch, schedule, baseline metrics, weakness demos |
| `03_improvement_plan.md` | Challenges, threat model, MedRec+ design, hypotheses and experiments, priorities |
| `04_report_roadmap.md` | Maps your teacher's nine sections to what you build, plus a checklist against the six instructions |
| `papers/README_papers.md` | Citations, download links, instructions to add the PDFs |
| `papers/references.bib` | BibTeX |
| `code/envelope.selftest.js` | Tested Node.js example of the encryption and key-wrapping core (`node envelope.selftest.js`, needs only Node.js) |

## How to Run

### 1. Prerequisites & Installation

Ensure you have Node.js (v18+) installed.

```bash
cd medrec-lab
npm install
```

---

### 2. Quick Automated Tests & Benchmarks (Single Command)

All tests run against a built-in ephemeral blockchain node and complete in seconds:

- **Smart Contract Test Suite (15 unit tests):**
  ```bash
  npm test
  ```
- **MedRec Baseline Weakness Demos (D1–D4):**
  ```bash
  npm run demo:weakness
  ```
  *(Demonstrates plaintext database, linkable on-chain metadata, forward-only revocation, and gatekeeper bypass)*
- **Chain Observer & Graph Reconstruction:**
  ```bash
  npm run demo:observer
  ```
- **Gas Benchmark (B1–B2):**
  ```bash
  npm run bench:gas
  ```
  *(Outputs results to `bench/results/gas-bench.csv`)*
- **Latency Benchmark (B3/B5/B6):**
  ```bash
  npm run bench:latency
  ```
  *(Outputs results to `bench/results/latency-bench.csv`)*
- **MedRec+ Cryptographic Key-Wrapping Self-Test:**
  ```bash
  node ../code/envelope.selftest.js
  ```
  *(Zero dependencies; tests AES-256-GCM + X25519 ECIES envelope encryption)*

---

### 3. Interactive Multi-Process System (Node + Gatekeeper + CLI)

To test the live distributed architecture across independent processes:

1. **Terminal 1 — Start Local Blockchain Node:**
   ```bash
   cd medrec-lab
   npm run node
   ```
   *(Runs Hardhat node at `http://127.0.0.1:8545`)*

2. **Terminal 2 — Deploy Contracts & Seed Database:**
   ```bash
   cd medrec-lab
   npm run deploy -- --network localhost
   ```
   *(Deploys Registrar & PPR contracts, seeds SQLite provider DB, and writes `data/deploy-state.json`)*

3. **Terminal 2 — Start Gatekeeper Service:**
   ```bash
   npm run gatekeeper
   ```
   *(Starts HTTP Gatekeeper on `http://127.0.0.1:3000`)*

4. **Terminal 3 — Run Client CLI Workflows:**
   ```bash
   cd medrec-lab

   # View current relationship & permission status
   node client/cli.js status

   # Authorized viewer retrieval (200 OK + data verified against on-chain hash)
   node client/cli.js retrieve --role viewer

   # Patient retrieves own records
   node client/cli.js retrieve --role patient

   # Patient revokes viewer access on-chain
   node client/cli.js revoke

   # Viewer retrieval re-attempt (fails with 403 Forbidden)
   node client/cli.js retrieve --role viewer

   # Patient restores viewer access
   node client/cli.js share
   ```

5. **Terminal 3 — Run Gatekeeper Integration Tests:**
   ```bash
   npx hardhat run test/gatekeeper-integration.js --network localhost
   ```

---

## Suggested order of work

1. Read `01` and confirm the choice with your teacher or group.
2. Follow `02` for the baseline (about three weeks of effort), collecting the baseline numbers as you go.
3. Follow `03`, finishing the "Must" tier first.
4. Use `04` while writing the report.

## What I verified and what is yours to check

Verified by reading the papers' text: the three-contract design, off-chain storage, the authors' stated limitations for MedRec, and Li et al.'s domains, revocation, break-glass and evaluation setup. The scoring table and the improvement design are my own judgment. Gas, latency and linkability numbers will come from your own experiments; none are quoted here. Check regulation references (DPDP Act, ABDM, HIPAA) before citing them.

