# Privacy-Preserving Medical Record Sharing System (MedRec + MedRec+)

This repository contains the complete implementation, security evaluations, benchmarks, and progress documentation for:
1. **MedRec Baseline** (Azaria et al., 2016): Smart contracts manage pointers, hashes, and access permissions while medical records reside off-chain behind an authenticating Gatekeeper.
2. **MedRec+ Privacy & Security Improvements**: E1 envelope encryption (AES-256-GCM + X25519 ECIES key wrapping), E2 pairwise pseudonymous addresses and hidden salted commitments, E3 time-bound expiring grants and DEK rotation, and E4 emergency break-glass access.

---

## Repository Map

| File / Directory | Description |
|---|---|
| `PROJECT_PROGRESS.md` | Single source of truth tracking all 36 requirements, test statistics, and side-by-side results |
| `FINAL_EVALUATION.md` | Comprehensive evaluation summary, threat model verification, and honest limitations |
| `medrec-lab/contracts/` | Solidity contracts: `Registrar.sol`, `Summary.sol`, `PPR.sol` (baseline) + `PPRPlus.sol`, `RegistrarPlus.sol` (MedRec+) |
| `medrec-lab/gatekeeper/` | Dual-mode Gatekeeper service (`index.js`) and cryptographic envelope library (`crypto-envelope.js`) |
| `medrec-lab/client/` | Deployment and CLI workflows: `cli.js` & `deploy.js` (baseline) + `cli-plus.js` & `deploy-plus.js` (MedRec+) |
| `medrec-lab/test/` | Automated test suites: `medrec.test.js` (contracts), `gatekeeper-integration.js` (Gatekeeper), `medrec-plus.test.js` (MedRec+ & security) |
| `medrec-lab/bench/` | Benchmarks: `gas-bench.js`, `latency-bench.js`, `throughput-bench.js`, `security-experiments.js`, `generate-charts.js` |
| `medrec-lab/analysis/` | Weakness and observer scripts: `weakness-demos.js` (D1–D4), `chain-observer.js` (D2), `observer-compare.js` (H2) |
| `medrec-lab/bench/results/` | CSV benchmarks, JSON reports, and generated SVG visualization charts |
| `code/envelope.selftest.js` | Standalone zero-dependency self-test for AES-256-GCM + X25519 key wrapping |

---

## Quick Start & Verification

### 1. Installation

Ensure Node.js (v18+) is installed:

```bash
cd medrec-lab
npm install
```

### 2. Run All Automated Tests (41 Tests in < 1 Second)

Executes all contract unit tests, Gatekeeper in-process integration tests, cryptographic envelope tests, and security tests:

```bash
npm test
```

*Output summary: 41 passing (0 failures).*

### 3. Run Security Experiments (H1–H7)

Runs the comprehensive security evaluation suite (database plaintext scan H1, cryptographic overhead H3, gas ablation H4, access cutoff H5, emergency break-glass H6, and tamper detection H7):

```bash
npm run bench:security
```

*Outputs CSV and JSON reports to `bench/results/security-experiments.csv` and `bench/results/security-experiments.json`.*

### 4. Run Linkability & Observer Analysis (D2 & H2)

- **Baseline Chain Observer (D2):**
  ```bash
  npm run demo:observer
  ```
- **Side-by-Side Linkability Comparison (H2 Baseline vs MedRec+):**
  ```bash
  npm run demo:compare
  ```

*Outputs to `bench/results/observer-comparison.csv` and `bench/results/observer-report.json`.*

### 5. Run Baseline Weakness Demonstrations (D1–D4)

Demonstrates plaintext database exposure (D1), metadata linkability (D2), forward-only revocation (D3), and direct database bypass (D4):

```bash
npm run demo:weakness
```

### 6. Run Performance Benchmarks (B1–B6)

- **Gas Benchmark (B1–B2):**
  ```bash
  npm run bench:gas
  ```
  *(Outputs to `bench/results/gas-bench.csv`)*

- **Latency Benchmark (B3, B5, B6):**
  ```bash
  npm run bench:latency
  ```
  *(Measures instant, 2s, and 12s mining intervals; outputs to `bench/results/latency-bench.csv`)*

- **Concurrent Client Throughput (B4):**
  ```bash
  npm run bench:throughput
  ```
  *(Measures 1, 10, 50, 100 concurrent clients; outputs to `bench/results/throughput-bench.csv`)*

- **Generate SVG Charts:**
  ```bash
  npm run charts
  ```
  *(Generates `chart-gas-comparison.svg`, `chart-latency-payload.svg`, and `chart-throughput-latency.svg` in `bench/results/`)*

---

## Interactive CLI Workflows

### MedRec+ Workflows (`client/cli-plus.js`)

1. **Deploy MedRec+ & Seed Encrypted Database:**
   ```bash
   npm run deploy:plus
   ```

2. **Retrieve and Decrypt Record (Viewer Role):**
   ```bash
   node client/cli-plus.js retrieve --role viewer
   ```
   *(Gatekeeper returns ciphertext blob; client unwraps DEK using X25519 private key and decrypts via AES-256-GCM)*

3. **Check PPRPlus State & Expiry Timestamps:**
   ```bash
   node client/cli-plus.js status
   ```

4. **Revoke Viewer Access:**
   ```bash
   node client/cli-plus.js revoke
   ```

5. **Attempt Retrieval as Revoked Viewer (Fails with 403 Forbidden):**
   ```bash
   node client/cli-plus.js retrieve --role viewer
   ```

6. **Trigger Break-Glass Emergency Access:**
   ```bash
   node client/cli-plus.js emergency "ACUTE_MYOCARDIAL_INFARCTION" 3600
   node client/cli-plus.js retrieve --role emergency
   ```

---

### Baseline Workflows (`client/cli.js`)

1. **Deploy Baseline System:**
   ```bash
   npm run deploy
   ```

2. **Retrieve Plaintext Records:**
   ```bash
   node client/cli.js retrieve --role viewer
   ```

3. **Revoke and Share:**
   ```bash
   node client/cli.js revoke
   node client/cli.js share
   ```
