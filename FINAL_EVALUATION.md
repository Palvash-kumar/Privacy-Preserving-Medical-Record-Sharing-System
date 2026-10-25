# Final Evaluation Summary: MedRec Baseline vs MedRec+ Improvements

## Executive Summary

This document provides the audited technical evaluation of **MedRec** (Azaria et al., 2016) and its privacy-preserving enhancement, **MedRec+**. 

The baseline MedRec architecture pioneered blockchain-based electronic health record (EHR) management by delegating data storage to off-chain provider databases while managing identity, access permissions, and integrity hashes via Ethereum smart contracts. However, empirical analysis and scripted weakness demonstrations revealed four critical architectural limitations:
1. **Plaintext Off-Chain Storage (Challenge C1 / Demo D1)**: Medical records sit unencrypted in SQLite provider databases; direct database extraction or Gatekeeper bypass reveals 100% of patient records in plaintext.
2. **On-Chain Metadata Linkability (Challenge C2 / Demo D2)**: Plaintext identity strings stored in the Registrar and public transactions reveal who treats whom, which doctors hold access, and what treatment types/diagnoses are queried.
3. **Absence of Access Expiry (Challenge C3 / Demo D3)**: Grants persist indefinitely unless manually revoked; furthermore, revocation is forward-looking only and cannot recall data already fetched.
4. **No Audited Emergency Break-Glass Route (Challenge C3)**: Urgent medical care paths without pre-existing grants are unsupported.

To resolve these challenges without the prohibitive pairing overhead of Attribute-Based Encryption (ABE), we implemented and evaluated **MedRec+**:
- **E1 (Envelope Encryption & Per-Viewer Key Wrapping)**: Records are encrypted with AES-256-GCM with unique 256-bit Data Encryption Keys (DEKs). DEKs are wrapped using ECIES (ephemeral X25519 ECDH + HKDF-SHA256 + AES-GCM). The record ID is bound as Authenticated Associated Data (AAD).
- **E2 (Reduced Linkability)**: Replaced on-chain identity strings with pairwise pseudonymous addresses and replaced plaintext query selectors with salted cryptographic commitments $H(\text{selector} \parallel \text{salt})$.
- **E3 (Time-Bound & Revocable Grants)**: Grants enforce expiry timestamps on-chain; record updates following revocation employ DEK rotation.
- **E4 (Emergency Break-Glass Access)**: Designated emergency roles can trigger audited, time-limited emergency grants with public event logging.

---

## 1. Reconciled Experimental Results (Hypotheses H1–H7)

All metrics below are drawn directly from the underlying experiment output files in `medrec-lab/bench/results/`.

> [!NOTE]
> **Methodology & Data Source Clarifications**:
> - **Gas Comparison Methodology**: The side-by-side gas figures below for Baseline vs. MedRec+ are single-run transaction receipts measured directly in `bench/security-experiments.js` under identical EVM state. Baseline gas stability is separately corroborated by 30-run statistical distributions in `bench/results/gas-bench.csv` (e.g., Register mean = 336,401 gas, p95 = 336,404 gas).
> - **H2 Evaluation Source & Scope**: Hypothesis H2 (linkability reduction) is evaluated via `analysis/observer-compare.js` generating `observer-comparison.csv` and `observer-comparison.json`. The separate security experiment harness `bench/security-experiments.js` implements hypotheses H1 and H3–H7. The 0% attribution result reflects the evaluated simulated dataset and observer model; it does not eliminate external side-channel reidentification.
> - **H3 Baseline Crypto Latency & Workload Distinction**: Baseline cryptographic latency reflects strictly SHA-256 calculation for the on-chain pointer `dataHash` (measured in `latency-bench.csv`), whereas MedRec+ measures end-to-end authenticated envelope cryptography (AES-256-GCM record encryption, X25519 key wrapping, unwrapping, and decryption in `security-experiments.csv`), with measured processing times of 0.42–74.97 ms across the tested payload sizes (1 KB to 50 MB). Because these evaluate fundamentally different operations (a standalone digest vs. multi-step public-key envelope encryption), their difference represents a cross-architecture workload comparison rather than a pure marginal overhead measurement. Furthermore, the non-monotonic baseline hash timings (0.15ms for 1 KB vs. 0.04ms for 100 KB) may possibly reflect sub-millisecond timer resolution limits and micro-benchmark measurement noise under V8 runtime optimization.

### Reconciled Side-by-Side Performance & Security Matrix

| Metric / Experiment | Baseline MedRec | MedRec+ Improvement | Empirical Outcome / Verification | Source File |
|---|---|---|---|---|
| **H1: DB Clinical Plaintext Exposure** | **100.0% readable** (6/6 records) | **0.0% readable** (0/6 records) | Tested clinical/demographic fields absent in records_encrypted; metadata (patient_id, timestamps, digests) remains visible | `security-experiments.csv` |
| **H2: Identity Attribution Rate** | **100.0%** (all identities public) | **0.0%** (0/3 attributable) | 0% attributable in evaluated observer simulation; does not preclude real-world reidentification | `observer-comparison.csv` |
| **H2: Plaintext Selectors Leaked** | 2 exposed (`records:...`) | **0 exposed** (salted commitments) | Query semantics and treatment types hidden | `observer-comparison.csv` |
| **H2: Max Address Cluster** | 2 relationships per identity | **1 relationship** per pseudonym | Disjoint pairwise relationship graph | `observer-comparison.csv` |
| **H3: Crypto Overhead (1 KB)** | 0.15ms (hash only) | 0.69ms total crypto | +0.54ms; constant +28B overhead (+2.73%) | `latency-bench.csv` & `security-experiments.csv` |
| **H3: Crypto Overhead (100 KB)** | 0.04ms (hash only) | 0.42ms total crypto | +0.38ms; constant +28B overhead (+0.027%) | `latency-bench.csv` & `security-experiments.csv` |
| **H3: Crypto Overhead (1 MB)** | 0.42ms (hash only) | 2.10ms total crypto | +1.68ms; constant +28B overhead (+0.0027%) | `latency-bench.csv` & `security-experiments.csv` |
| **H3: Crypto Overhead (10 MB)** | 4.06ms (hash only) | 15.74ms total crypto | +11.68ms; constant +28B overhead (+0.0003%) | `latency-bench.csv` & `security-experiments.csv` |
| **H3: Crypto Overhead (50 MB)** | 20.39ms (hash only) | 74.97ms total crypto | +54.58ms; constant +28B overhead (+0.0001%) | `latency-bench.csv` & `security-experiments.csv` |
| **H4: Register Gas Cost** | 336,428 gas | 403,010 gas | +66,582 gas (+19.8% to store X25519 public key) | `security-experiments.csv` |
| **H4: Create PPR Gas Cost** | 1,160,475 gas | 1,268,715 gas | +108,240 gas (+9.3% for enhanced access control) | `security-experiments.csv` |
| **H4: Add Pointer Gas Cost** | 93,822 gas | 115,304 gas | +21,482 gas (+22.9% for commitment + timestamp) | `security-experiments.csv` |
| **H4: Share Access (Event-based)** | 161,579 gas | **166,498 gas** | **+4,919 gas (+3.0%)** minimal event overhead | `security-experiments.csv` |
| **H4: Share Access (Storage-based)** | 161,579 gas | **213,360 gas** | **+51,781 gas (+32.0%)** costly storage write | `security-experiments.csv` |
| **H4: Storage vs Event Overhead** | 166,498 gas (Event) | 213,360 gas (Storage) | Storage is **+46,862 gas (+28.1%)** more expensive | `security-experiments.csv` |
| **H4: Revoke Access Gas Cost** | 35,936 gas | **31,635 gas** | **-4,301 gas (-12.0%)** $O(1)$ boolean update | `security-experiments.csv` |
| **On-chain Calldata Bytes / Pointer** | 132 bytes | 132 bytes | 0 byte calldata size difference | `gas-bench.csv` |
| **H5: Cutoff After Expiry** | Not supported | **100% blocked** (0 leaks) | Denied immediately after TTL timestamp | `security-experiments.csv` |
| **H5: Cutoff After Revoke** | Denied | **100% blocked** (0 leaks) | Immediate revocation enforcement | `security-experiments.csv` |
| **H6: Break-Glass Auditability** | Not supported | **100/100 events caught** | Complete public audit trail of emergency access | `security-experiments.csv` |
| **H7: Tamper Detection (Bit-flip)** | SHA-256 mismatch only | **100% GCM + Hash rejected** | Dual cryptographic defense against altered bytes | `security-experiments.csv` |
| **H7: Tamper Detection (AAD swap)** | Not detected | **100% AAD rejected** | Records bound cryptographically to record ID | `security-experiments.csv` |

---

## 2. Benchmark Findings & Scalability Analysis

### B1 & H4: Gas Cost & Publishing Mechanism
- In the baseline MedRec contract, sharing a record cost 161,579 gas (single-run transaction receipt in `security-experiments.js`; 30-run baseline mean is 161,543 gas in `gas-bench.csv`).
- In MedRec+, publishing wrapped keys as **contract events** (`KeyWrapped`) incurred **166,498 gas** (+3.0% over baseline), whereas writing them to contract storage required **213,360 gas** (+32.0% over baseline).
- This empirically confirms hypothesis **H4**: *event-based wrapped key publishing saves 46,862 gas (28.1% cheaper than storage) while allowing authorized clients to retrieve wrapped keys off-chain by filtering events*.
- Furthermore, revocation in MedRec+ (31,635 gas) is **12.0% cheaper** than baseline (35,936 gas) because MedRec+ updates `grant.revoked = true` in $O(1)$ instead of shifting array elements.
- *Methodology Note*: The comparative gas values reflect exact, deterministic single-run execution receipts captured under identical EVM state in `bench/security-experiments.js`. Baseline operational consistency across runs is separately established in `bench/results/gas-bench.csv` (30 runs per operation).

### B3: Block Mining Latency
- Under instant automining, transaction confirmation took **0.67ms** (mean) and **0.93ms** (p95). Read-only calls (`canView`) took **0.28ms** (mean) and **0.53ms** (p95).
- Under 2-second block interval mining, latency scaled to **2,014.56ms** (mean, sd = 4.39ms, p95 = 2,020.64ms).
- Under 12-second block interval mining (emulating modern Ethereum L1 block time), latency scaled to **12,011.94ms** (mean, sd = 20.26ms, p95 = 12,035.30ms).
- *Observation*: Transaction latency is overwhelmingly governed by the blockchain consensus interval rather than smart contract execution overhead.

### B4: Concurrent Throughput & Scalability (Dual-Mode Measurement)
Across 3,220 total executed benchmark requests:
- **Baseline Mode**:
  - 1 client: 219.8 req/s (mean 4.55ms, p95 22.29ms)
  - 10 clients: 484.7 req/s (mean 19.88ms, p95 21.67ms)
  - 50 clients: 502.8 req/s (mean 95.73ms, p95 106.72ms)
  - 100 clients: 509.0 req/s (mean 189.29ms, p95 229.85ms)
- **MedRec+ Mode**:
  - 1 client: 341.1 req/s (mean 2.93ms, p95 4.90ms)
  - 10 clients: 441.1 req/s (mean 21.92ms, p95 23.74ms)
  - 50 clients: 434.7 req/s (mean 111.15ms, p95 128.15ms)
  - 100 clients: 426.8 req/s (mean 226.52ms, p95 304.89ms)
- *Analysis of Variance*: At low concurrency (1 client), MedRec+ was slightly faster because it looked up a single primary-key indexed record (`record_id`) rather than scanning `patient_id`. Under high concurrency (100 clients), baseline achieved 509.0 req/s vs MedRec+ 426.8 req/s due to the additional cryptographic overhead of resolving wrapped keys and verifying commitments. Zero errors occurred in either mode.

### H3: Payload Size & Cryptographic Overhead
- Measured MedRec+ envelope-cryptography processing times ranged from **0.42 ms to 74.97 ms** across tested payload sizes (1 KB to 50 MB), while baseline hash timings measure a different workload:
  - 1 KB: 0.69ms total crypto (Encrypt 0.17ms, Wrap 0.36ms, Unwrap 0.14ms, Decrypt 0.02ms) vs 0.15ms baseline hash (+0.54ms difference)
  - 100 KB: 0.42ms total crypto (Encrypt 0.11ms, Wrap 0.15ms, Unwrap 0.10ms, Decrypt 0.06ms) vs 0.04ms baseline hash (+0.38ms difference)
  - 1 MB: 2.10ms total crypto (Encrypt 1.21ms, Wrap 0.22ms, Unwrap 0.13ms, Decrypt 0.54ms) vs 0.42ms baseline hash (+1.68ms difference)
  - 10 MB: 15.74ms total crypto (Encrypt 9.24ms, Wrap 0.33ms, Unwrap 0.12ms, Decrypt 6.05ms) vs 4.06ms baseline hash (+11.68ms difference)
  - 50 MB: 74.97ms total crypto (Encrypt 53.37ms, Wrap 0.92ms, Unwrap 0.15ms, Decrypt 20.53ms) vs 20.39ms baseline hash (+54.58ms difference)
- *Workload Distinction & Measurement Nuance*: Baseline latency reflects strictly SHA-256 calculation for the pointer hash (`latency-bench.csv`), as baseline records are stored unencrypted, whereas MedRec+ performs end-to-end authenticated envelope cryptography (AES-GCM encryption, X25519 key wrapping, unwrapping, and decryption). Because these represent fundamentally different operations (a standalone digest vs. multi-step public-key envelope encryption), their arithmetic difference is a cross-architecture workload comparison rather than a pure marginal overhead measurement. In addition, the non-monotonic baseline hash timings (0.15ms for 1 KB vs. 0.04ms for 100 KB) may possibly reflect sub-millisecond timer resolution limits and micro-benchmark measurement noise under V8 runtime optimization.
- Ciphertext expansion is strictly constant: **exactly 28 bytes** (12-byte IV + 16-byte GCM authentication tag), regardless of payload size.

---

## 3. Audited Threat Model & Privacy Analysis

### Adversary A1: Curious Storage Operator (Database Dump)
- **Baseline**: An operator or insider who inspects `provider.db` reads 100% of patient records in plaintext (Demo D1).
- **MedRec+ (Tested Clinical Payload Scope)**: The `records_encrypted` table stores `ciphertext_blob`, `digest`, `record_id`, and `patient_id`. Across the 6 evaluated synthetic records, all tested clinical and demographic plaintext fields (`name`, `dob`, `blood_type`, `diagnosis`, `medication`, `visit_date`) were completely absent from cleartext storage and confined to encrypted blobs. Without the authorized viewer's X25519 private key to unwrap the DEK, the clinical payload cannot be decrypted (**H1 verified: 0.0% clinical plaintext exposure across tested fields**).
- **Residual Storage Metadata Leakage (Honest Scope)**:
  1. *Patient Encounter Clustering*: `patient_id` is a static provider-internal identifier (e.g., `"1"`), not an anonymous or pairwise pseudonymous token. An adversary with database access can cluster multiple encounters belonging to the same internal patient and observe visit frequencies.
  2. *Structural & Temporal Metadata*: `record_id` and `created_at` expose sequential record identifiers and unencrypted insertion timestamps.
  3. *Ciphertext Length Side-Channel*: AES-256-GCM expands payload size by a deterministic constant 28 bytes without padding ($L_{ct} = L_{pt} + 28$); variations in ciphertext length can reveal approximate plaintext payload sizes.
  4. *Cross-Layer Digest Correlation*: The off-chain `digest` matches the on-chain pointer `dataHash`. While digest matching alone does not reveal a patient's real-world identity, it permits an observer with access to both datasets to correlate an off-chain database row with a specific on-chain transaction or pointer.
- **Direct Database Bypass (Demo D4)**: Even if an attacker calls the Gatekeeper's unauthenticated `/direct/records_encrypted` endpoint or accesses the SQLite file directly, they receive only AES-GCM ciphertext blobs and table metadata without the DEK.

### Adversary A2: Passive Chain Observer (Scope & Residual Risks)
- **Baseline**: Reads all contract state and events, reconstructing the complete social and medical graph: which patient visited which hospital, which doctor was granted access, and what diagnoses were queried (Demo D2).
- **MedRec+ Scope & Result**:
  - On-chain string names are eliminated in `RegistrarPlus` (0.0% identity attribution vs 100.0% in baseline within the evaluated simulated dataset and observer model).
  - Selectors are stored as salted SHA-256 commitments $H(\text{selector} \parallel \text{salt})$, preventing observers from reading query text or treatment types.
  - Pairwise pseudonymous patient addresses yield a disconnected graph with max cluster size = 1 (vs cluster size = 2 in baseline).
  - *Evaluation Scope*: The 0.0% identity attribution metric strictly evaluates that on-chain identity strings are absent from the registry contract and that the simulated observer script cannot map addresses to identities via public contract calls. It does not imply that real-world reidentification is impossible, as external side channels and transaction graph topology persist.
- **Residual Linkability Risks (Honest Disclosure)**:
  1. *Gas Funding Linkability*: If all pairwise pseudonymous addresses are funded from the same primary wallet or exchange account, transaction graph clustering can link them together.
  2. *Temporal Correlation*: If a transaction on-chain coincides with an in-person clinic visit, an external observer with physical or operational metadata can correlate the pseudonym with the patient.
  3. *Counterparty Exposure*: Public `Shared` events still reveal provider and viewer addresses and block timestamps, leaking that an interaction occurred between those parties.
  4. *Network Traffic Analysis*: Gatekeeper HTTP queries leak client IP addresses unless routed through an anonymity network (e.g. Tor or VPN).

### Adversary A3: Revoked or Expired Viewer
- **Baseline**: Revocation removes the viewer on-chain, but the viewer retains already-fetched data indefinitely (Demo D3), and standing access never lapses.
- **MedRec+**: Grants enforce explicit block timestamp expiries. At the Gatekeeper, every retrieval verifies active on-chain status before releasing ciphertext.
- **DEK Rotation & Forward Revocation**: When records are updated following a revocation, a fresh random DEK is generated for the new record version and wrapped *only* for active viewers. Even if a revoked viewer intercepts the new ciphertext, their old DEK fails to decrypt it (**Tested in `medrec-plus.test.js`**).

### Adversary A4: Emergency Impostor
- **Baseline**: No emergency mechanism exists.
- **MedRec+**: Break-glass access is restricted to an authorized emergency role address. Emergency access auto-expires after a short TTL (max 24 hours) and emits an immutable `EmergencyAccess` event for auditing. Unauthorized callers revert on-chain (**H6 verified: 100% audit logging**).

---

## 4. Test Suite Audit & Categorization

To distinguish formal automated regression test suites from exploratory or supplemental scripts:

### Formal Automated Regression Suite (Mocha / Hardhat)

| Category | Count | Status | Description |
|---|---|---|---|
| **Contract Unit Tests (Baseline)** | 15 | Passed | Mocha tests verifying `Registrar`, `Summary`, and `PPR` access control (`test/medrec.test.js`) |
| **Gatekeeper Integration Tests** | 6 | Passed | Mocha in-memory tests verifying signature, replay, freshness, and tampering (`test/gatekeeper-integration.js`) |
| **MedRec+ & Security Unit Tests** | 21 | Passed | Mocha tests verifying `RegistrarPlus`, `PPRPlus`, time-bounds, revocation, emergency break-glass, Gatekeeper query, and DEK rotation (`test/medrec-plus.test.js`) |
| **Total Automated Regression Suite** | **42** | **Passed** | **Executed via `npm test` in ~620ms (0 failures, 0 skipped, 100% pass rate)** |

### Supplemental Scripted Evaluations & Demonstrations

| Evaluation Category | Actions / Items | Status | Source Script | Description & Overlap Notes |
|---|---|---|---|---|
| **Envelope Self-Tests** | 5 | Executed | `code/envelope.selftest.js` | Standalone Node.js crypto checks; logic overlaps tests in `medrec-plus.test.js` |
| **Weakness Demos (D1–D4)** | 4 | Executed | `analysis/weakness-demos.js` | Scripted illustrative vulnerability demonstrations (cleartext DB, linkability, forward revoke, direct bypass) |
| **Observer Experiments (D2 & H2)** | 2 | Executed | `analysis/chain-observer.js` & `analysis/observer-compare.js` | Scripted graph reconstructions and linkability reduction measurements |
| **Security Hypotheses (H1, H3–H7)** | 6 | Executed | `bench/security-experiments.js` | Scripted benchmark harness evaluating storage scan, crypto overhead, gas, cutoff, break-glass, tampering |
| **Total Supplemental Evaluations** | **17** | **Executed** | Multiple scripts | 8 experiment runs associated with persisted CSV/JSON artifacts; 9 console-based checks/demonstrations lack persistent execution logs |

> [!NOTE]
> The project maintains **42 formal automated Mocha tests** (all passing). The 17 supplemental actions comprise 5 overlapping standalone crypto assertions, 4 illustrative vulnerability demos, 2 graph-reconstruction observer runs, and 6 security benchmark experiments. Of these 17 actions, 8 experiment runs are associated with persisted CSV/JSON artifacts in `bench/results/`, while 9 console-based checks and demonstrations (5 envelope checks and 4 weakness demos) lack persistent execution logs and print directly to the console; they are recorded as scripted evaluation procedures rather than formally logged or passing test suites.

---

## 5. Honest Limitations & Trust Assumptions

1. **Forward-Looking Revocation**: As demonstrated in D3, revocation cannot retroactively delete data that an authorized viewer already fetched and saved locally. Cryptographic DEK rotation protects all *future* versions and updates, but historical leakage requires legal and operational remedies (e.g. HIPAA / GDPR / DPDP compliance).
2. **Key Custody & Recovery**: If a patient loses their private X25519 key, they lose access to their encrypted records. A production implementation would require social recovery or encrypted provider key escrow.
3. **Provider Custodianship**: The healthcare provider that generates the medical record legitimately holds the raw plaintext at the point of care. The system protects against curious third parties, compromised Gatekeepers, and storage operators, but the medical provider remains a trusted data custodian.
4. **Block Timing Emulation**: Block timing was emulated on an isolated Hardhat local chain; absolute latency figures on public testnets or mainnets will reflect variable network propagation delays and gas pricing dynamics.

---

## 6. Artifact Directory Index

All evaluation data, test suites, and charts are generated and reproducible in the repository:

- **Progress Tracker**: `PROJECT_PROGRESS.md`
- **Charts**:
  - `medrec-lab/bench/results/chart-gas-comparison.svg`
  - `medrec-lab/bench/results/chart-latency-payload.svg`
  - `medrec-lab/bench/results/chart-throughput-latency.svg`
- **CSV Data**:
  - `medrec-lab/bench/results/gas-bench.csv`
  - `medrec-lab/bench/results/latency-bench.csv`
  - `medrec-lab/bench/results/throughput-bench.csv`
  - `medrec-lab/bench/results/security-experiments.csv`
  - `medrec-lab/bench/results/observer-comparison.csv`
- **JSON Reports**:
  - `medrec-lab/bench/results/security-experiments.json`
  - `medrec-lab/bench/results/observer-comparison.json`
  - `medrec-lab/bench/results/observer-report.json`
