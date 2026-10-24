# 02 — Implementation Plan: MedRec (existing approach)

Goal of this phase: build a faithful, working, measurable version of MedRec so that Sections 2, 3 and 4 of your report have real results, and so that Section 7 has a baseline to compare against.

## 1. What to replicate and what to skip

| Replicate (as described in the paper) | Simplify or skip, and say so in the report |
|---|---|
| **Registrar Contract (RC):** maps identity strings to addresses | Proof-of-Work mining and the researcher "bounty" incentive model. Run a local chain instead; today's Ethereum no longer uses PoW |
| **Summary Contract (SC):** per-participant index of relationships, each with a status | Polished GUI. A CLI plus one simple web page is enough |
| **Patient–Provider Relationship contract (PPR):** data pointers (query + hash), provider location, viewer permissions | Raw SQL query strings as pointers. Use record IDs or field-list selectors with parameterized queries (see section 8) |
| **Database Gatekeeper:** verifies a signed request, checks permissions on-chain, runs the query, returns data | Real hospital integration. Use synthetic data |
| Add-record, patient retrieval, and share-with-third-party flows | |
| Integrity check: hash of returned data compared with the on-chain hash | |

## 2. Architecture

```
                         Local EVM chain (Hardhat node)
                 ┌──────────────────────────────────────────┐
                 │  Registrar ──► Summary(patient) ─┐        │
                 │                Summary(provider) ┼► PPR   │
                 │                Summary(viewer)  ─┘ (ptrs, │
                 └───────▲───────────────▲──────────  hashes, │
                         │ tx / events   │ view calls permissions)
   ┌──────────┐   ┌──────┴─────┐   ┌─────┴──────────┐
   │ Patient  │   │ Provider   │   │ Gatekeeper     │   ┌─────────────┐
   │ client   │──►│ client     │   │ (Node service) │──►│ SQLite      │
   │ (wallet) │   │ (wallet)   │   │ verify sig,    │   │ provider DB │
   └────┬─────┘   └────────────┘   │ canView(), SQL │   └─────────────┘
        │  signed request          └───────▲────────┘
        └──────────────────────────────────┘
        Viewer client (doctor / lab) uses the same path
```

## 3. Tech stack

| Layer | Choice | Notes |
|---|---|---|
| Contracts | Solidity + Hardhat, TypeScript tests | Local chain, instant mining; use `hardhat-gas-reporter` for gas tables |
| Gatekeeper | Node.js (NestJS or plain Express) | Signature check with `ethers` (`verifyMessage`) |
| Provider DB | SQLite (the paper's prototype also used SQLite) | One table per record type |
| Clients | Node CLI scripts first; optional Next.js page | CLI is enough for results |
| Synthetic data | Synthea (open-source synthetic patient generator, GitHub: synthetichealth/synthea) | Never use real patient data. Add padded files of 10 KB to 50 MB for size tests |
| Load testing | `autocannon` or `k6` | Throughput and latency |
| Plots | Python `matplotlib` or any JS charting you prefer | Export CSV from the bench scripts first |

Use current LTS Node.js and the latest stable Hardhat and ethers. Record the exact versions in the report.

## 4. Contract sketch (signatures only, not production code)

```solidity
contract Registrar {
  mapping(string => address) public idToAddress;      // identity string -> address (as in the paper)
  mapping(address => address) public summaryOf;       // address -> Summary contract
  function register(string calldata id) external;     // deploys/links a Summary for msg.sender
}

contract Summary {
  address public owner;
  enum Status { New, PendingUpdate, Acknowledged }
  struct Rel { address ppr; Status status; }
  Rel[] public rels;
  function addRelationship(address ppr) external;      // called by PPR creator
  function setStatus(uint idx, Status s) external;     // provider/patient rules per the paper
}

contract PPR {
  address public patient;
  address public provider;
  string  public dbHost;                               // "host:port" of the gatekeeper
  struct Pointer { string selector; bytes32 dataHash; }
  Pointer[] public pointers;
  mapping(address => string[]) public shares;          // viewer -> permitted selectors

  function addPointer(string calldata selector, bytes32 dataHash) external;  // provider only
  function share(address viewer, string calldata selector) external;         // patient only
  function revoke(address viewer, uint idx) external;                        // patient only
  function canView(address who, string calldata selector) external view returns (bool);
  event PointerAdded(address indexed ppr, bytes32 dataHash);
  event Shared(address indexed ppr, address indexed viewer);
}
```

Emit events for every state change. The patient and viewer clients use them for the "you have a new record / new share" notification described in the paper, and your later chain-observer analysis uses them too.

## 5. Gatekeeper request flow

1. Client builds `{ppr, selector, nonce, timestamp}` and signs it with its wallet (`personal_sign`).
2. Gatekeeper recovers the signer, rejects stale timestamps and reused nonces (replay protection).
3. Gatekeeper calls `ppr.canView(signer, selector)` as a read-only call.
4. If allowed, it runs the parameterized query on SQLite.
5. It hashes the result (SHA-256 or keccak256, but be consistent) and compares it with the pointer's on-chain hash. If they differ, return an integrity error.
6. Return the data and write a local access log.

Note for Section 4: in this baseline the access log is **off-chain**, and the response is **plaintext**.

## 6. Repository layout

```
medrec-lab/
  contracts/        Registrar.sol, Summary.sol, PPR.sol
  test/             contract tests + gatekeeper integration tests
  gatekeeper/       service + signature/replay middleware
  client/           patient / provider / viewer CLI
  data/             synthea output + generated large files
  bench/            benchmark scripts, results/*.csv
  analysis/         plot scripts + chain-observer script
  docs/             report drafts, screenshots
```

Plan for a `MODE=baseline|plus` switch from the start (or a `plus/` folder that extends the same interfaces). Running the identical bench harness on both modes is what makes your Section 7 comparison credible.

## 7. Schedule (stretch or compress to your submission date)

| Week | Build | "Done when" | Report section fed |
|---|---|---|---|
| 1 | Read both papers. Contracts RC, SC, PPR with tests | All contract tests pass; gas report prints | 1, 2 |
| 2 | Gatekeeper + SQLite + CLI clients; Synthea data loaded | Add-record, retrieve and share demo works end to end with screenshots | 3 |
| 3 | Baseline measurements and attack demos (sections 9 and 10 below) | CSVs saved, demos scripted, screenshots taken | 3, 4 |

The improvement phase continues in `03_improvement_plan.md`.

## 8. Deviations to document honestly

- **Selectors instead of raw SQL.** The paper stores query strings in the PPR and the gatekeeper runs them. Executing query text that came from a blockchain transaction is a risk by design (injection), so implement selectors as parameterized queries. This is a deviation and also a point you can raise in Section 4 as a consideration. Present it as your own observation, not as a claim by the authors.
- **No mining incentives, local chain.** Block time is emulated; say how.
- **Identity strings.** Keep them on-chain in the baseline as the paper describes. That is exactly what you will critique.

## 9. Baseline measurements (collect now, reuse later)

Run each measurement at least 30 times after 3 warm-up runs. Report mean, standard deviation and p95. Record the machine, OS, Node, Hardhat and ethers versions, and the random seed.

| ID | Metric | Method |
|---|---|---|
| B1 | Gas per operation: register, create PPR, add pointer, share, revoke | `hardhat-gas-reporter` or receipt `gasUsed` |
| B2 | On-chain bytes stored per record pointer | Inspect storage layout / calldata size |
| B3 | End-to-end latency of add-record, share and retrieve, at block time = instant, 2 s and 12 s | Hardhat `mining: { auto: false, interval: ... }` (check the docs for your Hardhat version) |
| B4 | Gatekeeper throughput and p95 latency with 1, 10, 50, 100 concurrent clients | `autocannon` or `k6` |
| B5 | Retrieval latency vs number of pointers in one PPR (10, 100, 1,000) | Loop over a scaled PPR |
| B6 | Payload size effect: 1 KB, 100 KB, 1 MB, 10 MB, 50 MB | Retrieval time and integrity-check time |

## 10. Baseline weakness demos (feed Section 4)

Script each one so it is repeatable and screenshot-ready.

| ID | Demo | What it shows |
|---|---|---|
| D1 | Open the SQLite file directly and print patient records | Off-chain data sits in the clear in your baseline (the paper describes no encryption of it and says contract-level encryption was not added) |
| D2 | Chain-observer script: read all contract state and events, then print who is linked to whom, which viewers hold access, and when | Identity strings, relationships and permissions are readable by anyone on the network |
| D3 | Revoke a viewer after they already fetched a record, then show they still hold the data | Revocation is forward-looking only |
| D4 | Call the gatekeeper's data layer directly, bypassing the contract check | Permission enforcement lives in the gatekeeper code, not in cryptography |
| D5 | (Optional) Send a malicious selector if you implemented raw SQL | Injection risk of executing on-chain query text |

## 11. Test checklist

- Only the provider can add pointers; only the patient can share or revoke.
- A viewer with no share is rejected; a revoked viewer is rejected.
- Replayed request (same nonce) is rejected; stale timestamp is rejected.
- Tampering with a stored row makes the hash comparison fail.
- Registrar rejects duplicate identity registration.
