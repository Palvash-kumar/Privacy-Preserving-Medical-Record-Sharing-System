# 04 — Report Roadmap

Maps your teacher's nine-section structure to what you build and what goes in each section.

| # | Section (as required) | What to write | Evidence to include |
|---|---|---|---|
| 1 | **Introduction** | Why medical record sharing is a privacy problem (fragmented records, breaches, patient consent). Why it matters in cyber security. Problem statement: sharing records without exposing them to storage insiders or chain observers. Objectives: replicate MedRec, find limitations, add encryption, pseudonymity and expiry, evaluate | Motivation facts with citations. If you cite regulation, verify the exact wording of India's DPDP Act 2023 and the ABDM consent model, or HIPAA, before including |
| 2 | **Overview of the Existing Technique** | MedRec: three contracts, gatekeeper, data stays off-chain, hashes for integrity, mining incentives. Workflow for add-record, retrieve, share. Advantages: patient visibility, immutable log, no central repository. Mention Li et al. briefly as the cryptographic alternative | Architecture figure (redraw the one in `02_...`), table of contracts |
| 3 | **Implementation of the Existing Approach** | Stack, versions, dataset (Synthea), experimental setup, what you skipped and why | Screenshots of tests, CLI flows, gas report, baseline tables B1 to B6 |
| 4 | **Challenges and Limitations** | C1 to C4 with evidence from the authors' own limitations and your demos D1 to D5; impact on security, performance, scalability | Demo screenshots, observer-script output |
| 5 | **Proposed Approach** | Choose C1 + C2 (and C3). Explain E1, E2, E3, optionally E4. Threat model | Architecture and sequence diagrams, pseudocode, ablation modes |
| 6 | **Implementation of the Proposed Approach** | How each feature was built, setup, what changed in contracts and gatekeeper | Code excerpts, test results, `code/envelope.selftest.js` output |
| 7 | **Results and Analysis** | Baseline vs proposed per hypothesis H1 to H7. State plainly where a hypothesis was not supported or the cost was higher than expected | Comparison tables, bar/line/box plots, ablation table, discussion of cost vs benefit |
| 8 | **Conclusion** | What was built, main findings with numbers, effectiveness, limits, future work (ABE, proxy re-encryption, ZK proofs, recovery) | |
| 9 | **References** | Both selected papers plus related work, tools (Hardhat, ethers, Synthea, Node crypto docs) | `papers/references.bib` |

## Check against the teacher's six instructions

| Instruction | How this plan meets it |
|---|---|
| 1. Pick a specific problem within the broad topic | Patient-controlled sharing with off-chain data and on-chain permissions |
| 2. A different approach from other groups on the same topic | MedRec is a popular choice, so differentiate on the improvement, dataset and stack. Ask classmates or your teacher which approaches others picked before you start the improvement phase, and adjust E-features if needed |
| 3. Implement and demonstrate, not just theory | Contracts, gatekeeper, clients, demos |
| 4. Identify at least one significant limitation | C1 and C2, sourced from the paper's own text and your demos |
| 5. Implement and evaluate the improvement | E1, E3 (must), E2 (should), E4 (could) with H1 to H7 |
| 6. Results, tables and graphs | Section 9 of `02_...` and section 5 of `03_...` define the tables and plots |

## Risks and how to handle them

| Risk | Mitigation |
|---|---|
| Time runs out before the improvement | Build E1 and E3 first; they alone give a complete before/after story |
| Blockchain setup friction | Use Hardhat's built-in local node; no external network needed |
| Numbers look noisy | 30 repetitions, warm-up runs, report SD and p95, fix the seed |
| Examiner asks "why not ABE?" | Section 8 of `03_...` has the answer, citing Li et al.'s own limitations |
| Claims you cannot support | Say "in our local test" rather than "in production"; keep the limitations list |

## Suggested figures

1. Baseline architecture
2. Add-record / share / retrieve sequence diagrams
3. Proposed architecture with encryption and key wrapping
4. Gas per operation, baseline vs proposed (bar)
5. Retrieval latency vs payload size (line)
6. Gatekeeper p95 latency by concurrency (box or line)
7. Observer-visible graph before and after pseudonymisation
8. Ablation table: cost of each feature
