# 01 — Paper Selection

Topic: **Privacy-Preserving Medical Record Sharing System**

## The two shortlisted papers

| | Paper A — MedRec | Paper B — Li et al. (ABE for PHRs) |
|---|---|---|
| Citation | Azaria, Ekblaw, Vieira, Lippman. *MedRec: Using Blockchain for Medical Data Access and Permission Management.* 2016 2nd Int. Conf. on Open and Big Data (OBD), pp. 25–30. DOI 10.1109/OBD.2016.11 | Li, Yu, Zheng, Ren, Lou. *Scalable and Secure Sharing of Personal Health Records in Cloud Computing Using Attribute-Based Encryption.* IEEE TPDS 24(1), Jan 2013, pp. 131–143. DOI 10.1109/TPDS.2012.97 |
| Core idea | Smart contracts on a blockchain keep **pointers, hashes and permissions**; the medical data itself stays in each provider's own database and is released by a "gatekeeper" after an on-chain permission check. | Patients encrypt each PHR file with **attribute-based encryption** before outsourcing it to a semi-trusted cloud server. Personal domain uses KP-ABE; public (professional) domain uses multi-authority ABE. Supports revocation and break-glass emergency access. |
| Security concept | Blockchain-backed access control, integrity (hashes), auditability | Cryptographically enforced fine-grained access control |
| Stated limitations (by the authors) | Contract-level encryption was not added to the prototype and the paper describes no encryption of the off-chain data; pseudonymous transactions still allow forensic analysis of treatment patterns; scalability unresolved; expiry only suggested; no performance simulation | CNF-only policies across authorities; larger public keys; weak for identity/workflow-based access; experiments on synthetic data, some results in supplementary material |
| Authors' own evaluation | None to reproduce — "simulation of system efficiency" is listed as future work | Timing with PBC library (50 attributes: keygen, encrypt, decrypt each under 0.5 s), analytical comparison table, revocation simulation |

## Scoring (my judgment, 1 = hard / poor, 5 = easy / strong)

| Criterion | MedRec | Li et al. |
|---|---|---|
| Implementable by a student team in about 4–5 weeks | 5 | 2 |
| Tooling is mainstream and installs cleanly | 5 | 2 |
| Produces measurable results (gas, latency, throughput, overhead) | 4 | 4 |
| Limitations are clear and citable | 5 | 4 |
| Room for a meaningful, implementable improvement | 5 | 4 |
| Fit with a JS/TS stack (Hardhat, Node/NestJS, Next.js) | 5 | 2 |
| **Total (max 30)** | **29** | **18** |

Why Li et al. scores low on effort: a faithful reproduction needs pairing-based crypto (the authors used the PBC library), a multi-authority ABE construction, proxy re-encryption for revocation, and a prototype EHR platform. That is a research-lab build, not a course project.

## Decision

**Implement MedRec (Paper A).** Contracts plus a small gatekeeper service plus SQLite is realistic to build, test and benchmark in a few weeks, and the paper hands you the improvement target directly: it says contract-level encryption was not added, describes no encryption of the off-chain data, and acknowledges that transaction patterns remain analysable.

**Use Li et al. (Paper B) as the source of improvement ideas**, not as something to reimplement:
- the file-encryption-key pattern, where each file is encrypted under a random key and only that key is protected by the access policy
- break-glass emergency access with later owner revocation
- lazy revocation, where re-encryption work is deferred instead of done immediately

This also gives you a clean related-work story for the report: Paper A shows what blockchain gives you (auditability, patient-visible permissions), Paper B shows what cryptography gives you (enforcement that does not depend on trusting the server), and your improvement combines them.

## Other papers worth citing in related work

I did not select these, but all were found while searching and fit the topic. Check each one yourself before citing.

| Paper | Why it is useful | Link |
|---|---|---|
| Benaloh, Chase, Horvitz, Lauter — *Patient Controlled Encryption* (CCSW 2009) | Classic argument for patient-held keys and hierarchical sharing; strong motivation for your improvement | https://www.erichorvitz.com/ccsw_2009_benaloh_chase_horvitz_lauter.pdf |
| Liu, Wu, Sun, Du, Guizani — *BMDS* (IEEE ICC 2021), DOI 10.1109/ICC42927.2021.9500966 | Blockchain + IPFS + attribute-based searchable encryption | https://archive.cps-vo.org/node/82930 |
| *A secure and efficient EMR data sharing scheme based on blockchain and proxy re-encryption* (Journal of Cloud Computing, 2024) | Recent blockchain + proxy re-encryption design to contrast with yours | https://journalofcloudcomputing.springeropen.com/articles/10.1186/s13677-024-00608-w |
| *A Blockchain-based approach and Attribute-based Encryption for Healthcare Record Data Exchange* (BABEHealth) | Evaluates transaction latency, encryption size change and encryption time, similar to your planned metrics | https://inseclab.uit.edu.vn/a-blockchain-based-approach-and-attribute-based-encryption-for-healthcare-record-data-exchange/ |
| *MedChain: A Privacy Preserving Framework* (SAI, vol. 17 no. 6) | Very recent related work on blockchain, IPFS and proxy re-encryption | https://thesai.org/Downloads/Volume17No6/Paper_52-MedChain_A_Privacy_Preserving_Framework.pdf |
