# Privacy-Preserving Medical Record Sharing System — Project Pack

## The decision

- **Paper to implement:** MedRec (Azaria et al., 2016). Smart contracts hold pointers, hashes and permissions; the data stays in the provider's database behind a gatekeeper.
- **Paper that feeds the improvement:** Li et al. (IEEE TPDS 2013), attribute-based encryption for personal health records. Its file-key pattern and break-glass idea are reused, but it is not reimplemented because it needs pairing cryptography and is too heavy for a course timeline.
- **Improvement ("MedRec+"):** encrypt records and wrap keys per viewer, reduce what a chain observer can link, and add expiring grants (optionally emergency break-glass access). The MedRec paper describes no encryption of the off-chain data (contract-level encryption was left out of the prototype) and its authors acknowledge that pseudonymous transactions still reveal treatment patterns, so the improvement targets a documented gap.

## What is in this zip

| File | Purpose |
|---|---|
| `01_paper_selection.md` | The two papers, scoring, why MedRec wins, other papers for related work |
| `02_implementation_plan_baseline.md` | How to build MedRec: architecture, contract sketch, schedule, baseline metrics, weakness demos |
| `03_improvement_plan.md` | Challenges, threat model, MedRec+ design, hypotheses and experiments, priorities |
| `04_report_roadmap.md` | Maps your teacher's nine sections to what you build, plus a checklist against the six instructions |
| `papers/README_papers.md` | Citations, download links, instructions to add the PDFs |
| `papers/references.bib` | BibTeX |
| `code/envelope.selftest.js` | Tested Node.js example of the encryption and key-wrapping core (`node envelope.selftest.js`, needs only Node.js) |

## The research PDFs are not included

My workspace blocks downloads from the paper websites, so I could not save the PDF files into the zip. `papers/README_papers.md` has the direct links and exact filenames; drop the PDFs into `papers/`. If you attach them in chat I can rebuild the zip with them inside.

## Suggested order of work

1. Read `01` and confirm the choice with your teacher or group.
2. Follow `02` for the baseline (about three weeks of effort), collecting the baseline numbers as you go.
3. Follow `03`, finishing the "Must" tier first.
4. Use `04` while writing the report.

## What I verified and what is yours to check

Verified by reading the papers' text: the three-contract design, off-chain storage, the authors' stated limitations for MedRec, and Li et al.'s domains, revocation, break-glass and evaluation setup. The scoring table and the improvement design are my own judgment. Gas, latency and linkability numbers will come from your own experiments; none are quoted here. Check regulation references (DPDP Act, ABDM, HIPAA) before citing them.
