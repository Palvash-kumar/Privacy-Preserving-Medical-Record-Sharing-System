# 03 — Improvement Plan: MedRec+ (encrypted, pseudonymous, time-bound)

## 1. Challenges identified in the existing approach

| ID | Challenge | Evidence | Impact |
|---|---|---|---|
| C1 | **Off-chain data and gatekeeper responses are plaintext; enforcement is only as strong as the gatekeeper code and database** | The paper describes no encryption of the off-chain data and says contract-level encryption was not added to the prototype. Your demos D1 and D4 | A database dump, a storage-level insider or a compromised gatekeeper exposes every record |
| C2 | **On-chain metadata is linkable** | Identity strings in the Registrar, patient–provider links, and viewer addresses in permissions are public. The authors note that pseudonymous transactions still allow forensic analysis of treatment patterns. Demo D2 | Who treats whom, who was given access, and when are visible to every node |
| C3 | **No expiry and no emergency path** | The authors only suggest expiry dates as a contract extension. Demo D3 shows revocation cannot recall data already fetched | Standing access never lapses; urgent care has no safe route |
| C4 | Scalability and block-time cost | The authors list scalability as unresolved | Latency and gas grow with usage (measure with B3 to B5) |

**Primary challenge to address: C1 plus C2.** Together they are the "privacy-preserving" part of the topic. **Secondary: C3.** C4 you only measure and discuss; do not try to solve it.

## 2. Threat model

| Adversary | Capability | In scope? |
|---|---|---|
| A1 Curious storage operator | Reads the provider database and the gatekeeper's stored data, but does **not** hold the key material | Yes |
| A2 Passive chain observer | Reads all contract state, calldata and events | Yes |
| A3 Revoked or expired viewer | Previously authorised; tries to fetch again | Yes |
| A4 Impostor claiming an emergency | Tries to abuse break-glass | Yes (if E4 is built) |
| The provider itself | It created the record and legitimately holds its key | Out of scope. State this plainly: the provider is a data custodian, not an adversary |
| Endpoint malware, side channels, network traffic analysis | | Out of scope. Mention as limitations |

## 3. Proposed design

### E1 — Envelope encryption with per-viewer key wrapping (addresses C1)

- For each record, generate a random 256-bit data key (DEK). Encrypt the record with **AES-256-GCM**, binding the record ID as associated data.
- Wrap the DEK for each authorised party using an ECIES-style construction: ephemeral X25519 key agreement, HKDF-SHA256, AES-GCM. The provider wraps for the patient when the record is created. The patient re-wraps for each viewer when sharing.
- Only ciphertext goes to the provider database. The gatekeeper serves ciphertext. The on-chain hash is the SHA-256 of the ciphertext blob.
- Wrapped keys are published as contract **events** (cheap) or in storage (costly). Comparing the two is one of your experiments.
- Reference code: `code/envelope.selftest.js`. It checks that the right recipient can unwrap and decrypt, a wrong recipient cannot, ciphertext tampering is detected, and a record swapped to another ID is rejected. A wrapped key is 104 bytes with a DER-encoded ephemeral public key (92 bytes if you send the raw 32-byte key).

This follows the file-encryption-key pattern in Li et al., where only a small key is protected by the policy and the bulk data is symmetric. You use public-key wrapping instead of ABE.

```js
// shape of the API you will implement (ES6)
const { dek, blob, digest } = encryptRecord(recordBytes, recordId);   // blob = iv | tag | ciphertext
const wrapped = wrapKey(dek, viewerPublicKey);                        // { epk, iv, tag, ct }
const dekBack = unwrapKey(wrapped, viewerPrivateKey);
const plain   = decryptRecord(blob, dekBack, recordId);
```

### E2 — Reduce on-chain linkability (addresses C2)

1. **Pairwise pseudonymous addresses.** The patient derives a fresh address per provider relationship from an HD wallet (BIP-32 path with an incrementing index), so one patient's relationships do not share an address.
2. **No identity strings on-chain.** Replace the Registrar's `string -> address` mapping with a one-time hand-off: the patient shows a QR code or link carrying the pairwise address and public key; the provider creates the PPR directly to that address. A salted hash can be stored if a lookup is unavoidable, but note that hashes of low-entropy identifiers such as phone or ID numbers can be brute-forced, so use a high-entropy salt shared only with the counterparty.
3. **Hidden selectors.** Store `H(selector ‖ salt)` instead of the selector text in pointers and shares. The salt travels inside the encrypted metadata.

Phasing: E2.1 and E2.3 are quick. E2.2 changes the onboarding flow and is the riskiest, so it is "should", not "must".

### E3 — Time-bound, revocable grants (addresses C3, part 1)

- Replace `shares[viewer]` with `Grant { viewer, selectorCommit, expiresAt, revoked }`.
- `canView` checks `block.timestamp < expiresAt && !revoked`.
- On revoke, the patient rotates the DEK for future versions of the record (new DEK, re-wrap to remaining viewers). Be explicit that this cannot recall data a viewer already decrypted. Li et al. defer re-encryption work with lazy revocation, which you can cite as the inspiration.

### E4 — Break-glass emergency access (addresses C3, part 2; stretch goal)

Inspired by the break-glass mechanism in Li et al.

1. The patient designates an emergency role address (for example an emergency department) and flags a minimal "emergency set" of records (allergies, blood group, current medication).
2. The patient pre-wraps those DEKs to an escrow public key held by the emergency role.
3. In an emergency, authorised staff call `emergencyAccess(ppr, reasonCode)`. The contract emits an `EmergencyAccess` event, sets a short expiry (for example one hour), and notifies the patient's client.
4. The gatekeeper releases only the emergency set while the grant is active.
5. The patient can review the audit trail and revoke afterwards.

Trust assumption to state: the emergency role is trusted to authenticate staff honestly, as in Li et al. Your contribution is that every use is publicly auditable and automatically expires.

## 4. Contract changes at a glance

| Contract | Change |
|---|---|
| Registrar | Remove identity strings (E2.2), or store salted commitments |
| PPR | `Pointer.selector` becomes a salted hash; grants gain `expiresAt` and `revoked`; add `WrappedKey` event; add `emergencyAccess` (E4) |
| Summary | Per-pairwise-address summaries; status handling unchanged |

## 5. Experiments (same harness as the baseline)

Run **ablation modes** so each feature's cost is visible: `baseline`, `+E1`, `+E1+E3`, `+E1+E2+E3`, `+all`.

| ID | Hypothesis | Metric and method | Pass condition |
|---|---|---|---|
| H1 | A storage-level attacker learns nothing from the DB in `+E1` | Script scans the DB file for plaintext fields from Synthea records (demo D1 repeated) | 0 records readable, versus 100 percent in baseline |
| H2 | A chain observer can link far fewer relationships in `+E2` | Observer script builds the patient–provider–viewer graph from state and events; report fraction of PPRs attributable to a real identity and the largest address cluster per patient | Clear reduction versus baseline (report the numbers whatever they are) |
| H3 | Crypto overhead is small relative to end-to-end latency | Encrypt, wrap, unwrap, decrypt time for 1 KB to 50 MB; ciphertext size overhead; share of total retrieval time | Report percentage overhead per size |
| H4 | Extra gas is acceptable, and events are cheaper than storage for wrapped keys | Gas per operation (B1 repeated) in each mode; compare event vs storage | Report absolute and percentage increase |
| H5 | Expired and revoked viewers cannot retrieve | Grant with 5 s expiry, retry before and after; revoke and retry | 0 successful retrievals after the cut-off, within one block |
| H6 | (Stretch) Every break-glass use is auditable | Run 100 emergency accesses; count events and patient notifications | 100 events, 100 notifications, access ends at TTL |
| H7 | Tampering is detected | Flip a byte in stored ciphertext | GCM failure and hash mismatch every time |

Also re-run B3 to B6 on `+all` so Section 7 can show the cost side by side. Present every metric as a table plus at least one graph: bar chart for gas, line chart for latency vs payload size, box plot for p95 latency.

## 6. Priorities

| Tier | Items |
|---|---|
| **Must** | E1 envelope encryption and wrapping; E3 expiry and revoke; H1, H3, H4, H5, H7 |
| **Should** | E2.1 pairwise addresses; E2.3 hidden selectors; H2 observer analysis |
| **Could** | E2.2 handshake onboarding; E4 break-glass; H6; key recovery (backup phrase or provider escrow) |

If time is short, finishing **Must** plus the observer analysis from H2 already satisfies the teacher's requirement of identifying a challenge, implementing an improvement and evaluating it.

## 7. Honest limitations of the improvement

- Revocation cannot undo data already decrypted. DEK rotation protects future versions only.
- Patient key loss means data loss unless you add recovery. Mention it, implement it only if time allows.
- Wrapped keys on-chain are encrypted but still leak that a grant happened and when.
- Network traffic analysis and endpoint compromise are out of scope.
- The provider remains a trusted custodian of its own records.
- Block timing is emulated on a local chain, so absolute latency figures will not match a public network.

## 8. Alternatives considered

| Option | Why not chosen as the main improvement |
|---|---|
| Full CP-ABE or multi-authority ABE | Li et al. themselves note larger keys and policy-language limits, and pairing libraries are hard to build for a course timeline. Cite as future work |
| Proxy re-encryption for sharing | Good fit, and recent blockchain schemes use it (see the 2024 Journal of Cloud Computing paper in `01_paper_selection.md`), but heavier to implement. Mention as an extension |
| Zero-knowledge access proofs | Strongest metadata privacy but well beyond the timeline. Mention as future work |
