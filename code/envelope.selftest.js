const crypto = require("crypto");

// --- AES-256-GCM helpers -------------------------------------------------
const aesEncrypt = (key, plaintext, aad = Buffer.alloc(0)) => {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", key, iv);
  c.setAAD(aad);
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  return { iv, ct, tag: c.getAuthTag() };
};

const aesDecrypt = (key, { iv, ct, tag }, aad = Buffer.alloc(0)) => {
  const d = crypto.createDecipheriv("aes-256-gcm", key, iv);
  d.setAAD(aad);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
};

// --- ECIES-style key wrapping (X25519 + HKDF-SHA256 + AES-GCM) ----------
const kdf = (shared, info) =>
  Buffer.from(crypto.hkdfSync("sha256", shared, Buffer.alloc(32), info, 32));

const wrapKey = (dek, recipientPublicKey, info = "medrec+/wrap/v1") => {
  const eph = crypto.generateKeyPairSync("x25519");
  const shared = crypto.diffieHellman({
    privateKey: eph.privateKey,
    publicKey: recipientPublicKey,
  });
  const box = aesEncrypt(kdf(shared, info), dek, Buffer.from(info));
  return { epk: eph.publicKey.export({ type: "spki", format: "der" }), ...box };
};

const unwrapKey = (wrapped, recipientPrivateKey, info = "medrec+/wrap/v1") => {
  const epk = crypto.createPublicKey({ key: wrapped.epk, type: "spki", format: "der" });
  const shared = crypto.diffieHellman({ privateKey: recipientPrivateKey, publicKey: epk });
  return aesDecrypt(kdf(shared, info), wrapped, Buffer.from(info));
};

// --- Envelope encryption of one record -----------------------------------
const encryptRecord = (recordBytes, recordId) => {
  const dek = crypto.randomBytes(32);
  const box = aesEncrypt(dek, recordBytes, Buffer.from(recordId));
  const blob = Buffer.concat([box.iv, box.tag, box.ct]);
  const digest = crypto.createHash("sha256").update(blob).digest("hex");
  return { dek, blob, digest };
};

const decryptRecord = (blob, dek, recordId) =>
  aesDecrypt(dek, { iv: blob.subarray(0, 12), tag: blob.subarray(12, 28), ct: blob.subarray(28) }, Buffer.from(recordId));

// --- Self-test ------------------------------------------------------------
const doctor = crypto.generateKeyPairSync("x25519");
const stranger = crypto.generateKeyPairSync("x25519");
const record = Buffer.from(JSON.stringify({ patient: "synthetic-001", dx: "J45", note: "demo" }));

const { dek, blob, digest } = encryptRecord(record, "rec-42");
const wrapped = wrapKey(dek, doctor.publicKey);

const dekBack = unwrapKey(wrapped, doctor.privateKey);
console.log("doctor unwraps DEK:", dekBack.equals(dek));
console.log("doctor decrypts record:", decryptRecord(blob, dekBack, "rec-42").equals(record));

let strangerFailed = false;
try { unwrapKey(wrapped, stranger.privateKey); } catch { strangerFailed = true; }
console.log("stranger cannot unwrap:", strangerFailed);

const tampered = Buffer.from(blob); tampered[tampered.length - 1] ^= 1;
let tamperDetected = false;
try { decryptRecord(tampered, dek, "rec-42"); } catch { tamperDetected = true; }
console.log("tamper detected by GCM:", tamperDetected);

let wrongAad = false;
try { decryptRecord(blob, dek, "rec-43"); } catch { wrongAad = true; }
console.log("record swapped to other id rejected (AAD):", wrongAad);
console.log("sha256 anchor length:", digest.length, "| wrapped bytes (epk+iv+tag+ct):",
  wrapped.epk.length + wrapped.iv.length + wrapped.tag.length + wrapped.ct.length);
