/**
 * Cryptographic Envelope & Key-Wrapping Module for MedRec+
 *
 * Implements ECIES-style envelope encryption:
 * - Data Encryption Key (DEK): Random 256-bit symmetric key per record
 * - Bulk encryption: AES-256-GCM binding record ID as Authenticated Associated Data (AAD)
 * - Key wrapping: Ephemeral X25519 key agreement + HKDF-SHA256 + AES-256-GCM
 * - Digest: SHA-256 of the ciphertext blob (iv | tag | ct)
 */

const crypto = require("crypto");

const INFO_WRAP = "medrec+/wrap/v1";

// ── Key Pair Management ──────────────────────────────────────────────────

function generateKeyPair() {
  return crypto.generateKeyPairSync("x25519");
}

function exportPublicKey(publicKey) {
  return publicKey.export({ type: "spki", format: "der" });
}

function importPublicKey(derBuffer) {
  return crypto.createPublicKey({ key: derBuffer, type: "spki", format: "der" });
}

function exportPrivateKey(privateKey) {
  return privateKey.export({ type: "pkcs8", format: "der" });
}

function importPrivateKey(derBuffer) {
  return crypto.createPrivateKey({ key: derBuffer, type: "pkcs8", format: "der" });
}

// ── AES-256-GCM Helpers ──────────────────────────────────────────────────

function aesEncrypt(key, plaintext, aad = Buffer.alloc(0)) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv, ct, tag };
}

function aesDecrypt(key, { iv, ct, tag }, aad = Buffer.alloc(0)) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

// ── ECIES-style Key Wrapping (X25519 + HKDF + AES-GCM) ────────────────────

function kdf(sharedSecret, info = INFO_WRAP) {
  return Buffer.from(crypto.hkdfSync("sha256", sharedSecret, Buffer.alloc(32), info, 32));
}

function wrapKey(dek, recipientPublicKey, info = INFO_WRAP) {
  const eph = crypto.generateKeyPairSync("x25519");
  const shared = crypto.diffieHellman({
    privateKey: eph.privateKey,
    publicKey: recipientPublicKey,
  });
  const box = aesEncrypt(kdf(shared, info), dek, Buffer.from(info));
  const epk = eph.publicKey.export({ type: "spki", format: "der" });
  return { epk, iv: box.iv, tag: box.tag, ct: box.ct };
}

function unwrapKey(wrapped, recipientPrivateKey, info = INFO_WRAP) {
  const epk = crypto.createPublicKey({ key: wrapped.epk, type: "spki", format: "der" });
  const shared = crypto.diffieHellman({ privateKey: recipientPrivateKey, publicKey: epk });
  return aesDecrypt(kdf(shared, info), wrapped, Buffer.from(info));
}

function serializeWrappedKey(wrapped) {
  // Format: [1 byte epk_len][epk][12 bytes iv][16 bytes tag][ct]
  const epkLen = Buffer.from([wrapped.epk.length]);
  return Buffer.concat([epkLen, wrapped.epk, wrapped.iv, wrapped.tag, wrapped.ct]);
}

function deserializeWrappedKey(buffer) {
  const epkLen = buffer[0];
  let offset = 1;
  const epk = buffer.subarray(offset, offset + epkLen);
  offset += epkLen;
  const iv = buffer.subarray(offset, offset + 12);
  offset += 12;
  const tag = buffer.subarray(offset, offset + 16);
  offset += 16;
  const ct = buffer.subarray(offset);
  return { epk, iv, tag, ct };
}

// ── Record Encryption & Decryption ───────────────────────────────────────

function encryptRecord(recordBytes, recordId) {
  const dek = crypto.randomBytes(32);
  const aad = Buffer.from(String(recordId));
  const box = aesEncrypt(dek, recordBytes, aad);
  // Blob layout: 12 bytes IV + 16 bytes Tag + Ciphertext
  const blob = Buffer.concat([box.iv, box.tag, box.ct]);
  const digest = "0x" + crypto.createHash("sha256").update(blob).digest("hex");
  return { dek, blob, digest };
}

function decryptRecord(blob, dek, recordId) {
  if (blob.length < 28) throw new Error("Invalid ciphertext blob length");
  const iv = blob.subarray(0, 12);
  const tag = blob.subarray(12, 28);
  const ct = blob.subarray(28);
  const aad = Buffer.from(String(recordId));
  return aesDecrypt(dek, { iv, tag, ct }, aad);
}

// ── Commitments (Hidden Selectors) ────────────────────────────────────────

function computeSelectorCommit(selector, salt) {
  return "0x" + crypto.createHash("sha256").update(Buffer.concat([Buffer.from(selector), Buffer.from(salt)])).digest("hex");
}

module.exports = {
  generateKeyPair,
  exportPublicKey,
  importPublicKey,
  exportPrivateKey,
  importPrivateKey,
  wrapKey,
  unwrapKey,
  serializeWrappedKey,
  deserializeWrappedKey,
  encryptRecord,
  decryptRecord,
  computeSelectorCommit,
};
