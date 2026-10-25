/**
 * Gatekeeper Service — MedRec baseline & MedRec+ (dual mode)
 *
 * Verifies signed requests, checks on-chain permissions via PPR.canView() / PPRPlus.canView(),
 * runs parameterised queries on SQLite, and verifies data integrity (hash).
 *
 * Baseline: Plaintext records returned.
 * MedRec+ (E1-E4): Only encrypted ciphertext returned; keys wrapped per-viewer;
 *                  hidden selector commitments verified; expiry enforced on-chain.
 */

const express = require("express");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const { ethers } = require("ethers");
const path = require("path");
const fs = require("fs");

// ── ABIs ─────────────────────────────────────────────────────────────────
const PPR_BASELINE_ABI = [
  "function canView(address who, string calldata selector) external view returns (bool)",
  "function pointers(uint256 idx) external view returns (string selector, bytes32 dataHash)",
  "function pointerCount() external view returns (uint256)",
];

const PPR_PLUS_ABI = [
  "function canView(address who, bytes32 selectorCommit) external view returns (bool)",
  "function pointers(uint256 idx) external view returns (bytes32 selectorCommit, bytes32 dataHash, uint64 createdAt)",
  "function pointerCount() external view returns (uint256)",
  "function wrappedKeyStorage(address viewer, bytes32 selectorCommit) external view returns (bytes)",
  "event KeyWrapped(address indexed ppr, address indexed viewer, bytes32 indexed selectorCommit, bytes wrappedKey)",
];

// ── Configuration ────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const RPC_URL = process.env.RPC_URL || "http://127.0.0.1:8545";
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "..", "data", "provider.db");

// ── State ────────────────────────────────────────────────────────────────
const usedNonces = new Set();
const TIMESTAMP_WINDOW_MS = 60_000; // 60s

// ── Express app ──────────────────────────────────────────────────────────
const app = express();
app.use(express.json({ limit: "50mb" }));

let ethProvider;

function getDB() {
  return new Database(DB_PATH, { readonly: true });
}

function setProvider(provider) {
  ethProvider = provider;
}

function getEthProvider() {
  if (!ethProvider) {
    ethProvider = new ethers.JsonRpcProvider(RPC_URL);
  }
  return ethProvider;
}

/**
 * POST /query
 *
 * Body:
 *  Baseline: { ppr, selector, nonce, timestamp, signature }
 *  MedRec+:  { ppr, selectorCommit, recordId, nonce, timestamp, signature, mode: "plus" }
 */
app.post("/query", async (req, res) => {
  try {
    const { ppr: pprAddr, selector, selectorCommit, recordId, nonce, timestamp, signature, mode } = req.body;

    if (!pprAddr || !nonce || !timestamp || !signature) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const isPlusMode = mode === "plus" || Boolean(selectorCommit);

    // 1. Recover signer from signature
    const messageContent = isPlusMode
      ? { ppr: pprAddr, selectorCommit, nonce, timestamp }
      : { ppr: pprAddr, selector, nonce, timestamp };

    const message = JSON.stringify(messageContent);
    let signer;
    try {
      signer = ethers.verifyMessage(message, signature);
    } catch {
      return res.status(401).json({ error: "Invalid signature" });
    }

    // 2. Replay & timestamp freshness protection
    const now = Date.now();
    if (Math.abs(now - timestamp) > TIMESTAMP_WINDOW_MS) {
      return res.status(401).json({ error: "Stale timestamp" });
    }
    if (usedNonces.has(nonce)) {
      return res.status(401).json({ error: "Replayed nonce" });
    }
    usedNonces.add(nonce);

    const provider = getEthProvider();

    // ── MEDREC+ MODE ─────────────────────────────────────────────────────
    if (isPlusMode) {
      if (!selectorCommit) {
        return res.status(400).json({ error: "selectorCommit required in plus mode" });
      }

      const pprContract = new ethers.Contract(pprAddr, PPR_PLUS_ABI, provider);

      // Check on-chain permission (enforces expiry, revocation & emergency role)
      const allowed = await pprContract.canView(signer, selectorCommit);
      if (!allowed) {
        return res.status(403).json({ error: "Permission denied on-chain (expired, revoked, or unauthorized)" });
      }

      // Query encrypted table
      const db = getDB();
      let row;
      if (recordId) {
        row = db.prepare("SELECT * FROM records_encrypted WHERE record_id = ?").get(String(recordId));
      } else {
        row = db.prepare("SELECT * FROM records_encrypted LIMIT 1").get();
      }
      db.close();

      if (!row) {
        return res.status(404).json({ error: "Encrypted record not found in database" });
      }

      // Verify integrity against on-chain pointer
      const count = await pprContract.pointerCount();
      let hashMatch = false;
      for (let i = 0; i < count; i++) {
        const [ptrCommit, ptrHash] = await pprContract.pointers(i);
        if (ptrCommit === selectorCommit) {
          hashMatch = (ptrHash === row.digest);
          break;
        }
      }

      // Fetch wrapped key for viewer:
      // First check storage mode
      let wrappedKeyHex = null;
      try {
        const stored = await pprContract.wrappedKeyStorage(signer, selectorCommit);
        if (stored && stored !== "0x") {
          wrappedKeyHex = stored;
        }
      } catch {}

      // If not stored in contract, search events
      if (!wrappedKeyHex) {
        const filter = pprContract.filters.KeyWrapped(pprAddr, signer, selectorCommit);
        const events = await pprContract.queryFilter(filter);
        if (events.length > 0) {
          wrappedKeyHex = events[events.length - 1].args[3];
        }
      }

      const logEntry = {
        time: new Date().toISOString(),
        signer,
        ppr: pprAddr,
        selectorCommit,
        recordId: row.record_id,
        hashMatch,
        mode: "plus",
      };
      appendAccessLog(logEntry);

      return res.json({
        mode: "plus",
        recordId: row.record_id,
        patientId: row.patient_id,
        ciphertextBlob: Buffer.from(row.ciphertext_blob).toString("hex"),
        digest: row.digest,
        wrappedKey: wrappedKeyHex,
        integrity: { hash: row.digest, match: hashMatch },
        warning: hashMatch ? null : "Ciphertext digest does not match on-chain hash — tampering detected",
      });
    }

    // ── BASELINE MODE ────────────────────────────────────────────────────
    if (!selector) {
      return res.status(400).json({ error: "selector required in baseline mode" });
    }

    const ppr = new ethers.Contract(pprAddr, PPR_BASELINE_ABI, provider);
    const allowed = await ppr.canView(signer, selector);
    if (!allowed) {
      return res.status(403).json({ error: "Permission denied on-chain" });
    }

    const { table, column, value } = parseSelector(selector);
    const db = getDB();
    const rows = db.prepare(`SELECT * FROM ${sanitizeTable(table)} WHERE ${sanitizeColumn(column)} = ?`).all(value);
    db.close();

    const resultJson = JSON.stringify(rows);
    const resultHash = "0x" + crypto.createHash("sha256").update(resultJson).digest("hex");

    const count = await ppr.pointerCount();
    let hashMatch = false;
    for (let i = 0; i < count; i++) {
      const [ptrSelector, ptrHash] = await ppr.pointers(i);
      if (ptrSelector === selector) {
        hashMatch = (ptrHash === resultHash);
        break;
      }
    }

    const logEntry = {
      time: new Date().toISOString(),
      signer,
      ppr: pprAddr,
      selector,
      hashMatch,
      rows: rows.length,
      mode: "baseline",
    };
    appendAccessLog(logEntry);

    return res.json({
      mode: "baseline",
      data: rows,
      integrity: { hash: resultHash, match: hashMatch },
      warning: hashMatch ? null : "Data hash does not match on-chain hash — possible tampering",
    });
  } catch (err) {
    console.error("Gatekeeper error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── Health endpoint ──────────────────────────────────────────────────────
app.get("/health", (_req, res) => res.json({ status: "ok", mode: process.env.MODE || "dual" }));

// ── Direct data access (for weakness demo D4) ───────────────────────────
app.get("/direct/:table", (req, res) => {
  try {
    const db = getDB();
    const rows = db.prepare(`SELECT * FROM ${sanitizeTable(req.params.table)}`).all();
    db.close();
    res.json({ data: rows, warning: "BYPASSED PERMISSION CHECK — demo D4" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Helpers ──────────────────────────────────────────────────────────────

function parseSelector(selector) {
  const [table, rest] = selector.split(":");
  if (!rest) throw new Error("Bad selector format");
  const [column, value] = rest.split("=");
  if (!column || value === undefined) throw new Error("Bad selector format");
  return { table, column, value };
}

function sanitizeTable(name) {
  if (!/^[a-zA-Z_]+$/.test(name)) throw new Error("Invalid table name");
  return name;
}

function sanitizeColumn(name) {
  if (!/^[a-zA-Z_]+$/.test(name)) throw new Error("Invalid column name");
  return name;
}

function appendAccessLog(entry) {
  const logPath = path.join(__dirname, "access.log");
  fs.appendFileSync(logPath, JSON.stringify(entry) + "\n");
}

async function start(port = PORT) {
  if (!ethProvider) {
    ethProvider = new ethers.JsonRpcProvider(RPC_URL);
  }
  return new Promise((resolve) => {
    const server = app.listen(port, () => {
      const actualPort = server.address().port;
      console.log(`Gatekeeper listening on :${actualPort} (dual mode: baseline + MedRec+)`);
      resolve(server);
    });
  });
}

if (require.main === module) {
  start();
} else {
  module.exports = { app, start, setProvider, getEthProvider };
}
