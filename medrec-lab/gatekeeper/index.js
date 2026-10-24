/**
 * Gatekeeper Service — MedRec baseline
 *
 * Verifies signed requests, checks on-chain permissions via PPR.canView(),
 * runs parameterised queries on SQLite, and verifies data integrity (hash).
 *
 * Baseline: responses are plaintext. Access log is off-chain only.
 * These are intentional weaknesses documented in section 8 of the plan.
 */

const express = require("express");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const { ethers } = require("ethers");
const path = require("path");
const fs = require("fs");

// ── ABI for PPR.canView ──────────────────────────────────────────────────
const PPR_ABI = [
  "function canView(address who, string calldata selector) external view returns (bool)",
  "function pointers(uint256 idx) external view returns (string selector, bytes32 dataHash)",
  "function pointerCount() external view returns (uint256)",
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
app.use(express.json());

let ethProvider;

function getDB() {
  return new Database(DB_PATH, { readonly: true });
}

/**
 * POST /query
 *
 * Body: { ppr, selector, nonce, timestamp, signature }
 *
 * Flow (section 5 of 02_implementation_plan_baseline.md):
 *  1. Recover signer from signature
 *  2. Reject stale timestamps and reused nonces
 *  3. Call PPR.canView(signer, selector)
 *  4. Run parameterised query
 *  5. Hash result, compare with on-chain hash
 *  6. Return data + log access
 */
app.post("/query", async (req, res) => {
  try {
    const { ppr: pprAddr, selector, nonce, timestamp, signature } = req.body;

    if (!pprAddr || !selector || !nonce || !timestamp || !signature) {
      return res.status(400).json({ error: "Missing fields" });
    }

    // 1. Recover signer
    const message = JSON.stringify({ ppr: pprAddr, selector, nonce, timestamp });
    let signer;
    try {
      signer = ethers.verifyMessage(message, signature);
    } catch {
      return res.status(401).json({ error: "Invalid signature" });
    }

    // 2. Replay protection
    const now = Date.now();
    if (Math.abs(now - timestamp) > TIMESTAMP_WINDOW_MS) {
      return res.status(401).json({ error: "Stale timestamp" });
    }
    if (usedNonces.has(nonce)) {
      return res.status(401).json({ error: "Replayed nonce" });
    }
    usedNonces.add(nonce);

    // 3. On-chain permission check
    const ppr = new ethers.Contract(pprAddr, PPR_ABI, ethProvider);
    const allowed = await ppr.canView(signer, selector);
    if (!allowed) {
      return res.status(403).json({ error: "Permission denied on-chain" });
    }

    // 4. Parse selector and run parameterised query
    //    Selector format: "table:column=value" (e.g., "records:patient_id=1")
    const { table, column, value } = parseSelector(selector);
    const db = getDB();
    const rows = db.prepare(`SELECT * FROM ${sanitizeTable(table)} WHERE ${sanitizeColumn(column)} = ?`).all(value);
    db.close();

    // 5. Hash result and compare with on-chain hash
    const resultJson = JSON.stringify(rows);
    const resultHash = "0x" + crypto.createHash("sha256").update(resultJson).digest("hex");

    // Find matching pointer on-chain
    const count = await ppr.pointerCount();
    let hashMatch = false;
    for (let i = 0; i < count; i++) {
      const [ptrSelector, ptrHash] = await ppr.pointers(i);
      if (ptrSelector === selector) {
        // ponytail: comparing keccak vs sha256 — baseline uses sha256 for off-chain hashes
        // On-chain hash might be keccak256; we compare the hex strings directly
        hashMatch = (ptrHash === resultHash);
        break;
      }
    }

    // 6. Return data + access log
    const logEntry = {
      time: new Date().toISOString(),
      signer,
      ppr: pprAddr,
      selector,
      hashMatch,
      rows: rows.length,
    };
    appendAccessLog(logEntry);

    res.json({
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
app.get("/health", (_req, res) => res.json({ status: "ok", mode: "baseline" }));

// ── Direct data access (for weakness demo D4) ───────────────────────────
// This endpoint bypasses on-chain permission checks — intentionally insecure
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
  // "records:patient_id=1" → { table: "records", column: "patient_id", value: "1" }
  const [table, rest] = selector.split(":");
  if (!rest) throw new Error("Bad selector format");
  const [column, value] = rest.split("=");
  if (!column || value === undefined) throw new Error("Bad selector format");
  return { table, column, value };
}

// ponytail: whitelist approach — only allow [a-zA-Z_] identifiers
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

// ── Start ────────────────────────────────────────────────────────────────

async function start() {
  ethProvider = new ethers.JsonRpcProvider(RPC_URL);
  app.listen(PORT, () => {
    console.log(`Gatekeeper listening on :${PORT} (baseline mode)`);
    console.log(`DB: ${DB_PATH}`);
    console.log(`RPC: ${RPC_URL}`);
  });
}

// Allow both direct run and import for testing
if (require.main === module) {
  start();
} else {
  module.exports = { app, start };
}
