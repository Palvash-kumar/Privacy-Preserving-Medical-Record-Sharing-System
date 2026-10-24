/**
 * MedRec CLI — demonstrates all baseline flows:
 *   add-record, retrieve (patient/provider/viewer), share, revoke
 *
 * Usage (after Hardhat node is running and deploy.js has been run):
 *   node client/cli.js retrieve --role viewer
 *   node client/cli.js revoke
 *   node client/cli.js retrieve --role viewer   # should fail after revoke
 */

const { ethers } = require("ethers");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const STATE_PATH = path.join(__dirname, "..", "data", "deploy-state.json");
const RPC_URL = process.env.RPC_URL || "http://127.0.0.1:8545";
const GATEKEEPER_URL = process.env.GATEKEEPER_URL || "http://127.0.0.1:3000";

const PPR_ABI = [
  "function canView(address who, string calldata selector) view returns (bool)",
  "function share(address viewer, string calldata selector)",
  "function revoke(address viewer, string calldata selector)",
  "function addPointer(string calldata selector, bytes32 dataHash)",
  "function pointerCount() view returns (uint256)",
  "function pointers(uint256 idx) view returns (string selector, bytes32 dataHash)",
  "function patient() view returns (address)",
  "function provider() view returns (address)",
  "function getViewers() view returns (address[])",
  "function getShares(address viewer) view returns (string[])",
  "event PointerAdded(address indexed ppr, uint256 index, bytes32 dataHash)",
  "event Shared(address indexed ppr, address indexed viewer, string selector)",
  "event Revoked(address indexed ppr, address indexed viewer, string selector)",
];

// Hardhat default signers (private keys for indices 0-3)
const HARDHAT_KEYS = [
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
  "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
  "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
];

function loadState() {
  if (!fs.existsSync(STATE_PATH)) {
    console.error("Deploy state not found. Run deploy.js first.");
    process.exit(1);
  }
  return JSON.parse(fs.readFileSync(STATE_PATH, "utf-8"));
}

function getWallet(roleIndex) {
  const provider = new ethers.JsonRpcProvider(RPC_URL);
  return new ethers.Wallet(HARDHAT_KEYS[roleIndex], provider);
}

async function signRequest(wallet, pprAddr, selector) {
  const nonce = crypto.randomUUID();
  const timestamp = Date.now();
  const message = JSON.stringify({ ppr: pprAddr, selector, nonce, timestamp });
  const signature = await wallet.signMessage(message);
  return { ppr: pprAddr, selector, nonce, timestamp, signature };
}

async function queryGatekeeper(body) {
  const res = await fetch(`${GATEKEEPER_URL}/query`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json() };
}

// ── Commands ─────────────────────────────────────────────────────────────

async function cmdRetrieve(role) {
  const state = loadState();
  const roleMap = { patient: 1, provider: 2, viewer: 3 };
  const idx = roleMap[role];
  if (idx === undefined) { console.error("Role must be: patient, provider, viewer"); return; }

  const wallet = getWallet(idx);
  console.log(`\n── Retrieve as ${role} (${wallet.address}) ──`);

  const reqBody = await signRequest(wallet, state.ppr, state.selector);
  const { status, body } = await queryGatekeeper(reqBody);

  if (status === 200) {
    console.log(`✓ Retrieved ${body.data.length} record(s)`);
    console.log(`  Integrity match: ${body.integrity.match}`);
    console.table(body.data);
  } else {
    console.log(`✗ Denied (${status}): ${body.error}`);
  }
}

async function cmdRevoke() {
  const state = loadState();
  const patientWallet = getWallet(1);
  const provider = new ethers.JsonRpcProvider(RPC_URL);
  const ppr = new ethers.Contract(state.ppr, PPR_ABI, patientWallet);

  console.log(`\n── Patient revoking viewer's access ──`);
  const tx = await ppr.revoke(state.viewer, state.selector);
  await tx.wait();
  console.log(`✓ Revoked "${state.selector}" from ${state.viewer}`);
}

async function cmdShare(viewerAddress, selector) {
  const state = loadState();
  const patientWallet = getWallet(1);
  const ppr = new ethers.Contract(state.ppr, PPR_ABI, patientWallet);

  console.log(`\n── Patient sharing access ──`);
  const sel = selector || state.selector;
  const tx = await ppr.share(viewerAddress || state.viewer, sel);
  await tx.wait();
  console.log(`✓ Shared "${sel}" with ${viewerAddress || state.viewer}`);
}

async function cmdStatus() {
  const state = loadState();
  const provider = new ethers.JsonRpcProvider(RPC_URL);
  const ppr = new ethers.Contract(state.ppr, PPR_ABI, provider);

  console.log("\n── PPR Status ──");
  console.log(`  Patient:  ${await ppr.patient()}`);
  console.log(`  Provider: ${await ppr.provider()}`);
  console.log(`  Pointers: ${await ppr.pointerCount()}`);

  const viewers = await ppr.getViewers();
  for (const v of viewers) {
    const shares = await ppr.getShares(v);
    console.log(`  Viewer ${v}: [${shares.join(", ")}]`);
  }
}

// ── Main ─────────────────────────────────────────────────────────────────

const [,, cmd, ...args] = process.argv;

const commands = {
  retrieve: () => {
    const role = args.includes("--role") ? args[args.indexOf("--role") + 1] : "viewer";
    cmdRetrieve(role);
  },
  revoke: () => cmdRevoke(),
  share: () => cmdShare(args[0], args[1]),
  status: () => cmdStatus(),
};

if (!commands[cmd]) {
  console.log("Usage: node cli.js <retrieve|revoke|share|status> [options]");
  console.log("  retrieve --role <patient|provider|viewer>");
  console.log("  revoke");
  console.log("  share [viewerAddress] [selector]");
  console.log("  status");
  process.exit(1);
}

commands[cmd]();
