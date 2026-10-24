require("@nomicfoundation/hardhat-toolbox");
require("hardhat-gas-reporter");

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.24",
    settings: { optimizer: { enabled: true, runs: 200 } },
  },
  networks: {
    hardhat: {
      // Instant mining by default (auto-mine).
      // For latency benchmarks, set mining.interval via scripts.
    },
  },
  gasReporter: {
    enabled: true,
    currency: "USD",
    outputFile: "bench/results/gas-report.txt",
    noColors: true,
  },
};
