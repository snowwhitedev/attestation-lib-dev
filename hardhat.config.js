/**
 * @type import('hardhat/config').HardhatUserConfig
 */
require("@nomiclabs/hardhat-waffle");
// require("@nomiclabs/hardhat-etherscan");
require("@nomiclabs/hardhat-ethers");
require("hardhat-gas-reporter");

const accounts = {
  mnemonic: process.env.MNEMONIC || "test test test test test test test test test test test junk",
  // accountsBalance: "990000000000000000000",
}

module.exports = {
  networks: {
    hardhat: {
      gasPrice: "auto",
      accounts
    },
  },
  solidity: "0.8.5",
  gasReporter: {
    currency: 'USD',
    gasPrice: 21
  }
};
