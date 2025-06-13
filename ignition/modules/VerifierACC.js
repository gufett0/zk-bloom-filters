const { buildModule } = require("@nomicfoundation/hardhat-ignition/modules");

module.exports = buildModule("VerifierACCModule", (m) => {
  const verifierACC = m.contract("VerifierACC", []);

  return { verifierACC };
});