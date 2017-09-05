var DPKI = artifacts.require("./DPKI.sol");

module.exports = function(deployer) {
  deployer.deploy(DPKI);
};
