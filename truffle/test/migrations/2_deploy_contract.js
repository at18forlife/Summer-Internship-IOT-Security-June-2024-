const Metadata = artifacts.require("Metadata");

module.exports = function(deployer){
	deployer.deploy(Metadata);
};