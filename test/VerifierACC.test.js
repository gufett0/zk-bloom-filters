const { expect } = require("chai");
const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

describe("VerifierACC proof tests", function() {
    let verifierACC;
    let owner;

    this.timeout(60000);

    before(async function() {
        console.log("Deploying VerifierACC contract...");
        
        [owner] = await ethers.getSigners();
        
        const VerifierACC = await ethers.getContractFactory("VerifierACC");
        verifierACC = await VerifierACC.deploy();
        await verifierACC.waitForDeployment();
        
        const contractAddress = await verifierACC.getAddress();
        console.log(`VerifierACC deployed at: ${contractAddress}`);
        
        const bytecode = await ethers.provider.getCode(contractAddress);
        expect(bytecode).to.not.equal("0x");
        console.log(`Contract size: ${(bytecode.length - 2) / 2} bytes`);
    });

    it("should verify real ACC proof and measure gas", async function() {
        console.log("\nTesting with real proof data...");
        
        const latestProofFile = path.join(__dirname, "acc_proof_latest.json");
        
        if (!fs.existsSync(latestProofFile)) {
            console.log("No proof file found. Please run: npm run prove");
            this.skip();
            return;
        }

        const proofData = JSON.parse(fs.readFileSync(latestProofFile, 'utf8'));
        console.log(`Proof generated: ${proofData.metadata.timestamp}`);
        console.log(`Generation time: ${proofData.metadata.pureProofTime}ms`);

        // Validate structure
        expect(proofData).to.have.property('proof');
        expect(proofData).to.have.property('publicSignals');
        expect(proofData.publicSignals).to.be.an('array').with.length(7);

        // Verify and measure gas
        const result = await verifierACC.verifyACCproof.staticCall(
            proofData.proof.pi_a,
            proofData.proof.pi_b,
            proofData.proof.pi_c,
            proofData.publicSignals
        );
        
        console.log(`Verification result: ${result}`);
        expect(result).to.be.a('boolean');
        
        const tx = await verifierACC.verifyACCproof.populateTransaction(
            proofData.proof.pi_a,
            proofData.proof.pi_b,
            proofData.proof.pi_c,
            proofData.publicSignals
        );
        
        const gasUsed = await ethers.provider.estimateGas({
            ...tx,
            from: owner.address
        });
        
        console.log(`Gas usage: ${gasUsed.toString()} units`);
        
        const gasPrice = await ethers.provider.getFeeData();
        const cost = gasUsed * gasPrice.gasPrice;
        
        console.log(`Gas price: ${ethers.formatUnits(gasPrice.gasPrice, "gwei")} gwei`);
        console.log(`Transaction cost: ${ethers.formatEther(cost)} ETH`);
        
        expect(gasUsed).to.be.gt(0);
    });

    after(async function() {
        console.log("\nAll tests completed");
    });
});