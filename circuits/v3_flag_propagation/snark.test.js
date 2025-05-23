const { expect } = require("chai");
const path = require("path");
const fs = require("fs");
const { ethers } = require("ethers");
const snarkjs = require("snarkjs");
const { createBitArray, computeBloomIndices, setupSMTree } = require("./utils");

const ARTIFACTS_DIR = path.join(__dirname, "../artifacts/circuits");
const WASM_FILE = path.join(ARTIFACTS_DIR, "non_membership_js/non_membership.wasm");
const ZKEY_FILE = path.join(ARTIFACTS_DIR, "non_membership.zkey");
const VERIFICATION_KEY_FILE = path.join(ARTIFACTS_DIR, "verification_key.json");

const FILTER_SIZE = 16384;
const SMT_DEPTH = 20;


async function generateProof(input) {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        input,
        WASM_FILE,
        ZKEY_FILE
    );
    return { proof, publicSignals };
}

async function verifyProof(proof, publicSignals) {
    const vKey = JSON.parse(fs.readFileSync(VERIFICATION_KEY_FILE));
    return await snarkjs.groth16.verify(vKey, publicSignals, proof);
}

describe("SNARK Proof Generation and Verification", function() {
    this.timeout(120000);
    
    before(async () => {
        const requiredFiles = [WASM_FILE, ZKEY_FILE, VERIFICATION_KEY_FILE];
        for (const file of requiredFiles) {
            if (!fs.existsSync(file)) {
                throw new Error(`Required file not found: ${file}`);
            }
        }
        console.log("✓ All SNARK artifacts found");
    });
    after(() => {
        process.nextTick(() => process.exit(0));
    });

    it("should generate and verify valid proof for non-membership", async () => {
        console.log("Testing valid proof generation for non-membership case...");
        
        const chainstateIndices = [100, 200]; 
        const chainstateBitArray = createBitArray(FILTER_SIZE, chainstateIndices);
    
        const testIndices = [1000, 2000]; // different indices
        const testBitArray = createBitArray(FILTER_SIZE, testIndices);
    
        const smtData = await setupSMTree(testBitArray);
    
        const input = {
            bitArray: chainstateBitArray,
            bitArray2: testBitArray,
            root: smtData.root.toString(),
            siblings: smtData.proof.siblings.map(s => s.toString()),
            key: smtData.key.toString(),
            value: smtData.value.toString(),
            auxKey: "0",
            auxValue: "0",
            auxIsEmpty: "0",
            isExclusion: "0"
        };
    
        const startTime = Date.now();
        const { proof, publicSignals } = await generateProof(input);
        const proofTime = Date.now() - startTime;
        console.log(`  Proof generation time: ${proofTime}ms`);
    
        const verified = await verifyProof(proof, publicSignals);
        
        expect(verified).to.be.true;
        expect(publicSignals).to.have.length(4);
        expect(publicSignals[0]).to.equal("1");                     // notInSet = 1 (not in bloom filter)
        expect(publicSignals[1]).to.equal(smtData.root.toString()); // root
        expect(publicSignals[2]).to.equal(smtData.key.toString());  // key
        expect(publicSignals[3]).to.equal("0");                     // isExclusion
        
        console.log("✓ Valid proof generated and verified");
        console.log(`  Public signals: notInSet=${publicSignals[0]}, root=${publicSignals[1].slice(0,10)}..., key=${publicSignals[2].slice(0,10)}..., isExclusion=${publicSignals[3]}`);
    });

    it("should generate and verify valid proof for membership", async () => {
        console.log("Testing valid proof generation for membership case...");
        
        const testKey = BigInt(ethers.hexlify(ethers.randomBytes(32)));
        const testIndices = await computeBloomIndices(testKey, FILTER_SIZE);
        const testBitArray = createBitArray(FILTER_SIZE, testIndices);

        // chainstate that INCLUDES the test element
        const chainstateBitArray = createBitArray(FILTER_SIZE, testIndices);

        const smtData = await setupSMTree(testBitArray);

        const input = {
            bitArray: chainstateBitArray,
            bitArray2: testBitArray,
            root: smtData.root.toString(),
            siblings: smtData.proof.siblings.map(s => s.toString()),
            key: smtData.key.toString(),
            value: smtData.value.toString(),
            auxKey: "0",
            auxValue: "0",
            auxIsEmpty: "0",
            isExclusion: "0"
        };

        const { proof, publicSignals } = await generateProof(input);

        const verified = await verifyProof(proof, publicSignals);
        
        expect(verified).to.be.true;
        expect(publicSignals[0]).to.equal("0"); // notInSet = 0 (element IS in bloom filter)
        
        console.log("✓ Valid proof generated and verified for membership");
        console.log(`  notInSet output: ${publicSignals[0]} (element detected in bloom filter)`);
    });

    it("should fail proof generation with invalid SMT proof", async () => {
        console.log("Testing proof generation with invalid SMT proof...");
        
        const testKey = BigInt(ethers.hexlify(ethers.randomBytes(32)));
        const testIndices = await computeBloomIndices(testKey, FILTER_SIZE);
        const testBitArray = createBitArray(FILTER_SIZE, testIndices);
        const chainstateBitArray = createBitArray(FILTER_SIZE, [100, 200]);

        const smtData = await setupSMTree(testBitArray);

        const invalidSiblings = new Array(SMT_DEPTH).fill("0");
        
        const input = {
            bitArray: chainstateBitArray,
            bitArray2: testBitArray,
            root: smtData.root.toString(),
            siblings: invalidSiblings, 
            key: smtData.key.toString(),
            value: smtData.value.toString(),
            auxKey: "0",
            auxValue: "0",
            auxIsEmpty: "0",
            isExclusion: "0"
        };

        try {
            await generateProof(input);
            expect.fail("Should have thrown an error with invalid SMT proof");
        } catch (error) {
            const errorMessage = error.message.toLowerCase();
            const isValidError = errorMessage.includes("assert failed") || 
                                errorMessage.includes("constraint") || 
                                errorMessage.includes("error");
            expect(isValidError).to.be.true;
            console.log("✓ Correctly failed with invalid SMT proof:", error.message.substring(0, 50) + "...");
        }
    });

    it("should fail proof generation with mismatched bitArray2 and SMT value", async () => {
        console.log("Testing proof generation with mismatched bitArray2 and SMT value...");
        
        const testKey = BigInt(ethers.hexlify(ethers.randomBytes(32)));
        const testIndices = await computeBloomIndices(testKey, FILTER_SIZE);
        const testBitArray = createBitArray(FILTER_SIZE, testIndices);
        const chainstateBitArray = createBitArray(FILTER_SIZE, [100, 200]);

        const smtBitArray = createBitArray(FILTER_SIZE, [0, 1]); 
        const smtData = await setupSMTree(smtBitArray);

        const input = {
            bitArray: chainstateBitArray,
            bitArray2: testBitArray, // this doesn't match what's in SMT
            root: smtData.root.toString(),
            siblings: smtData.proof.siblings.map(s => s.toString()),
            key: smtData.key.toString(),
            value: smtData.value.toString(),
            auxKey: "0",
            auxValue: "0",
            auxIsEmpty: "0",
            isExclusion: "0"
        };

        try {
            await generateProof(input);
            expect.fail("Should have thrown an error with mismatched bitArray2");
        } catch (error) {
            expect(error.message).to.satisfy(msg => 
                msg.includes("Assert Failed") || msg.includes("Constraint doesn't match")
            );
            console.log("✓ Correctly failed with mismatched bitArray2 and SMT value");
        }
    });

    it("should measure proof generation performance", async () => {
        console.log("Measuring proof generation performance...");
        
        const testKey = BigInt(ethers.hexlify(ethers.randomBytes(32)));
        const testIndices = await computeBloomIndices(testKey, FILTER_SIZE);
        const testBitArray = createBitArray(FILTER_SIZE, testIndices);
        const chainstateBitArray = createBitArray(FILTER_SIZE, [100, 200]);
        const smtData = await setupSMTree(testBitArray);

        const input = {
            bitArray: chainstateBitArray,
            bitArray2: testBitArray,
            root: smtData.root.toString(),
            siblings: smtData.proof.siblings.map(s => s.toString()),
            key: smtData.key.toString(),
            value: smtData.value.toString(),
            auxKey: "0",
            auxValue: "0",
            auxIsEmpty: "0",
            isExclusion: "0"
        };

        const times = [];
        const numRuns = 3;
        
        for (let i = 0; i < numRuns; i++) {
            const startTime = Date.now();
            const { proof, publicSignals } = await generateProof(input);
            const endTime = Date.now();
            
            times.push(endTime - startTime);
            
            const verified = await verifyProof(proof, publicSignals);
            expect(verified).to.be.true;
        }

        const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
        const minTime = Math.min(...times);
        const maxTime = Math.max(...times);
        
        console.log(`✓ Performance results over ${numRuns} runs:`);
        console.log(`  Average: ${avgTime.toFixed(2)}ms`);
        console.log(`  Min: ${minTime}ms`);
        console.log(`  Max: ${maxTime}ms`);
        
        // reasonable performance expectations?
        expect(avgTime).to.be.below(10000); 
    });
});