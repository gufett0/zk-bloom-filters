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

const ARTIFACTS_DIR2 = path.join(__dirname, "../artifacts/circuits2");
const UNION_WASM_FILE = path.join(ARTIFACTS_DIR2, "union_set_js/union_set.wasm");
const UNION_ZKEY_FILE = path.join(ARTIFACTS_DIR2, "union_set.zkey");
const UNION_VERIFICATION_KEY_FILE = path.join(ARTIFACTS_DIR2, "verification_key.json");

const NUM_INPUTS = 16;

async function generateProof(input, circuitType = 'non_membership') {
    const wasmFile = circuitType === 'union' ? UNION_WASM_FILE : WASM_FILE;
    const zkeyFile = circuitType === 'union' ? UNION_ZKEY_FILE : ZKEY_FILE;
    
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        input,
        wasmFile,
        zkeyFile
    );
    return { proof, publicSignals };
}

async function verifyProof(proof, publicSignals, circuitType = 'non_membership') {
    const vkeyFile = circuitType === 'union' ? UNION_VERIFICATION_KEY_FILE : VERIFICATION_KEY_FILE;
    const vKey = JSON.parse(fs.readFileSync(vkeyFile));
    return await snarkjs.groth16.verify(vKey, publicSignals, proof);
}

describe("SNARK Proof Generation and Verification", function() {
    this.timeout(180000); // Increased timeout for union proofs
    
    before(async () => {
        const requiredFiles = [WASM_FILE, ZKEY_FILE, VERIFICATION_KEY_FILE];
        for (const file of requiredFiles) {
            if (!fs.existsSync(file)) {
                throw new Error(`Required file not found: ${file}`);
            }
        }
        console.log("All non-membership SNARK artifacts found");
        
        // Check union artifacts
        const unionFiles = [UNION_WASM_FILE, UNION_ZKEY_FILE, UNION_VERIFICATION_KEY_FILE];
        let unionAvailable = true;
        for (const file of unionFiles) {
            if (!fs.existsSync(file)) {
                console.log(`Union file not found: ${file} - skipping union tests`);
                unionAvailable = false;
                break;
            }
        }
        if (unionAvailable) {
            console.log("All BloomFilterUnion SNARK artifacts found");
        }
    });
    
    after(() => {
        process.nextTick(() => process.exit(0));
    });

    // ========== NON-MEMBERSHIP TESTS ==========

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

    // ========== BLOOM FILTER UNION TESTS ==========

    it("should fail proof generation with incorrect union computation", async () => {
        if (!fs.existsSync(UNION_WASM_FILE)) {
            console.log("!!! Skipping union test - artifacts not found");
            return;
        }
        
        console.log("Testing SNARK proof failure with incorrect union...");
        
        const parentStates = [];
        for (let i = 0; i < NUM_INPUTS; i++) {
            if (i < 3) {
                const key = BigInt(ethers.hexlify(ethers.randomBytes(32)));
                const indices = await computeBloomIndices(key, FILTER_SIZE);
                parentStates.push(createBitArray(FILTER_SIZE, indices));
            } else {
                parentStates.push(new Array(FILTER_SIZE).fill(0));
            }
        }
        
        const incorrectUnion = [...parentStates[0]];

        const input = {
            parentStates: parentStates.map(state => state.map(bit => bit.toString())),
            unionState: incorrectUnion.map(bit => bit.toString())
        };

        try {
            await generateProof(input, 'union');
            expect.fail("Should have failed with incorrect union");
        } catch (error) {
            const errorMessage = error.message.toLowerCase();
            const isValidError = errorMessage.includes("assert failed") || 
                                errorMessage.includes("constraint") || 
                                errorMessage.includes("error");
            expect(isValidError).to.be.true;
            console.log("✓ Correctly failed SNARK proof with incorrect union");
        }
    });

    it("should measure proof generation performance for different union complexities", async () => {
        if (!fs.existsSync(UNION_WASM_FILE)) {
            console.log("!!! Skipping union performance test - artifacts not found");
            return;
        }
        
        console.log("Measuring BloomFilterUnion proof generation performance...");
        
        const scenarios = [
            { name: "All Empty", numNonEmpty: 0 },
            { name: "Single Element", numNonEmpty: 1 },
            { name: "Quarter Full", numNonEmpty: 4 },
            { name: "Half Full", numNonEmpty: 8 }
        ];

        for (const scenario of scenarios) {
            console.log(`  Testing scenario: ${scenario.name}`);
            
            const parentStates = [];
            for (let i = 0; i < NUM_INPUTS; i++) {
                if (i < scenario.numNonEmpty) {
                    const key = BigInt(ethers.hexlify(ethers.randomBytes(32)));
                    const indices = await computeBloomIndices(key, FILTER_SIZE);
                    parentStates.push(createBitArray(FILTER_SIZE, indices));
                } else {
                    parentStates.push(new Array(FILTER_SIZE).fill(0));
                }
            }
            
            const expectedUnion = new Array(FILTER_SIZE).fill(0);
            for (let i = 0; i < FILTER_SIZE; i++) {
                for (let j = 0; j < NUM_INPUTS; j++) {
                    if (parentStates[j][i] === 1) {
                        expectedUnion[i] = 1;
                        break;
                    }
                }
            }

            const input = {
                parentStates: parentStates.map(state => state.map(bit => bit.toString())),
                unionState: expectedUnion.map(bit => bit.toString())
            };

            const startTime = Date.now();
            const { proof, publicSignals } = await generateProof(input, 'union');
            const proofTime = Date.now() - startTime;
            
            const verified = await verifyProof(proof, publicSignals, 'union');
            expect(verified).to.be.true;
            
            console.log(`    ${scenario.name}: ${proofTime}ms`);
        }
        
        console.log("✓ Performance testing completed for all scenarios");
    });

   it("should generate proof for realistic UTXO merge scenario", async () => {
        if (!fs.existsSync(UNION_WASM_FILE)) {
            console.log("!!! Skipping realistic UTXO test - artifacts not found");
            return;
        }
        
        console.log("Testing SNARK proof for realistic UTXO chain state merge...");
        
        // simulate a realistic scenario where UTXOs have accumulated chain states
        const parentStates = [];
        
        // first few utxos have accumulated many masked commitments
        for (let i = 0; i < 3; i++) {
            const filter = new Array(FILTER_SIZE).fill(0);
            for (let j = 0; j < 20; j++) { 
                const key = BigInt(ethers.hexlify(ethers.randomBytes(32)));
                const indices = await computeBloomIndices(key, FILTER_SIZE);
                indices.forEach(idx => filter[idx] = 1);
            }
            parentStates.push(filter);
        }
        
        // middle utxos have moderate chain states
        for (let i = 3; i < 8; i++) {
            const filter = new Array(FILTER_SIZE).fill(0);
            for (let j = 0; j < 5; j++) { // 5 masked commitments each
                const key = BigInt(ethers.hexlify(ethers.randomBytes(32)));
                const indices = await computeBloomIndices(key, FILTER_SIZE);
                indices.forEach(idx => filter[idx] = 1);
            }
            parentStates.push(filter);
        }
        
        // rest of the set has empty chain states
        for (let i = 8; i < NUM_INPUTS; i++) {
            parentStates.push(new Array(FILTER_SIZE).fill(0));
        }
        
        const expectedUnion = new Array(FILTER_SIZE).fill(0);
        for (let i = 0; i < FILTER_SIZE; i++) {
            for (let j = 0; j < NUM_INPUTS; j++) {
                if (parentStates[j][i] === 1) {
                    expectedUnion[i] = 1;
                    break;
                }
            }
        }

        const input = {
            parentStates: parentStates.map(state => state.map(bit => bit.toString())),
            unionState: expectedUnion.map(bit => bit.toString())
        };

        const startTime = Date.now();
        const { proof, publicSignals } = await generateProof(input, 'union');
        const proofTime = Date.now() - startTime;
        console.log(`  Realistic scenario proof time: ${proofTime}ms`);

        const verified = await verifyProof(proof, publicSignals, 'union');
        
        expect(verified).to.be.true;
        console.log("✓ Valid proof generated for realistic UTXO merge scenario");
        
        const setBits = expectedUnion.filter(bit => bit === 1).length;
        console.log(`  Final union has ${setBits} bits set out of ${FILTER_SIZE} (${(setBits/FILTER_SIZE*100).toFixed(2)}% density)`);
    });
});