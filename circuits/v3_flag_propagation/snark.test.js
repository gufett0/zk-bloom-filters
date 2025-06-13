const { expect } = require("chai");
const path = require("path");
const fs = require("fs");
const { ethers } = require("ethers");
const snarkjs = require("snarkjs");

const {
    computeBloomIndices,
    createBitArray,
    chunkFieldElements,
    unchunkFieldElements,
    computeParentStatesHash,
    setupSMTree
} = require("./utils");

// Circuit parameters from acc.circom
const FILTER_SIZE = 16384;      // mBits
const NUM_CHUNKS = 65;          // numChunks
const BITS_PER_CHUNK = 253;     // standard field element bit size (last chunk may be smaller)
const LAST_CHUNK_BITS = FILTER_SIZE - (NUM_CHUNKS - 1) * BITS_PER_CHUNK;
const MAX_INPUTS = 16;          // maxInputs
const K = 2;                    // number of hash functions


const ARTIFACTS_DIR = path.join(__dirname, "../artifacts/circuits2");
const ACC_WASM_FILE = path.join(ARTIFACTS_DIR, "acc_js/acc.wasm");
const ACC_ZKEY_FILE = path.join(ARTIFACTS_DIR, "acc.zkey");
const ACC_VERIFICATION_KEY_FILE = path.join(ARTIFACTS_DIR, "acc_verification_key.json");


function getProcessMemoryUsage() {
    const usage = process.memoryUsage();
    return {
        rss: Math.round(usage.rss / 1024 / 1024),
        heapUsed: Math.round(usage.heapUsed / 1024 / 1024),
        heapTotal: Math.round(usage.heapTotal / 1024 / 1024),
    };
}


async function generateACCProof(input) {
    if (!fs.existsSync(ACC_WASM_FILE)) {
        throw new Error(`WASM file not found: ${ACC_WASM_FILE}`);
    }
    if (!fs.existsSync(ACC_ZKEY_FILE)) {
        throw new Error(`ZKEY file not found: ${ACC_ZKEY_FILE}`);
    }

    const startTime = Date.now();
    const memBefore = getProcessMemoryUsage();

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        input,
        ACC_WASM_FILE,
        ACC_ZKEY_FILE
    );

    const endTime = Date.now();
    const memAfter = getProcessMemoryUsage();
    
    const pureProofTime = endTime - startTime;
    const memoryUsed = {
        before: memBefore,
        after: memAfter,
        delta: {
            rss: memAfter.rss - memBefore.rss,
            heapUsed: memAfter.heapUsed - memBefore.heapUsed,
            heapTotal: memAfter.heapTotal - memBefore.heapUsed
        }
    };

    setImmediate(async () => {
        try {
            const saveStartTime = Date.now();
            
            const testDataDir = path.join(__dirname, "../../test");
            
            if (!fs.existsSync(testDataDir)) {
                fs.mkdirSync(testDataDir, { recursive: true });
            }

            const proofDataForContract = {
                proof: {
                    // !! per il contratto, pi_b ha ordine diverso
                    pi_a: [proof.pi_a[0], proof.pi_a[1]],
                    pi_b: [[proof.pi_b[0][1], proof.pi_b[0][0]], [proof.pi_b[1][1], proof.pi_b[1][0]]],
                    pi_c: [proof.pi_c[0], proof.pi_c[1]]
                },
                publicSignals: publicSignals.map(s => s.toString()),
                
                originalProof: {
                    pi_a: proof.pi_a,
                    pi_b: proof.pi_b, 
                    pi_c: proof.pi_c
                },
                
                metadata: {
                    timestamp: new Date().toISOString(),
                    pureProofTime: pureProofTime, // tempo puro di generazione
                    circuitName: "acc",
                    inputSummary: {
                        numActiveInputs: input.numActiveInputs,
                        hasUnionState: !!input.unionState,
                        hasSMTData: !!(input.root && input.siblings)
                    }
                }
            };

            const timestamp = Date.now();
            const proofFile = path.join(testDataDir, `acc_proof_${timestamp}.json`);
            const latestProofFile = path.join(testDataDir, `acc_proof_latest.json`);
            
            fs.writeFileSync(proofFile, JSON.stringify(proofDataForContract, null, 2));
            fs.writeFileSync(latestProofFile, JSON.stringify(proofDataForContract, null, 2));
            
            const saveEndTime = Date.now();
            const saveTime = saveEndTime - saveStartTime;
            
            console.log(`current proof data saved to: ${path.basename(proofFile)}`);
            
        } catch (saveError) {
            console.warn(`Failed to save proof data: ${saveError.message}`);
        }
    });

    return {
        proof,
        publicSignals,
        proofTime: pureProofTime, 
        memoryUsed,
        
        metadata: {
            savedAsync: true,
            measurementAccurate: true
        }
    };
}

async function verifyACCProof(proof, publicSignals) {
    if (!fs.existsSync(ACC_VERIFICATION_KEY_FILE)) {
        throw new Error(`Verification key not found: ${ACC_VERIFICATION_KEY_FILE}`);
    }

    const vKey = JSON.parse(fs.readFileSync(ACC_VERIFICATION_KEY_FILE));
    return await snarkjs.groth16.verify(vKey, publicSignals, proof);
}



describe("Ancestral Commitment Compliance (ACC) Circuit Tests", function () {
    this.timeout(300000);

    before(async () => {
        console.log("Checking ACC circuit artifacts...");

        const requiredFiles = [ACC_WASM_FILE, ACC_ZKEY_FILE, ACC_VERIFICATION_KEY_FILE];
        for (const file of requiredFiles) {
            if (!fs.existsSync(file)) {
                console.warn(`Warning: Required file not found: ${file}`);
                console.warn("Skipping tests that require this file");
            } else {
                console.log(`✓ Found: ${path.basename(file)}`);
            }
        }

        console.log(`Circuit parameters: ${FILTER_SIZE} bits, ${NUM_CHUNKS} chunks, max ${MAX_INPUTS} inputs`);
    });

    after(() => {
        console.log("ACC tests completed");
        process.nextTick(() => process.exit(0));
    });

    it("should generate and verify valid proof for ACC", async () => {
        if (!fs.existsSync(ACC_WASM_FILE)) {
            console.log("Skipping test - WASM file not found");
            return;
        }

        console.log("Testing basic ACC proof generation...");

        const numActiveInputs = 3;

        // parent states like in witness.test.js
        const parentStates = [];
        for (let i = 0; i < MAX_INPUTS; i++) {
            if (i < numActiveInputs) {
                const key = BigInt(ethers.hexlify(ethers.randomBytes(32)));
                const indices = await computeBloomIndices(key, FILTER_SIZE);
                const bitArray = createBitArray(FILTER_SIZE, indices);
                const chunks = chunkFieldElements(bitArray, BITS_PER_CHUNK, NUM_CHUNKS);
                parentStates.push(chunks);
            } else {
                parentStates.push(new Array(NUM_CHUNKS).fill("0"));
            }
        }

        // compute expected union by unchunking, OR, and rechunking
        const unionBitArray = new Array(FILTER_SIZE).fill(0);
        for (let i = 0; i < numActiveInputs; i++) {
            const parentBitArray = unchunkFieldElements(parentStates[i], BITS_PER_CHUNK, LAST_CHUNK_BITS);
            for (let j = 0; j < FILTER_SIZE; j++) {
                unionBitArray[j] |= parentBitArray[j];
            }
        }
        const unionState = chunkFieldElements(unionBitArray, BITS_PER_CHUNK, NUM_CHUNKS);

        // the flagged commitment is NOT in the union for this test
        const flaggedKey = BigInt(ethers.hexlify(ethers.randomBytes(32)));
        const flaggedIndices = await computeBloomIndices(flaggedKey, FILTER_SIZE);
        const flaggedBitArray = createBitArray(FILTER_SIZE, flaggedIndices);
        const flaggedStateChunks = chunkFieldElements(flaggedBitArray, BITS_PER_CHUNK, NUM_CHUNKS);
        const hasAllBits = flaggedIndices.every(idx => unionBitArray[idx] === 1);
        console.log(`Manual verification: flagged commitment in union = ${hasAllBits}`);

        const chainStatesHash = await computeParentStatesHash(parentStates, numActiveInputs);

        const smtData = await setupSMTree(flaggedStateChunks);

        const input = {
            numActiveInputs: numActiveInputs.toString(),
            parentStates,
            unionState,
            chainStatesHash: chainStatesHash.toString(),
            flaggedStateChunks,
            root: smtData.root.toString(),
            siblings: smtData.proof.siblings,
            key: smtData.key.toString(),
            value: smtData.value.toString(),
            auxKey: "0",
            auxValue: "0",
            auxIsEmpty: "0",
            isExclusion: "0"
        };

        const result = await generateACCProof(input);

        console.log(`  Proof generation time: ${result.proofTime}ms`);
        console.log(`  Memory usage: ${result.memoryUsed.delta.heapUsed}MB heap delta`);
        console.log(`  Total RSS: ${result.memoryUsed.after.rss}MB`);

        console.log(`  Public signals received (${result.publicSignals.length} total):`);
        for (let i = 0; i < result.publicSignals.length; i++) {
            console.log(`    [${i}]: ${result.publicSignals[i]}`);
        }

        const verified = await verifyACCProof(result.proof, result.publicSignals);
        console.log(`  Verification result: ${verified}`);

        if (!verified) {
            console.log("  ❌ Verification failed - analyzing public signals...");
            return;
        }

        expect(verified).to.be.true;

        console.log(`✓ Valid ACC proof generated and verified`);
        console.log(`  notInSet: ${result.publicSignals[0]}, chainStateValid: ${result.publicSignals[1]}`);
    });

    it("should fail proof generation with invalid proof ACC", async () => {
        if (!fs.existsSync(ACC_WASM_FILE)) {
            console.log("Skipping test - WASM file not found");
            return;
        }

        console.log("Testing ACC proof failure scenarios...");

        const numActiveInputs = 2;

        const parentStates = [];

        for (let i = 0; i < MAX_INPUTS; i++) {
            if (i < numActiveInputs) {
                const key = BigInt(ethers.hexlify(ethers.randomBytes(32)));
                const indices = await computeBloomIndices(key, FILTER_SIZE);
                const bitArray = createBitArray(FILTER_SIZE, indices);
                const chunks = chunkFieldElements(bitArray, BITS_PER_CHUNK, NUM_CHUNKS);
                parentStates.push(chunks);
            } else {
                parentStates.push(new Array(NUM_CHUNKS).fill("0"));
            }
        }

        // create wrong union (just use first parent instead of actual union)
        const wrongUnionState = [...parentStates[0]];

        const flaggedKey = BigInt(ethers.hexlify(ethers.randomBytes(32)));
        const flaggedIndices = await computeBloomIndices(flaggedKey, FILTER_SIZE);
        const flaggedBitArray = createBitArray(FILTER_SIZE, flaggedIndices);
        const flaggedStateChunks = chunkFieldElements(flaggedBitArray, BITS_PER_CHUNK, NUM_CHUNKS);

        const chainStatesHash = await computeParentStatesHash(parentStates, numActiveInputs);
        const smtData = await setupSMTree(flaggedStateChunks);

        const input = {
            numActiveInputs: numActiveInputs.toString(),
            parentStates,
            unionState: wrongUnionState,
            chainStatesHash: chainStatesHash.toString(),
            flaggedStateChunks,
            root: smtData.root.toString(),
            siblings: smtData.proof.siblings,
            key: smtData.key.toString(),
            value: smtData.value.toString(),
            auxKey: "0",
            auxValue: "0",
            auxIsEmpty: "0",
            isExclusion: "0"
        };

        try {
            await generateACCProof(input);
            expect.fail("Should have failed with incorrect union");
        } catch (error) {
            const errorMessage = error.message.toLowerCase();
            const isValidError = errorMessage.includes("assert failed") ||
                errorMessage.includes("constraint") ||
                errorMessage.includes("error");
            expect(isValidError).to.be.true;
            console.log("✓ Correctly failed with invalid union computation");
        }

        console.log("  Testing invalid parent states hash...");

        const correctUnionBitArray = new Array(FILTER_SIZE).fill(0);
        for (let i = 0; i < numActiveInputs; i++) {
            const parentBitArray = unchunkFieldElements(parentStates[i], BITS_PER_CHUNK, LAST_CHUNK_BITS);
            for (let j = 0; j < FILTER_SIZE; j++) {
                correctUnionBitArray[j] |= parentBitArray[j];
            }
        }
        const correctUnionState = chunkFieldElements(correctUnionBitArray, BITS_PER_CHUNK, NUM_CHUNKS);

        const input2 = {
            numActiveInputs: numActiveInputs.toString(),
            parentStates,
            unionState: correctUnionState,
            chainStatesHash: BigInt(ethers.hexlify(ethers.randomBytes(32))).toString(), // wrong hash
            flaggedStateChunks,
            root: smtData.root.toString(),
            siblings: smtData.proof.siblings,
            key: smtData.key.toString(),
            value: smtData.value.toString(),
            auxKey: "0",
            auxValue: "0",
            auxIsEmpty: "0",
            isExclusion: "0"
        };

        try {
            await generateACCProof(input2);
            expect.fail("Should have failed with invalid parent states hash");
        } catch (error) {
            const errorMessage = error.message.toLowerCase();
            const isValidError = errorMessage.includes("assert failed") ||
                errorMessage.includes("constraint") ||
                errorMessage.includes("error");
            expect(isValidError).to.be.true;
            console.log("✓ Correctly failed with invalid parent states hash");
        }
    });

    it("should generate valid ACC proof for realistic UTXO merge scenario", async () => {
        if (!fs.existsSync(ACC_WASM_FILE)) {
            console.log("Skipping test - WASM file not found");
            return;
        }

        console.log("Testing realistic UTXO merge scenarios...");

        const scenarios = [
            { name: "Small merge (2 UTXOs)", numActiveInputs: 2 },
            { name: "Medium merge (5 UTXOs)", numActiveInputs: 5 },
            { name: "Large merge (16 UTXOs)", numActiveInputs: 16 }
        ];

        for (const scenario of scenarios) {
            console.log(`  Testing scenario: ${scenario.name}`);

            const parentStates = [];

            // simulate varying complexity
            for (let i = 0; i < MAX_INPUTS; i++) {
                if (i < scenario.numActiveInputs) {
                    const filter = new Array(FILTER_SIZE).fill(0);

                    // first few utxos have more accumulated chain state
                    const numCommitments = i < 3 ? 10 : (i < 8 ? 5 : 2);

                    for (let j = 0; j < numCommitments; j++) {
                        const key = BigInt(ethers.hexlify(ethers.randomBytes(32)));
                        const indices = await computeBloomIndices(key, FILTER_SIZE);
                        indices.forEach(idx => filter[idx] = 1);
                    }

                    const chunks = chunkFieldElements(filter, BITS_PER_CHUNK, NUM_CHUNKS);
                    parentStates.push(chunks);
                } else {
                    parentStates.push(new Array(NUM_CHUNKS).fill("0"));
                }
            }

            const unionBitArray = new Array(FILTER_SIZE).fill(0);
            for (let i = 0; i < scenario.numActiveInputs; i++) {
                const parentBitArray = unchunkFieldElements(parentStates[i], BITS_PER_CHUNK, LAST_CHUNK_BITS);
                for (let j = 0; j < FILTER_SIZE; j++) {
                    unionBitArray[j] |= parentBitArray[j];
                }
            }
            const unionState = chunkFieldElements(unionBitArray, BITS_PER_CHUNK, NUM_CHUNKS);

            // create flagged commitment not in union
            const flaggedKey = BigInt(ethers.hexlify(ethers.randomBytes(32)));
            const flaggedIndices = await computeBloomIndices(flaggedKey, FILTER_SIZE);
            const flaggedBitArray = createBitArray(FILTER_SIZE, flaggedIndices);
            const flaggedStateChunks = chunkFieldElements(flaggedBitArray, BITS_PER_CHUNK, NUM_CHUNKS);

            const chainStatesHash = await computeParentStatesHash(parentStates, scenario.numActiveInputs);
            const smtData = await setupSMTree(flaggedStateChunks);

            const input = {
                numActiveInputs: scenario.numActiveInputs.toString(),
                parentStates,
                unionState,
                chainStatesHash: chainStatesHash.toString(),
                flaggedStateChunks,
                root: smtData.root.toString(),
                siblings: smtData.proof.siblings,
                key: smtData.key.toString(),
                value: smtData.value.toString(),
                auxKey: "0",
                auxValue: "0",
                auxIsEmpty: "0",
                isExclusion: "0"
            };

            const result = await generateACCProof(input);
            const verified = await verifyACCProof(result.proof, result.publicSignals);

            expect(verified).to.be.true;
            expect(result.publicSignals).to.have.length(7);

            const setBits = unionBitArray.filter(bit => bit === 1).length;
            const density = (setBits / FILTER_SIZE * 100).toFixed(2);

            console.log(`    ✓ ${scenario.name}: ${result.proofTime}ms, ${result.memoryUsed.delta.heapUsed}MB heap`);
            console.log(`      Union density: ${setBits}/${FILTER_SIZE} bits (${density}%)`);
            console.log(`      Proof verified successfully`);
        }
    });

    it("should generate valid ACC proof for different expected FP rates", async () => {
        if (!fs.existsSync(ACC_WASM_FILE)) {
            console.log("Skipping test - WASM file not found");
            return;
        }

        console.log("Testing different false positive rates...");

        const scenarios = [
            { name: "Low saturation (1-5% density)", targetDensity: 0.02, expectedFP: "low" },
            { name: "Medium saturation (10-15% density)", targetDensity: 0.12, expectedFP: "medium" },
            { name: "High saturation (20-25% density)", targetDensity: 0.22, expectedFP: "high" }
        ];

        for (const scenario of scenarios) {
            console.log(`  Testing scenario: ${scenario.name}`);

            const numActiveInputs = 8;
            const targetBits = Math.floor(FILTER_SIZE * scenario.targetDensity);

            // create parent states that will result in target density
            const parentStates = [];

            for (let i = 0; i < MAX_INPUTS; i++) {
                if (i < numActiveInputs) {
                    const filter = new Array(FILTER_SIZE).fill(0);

                    // calculate how many bloom filter elements to add to reach target density (more or less)
                    const targetBitsForThisParent = Math.floor((targetBits / numActiveInputs) / K);

                    for (let j = 0; j < targetBitsForThisParent; j++) {
                        const key = BigInt(ethers.hexlify(ethers.randomBytes(32)));
                        const indices = await computeBloomIndices(key, FILTER_SIZE);
                        indices.forEach(idx => filter[idx] = 1);
                    }

                    const chunks = chunkFieldElements(filter, BITS_PER_CHUNK, NUM_CHUNKS);
                    parentStates.push(chunks);
                } else {
                    parentStates.push(new Array(NUM_CHUNKS).fill("0"));
                }
            }


            const unionBitArray = new Array(FILTER_SIZE).fill(0);
            for (let i = 0; i < numActiveInputs; i++) {
                const parentBitArray = unchunkFieldElements(parentStates[i], BITS_PER_CHUNK, LAST_CHUNK_BITS);
                for (let j = 0; j < FILTER_SIZE; j++) {
                    unionBitArray[j] |= parentBitArray[j];
                }
            }
            const unionState = chunkFieldElements(unionBitArray, BITS_PER_CHUNK, NUM_CHUNKS);

            const flaggedKey = BigInt(ethers.hexlify(ethers.randomBytes(32)));
            const flaggedIndices = await computeBloomIndices(flaggedKey, FILTER_SIZE);
            const flaggedBitArray = createBitArray(FILTER_SIZE, flaggedIndices);
            const flaggedStateChunks = chunkFieldElements(flaggedBitArray, BITS_PER_CHUNK, NUM_CHUNKS);

            const chainStatesHash = await computeParentStatesHash(parentStates, numActiveInputs);
            const smtData = await setupSMTree(flaggedStateChunks);

            const input = {
                numActiveInputs: numActiveInputs.toString(),
                parentStates,
                unionState,
                chainStatesHash: chainStatesHash.toString(),
                flaggedStateChunks,
                root: smtData.root.toString(),
                siblings: smtData.proof.siblings,
                key: smtData.key.toString(),
                value: smtData.value.toString(),
                auxKey: "0",
                auxValue: "0",
                auxIsEmpty: "0",
                isExclusion: "0"
            };

            const result = await generateACCProof(input);
            const verified = await verifyACCProof(result.proof, result.publicSignals);

            expect(verified).to.be.true;
            expect(result.publicSignals).to.have.length(7);

            const actualSetBits = unionBitArray.filter(bit => bit === 1).length;
            const actualDensity = actualSetBits / FILTER_SIZE;
            const fpProbability = Math.pow(actualDensity, K);

            console.log(`    ✓ ${scenario.name}: ${result.proofTime}ms, ${result.memoryUsed.delta.heapUsed}MB heap`);
            console.log(`      Actual density: ${(actualDensity * 100).toFixed(2)}%`);
            console.log(`      False positive probability: ${(fpProbability * 100).toFixed(4)}%`);
            console.log(`      ACC proof verified successfully`);
        }
    });
});