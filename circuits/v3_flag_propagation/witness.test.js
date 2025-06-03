const { expect } = require("chai");
const path = require("path");
const { ethers } = require("ethers");
const { wasm } = require("circom_tester");
const { computeBloomIndices, createBitArray, setupSMTree, createPoseidonHasher, chunkFieldElements, unchunkFieldElements, computeParentStatesHash } = require("./utils");

describe("Ancestral Commitment Compliance Tests", function() {
    this.timeout(1000000);
    
    let circuit;
    const FILTER_SIZE = 16384;
    const NUM_CHUNKS = 65; // 16384 bits / 254 bits per chunk ≈ 65 chunks
    const BITS_PER_CHUNK = 254;
    const LAST_CHUNK_BITS = FILTER_SIZE - (NUM_CHUNKS - 1) * BITS_PER_CHUNK; // remaining bits in last chunk
    const MAX_INPUTS = 16;
    const K = 2; // number of hash functions
    const SMT_DEPTH = 20;
    
    before(async () => {
        circuit = await wasm(path.join(__dirname, "acc.circom"));
    });

    describe("Bloom Filter parent states authentication", function() {
        
        it("should authenticate valid parent states hash", async () => {
            const numActiveInputs = 3;
            
            // Create parent states (chunked bloom filters)
            const parentStates = [];
            for (let i = 0; i < MAX_INPUTS; i++) {
                if (i < numActiveInputs) {
                    // Create a bloom filter for active parents
                    const key = BigInt(ethers.hexlify(ethers.randomBytes(32)));
                    const indices = await computeBloomIndices(key, FILTER_SIZE);
                    const bitArray = createBitArray(FILTER_SIZE, indices);
                    const chunks = chunkFieldElements(bitArray, BITS_PER_CHUNK, NUM_CHUNKS);
                    parentStates.push(chunks);
                } else {
                    // Empty state for inactive parents
                    parentStates.push(new Array(NUM_CHUNKS).fill(0));
                }
            }
            
            // Compute union state
            const unionBitArray = new Array(FILTER_SIZE).fill(0);
            for (let i = 0; i < numActiveInputs; i++) {
                const parentBitArray = unchunkFieldElements(parentStates[i], BITS_PER_CHUNK, LAST_CHUNK_BITS);
                for (let j = 0; j < FILTER_SIZE; j++) {
                    unionBitArray[j] |= parentBitArray[j];
                }
            }
            const unionState = chunkFieldElements(unionBitArray, BITS_PER_CHUNK, NUM_CHUNKS);
            
            // Create a flagged commitment (not in union)
            const flaggedKey = BigInt(ethers.hexlify(ethers.randomBytes(32)));
            const flaggedIndices = await computeBloomIndices(flaggedKey, FILTER_SIZE);
            const flaggedBitArray = createBitArray(FILTER_SIZE, flaggedIndices);
            const flaggedStateChunks = chunkFieldElements(flaggedBitArray, BITS_PER_CHUNK, NUM_CHUNKS);
            
            // Compute parent states hash (simplified - in practice this would be done by the hasher component)
            const chainStatesHash = await computeParentStatesHash(parentStates, numActiveInputs);
            
            // Setup SMT for flagged commitment
            const smtData = await setupSMTree(flaggedStateChunks);
            
            const input = {
                numActiveInputs,
                parentStates,
                unionState,
                chainStatesHash,
                flaggedStateChunks,
                root: smtData.root,
                siblings: smtData.proof.siblings,
                key: smtData.key,
                value: smtData.value,
                auxKey: 0,
                auxValue: 0,
                auxIsEmpty: 0,
                isExclusion: 0
            };
            
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            
            const chainStateValid = witness[2]; // assuming this is the output index
            expect(chainStateValid.toString()).to.equal("1");
            console.log("Parent states authentication passed");
        });

        it("should reject invalid parent states hash", async () => {
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
                    parentStates.push(new Array(NUM_CHUNKS).fill(0));
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
            
            // Use WRONG hash
            const wrongHash = BigInt(ethers.hexlify(ethers.randomBytes(32)));
            
            const smtData = await setupSMTree(flaggedStateChunks);
            
            const input = {
                numActiveInputs,
                parentStates,
                unionState,
                chainStatesHash: wrongHash,
                flaggedStateChunks,
                root: smtData.root,
                siblings: smtData.proof.siblings,
                key: smtData.key,
                value: smtData.value,
                auxKey: 0,
                auxValue: 0,
                auxIsEmpty: 0,
                isExclusion: 0
            };
            
            try {
                await circuit.calculateWitness(input);
                expect.fail("Should have failed with wrong parent states hash");
            } catch (err) {
                expect(err.toString()).to.satisfy(msg => 
                    msg.includes("Assert Failed") || msg.includes("Constraint doesn't match")
                );
                console.log("Correctly rejected invalid parent states hash");
            }
        });
    });

    describe("Bloom Filter utxo merge phase", function() {
        
        it("should correctly verify union of multiple parent states", async () => {
            const numActiveInputs = 4;
            
            // Create distinct parent states
            const parentStates = [];
            const parentKeys = [];
            
            for (let i = 0; i < MAX_INPUTS; i++) {
                if (i < numActiveInputs) {
                    const key = BigInt(ethers.hexlify(ethers.randomBytes(32)));
                    parentKeys.push(key);
                    const indices = await computeBloomIndices(key, FILTER_SIZE);
                    const bitArray = createBitArray(FILTER_SIZE, indices);
                    const chunks = chunkFieldElements(bitArray, BITS_PER_CHUNK, NUM_CHUNKS);
                    parentStates.push(chunks);
                } else {
                    parentStates.push(new Array(NUM_CHUNKS).fill(0));
                }
            }
            
            // Compute correct union
            const unionBitArray = new Array(FILTER_SIZE).fill(0);
            for (let i = 0; i < numActiveInputs; i++) {
                const parentBitArray = unchunkFieldElements(parentStates[i], BITS_PER_CHUNK, LAST_CHUNK_BITS);
                for (let j = 0; j < FILTER_SIZE; j++) {
                    unionBitArray[j] |= parentBitArray[j];
                }
            }
            const unionState = chunkFieldElements(unionBitArray, BITS_PER_CHUNK, NUM_CHUNKS);
            
            // Create flagged commitment not in any parent
            const flaggedKey = BigInt(ethers.hexlify(ethers.randomBytes(32)));
            const flaggedIndices = await computeBloomIndices(flaggedKey, FILTER_SIZE);
            const flaggedBitArray = createBitArray(FILTER_SIZE, flaggedIndices);
            const flaggedStateChunks = chunkFieldElements(flaggedBitArray, BITS_PER_CHUNK, NUM_CHUNKS);
            
            const chainStatesHash = await computeParentStatesHash(parentStates, numActiveInputs);
            const smtData = await setupSMTree(flaggedStateChunks);
            
            const input = {
                numActiveInputs,
                parentStates,
                unionState,
                chainStatesHash,
                flaggedStateChunks,
                root: smtData.root,
                siblings: smtData.proof.siblings,
                key: smtData.key,
                value: smtData.value,
                auxKey: 0,
                auxValue: 0,
                auxIsEmpty: 0,
                isExclusion: 0
            };
            
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            
            const notInSet = witness[1]; // assuming this is the output index
            expect(notInSet.toString()).to.equal("1"); // should be NOT in set
            console.log("Union computation verified successfully");
        });

        it("should reject incorrect union state", async () => {
            const numActiveInputs = 3;
            
            const parentStates = [];
            for (let i = 0; i < MAX_INPUTS; i++) {
                if (i < numActiveInputs) {
                    const key = BigInt(ethers.hexlify(ethers.randomBytes(32)));
                    const indices = await computeBloomIndices(key, FILTER_SIZE);
                    const bitArray = createBitArray(FILTER_SIZE, indices);
                    const chunks = chunkFieldElements(bitArray, BITS_PER_CHUNK, NUM_CHUNKS);
                    parentStates.push(chunks);
                } else {
                    parentStates.push(new Array(NUM_CHUNKS).fill(0));
                }
            }
            
            // Create WRONG union (just use first parent instead of actual union)
            const wrongUnionState = [...parentStates[0]];
            
            const flaggedKey = BigInt(ethers.hexlify(ethers.randomBytes(32)));
            const flaggedIndices = await computeBloomIndices(flaggedKey, FILTER_SIZE);
            const flaggedBitArray = createBitArray(FILTER_SIZE, flaggedIndices);
            const flaggedStateChunks = chunkFieldElements(flaggedBitArray, BITS_PER_CHUNK, NUM_CHUNKS);
            
            const chainStatesHash = await computeParentStatesHash(parentStates, numActiveInputs);
            const smtData = await setupSMTree(flaggedStateChunks);
            
            const input = {
                numActiveInputs,
                parentStates,
                unionState: wrongUnionState, // WRONG!
                chainStatesHash,
                flaggedStateChunks,
                root: smtData.root,
                siblings: smtData.proof.siblings,
                key: smtData.key,
                value: smtData.value,
                auxKey: 0,
                auxValue: 0,
                auxIsEmpty: 0,
                isExclusion: 0
            };
            
            try {
                await circuit.calculateWitness(input);
                expect.fail("Should have failed with incorrect union state");
            } catch (err) {
                expect(err.toString()).to.satisfy(msg => 
                    msg.includes("Assert Failed") || msg.includes("Constraint doesn't match")
                );
                console.log("Correctly rejected incorrect union state");
            }
        });

        it("should handle complex union with multiple overlapping elements", async () => {
            const numActiveInputs = 6;
            
            const parentStates = [];
            const allKeys = [];
            
            // Create parent states with some overlapping elements
            for (let i = 0; i < MAX_INPUTS; i++) {
                if (i < numActiveInputs) {
                    const keys = [];
                    
                    // Each parent gets 1-2 unique keys
                    keys.push(BigInt(ethers.hexlify(ethers.randomBytes(32))));
                    if (Math.random() > 0.5) {
                        keys.push(BigInt(ethers.hexlify(ethers.randomBytes(32))));
                    }
                    
                    // Every other parent shares a key with the previous one for overlap
                    if (i > 0 && i % 2 === 1 && allKeys.length > 0) {
                        keys.push(allKeys[allKeys.length - 1]);
                    }
                    
                    allKeys.push(...keys);
                    
                    // Build bloom filter for this set of keys
                    const parentBitArray = new Array(FILTER_SIZE).fill(0);
                    for (const key of keys) {
                        const indices = await computeBloomIndices(key, FILTER_SIZE);
                        indices.forEach(idx => parentBitArray[idx] = 1);
                    }
                    
                    const chunks = chunkFieldElements(parentBitArray, BITS_PER_CHUNK, NUM_CHUNKS);
                    parentStates.push(chunks);
                } else {
                    parentStates.push(new Array(NUM_CHUNKS).fill(0));
                }
            }
            
            // Compute expected union
            const unionBitArray = new Array(FILTER_SIZE).fill(0);
            for (let i = 0; i < numActiveInputs; i++) {
                const parentBitArray = unchunkFieldElements(parentStates[i], BITS_PER_CHUNK, LAST_CHUNK_BITS);
                for (let j = 0; j < FILTER_SIZE; j++) {
                    unionBitArray[j] |= parentBitArray[j];
                }
            }
            const unionState = chunkFieldElements(unionBitArray, BITS_PER_CHUNK, NUM_CHUNKS);
            
            // Create flagged commitment not in any parent
            const flaggedKey = BigInt(ethers.hexlify(ethers.randomBytes(32)));
            const flaggedIndices = await computeBloomIndices(flaggedKey, FILTER_SIZE);
            const flaggedBitArray = createBitArray(FILTER_SIZE, flaggedIndices);
            const flaggedStateChunks = chunkFieldElements(flaggedBitArray, BITS_PER_CHUNK, NUM_CHUNKS);
            
            const chainStatesHash = await computeParentStatesHash(parentStates, numActiveInputs);
            const smtData = await setupSMTree(flaggedStateChunks);
            
            const input = {
                numActiveInputs,
                parentStates,
                unionState,
                chainStatesHash,
                flaggedStateChunks,
                root: smtData.root,
                siblings: smtData.proof.siblings,
                key: smtData.key,
                value: smtData.value,
                auxKey: 0,
                auxValue: 0,
                auxIsEmpty: 0,
                isExclusion: 0
            };
            
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            
            const notInSet = witness[1];
            const chainStateValid = witness[2];
            
            expect(chainStateValid.toString()).to.equal("1");
            
            // Verify bloom filter logic
            const hasAllBits = flaggedIndices.every(idx => unionBitArray[idx] === 1);
            expect(notInSet.toString()).to.equal(hasAllBits ? "0" : "1");
            
            console.log(`Complex overlapping union test passed - notInSet: ${notInSet.toString()}`);
            console.log(`Number of active inputs: ${numActiveInputs}, Union density: ${unionBitArray.filter(b => b === 1).length}/${FILTER_SIZE}`);
        });
    });

    describe("Bloom Filter flagged commitment non-membership", function() {
        
        it("should prove non-membership of flagged commitment", async () => {
            const numActiveInputs = 2;
            
            // Create parent states with specific keys
            const parentKeys = [
                BigInt("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
                BigInt("0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321")
            ];
            
            const parentStates = [];
            for (let i = 0; i < MAX_INPUTS; i++) {
                if (i < numActiveInputs) {
                    const indices = await computeBloomIndices(parentKeys[i], FILTER_SIZE);
                    const bitArray = createBitArray(FILTER_SIZE, indices);
                    const chunks = chunkFieldElements(bitArray, BITS_PER_CHUNK, NUM_CHUNKS);
                    parentStates.push(chunks);
                } else {
                    parentStates.push(new Array(NUM_CHUNKS).fill(0));
                }
            }
            
            // Compute union
            const unionBitArray = new Array(FILTER_SIZE).fill(0);
            for (let i = 0; i < numActiveInputs; i++) {
                const parentBitArray = unchunkFieldElements(parentStates[i], BITS_PER_CHUNK, LAST_CHUNK_BITS);
                for (let j = 0; j < FILTER_SIZE; j++) {
                    unionBitArray[j] |= parentBitArray[j];
                }
            }
            const unionState = chunkFieldElements(unionBitArray, BITS_PER_CHUNK, NUM_CHUNKS);
            
            // Create flagged commitment that's definitely NOT in the union
            const flaggedKey = BigInt("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            const flaggedIndices = await computeBloomIndices(flaggedKey, FILTER_SIZE);
            const flaggedBitArray = createBitArray(FILTER_SIZE, flaggedIndices);
            const flaggedStateChunks = chunkFieldElements(flaggedBitArray, BITS_PER_CHUNK, NUM_CHUNKS);
            
            // Verify non-membership manually
            const hasAllBits = flaggedIndices.every(idx => unionBitArray[idx] === 1);
            console.log("Manual check - flagged commitment in union:", hasAllBits);
            
            const chainStatesHash = await computeParentStatesHash(parentStates, numActiveInputs);
            const smtData = await setupSMTree(flaggedStateChunks);
            
            const input = {
                numActiveInputs,
                parentStates,
                unionState,
                chainStatesHash,
                flaggedStateChunks,
                root: smtData.root,
                siblings: smtData.proof.siblings,
                key: smtData.key,
                value: smtData.value,
                auxKey: 0,
                auxValue: 0,
                auxIsEmpty: 0,
                isExclusion: 0
            };
            
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            
            const notInSet = witness[1];
            expect(notInSet.toString()).to.equal(hasAllBits ? "0" : "1");
            console.log(`Non-membership proof: notInSet = ${notInSet.toString()}`);
        });

        it("should detect membership (false positive case)", async () => {
            const numActiveInputs = 2;
            
            // Create parent state containing the flagged commitment
            const flaggedKey = BigInt(ethers.hexlify(ethers.randomBytes(32)));
            const flaggedIndices = await computeBloomIndices(flaggedKey, FILTER_SIZE);
            
            const parentStates = [];
            for (let i = 0; i < MAX_INPUTS; i++) {
                if (i < numActiveInputs) {
                    if (i === 0) {
                        // First parent contains the flagged commitment
                        const bitArray = createBitArray(FILTER_SIZE, flaggedIndices);
                        const chunks = chunkFieldElements(bitArray, BITS_PER_CHUNK, NUM_CHUNKS);
                        parentStates.push(chunks);
                    } else {
                        // Other active parents
                        const key = BigInt(ethers.hexlify(ethers.randomBytes(32)));
                        const indices = await computeBloomIndices(key, FILTER_SIZE);
                        const bitArray = createBitArray(FILTER_SIZE, indices);
                        const chunks = chunkFieldElements(bitArray, BITS_PER_CHUNK, NUM_CHUNKS);
                        parentStates.push(chunks);
                    }
                } else {
                    parentStates.push(new Array(NUM_CHUNKS).fill(0));
                }
            }
            
            // Compute union (will contain flagged commitment)
            const unionBitArray = new Array(FILTER_SIZE).fill(0);
            for (let i = 0; i < numActiveInputs; i++) {
                const parentBitArray = unchunkFieldElements(parentStates[i], BITS_PER_CHUNK, LAST_CHUNK_BITS);
                for (let j = 0; j < FILTER_SIZE; j++) {
                    unionBitArray[j] |= parentBitArray[j];
                }
            }
            const unionState = chunkFieldElements(unionBitArray, BITS_PER_CHUNK, NUM_CHUNKS);
            
            const flaggedBitArray = createBitArray(FILTER_SIZE, flaggedIndices);
            const flaggedStateChunks = chunkFieldElements(flaggedBitArray, BITS_PER_CHUNK, NUM_CHUNKS);
            
            const chainStatesHash = await computeParentStatesHash(parentStates, numActiveInputs);
            const smtData = await setupSMTree(flaggedStateChunks);
            
            const input = {
                numActiveInputs,
                parentStates,
                unionState,
                chainStatesHash,
                flaggedStateChunks,
                root: smtData.root,
                siblings: smtData.proof.siblings,
                key: smtData.key,
                value: smtData.value,
                auxKey: 0,
                auxValue: 0,
                auxIsEmpty: 0,
                isExclusion: 0
            };
            
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            
            const notInSet = witness[1];
            expect(notInSet.toString()).to.equal("0"); // should detect membership
            console.log("Membership detected (flagged commitment found in union)");
        });

        it("should reject invalid SMT proof for flagged commitment", async () => {
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
                    parentStates.push(new Array(NUM_CHUNKS).fill(0));
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
            
            // Create SMT with DIFFERENT data
            const differentBitArray = createBitArray(FILTER_SIZE, [0, 1]);
            const differentChunks = chunkFieldElements(differentBitArray, BITS_PER_CHUNK, NUM_CHUNKS);
            const wrongSmtData = await setupSMTree(differentChunks);
            
            const input = {
                numActiveInputs,
                parentStates,
                unionState,
                chainStatesHash,
                flaggedStateChunks, // this doesn't match SMT data
                root: wrongSmtData.root,
                siblings: wrongSmtData.proof.siblings,
                key: wrongSmtData.key,
                value: wrongSmtData.value,
                auxKey: 0,
                auxValue: 0,
                auxIsEmpty: 0,
                isExclusion: 0
            };
            
            try {
                await circuit.calculateWitness(input);
                expect.fail("Should have failed with invalid SMT proof");
            } catch (err) {
                expect(err.toString()).to.satisfy(msg => 
                    msg.includes("Assert Failed") || msg.includes("Constraint doesn't match")
                );
                console.log("Correctly rejected invalid SMT proof");
            }
        });
    });
});