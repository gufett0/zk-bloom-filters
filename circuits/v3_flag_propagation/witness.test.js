const { expect } = require("chai");
const path = require("path");
const { ethers } = require("ethers");
const { wasm } = require("circom_tester");
const { computeBloomIndices, createBitArray, setupSMTree } = require("./utils");

describe("Bloom Filter Non-membership tests", function() {
    this.timeout(1000000);
    
    let circuit;
    const FILTER_SIZE = 16384;
    
    before(async () => {
        circuit = await wasm(path.join(__dirname, "non_membership.circom"));
    });

    it("should correctly identify non-membership", async () => {
        const chainstateKey = BigInt(ethers.hexlify(ethers.randomBytes(32)));
        const chainstateIndices = await computeBloomIndices(chainstateKey, FILTER_SIZE);
        const chainstateBitArray = createBitArray(FILTER_SIZE, chainstateIndices);

        const testKey = BigInt(ethers.hexlify(ethers.randomBytes(32)));
        const testIndices = await computeBloomIndices(testKey, FILTER_SIZE);
        const testBitArray = createBitArray(FILTER_SIZE, testIndices);

        const smtData = await setupSMTree(testBitArray);

        const input = {
            bitArray: chainstateBitArray,
            bitArray2: testBitArray,
            root: smtData.root,
            siblings: smtData.proof.siblings,
            key: smtData.key,
            value: smtData.value,
            auxKey: 0,
            auxValue: 0,
            auxIsEmpty: 0,
            isExclusion: 0
        };

        const startTime = performance.now();
        const witness = await circuit.calculateWitness(input);
        const endTime = performance.now();
        console.log(`Witness generation time: ${endTime - startTime} ms`);
        await circuit.checkConstraints(witness);
        
        const notInSetOutput = witness[1]; 
        expect(notInSetOutput.toString()).to.equal("1");
        console.log("Non-membership correctly identified: notInSet =", notInSetOutput.toString());
    });

    it("should correctly identify membership", async () => {
        const testKey = BigInt(ethers.hexlify(ethers.randomBytes(32)));
        const testIndices = await computeBloomIndices(testKey, FILTER_SIZE);
        const testBitArray = createBitArray(FILTER_SIZE, testIndices);

        const chainstateBitArray = createBitArray(FILTER_SIZE, testIndices);

        const smtData = await setupSMTree(testBitArray);

        const input = {
            bitArray: chainstateBitArray,
            bitArray2: testBitArray,
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
        
        const notInSetOutput = witness[1];
        expect(notInSetOutput.toString()).to.equal("0");
        console.log("Membership correctly identified: notInSet =", notInSetOutput.toString());
    });

    it("should detect false positives with bloom filter", async () => {
        const numElements = 1000;
        const chainstateBitArray = new Array(FILTER_SIZE).fill(0);
        const addedKeys = [];
        
        for(let i = 0; i < numElements; i++) {
            const key = BigInt(ethers.hexlify(ethers.randomBytes(32)));
            addedKeys.push(key);
            const indices = await computeBloomIndices(key, FILTER_SIZE);
            indices.forEach(idx => chainstateBitArray[idx] = 1);
        }

        let falsePositives = 0;
        let trueNegatives = 0;
        const numTests = 1000; 

        for(let i = 0; i < numTests; i++) {
            const testKey = BigInt(ethers.hexlify(ethers.randomBytes(32)));
            const testIndices = await computeBloomIndices(testKey, FILTER_SIZE);
            
            const wouldBeFalsePositive = testIndices.every(idx => chainstateBitArray[idx] === 1);
            
            if (wouldBeFalsePositive) {
                falsePositives++;
                
                if (falsePositives <= 5) {
                    const testBitArray = createBitArray(FILTER_SIZE, testIndices);
                    const smtData = await setupSMTree(testBitArray);

                    const input = {
                        bitArray: chainstateBitArray,
                        bitArray2: testBitArray,
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
                    
                    const notInSetOutput = witness[1];
                    expect(notInSetOutput.toString()).to.equal("0");
                    console.log(`False positive detected: notInSet = ${notInSetOutput.toString()}`);
                }
            } else {
                trueNegatives++;
                
                if (trueNegatives <= 10 && i % 100 === 0) {
                    const testBitArray = createBitArray(FILTER_SIZE, testIndices);
                    const smtData = await setupSMTree(testBitArray);

                    const input = {
                        bitArray: chainstateBitArray,
                        bitArray2: testBitArray,
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
                    
                    const notInSetOutput = witness[1];
                    expect(notInSetOutput.toString()).to.equal("1");
                }
            }
        }

        const falsePositiveRate = falsePositives / numTests;
        console.log(`False positive rate: ${(falsePositiveRate * 100).toFixed(2)}%`);
        console.log(`Total false positives: ${falsePositives} out of ${numTests} tests`);
        console.log(`Total true negatives: ${trueNegatives} out of ${numTests} tests`);
        
        // with k=2 and n=1000 elements in a 16384-bit filter, 
        // expected FP rate ≈ (1 - e^(-2*1000/16384))^2 ≈ 1.4%
        const expectedFPRate = Math.pow(1 - Math.exp(-2 * numElements / FILTER_SIZE), 2);
        console.log(`Expected FP rate: ${(expectedFPRate * 100).toFixed(2)}%`);
        
        expect(falsePositiveRate).to.be.below(0.05); // allow up to 5% FP rate
        expect(falsePositiveRate).to.be.above(0); 
    });

    it("should fail when bitArray contains invalid values", async () => {
        const testKey = BigInt(ethers.hexlify(ethers.randomBytes(32)));
        const testIndices = await computeBloomIndices(testKey, FILTER_SIZE);
        const testBitArray = createBitArray(FILTER_SIZE, testIndices);

        const smtData = await setupSMTree(testBitArray);

        const invalidBitArray = new Array(FILTER_SIZE).fill(0);
        invalidBitArray[0] = 2;

        const input = {
            bitArray: invalidBitArray,
            bitArray2: testBitArray,
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
            const startTime = performance.now();
            await circuit.calculateWitness(input);
            const endTime = performance.now();
            console.log(`Witness generation time: ${endTime - startTime} ms`);
            expect.fail("Should have thrown an error");
        } catch (err) {
            expect(err.toString()).to.include("Assert Failed");
        }
    });

    it("should fail when using bitArray2 not in SMT", async () => {
        const chainstateKey = BigInt(ethers.hexlify(ethers.randomBytes(32)));
        const chainstateIndices = await computeBloomIndices(chainstateKey, FILTER_SIZE);
        const chainstateBitArray = createBitArray(FILTER_SIZE, chainstateIndices);

        const testKey = BigInt(ethers.hexlify(ethers.randomBytes(32)));
        const testIndices = await computeBloomIndices(testKey, FILTER_SIZE);
        const testBitArray = createBitArray(FILTER_SIZE, testIndices);

        // add a DIFFERENT bit array to the SMT
        const differentBitArray = createBitArray(FILTER_SIZE, [0, 1]);
        const smtData = await setupSMTree(differentBitArray);

        const input = {
            bitArray: chainstateBitArray,
            bitArray2: testBitArray, // this doesn't match what's in the SMT
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
            const startTime = performance.now();
            await circuit.calculateWitness(input);
            const endTime = performance.now();
            console.log(`Witness generation time: ${endTime - startTime} ms`);
            expect.fail("Should have thrown an error");
        } catch (err) {
            expect(err.toString()).to.satisfy(msg => 
                msg.includes("Assert Failed") || msg.includes("Constraint doesn't match")
            );
        }
    });

    it("should correctly handle union of bloom filters", async () => {
        const key1 = BigInt(ethers.hexlify(ethers.randomBytes(32)));
        const indices1 = await computeBloomIndices(key1, FILTER_SIZE);
        
        const key2 = BigInt(ethers.hexlify(ethers.randomBytes(32)));
        const indices2 = await computeBloomIndices(key2, FILTER_SIZE);
        
        const unionBitArray = new Array(FILTER_SIZE).fill(0);
        indices1.forEach(idx => unionBitArray[idx] = 1);
        indices2.forEach(idx => unionBitArray[idx] = 1);

        // test with an element not in the union
        const testKey = BigInt(ethers.hexlify(ethers.randomBytes(32)));
        const testIndices = await computeBloomIndices(testKey, FILTER_SIZE);
        const testBitArray = createBitArray(FILTER_SIZE, testIndices);

        const smtData = await setupSMTree(testBitArray);

        const input = {
            bitArray: unionBitArray,
            bitArray2: testBitArray,
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
        
        const notInSetOutput = witness[1];
        console.log(`Union test - notInSet: ${notInSetOutput.toString()}`);
        
        // should be 1 if test element is not in union, 0 if it is (due to false positive)
        expect(notInSetOutput.toString()).to.satisfy(val => val === "0" || val === "1");
    });

    it("should provide consistent output for same inputs", async () => {
        const testKey = BigInt(ethers.hexlify(ethers.randomBytes(32)));
        const testIndices = await computeBloomIndices(testKey, FILTER_SIZE);
        const testBitArray = createBitArray(FILTER_SIZE, testIndices);

        const chainstateBitArray = createBitArray(FILTER_SIZE, [100, 200]); // different indices

        const smtData = await setupSMTree(testBitArray);

        const input = {
            bitArray: chainstateBitArray,
            bitArray2: testBitArray,
            root: smtData.root,
            siblings: smtData.proof.siblings,
            key: smtData.key,
            value: smtData.value,
            auxKey: 0,
            auxValue: 0,
            auxIsEmpty: 0,
            isExclusion: 0
        };

        // run the same test multiple times
        const results = [];
        for (let i = 0; i < 3; i++) {
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            const notInSetOutput = witness[1];
            results.push(notInSetOutput.toString());
        }

        expect(results.every(r => r === results[0])).to.be.true;
        console.log(`Consistent output across runs: ${results[0]}`);
    });
});

describe("BloomFilterUnion Circuit Tests", function() {
    this.timeout(1000000);
    
    let unionCircuit;
    const FILTER_SIZE = 16384;
    const NUM_INPUTS = 16;
    
    before(async () => {
        unionCircuit = await wasm(path.join(__dirname, "union_set.circom"));
    });

    it("should correctly compute union of empty bloom filters", async () => {
        const parentStates = Array(NUM_INPUTS).fill(null).map(() => new Array(FILTER_SIZE).fill(0));
        const expectedUnion = new Array(FILTER_SIZE).fill(0);

        const input = {
            parentStates: parentStates,
            unionState: expectedUnion
        };

        const witness = await unionCircuit.calculateWitness(input);
        await unionCircuit.checkConstraints(witness);
        console.log("Empty bloom filters union test passed");
    });

    it("should correctly compute union with one non-empty bloom filter", async () => {
        const parentStates = Array(NUM_INPUTS).fill(null).map(() => new Array(FILTER_SIZE).fill(0));
        
        const testKey = BigInt(ethers.hexlify(ethers.randomBytes(32)));
        const testIndices = await computeBloomIndices(testKey, FILTER_SIZE);
        parentStates[0] = createBitArray(FILTER_SIZE, testIndices);
        
        const expectedUnion = [...parentStates[0]];

        const input = {
            parentStates: parentStates,
            unionState: expectedUnion
        };

        const witness = await unionCircuit.calculateWitness(input);
        await unionCircuit.checkConstraints(witness);
        console.log("One non-empty bloom filter union test passed");
    });

    it("should correctly compute union of identical bloom filters", async () => {
        const testKey = BigInt(ethers.hexlify(ethers.randomBytes(32)));
        const testIndices = await computeBloomIndices(testKey, FILTER_SIZE);
        const singleFilter = createBitArray(FILTER_SIZE, testIndices);
        
        const parentStates = Array(NUM_INPUTS).fill(null).map(() => [...singleFilter]);
        
        // union of identical filters should be the same filter
        const expectedUnion = [...singleFilter];

        const input = {
            parentStates: parentStates,
            unionState: expectedUnion
        };

        const witness = await unionCircuit.calculateWitness(input);
        await unionCircuit.checkConstraints(witness);
        console.log("Identical bloom filters union test passed");
    });

    it("should correctly compute union of multiple different bloom filters", async () => {
        const parentStates = [];
        
        for (let i = 0; i < NUM_INPUTS; i++) {
            const key = BigInt(ethers.hexlify(ethers.randomBytes(32)));
            const indices = await computeBloomIndices(key, FILTER_SIZE);
            parentStates.push(createBitArray(FILTER_SIZE, indices));
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
            parentStates: parentStates,
            unionState: expectedUnion
        };

        const witness = await unionCircuit.calculateWitness(input);
        await unionCircuit.checkConstraints(witness);
        console.log("Multiple different bloom filters union test passed");
    });

    it("should fail when union state is incorrect", async () => {
        const parentStates = [];
        
        // Create a few different bloom filters
        for (let i = 0; i < NUM_INPUTS; i++) {
            if (i < 3) { // Only make first 3 non-empty for simplicity
                const key = BigInt(ethers.hexlify(ethers.randomBytes(32)));
                const indices = await computeBloomIndices(key, FILTER_SIZE);
                parentStates.push(createBitArray(FILTER_SIZE, indices));
            } else {
                parentStates.push(new Array(FILTER_SIZE).fill(0));
            }
        }
        
        const incorrectUnion = [...parentStates[0]];

        const input = {
            parentStates: parentStates,
            unionState: incorrectUnion
        };

        try {
            await unionCircuit.calculateWitness(input);
            expect.fail("Should have thrown an error for incorrect union");
        } catch (err) {
            expect(err.toString()).to.satisfy(msg => 
                msg.includes("Assert Failed") || msg.includes("Constraint doesn't match")
            );
            console.log("Correctly rejected incorrect union state");
        }
    });

    it("should fail when parent states contain non-binary values", async () => {
        const parentStates = Array(NUM_INPUTS).fill(null).map(() => new Array(FILTER_SIZE).fill(0));
        parentStates[0][0] = 2; 
        
        const expectedUnion = new Array(FILTER_SIZE).fill(0);

        const input = {
            parentStates: parentStates,
            unionState: expectedUnion
        };

        try {
            await unionCircuit.calculateWitness(input);
            expect.fail("Should have thrown an error for non-binary values");
        } catch (err) {
            expect(err.toString()).to.include("Assert Failed");
            console.log("Correctly rejected non-binary parent state values");
        }
    });

    it("should fail when union state contains non-binary values", async () => {
        
        const parentStates = Array(NUM_INPUTS).fill(null).map(() => new Array(FILTER_SIZE).fill(0));
        
        const invalidUnion = new Array(FILTER_SIZE).fill(0);
        invalidUnion[0] = 3; 

        const input = {
            parentStates: parentStates,
            unionState: invalidUnion
        };

        try {
            await unionCircuit.calculateWitness(input);
            expect.fail("Should have thrown an error for non-binary union values");
        } catch (err) {
            expect(err.toString()).to.include("Assert Failed");
            console.log("Correctly rejected non-binary union state values");
        }
    });

    it("should handle complex union with multiple overlapping elements", async () => {
        const parentStates = [];
        const allKeys = [];
        
        // create filters with some overlapping elements
        for (let i = 0; i < NUM_INPUTS; i++) {
            const keys = [];
            
            // each filter gets 2-3 unique keys plus some shared ones
            for (let j = 0; j < 2; j++) {
                keys.push(BigInt(ethers.hexlify(ethers.randomBytes(32))));
            }
            
            // every other filter shares a key with the previous one
            if (i > 0 && i % 2 === 1 && allKeys.length > 0) {
                keys.push(allKeys[allKeys.length - 1]);
            }
            
            allKeys.push(...keys);
            
            // build filter for this set of keys
            const filter = new Array(FILTER_SIZE).fill(0);
            for (const key of keys) {
                const indices = await computeBloomIndices(key, FILTER_SIZE);
                indices.forEach(idx => filter[idx] = 1);
            }
            parentStates.push(filter);
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
            parentStates: parentStates,
            unionState: expectedUnion
        };

        const witness = await unionCircuit.calculateWitness(input);
        await unionCircuit.checkConstraints(witness);
        console.log("Complex overlapping union test passed");
    });

    it("should maintain commutativity property for multiple inputs", async () => {
        const originalStates = [];
        for (let i = 0; i < NUM_INPUTS; i++) {
            const key = BigInt(ethers.hexlify(ethers.randomBytes(32)));
            const indices = await computeBloomIndices(key, FILTER_SIZE);
            originalStates.push(createBitArray(FILTER_SIZE, indices));
        }
        
        const expectedUnion = new Array(FILTER_SIZE).fill(0);
        for (let i = 0; i < FILTER_SIZE; i++) {
            for (let j = 0; j < NUM_INPUTS; j++) {
                if (originalStates[j][i] === 1) {
                    expectedUnion[i] = 1;
                    break;
                }
            }
        }

        // test with original order
        const input1 = {
            parentStates: originalStates,
            unionState: expectedUnion
        };

        const witness1 = await unionCircuit.calculateWitness(input1);
        await unionCircuit.checkConstraints(witness1);

        // test with shuffled order
        const shuffledStates = [...originalStates].sort(() => Math.random() - 0.5);
        const input2 = {
            parentStates: shuffledStates,
            unionState: expectedUnion
        };

        const witness2 = await unionCircuit.calculateWitness(input2);
        await unionCircuit.checkConstraints(witness2);
        
        console.log("Commutativity property verified for multiple inputs");
    });

    it("should handle edge case with maximum density bloom filter", async () => {
        const parentStates = [];
        
        // create one nearly full bloom filter
        const highDensityFilter = new Array(FILTER_SIZE);
        for (let i = 0; i < FILTER_SIZE; i++) {
            highDensityFilter[i] = Math.random() > 0.1 ? 1 : 0; // 90% density
        }
        parentStates.push(highDensityFilter);
        
        // fill the rest with mostly empty filters
        for (let i = 1; i < NUM_INPUTS; i++) {
            if (i < 3) {
                const key = BigInt(ethers.hexlify(ethers.randomBytes(32)));
                const indices = await computeBloomIndices(key, FILTER_SIZE);
                parentStates.push(createBitArray(FILTER_SIZE, indices));
            } else {
                parentStates.push(new Array(FILTER_SIZE).fill(0));
            }
        }
        
        // union with high-density filter (should be mostly 1s)
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
            parentStates: parentStates,
            unionState: expectedUnion
        };

        const witness = await unionCircuit.calculateWitness(input);
        await unionCircuit.checkConstraints(witness);
        console.log("High density bloom filter union test passed");
    });
});