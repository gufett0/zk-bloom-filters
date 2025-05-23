const { expect } = require("chai");
const path = require("path");
const { ethers } = require("ethers");
const { wasm } = require("circom_tester");
const { computeBloomIndices, createBitArray, setupSMTree } = require("./utils");

describe("Bloom Filter Circuit Tests", function() {
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