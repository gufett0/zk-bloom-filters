const { buildPoseidon, poseidon } = require("circomlibjs");
const { ethers } = require("ethers");
const { SMT } = require("@zk-kit/smt");


let poseidonInstance = null;

async function initializePoseidon() {
    
    if (!poseidonInstance) {
        poseidonInstance = await buildPoseidon();
    }
    return poseidonInstance;
}

async function createPoseidonHasher() {
    const poseidon = await initializePoseidon();
    
    
    return (inputs) => {
        const hash = poseidon(inputs);
        return BigInt(poseidon.F.toObject(hash));
    };
}


function padSiblings(siblings, depth) {
    return siblings.length < depth 
        ? siblings.concat(Array(depth - siblings.length).fill(0n))
        : siblings;
}

function bits2Num(bits) {
    return bits.reduce((acc, bit, i) => {
        return acc + BigInt(bit) * (2n ** BigInt(i));
    }, 0n);
}

function toHex(number, length = 32) {
    const str = number instanceof Buffer ? number.toString('hex') : BigInt(number).toString(16);
    return '0x' + str.padStart(length * 2, '0');
}

function toFixedHex(number, length = 32) {
    let hexString;
    if (Buffer.isBuffer(number)) {
        hexString = number.toString('hex');
    } else {
        hexString = toHex(number).replace('0x', '');
    }
    return '0x' + hexString.padStart(length * 2, '0');
}

function convertNodeToBigInt(node) {
    if (typeof node === 'bigint') {
        return node;
    }
    if (typeof node === 'string') {
        return BigInt(node);
    }
    return BigInt(node.toString());
}

function convertSiblingsToArray(siblings) {
    const result = [];
    const keys = Object.keys(siblings).sort((a, b) => Number(a) - Number(b));
    
    for (const key of keys) {
        const node = siblings[Number(key)];
        result.push(convertNodeToBigInt(node));
    }
    
    return result;
}

async function setupSMTree(input) {
    const hasher = await createPoseidonHasher();
    
    const smt = new SMT(hasher, true);
    const key = BigInt(ethers.hexlify(ethers.randomBytes(32)));
    
    let value;
    
    // Check if input is chunks (array of strings/numbers) or bitArray (array of 0s and 1s)
    if (Array.isArray(input) && input.length > 0) {
        if (typeof input[0] === 'string' || typeof input[0] === 'number' || typeof input[0] === 'bigint') {
            // Input is chunks - use poseidonHashVec to compute value
            value = await poseidonHashVec(input);
        } else if (input[0] === 0 || input[0] === 1) {
            // Input is bitArray - use bits2Num to compute value
            value = bits2Num(input);
        } else {
            throw new Error('Invalid input format for setupSMTree');
        }
    } else {
        throw new Error('Invalid input for setupSMTree');
    }
    
    await smt.add(key, value);

    const rawProof = smt.createProof(key);
    
    const convertedProof = {
        siblings: convertSiblingsToArray(padSiblings(rawProof.siblings, 20))
    };
    
    return {
        smt,
        key,
        proof: convertedProof,
        root: convertNodeToBigInt(smt.root),
        value
    };
}

async function computeBloomIndices(key, filterSize) {
    const hasher = await createPoseidonHasher();
    const hash1 = hasher([key]);
    const hash2 = hasher([hash1]);
    
    const index1 = Number(hash1 % BigInt(filterSize));
    const index2 = Number(hash2 % BigInt(filterSize));
    
    return [index1, index2];
}

function createBitArray(size, indices) {
    const arr = new Array(size).fill(0);
    indices.forEach(idx => arr[idx] = 1);
    return arr;
}

// NEW FUNCTIONS FOR ACC CIRCUIT TESTS

function chunkFieldElements(bitArray, bitsPerChunk, numChunks) {
    const chunks = [];
    for (let i = 0; i < numChunks; i++) {
        let chunk = BigInt(0);
        const startBit = i * bitsPerChunk;
        const endBit = Math.min(startBit + bitsPerChunk, bitArray.length);
        
        for (let j = startBit; j < endBit; j++) {
            if (bitArray[j] === 1) {
                chunk |= BigInt(1) << BigInt(j - startBit);
            }
        }
        chunks.push(chunk.toString());
    }
    return chunks;
}

function unchunkFieldElements(chunks, bitsPerChunk, lastChunkBits) {
    const bitArray = [];
    for (let i = 0; i < chunks.length; i++) {
        const chunk = BigInt(chunks[i]);
        const bitsInChunk = (i === chunks.length - 1) ? lastChunkBits : bitsPerChunk;
        
        for (let j = 0; j < bitsInChunk; j++) {
            bitArray.push((chunk & (BigInt(1) << BigInt(j))) !== BigInt(0) ? 1 : 0);
        }
    }
    return bitArray;
}

// Implements the same hashing logic as PoseidonHashVec in bloom.circom
async function poseidonHashVec(elements) {
    if (elements.length === 0) return BigInt(0);
    
    const hasher = await createPoseidonHasher();
    const RATE = 4; // 4 elements per Poseidon call
    const WIDTH = 5; // total Poseidon state size
    
    if (elements.length <= RATE) {
        // Single Poseidon call sufficient
        const inputs = [BigInt(0)]; // initial state
        for (let i = 0; i < RATE; i++) {
            if (i < elements.length) {
                inputs.push(BigInt(elements[i]));
            } else {
                inputs.push(BigInt(0)); // padding
            }
        }
        return hasher(inputs);
    } else {
        // Multiple Poseidon calls with chaining
        let state = BigInt(0);
        
        // First call
        const firstInputs = [state, BigInt(elements[0]), BigInt(elements[1]), BigInt(elements[2]), BigInt(elements[3])];
        state = hasher(firstInputs);
        
        // Subsequent calls
        let inputIndex = 4;
        while (inputIndex < elements.length) {
            const inputs = [state];
            for (let slot = 1; slot < WIDTH; slot++) {
                if (inputIndex < elements.length) {
                    inputs.push(BigInt(elements[inputIndex]));
                    inputIndex++;
                } else {
                    inputs.push(BigInt(0)); // padding
                }
            }
            state = hasher(inputs);
        }
        
        return state;
    }
}

// Realistic implementation matching ParentStatesHasherFieldChunked circuit
async function computeParentStatesHash(parentStates, numActiveInputs) {
    const MAX_INPUTS = parentStates.length;
    
    // Hash each individual parent state (active ones only)
    const stateHashes = [];
    for (let i = 0; i < MAX_INPUTS; i++) {
        if (i < numActiveInputs) {
            // Hash this parent state using PoseidonHashVec
            const stateHash = await poseidonHashVec(parentStates[i]);
            stateHashes.push(stateHash);
        } else {
            // Inactive parents contribute 0
            stateHashes.push(BigInt(0));
        }
    }
    
    // Hash all state hashes together
    const finalHash = await poseidonHashVec(stateHashes);
    return finalHash;
}

module.exports = {
    createPoseidonHasher,
    padSiblings,
    bits2Num,
    toFixedHex,
    convertNodeToBigInt,
    convertSiblingsToArray,
    setupSMTree,
    computeBloomIndices,
    createBitArray,
    chunkFieldElements,
    unchunkFieldElements,
    poseidonHashVec,
    computeParentStatesHash
};