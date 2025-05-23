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

async function setupSMTree(bitArray) {
    const hasher = await createPoseidonHasher();
    
    const smt = new SMT(hasher, true);
    const key = BigInt(ethers.hexlify(ethers.randomBytes(32)));
        
    let value = bits2Num(bitArray);
    
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

module.exports = {
    createPoseidonHasher,
    padSiblings,
    bits2Num,
    toFixedHex,
    convertNodeToBigInt,
    convertSiblingsToArray,
    setupSMTree,
    computeBloomIndices,
    createBitArray
};