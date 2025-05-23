const { expect } = require("chai");
const path = require("path");
const wasm_tester = require("circom_tester").wasm;
const { buildPoseidon, poseidon } = require("circomlibjs");

let poseidonInstance = null;

async function initializePoseidon() {
    if (!poseidonInstance) {
        poseidonInstance = await buildPoseidon();
    }
    return poseidonInstance;
}

// async function createPoseidonHasher() {
//     const poseidon = await initializePoseidon();
    
//     return (inputs) => {

//         const hash = poseidon(inputs);

//         const buffer = Buffer.from(hash); 
//         const hashBigInt = BigInt('0x' + buffer.toString('hex'));  

//         return hashBigInt;
//     };
// }

async function createPoseidonHasher() {
    const poseidon = await initializePoseidon();
    console.log("poseidon ", poseidon);
    
    return (inputs) => {
        const hash = poseidon(inputs);
        return BigInt(poseidon.F.toObject(hash));
    };
}

describe("Hash Test", function() {
    this.timeout(10000);
    
    let circuit;
    
    before(async () => {
        circuit = await wasm_tester(path.join(__dirname, "simpleHash.circom"));
    });

    it("should correctly calculate Hash", async () => {

        const hash = await createPoseidonHasher();
        const inputs = [1, 2];
        const result = hash(inputs);
        console.log(result);

        const input = {
            a: 1,
            b: 2
        };

        const witness = await circuit.calculateWitness(input);
        await circuit.checkConstraints(witness);
        
        expect(witness[1]).to.equal(result);
    });
});