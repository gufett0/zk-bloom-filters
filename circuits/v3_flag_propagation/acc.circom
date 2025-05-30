pragma circom 2.1.9;

include "./bloom.circom";

template AncestralCommitmentComplianceFieldChunked(numChunks, k, depth, maxInputs) {
    // Number of actual inputs (2 to maxInputs)
    signal input numActiveInputs;
    
    // Parent states as arrays of field element chunks
    signal input parentStates[maxInputs][numChunks];
    
    // Claimed union state as array of chunks
    signal input unionState[numChunks];
    
    // Hash of parent states (to be included in extDataHash)
    signal input chainStatesHash;
    
    // Flagged masked commitment as array of chunks
    signal input flaggedStateChunks[numChunks];
    
    // SMT proof inputs
    signal input root;
    signal input siblings[depth];
    signal input key;
    signal input value; // Hash of flaggedStateChunks
    signal input auxKey;
    signal input auxValue;
    signal input auxIsEmpty;
    signal input isExclusion;
    
    signal output notInSet;
    signal output chainStateValid;
    
    // Verify numActiveInputs is within valid range (2 to maxInputs)
    component gte = GreaterEqThan(5);
    gte.in[0] <== numActiveInputs;
    gte.in[1] <== 2;
    component lte = LessEqThan(5);
    lte.in[0] <== numActiveInputs;
    lte.in[1] <== maxInputs;
    signal validRange <== gte.out * lte.out;
    validRange === 1;
    
    // 1. Verify chainStatesHash matches the provided parentStates
    component parentHasher = ParentStatesHasherFieldChunked(numChunks, maxInputs);
    parentHasher.numActiveInputs <== numActiveInputs;
    for (var i = 0; i < maxInputs; i++) {
        for (var c = 0; c < numChunks; c++) {
            parentHasher.parentStates[i][c] <== parentStates[i][c];
        }
    }
    
    // This ensures the provided parentStates match the hash
    parentHasher.hash === chainStatesHash;
    
    // 2. Verify bloom filter union is computed correctly
    component bloomUnion = BloomFilterUnionFieldChunked(numChunks, maxInputs);
    bloomUnion.numActiveInputs <== numActiveInputs;
    for (var i = 0; i < maxInputs; i++) {
        for (var c = 0; c < numChunks; c++) {
            bloomUnion.parentStates[i][c] <== parentStates[i][c];
        }
    }
    for (var c = 0; c < numChunks; c++) {
        bloomUnion.unionState[c] <== unionState[c];
    }
    
    // 3. Verify the flagged masked commitment is NOT in the union chain state
    component bloomFilter = BloomFilterFieldChunked(numChunks, k, depth);
    for (var c = 0; c < numChunks; c++) {
        bloomFilter.chainStateChunks[c] <== unionState[c];
        bloomFilter.flaggedStateChunks[c] <== flaggedStateChunks[c];
    }
    
    bloomFilter.root <== root;
    for (var i = 0; i < depth; i++) {
        bloomFilter.siblings[i] <== siblings[i];
    }
    bloomFilter.key <== key;
    bloomFilter.value <== value;
    bloomFilter.auxKey <== auxKey;
    bloomFilter.auxValue <== auxValue;
    bloomFilter.auxIsEmpty <== auxIsEmpty;
    bloomFilter.isExclusion <== isExclusion;
    
    notInSet <== bloomFilter.notInSet;
    chainStateValid <== 1;
}

// Main component with parameters:
// - numChunks: 65 (16384 bits / 254 bits per chunk = 64.5, rounded up to 65)
// - k: 2 (number of hash functions)
// - depth: 20 (SMT depth)
// - maxInputs: 16 (maximum number of parent states)
component main {public [root, key, isExclusion, chainStatesHash, numActiveInputs]} = AncestralCommitmentComplianceFieldChunked(65, 2, 20, 16);