pragma circom 2.1.9;

include "./bloom.circom";

template AncestralCommitmentCompliance(n, k, depth, numInputs) {
    // Existing inputs
    signal input bitArray2[n];
    signal input root;
    signal input siblings[depth];
    signal input key;
    signal input value;
    signal input auxKey;
    signal input auxValue;
    signal input auxIsEmpty;
    signal input isExclusion;
    
    signal input parentStates[numInputs][n];
    signal input unionState[n];
    signal input chainStatesHash;  // Hash che dovrebbe corrispondere ai parentStates
    
    signal output notInSet;
    signal output chainStateValid;
    
    // 0. Verify chainStatesHash matches the provided parentStates
    component parentHasher = ParentStatesHasher(n, numInputs);
    for (var i = 0; i < numInputs; i++) {
        for (var j = 0; j < n; j++) {
            parentHasher.parentStates[i][j] <== parentStates[i][j];
        }
    }
    
    // This constraint ensures the provided parentStates match the hash
    parentHasher.hash === chainStatesHash;
    
    // 1. Verify bloom filter union is computed correctly
    component bloomUnion = BloomFilterUnion(n, numInputs);
    for (var i = 0; i < numInputs; i++) {
        for (var j = 0; j < n; j++) {
            bloomUnion.parentStates[i][j] <== parentStates[i][j];
        }
    }
    for (var j = 0; j < n; j++) {
        bloomUnion.unionState[j] <== unionState[j];
    }
    
    // 2. Verify the flagged masked commitment is NOT in the union chain state
    component bloomFilter = BloomFilter(n, k, depth);
    for (var i = 0; i < n; i++) {
        bloomFilter.bitArray[i] <== unionState[i];
        bloomFilter.bitArray2[i] <== bitArray2[i];
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

// (poseidon can handle up to 16 inputs efficiently)
component main {public [root, key, isExclusion, chainStatesHash]} = AncestralCommitmentCompliance(16384, 2, 20, 2);