pragma circom 2.1.9;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "./smtverifier.circom";

template BitArrayIntersection(n) {
    signal input array1[n];
    signal input array2[n];
    signal output sum; // this will be the sum of all indices resulting from intersection
    signal intersection[n];

    var tempSum = 0;

    // make sure outputs are binary
    for (var i = 0; i < n; i++) {
        array1[i] * (array1[i] - 1) === 0;
        array2[i] * (array2[i] - 1) === 0;

        // compute intersection
        intersection[i] <== array1[i] * array2[i];
        tempSum += intersection[i];
    }
    sum <== tempSum;
}


template BloomFilter(n, k, depth) {

    
    signal input bitArray[n]; // this would be the bloom filter representing the utxo chainstate
    signal input bitArray2[n]; // this would be a bloom filter with just one element (derived from the flagged masked commitment)
    // the bitarrays stay private to keep proof public signal small, and to shield anyone to see the chainstate of users utxo 
    
    signal output notInSet; // 1 if bitArray2 is NOT a member of bitArray

    // inputs for smt verification
    signal input root;
    signal input siblings[depth];
    signal input key; // maybe this would be the bytes32 element (masked commitment)
    signal input value; // this should correspond to bitArray2
    signal input auxKey;
    signal input auxValue;
    signal input auxIsEmpty;
    // not private bc everyone should know what we're testing for
    signal input isExclusion; // this will be input as 0, bc we want to prove that the used bitarray was indeed taken from the masked smt

    // add a constraint that the int value in SMT matches our input bitArray2
    component bits2Value = Bits2Num(n);
    for (var i = 0; i < n; i++) {
        bits2Value.in[i] <== bitArray2[i];
        //bitArray2[i] * (bitArray2[i] - 1) === 0; // additionally enforce that the bits are binary (not needed?)
    }

    // log(bits2Value.out);
    bits2Value.out === value;

    //log(root);

    // first verify that bitArray2 belongs to the authorized smt 
    component smtVerifier = SMTVerifier(depth);
    smtVerifier.root <== root;
    for (var i = 0; i < depth; i++) {
        smtVerifier.siblings[i] <== siblings[i];
    }
    smtVerifier.key <== key;
    smtVerifier.value <== value;
    smtVerifier.auxKey <== auxKey;
    smtVerifier.auxValue <== auxValue;
    smtVerifier.auxIsEmpty <== auxIsEmpty;
    smtVerifier.isExclusion <== isExclusion;

    // then do bloom filter check
    component intersection = BitArrayIntersection(n);
    for (var i = 0; i < n; i++) {
        intersection.array1[i] <== bitArray[i];
        intersection.array2[i] <== bitArray2[i];
    }
    
    // if intersection sum equals k, all bits were set
    component eq = IsEqual();
    eq.in[0] <== intersection.sum;
    eq.in[1] <== k;

    notInSet <== 1 - eq.out;
    //eq.out === 0;
}

template BloomFilterUnion(m, numInputs) {
    // Parent bloom filters from input UTXOs
    signal input parentStates[numInputs][m];
    
    // The claimed union bloom filter for the output UTXO
    signal input unionState[m];
    
    // Intermediate signals for computing the union iteratively
    signal intermediate[numInputs-1][m];
    
    // Process each bit position in the bloom filter
    for (var j = 0; j < m; j++) {
        // Verify all inputs are binary (0 or 1)
        for (var i = 0; i < numInputs; i++) {
            // Constraint: each bit must be 0 or 1
            parentStates[i][j] * (parentStates[i][j] - 1) === 0;
        }
        
        // Verify the output union bit is binary
        unionState[j] * (unionState[j] - 1) === 0;
        
        // Compute OR operation iteratively for this bit position
        if (numInputs == 2) {
            // Direct computation for 2 inputs (common case)
            // OR operation: A OR B = A + B - A*B
            unionState[j] === parentStates[0][j] + parentStates[1][j] - parentStates[0][j] * parentStates[1][j];
        } else {
            // For more inputs, compute iteratively
            // First OR: parentStates[0] OR parentStates[1]
            intermediate[0][j] <== parentStates[0][j] + parentStates[1][j] - parentStates[0][j] * parentStates[1][j];
            
            // Subsequent ORs: intermediate[i-1] OR parentStates[i+1]
            for (var i = 1; i < numInputs - 1; i++) {
                intermediate[i][j] <== intermediate[i-1][j] + parentStates[i+1][j] - intermediate[i-1][j] * parentStates[i+1][j];
            }
            
            // Final result must match the claimed union
            unionState[j] === intermediate[numInputs-2][j];
        }
    }
}

// Version with commitment binding to ensure chain states are linked to UTXOs
template BloomFilterUnionWithBinding(m, numInputs) {
    // Bloom filter inputs
    signal input parentStates[numInputs][m];
    signal input unionState[m];
    
    // Binding to existing Transaction circuit outputs
    signal input outputCommitment;  // This should match the outputCommitment from Transaction
    signal input outAmount;
    signal input outPubkey;
    signal input outBlinding;
    
    // First verify the bloom filter union
    component unionCheck = BloomFilterUnion(m, numInputs);
    for (var i = 0; i < numInputs; i++) {
        for (var j = 0; j < m; j++) {
            unionCheck.parentStates[i][j] <== parentStates[i][j];
        }
    }
    for (var j = 0; j < m; j++) {
        unionCheck.unionState[j] <== unionState[j];
    }
    
    // Hash the bloom filter state to a single value
    // Since m is large (e.g., 16384), we need to compress it
    // Option 1: Hash chunks of the bloom filter
    component stateHasher = Poseidon(2);
    
    // Convert bloom filter to number (for small portions)
    // In practice, you'd hash multiple chunks
    component bitsToNum = Bits2Num(254); // Poseidon field size limit
    var sum = 0;
    for (var i = 0; i < 254 && i < m; i++) {
        sum += unionState[i] * (1 << i);
    }
    
    // Simple binding: hash the bloom filter representation with the blinding
    stateHasher.inputs[0] <== sum;
    stateHasher.inputs[1] <== outBlinding;
    
    // Create extended commitment that includes chain state
    component extendedCommitment = Poseidon(4);
    extendedCommitment.inputs[0] <== outAmount;
    extendedCommitment.inputs[1] <== outPubkey;
    extendedCommitment.inputs[2] <== outBlinding;
    extendedCommitment.inputs[3] <== stateHasher.out;
    
    // This extended commitment should be stored alongside the regular commitment
    signal output chainBoundCommitment;
    chainBoundCommitment <== extendedCommitment.out;
}