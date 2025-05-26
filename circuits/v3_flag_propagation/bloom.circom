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
    
    signal input parentStates[numInputs][m]; // bloom filters from input utxos
    signal input unionState[m]; // this is the merged bloom filter claimed by the user

    signal intermediate[numInputs-1][m];
    
    for (var j = 0; j < m; j++) {
        // enforce binary outputs
        for (var i = 0; i < numInputs; i++) {
            parentStates[i][j] * (parentStates[i][j] - 1) === 0;
        }
        unionState[j] * (unionState[j] - 1) === 0;
        
        // compute OR:  
        if (numInputs == 2) {
            // this is simply A OR B = A + B - A*B
            unionState[j] === parentStates[0][j] + parentStates[1][j] - parentStates[0][j] * parentStates[1][j];
        } else {
            // first OR: parentStates[0] OR parentStates[1]
            intermediate[0][j] <== parentStates[0][j] + parentStates[1][j] - parentStates[0][j] * parentStates[1][j];
            
            // subsequent ORs: intermediate[i-1] OR parentStates[i+1]
            for (var i = 1; i < numInputs - 1; i++) {
                intermediate[i][j] <== intermediate[i-1][j] + parentStates[i+1][j] - intermediate[i-1][j] * parentStates[i+1][j];
            }
            
            // final result must match the claimed union at the given index
            unionState[j] === intermediate[numInputs-2][j];
        }
    }
}

// WIP
template BloomFilterUnionWithBinding(m, numInputs) {

    signal input parentStates[numInputs][m];
    signal input unionState[m];
    
    // we also take inputs from existing tx circuit outputs
    signal input outputCommitment;  // This should match the outputCommitment from Transaction
    signal input outAmount;
    signal input outPubkey;
    signal input outBlinding;
    
// steps:
//  - first we verify bloom filter union is correct (make a component of BloomFilterUnion)
//  - then we bind the chain state to the unioned bloom filter: 
//  - compress the large bloom filter into a manageable hash (e.g. take first 254 bits of unionState)
//  - convert those bits into a single number and hash (poseidon componente) it with the same blinding 
//  - this creates a commitment that binds the chain state to the unioned bloom filter
//  - chainBoundCommitment: a hash that proves this UTXO inherits the correct chain state
}