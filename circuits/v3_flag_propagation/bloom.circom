pragma circom 2.1.9;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "./smtverifier.circom";

// -----------------------------------------------------------------------------
//  Rolling Poseidon hash for arbitrary‑length vectors.
//  Uses width‑3 Poseidon permutations to absorb one element at a time:
//      state = Poseidon( state || element || 0 )
//  Width 3 (t = 3) is within the supported range (2 ≤ t ≤ 17) of circomlib,
//  so this helper lets us hash vectors of any compile‑time length without ever
//  calling Poseidon with an unsupported width (e.g. 65).
// -----------------------------------------------------------------------------
template PoseidonHashVec(n) {
    signal input inputs[n];
    signal output out;

    component roundHashers[n];
    signal chain[n + 1];
    chain[0] <== 0;
    for (var i = 0; i < n; i++) {
        roundHashers[i] = Poseidon(3);
        roundHashers[i].inputs[0] <== chain[i];      // previous running state
        roundHashers[i].inputs[1] <== inputs[i];     // new field element
        roundHashers[i].inputs[2] <== 0;             // padding / capacity
        chain[i + 1] <== roundHashers[i].out;
    }
    out <== chain[n];
}

// -----------------------------------------------------------------------------
//  Helper: bit‑wise OR of two 254‑bit field elements
// -----------------------------------------------------------------------------
template BitwiseORChunk() {
    signal input a;
    signal input b;
    signal output out;

    component aBits = Num2Bits(254);
    component bBits = Num2Bits(254);
    aBits.in <== a;
    bBits.in <== b;

    signal orBits[254];
    for (var i = 0; i < 254; i++) {
        // Boolean OR: a + b − a·b
        orBits[i] <== aBits.out[i] + bBits.out[i] - aBits.out[i]*bBits.out[i];
    }

    component bitsToNum = Bits2Num(254);
    for (var i = 0; i < 254; i++) {
        bitsToNum.in[i] <== orBits[i];
    }
    out <== bitsToNum.out;
}

// -----------------------------------------------------------------------------
//  Bloom‑filter membership test:
//
//  ‑ chainStateChunks:  current bloom‑filter state in **numChunks** limbs
//  ‑ flaggedStateChunks:  bloom bits we want to check (exactly *k* bits set)
//  output notInSet = 1  ⇨  at least one of the *k* bits is **not** set
//          notInSet = 0  ⇨  all *k* bits are already present
// -----------------------------------------------------------------------------
template BloomFilterFieldChunked(numChunks, k, depth) {
    signal input  chainStateChunks[numChunks];
    signal input  flaggedStateChunks[numChunks];
    signal output notInSet;

    // ------------------------------------------------------------------
    //  SMT‑related inputs (used to prove that the flagged commitment
    //  is *indeed* what appears in the account‑tree)
    // ------------------------------------------------------------------
    signal input root;
    signal input siblings[depth];
    signal input key;
    signal input value;         // Poseidon hash(flaggedStateChunks)
    signal input auxKey;
    signal input auxValue;
    signal input auxIsEmpty;
    signal input isExclusion;

    // Poseidon(hash) of flaggedStateChunks must equal *value*
    component flaggedHasher = PoseidonHashVec(numChunks);
    for (var i = 0; i < numChunks; i++) {
        flaggedHasher.inputs[i] <== flaggedStateChunks[i];
    }
    flaggedHasher.out === value;

    // Verify the sparse‑Merkle inclusion/exclusion proof
    component smtVerifier = SMTVerifier(depth);
    smtVerifier.root       <== root;
    for (var i = 0; i < depth; i++) {
        smtVerifier.siblings[i] <== siblings[i];
    }
    smtVerifier.key        <== key;
    smtVerifier.value      <== value;
    smtVerifier.auxKey     <== auxKey;
    smtVerifier.auxValue   <== auxValue;
    smtVerifier.auxIsEmpty <== auxIsEmpty;
    smtVerifier.isExclusion<== isExclusion;

    // ------------------------------------------------------------------
    // 1.  Count how many of the *k* flagged bits are already present
    // ------------------------------------------------------------------
    component chainBits[numChunks];
    component flaggedBits[numChunks];
    for (var c = 0; c < numChunks; c++) {
        chainBits[c]   = Num2Bits(254);
        flaggedBits[c] = Num2Bits(254);
        chainBits[c].in   <== chainStateChunks[c];
        flaggedBits[c].in <== flaggedStateChunks[c];
    }

    // andBits[c][i] = flaggedBit_i AND chainBit_i
    signal andBits[numChunks][254];
    for (var c = 0; c < numChunks; c++) {
        var chunkSize = (c < numChunks - 1) ? 254 : 74;
        for (var i = 0; i < chunkSize; i++) {
            andBits[c][i] <== chainBits[c].out[i] * flaggedBits[c].out[i];
        }
        // Un‑used high bits of the last (short) chunk are zero‑padded
        if (chunkSize < 254) {
            for (var j = chunkSize; j < 254; j++) {
                andBits[c][j] <== 0;
            }
        }
    }

    // Convert every 254‑bit AND slice to a number
    component chunkSum[numChunks];
    signal intersectionCounts[numChunks];
    for (var c = 0; c < numChunks; c++) {
        chunkSum[c] = Bits2Num(254);
        for (var i = 0; i < 254; i++) {
            chunkSum[c].in[i] <== andBits[c][i];
        }
        intersectionCounts[c] <== chunkSum[c].out;
    }

    // ------------------------------------------------------------------
    // 2.  Accumulate all chunk sums → totalIntersection
    // ------------------------------------------------------------------
    signal partial[numChunks + 1];
    partial[0] <== 0;
    for (var c = 0; c < numChunks; c++) {
        partial[c + 1] <== partial[c] + intersectionCounts[c];
    }
    signal totalIntersection;
    totalIntersection <== partial[numChunks];

    // ------------------------------------------------------------------
    // 3.  Compare with k  →  derive notInSet flag
    // ------------------------------------------------------------------
    component eq = IsEqual();
    eq.in[0] <== totalIntersection;
    eq.in[1] <== k;

    notInSet <== 1 - eq.out;
}

// -----------------------------------------------------------------------------
//  Verify that **unionState** is the component‑wise OR of the first
//  *numActiveInputs* entries in *parentStates*.  All inputs are already
//  chunked in **numChunks** limbs of 254 bits (74 bits for the last chunk).
// -----------------------------------------------------------------------------
template BloomFilterUnionFieldChunked(numChunks, maxInputs) {
    signal input numActiveInputs;
    signal input parentStates[maxInputs][numChunks];
    signal input unionState[numChunks];

    // -------------------- activity flags ------------------------------
    component lte[maxInputs];
    signal    isActive[maxInputs];
    for (var i = 0; i < maxInputs; i++) {
        lte[i] = LessEqThan(5);
        lte[i].in[0]  <== i;
        lte[i].in[1]  <== numActiveInputs - 1;
        isActive[i]   <== lte[i].out;        // 1 ⇨ active
    }

    // -------------------- OR reduction by chunk -----------------------
    signal    intermediate[numChunks][maxInputs];
    component orGates[numChunks][maxInputs-1];

    for (var c = 0; c < numChunks; c++) {
        // first element
        intermediate[c][0] <== parentStates[0][c] * isActive[0];

        // chain ORs through the rest
        for (var i = 1; i < maxInputs; i++) {
            orGates[c][i-1] = BitwiseORChunk();
            orGates[c][i-1].a <== intermediate[c][i-1];
            orGates[c][i-1].b <== parentStates[i][c] * isActive[i];

            // if the element is inactive, propagate previous value
            intermediate[c][i] <== (isActive[i] * (orGates[c][i-1].out - intermediate[c][i-1])) + intermediate[c][i-1];
        }

        // result must match claimed union
        unionState[c] === intermediate[c][maxInputs-1];
    }
}

// -----------------------------------------------------------------------------
//  Hashing helper used elsewhere in the circuits
// -----------------------------------------------------------------------------
template ParentStatesHasherFieldChunked(numChunks, maxInputs) {
    signal input numActiveInputs;
    signal input parentStates[maxInputs][numChunks];
    signal output hash;

    // activity flags
    component lte[maxInputs];
    signal isActive[maxInputs];
    for (var i = 0; i < maxInputs; i++) {
        lte[i] = LessEqThan(5);
        lte[i].in[0] <== i;
        lte[i].in[1] <== numActiveInputs - 1;
        isActive[i] <== lte[i].out;
    }

    // hash each individual parent state
    component stateHashers[maxInputs];
    for (var i = 0; i < maxInputs; i++) {
        stateHashers[i] = PoseidonHashVec(numChunks);
        for (var c = 0; c < numChunks; c++) {
            stateHashers[i].inputs[c] <== parentStates[i][c];
        }
    }

    // hash all active parents together
    component finalHasher = PoseidonHashVec(maxInputs);
    for (var i = 0; i < maxInputs; i++) {
        finalHasher.inputs[i] <== stateHashers[i].out * isActive[i];
    }
    hash <== finalHasher.out;
}
